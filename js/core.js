// Core logic: key derivation, vault encryption, generator, leak check, sync merge.
// No DOM access in this file so it can be unit tested outside the browser.
import WORDS from '../vendor/wordlist.js';

const te = new TextEncoder();
const td = new TextDecoder();

export const b64 = {
  enc(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
    return btoa(s);
  },
  dec(str) {
    const bin = atob(str);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  },
};

export function randomBytes(n) {
  const u8 = new Uint8Array(n);
  crypto.getRandomValues(u8);
  return u8;
}

/* ---------- Key derivation ---------- */

export const KDF_DEFAULT = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1 });

// The server supplies the KDF settings at sign-in. Refuse anything weak so a
// tampered server cannot talk the client into a cheap, crackable derivation.
export function checkKdf(kdf) {
  const ok = kdf && kdf.alg === 'argon2id'
    && Number.isInteger(kdf.m) && kdf.m >= 19456 && kdf.m <= 1048576
    && Number.isInteger(kdf.t) && kdf.t >= 2 && kdf.t <= 20
    && Number.isInteger(kdf.p) && kdf.p >= 1 && kdf.p <= 4;
  if (!ok) throw new Error('Unsafe key derivation settings, refusing to continue.');
  return { alg: kdf.alg, m: kdf.m, t: kdf.t, p: kdf.p };
}

let argon2idImpl = null;
export function setArgon2(fn) { argon2idImpl = fn; }

// master password -> Argon2id -> HKDF -> { encKey (stays on device), auth (sent to server) }
export async function deriveKeys(password, saltB64, kdfIn) {
  const kdf = checkKdf(kdfIn);
  const salt = b64.dec(saltB64);
  if (salt.length < 16) throw new Error('Bad salt.');
  const master = await argon2idImpl({
    password: password.normalize('NFKC'),
    salt,
    parallelism: kdf.p,
    iterations: kdf.t,
    memorySize: kdf.m,
    hashLength: 32,
    outputType: 'binary',
  });
  const hk = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey', 'deriveBits']);
  master.fill(0);
  const params = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) });
  const encKey = await crypto.subtle.deriveKey(
    params('vault-enc-v1'), hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const authBits = await crypto.subtle.deriveBits(params('vault-auth-v1'), hk, 256);
  return { encKey, auth: b64.enc(new Uint8Array(authBits)) };
}

/* ---------- Vault encryption (AES-256-GCM) ---------- */

const aad = (username) => te.encode('vault-v1|' + username);

export async function encryptVault(encKey, username, items) {
  const iv = randomBytes(12); // fresh nonce on every save
  const pt = te.encode(JSON.stringify({ items }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(username) }, encKey, pt);
  return JSON.stringify({ v: 1, iv: b64.enc(iv), ct: b64.enc(new Uint8Array(ct)) });
}

export async function decryptVault(encKey, username, blob) {
  const o = JSON.parse(blob);
  if (o.v !== 1) throw new Error('Unknown vault version.');
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64.dec(o.iv), additionalData: aad(username) }, encKey, b64.dec(o.ct));
  const data = JSON.parse(td.decode(pt));
  return Array.isArray(data.items) ? data.items : [];
}

/* ---------- Sync merge ---------- */

// Per-entry last-write-wins. Deletions are kept as tombstones so they sync too.
export function mergeItems(local, remote) {
  const map = new Map();
  for (const it of remote) map.set(it.id, it);
  for (const it of local) {
    const other = map.get(it.id);
    if (!other || (it.updatedAt || 0) > (other.updatedAt || 0)) map.set(it.id, it);
  }
  return [...map.values()];
}

export function newId() {
  return crypto.randomUUID ? crypto.randomUUID() : b64.enc(randomBytes(16));
}

/* ---------- Generator ---------- */

// Unbiased integer in [0, n) using rejection sampling.
export function randomInt(n) {
  if (!(n > 0) || n > 0xffffffff) throw new Error('range');
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % n;
}

export const CHARSETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
});

export function generatePassword({ length = 20, lower = true, upper = true, digits = true, symbols = true } = {}) {
  const sets = [];
  if (lower) sets.push(CHARSETS.lower);
  if (upper) sets.push(CHARSETS.upper);
  if (digits) sets.push(CHARSETS.digits);
  if (symbols) sets.push(CHARSETS.symbols);
  if (!sets.length) sets.push(CHARSETS.lower);
  length = Math.max(sets.length, Math.min(128, length | 0));
  const pool = sets.join('');
  for (;;) {
    let out = '';
    for (let i = 0; i < length; i++) out += pool[randomInt(pool.length)];
    // Re-roll whole candidates until every chosen set is present (keeps the result uniform).
    if (sets.every((s) => [...out].some((c) => s.includes(c)))) {
      return { value: out, bits: Math.round(length * Math.log2(pool.length)) };
    }
  }
}

export function generatePassphrase({ words = 6, separator = '-', capitalize = false, number = false } = {}) {
  words = Math.max(3, Math.min(12, words | 0));
  const parts = [];
  for (let i = 0; i < words; i++) {
    let w = WORDS[randomInt(WORDS.length)];
    if (capitalize) w = w[0].toUpperCase() + w.slice(1);
    parts.push(w);
  }
  let bits = words * Math.log2(WORDS.length);
  if (number) { parts.push(String(randomInt(10))); bits += Math.log2(10); }
  return { value: parts.join(separator), bits: Math.round(bits) };
}

/* ---------- Strength estimate for stored passwords ---------- */

export function estimateBits(pw) {
  if (!pw) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const unique = new Set(pw).size;
  // Repeated characters add little, so count unique characters at full value and repeats at a quarter.
  const effective = unique + (pw.length - unique) * 0.25;
  return Math.round(effective * Math.log2(pool || 1));
}

export const isWeak = (pw) => pw.length < 12 || estimateBits(pw) < 60;

/* ---------- Leak check (Have I Been Pwned, k-anonymity) ---------- */

export async function sha1Hex(str) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-1', te.encode(str)));
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

export function parseRange(text, suffix) {
  for (const line of text.split('\n')) {
    const [suf, count] = line.trim().split(':');
    if (suf && suf.toUpperCase() === suffix) return parseInt(count, 10) || 0;
  }
  return 0;
}

// Only the first 5 characters of the SHA-1 hash leave the device.
// Returns how many times the password appears in known breaches (0 = not found).
export async function pwnedCount(password, fetchFn = fetch) {
  const hash = await sha1Hex(password);
  const res = await fetchFn('https://api.pwnedpasswords.com/range/' + hash.slice(0, 5), {
    credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store',
  });
  if (!res.ok) throw new Error('Leak check service unavailable (' + res.status + ').');
  return parseRange(await res.text(), hash.slice(5));
}

export function findReused(items) {
  const byPw = new Map();
  for (const it of items) {
    if (it.deleted || !it.password) continue;
    if (!byPw.has(it.password)) byPw.set(it.password, []);
    byPw.get(it.password).push(it);
  }
  return [...byPw.values()].filter((g) => g.length > 1);
}
