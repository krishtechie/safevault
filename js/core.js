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

const hkdfParams = (info, salt = new Uint8Array(0)) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) });
const aesKey = (hk, info, salt) => crypto.subtle.deriveKey(
  hkdfParams(info, salt), hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

// master password -> Argon2id -> HKDF -> three separate keys:
//   kek       wraps the vault key (stays on device)
//   legacyRaw the vault key of accounts created before key wrapping (stays on device)
//   auth      sign-in key (sent to server, which stores only a hash of it)
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
  const kek = await aesKey(hk, 'vault-kek-v1');
  const legacyRaw = new Uint8Array(await crypto.subtle.deriveBits(hkdfParams('vault-enc-v1'), hk, 256));
  const authBits = await crypto.subtle.deriveBits(hkdfParams('vault-auth-v1'), hk, 256);
  return { kek, legacyRaw, auth: b64.enc(new Uint8Array(authBits)) };
}

/* ---------- Vault key and key wrapping ---------- */

// The vault key encrypts the vault and never changes. Changing the master password or
// recovering the account only re-wraps this key, so the vault data itself is never rewritten.
export const newVaultKeyRaw = () => randomBytes(32);

export function importVaultKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

const wrapAad = (kind, username) => te.encode(`vault-wrap-v1|${kind}|${username}`);

// kind is 'pw' (wrapped by the master password key) or 'rec' (wrapped by the recovery key).
export async function wrapKey(kek, username, raw, kind = 'pw') {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: wrapAad(kind, username) }, kek, raw);
  return JSON.stringify({ v: 1, iv: b64.enc(iv), ct: b64.enc(new Uint8Array(ct)) });
}

export async function unwrapKey(kek, username, wrap, kind = 'pw') {
  const o = JSON.parse(wrap);
  if (o.v !== 1) throw new Error('Unknown key format.');
  const raw = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64.dec(o.iv), additionalData: wrapAad(kind, username) }, kek, b64.dec(o.ct));
  if (raw.byteLength !== 32) throw new Error('Bad key.');
  return new Uint8Array(raw);
}

// Small strings (the sign-in key) encrypted under the vault key for the stay-unlocked feature.
export async function sealText(key, text) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text));
  return { iv: b64.enc(iv), ct: b64.enc(new Uint8Array(ct)) };
}
export async function openText(key, sealed) {
  return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(sealed.iv) }, key, b64.dec(sealed.ct)));
}

/* ---------- Quick unlock: PIN and Face ID / Touch ID ---------- */

// Six digits, and not an obvious one.
export function checkPin(pin) {
  if (!/^\d{6}$/.test(pin)) throw new Error('pin_format');
  if (/^(\d)\1{5}$/.test(pin) || '01234567890123456789'.includes(pin) || '98765432109876543210'.includes(pin)) throw new Error('pin_simple');
  return pin;
}

// What the server checks. It is salted with a random value kept only on this device, so a
// stolen server file alone cannot be used to guess the PIN.
export async function derivePinAuth(pin, kdev) {
  const slow = await argon2idImpl({
    password: pin, salt: kdev.slice(0, 16), parallelism: 1, iterations: 2, memorySize: 19456, hashLength: 32, outputType: 'binary',
  });
  const hk = await crypto.subtle.importKey('raw', slow, 'HKDF', false, ['deriveBits']);
  slow.fill(0);
  return b64.enc(new Uint8Array(await crypto.subtle.deriveBits(hkdfParams('vault-pin-auth-v1', kdev), hk, 256)));
}

// The key that wraps the vault key for PIN unlock is built from two random halves: one stored
// on the device, one held by the server and released only for the right PIN (three tries).
export async function pinKek(kdev, ksrv) {
  if (kdev.length !== 32 || ksrv.length !== 32) throw new Error('Bad key.');
  const ikm = new Uint8Array(64);
  ikm.set(kdev, 0);
  ikm.set(ksrv, 32);
  const hk = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  ikm.fill(0);
  return aesKey(hk, 'vault-pin-kek-v1');
}

// Face ID / Touch ID: the device's secure hardware returns a secret only after a successful
// face or fingerprint check (WebAuthn PRF). That secret becomes the wrapping key.
export async function bioKek(secret) {
  const bytes = new Uint8Array(secret);
  if (bytes.length < 32) throw new Error('Bad key.');
  const hk = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
  return aesKey(hk, 'vault-bio-kek-v1');
}

/* ---------- Recovery key ---------- */

// 160 random bits shown as 8 groups of 4 characters. No I, L, O or U, to avoid misreading.
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateRecoveryCode() {
  const bytes = randomBytes(20);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < 160; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out.match(/.{4}/g).join('-');
}

export function normalizeRecoveryCode(input) {
  const s = String(input).toUpperCase().replace(/[^0-9A-Z]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length !== 32 || [...s].some((c) => !B32.includes(c))) throw new Error('bad_recovery_code');
  return s;
}

// The recovery code has 160 bits of entropy, so a plain HKDF is enough (no slow hashing needed).
export async function deriveRecoveryKeys(code, username) {
  const hk = await crypto.subtle.importKey('raw', te.encode(normalizeRecoveryCode(code)), 'HKDF', false, ['deriveKey', 'deriveBits']);
  const salt = te.encode('vault-recovery|' + username);
  const kek = await aesKey(hk, 'vault-rec-kek-v1', salt);
  const authBits = await crypto.subtle.deriveBits(hkdfParams('vault-rec-auth-v1', salt), hk, 256);
  return { kek, auth: b64.enc(new Uint8Array(authBits)) };
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
  return sanitizeItems(data.items);
}

/* ---------- Field rules ---------- */

// Characters that never belong in a credential: control codes, zero-width characters and
// text-direction overrides (used to disguise text).
const HIDDEN_SRC = '\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff';
const NOTES_SRC = '\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff';
const hidden = (v) => new RegExp('[' + HIDDEN_SRC + ']').test(v);
const hiddenNotes = (v) => new RegExp('[' + NOTES_SRC + ']').test(v); // notes may keep line breaks and tabs
export const LIMITS = Object.freeze({ title: 100, username: 254, password: 256, url: 2048, notes: 5000 });

// Returns '' for empty input or a normalized http(s) address. Anything else (javascript:, data:, file:) is refused.
export function normalizeUrl(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return '';
  if (raw.length > LIMITS.url || hidden(raw) || /\s/.test(raw)) throw new Error('bad_url');
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : 'https://' + raw); } catch { throw new Error('bad_url'); }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || !u.hostname.includes('.') || u.username || u.password) throw new Error('bad_url');
  return u.href;
}

// Checks what was typed into the entry form. Throws an error code naming the first problem.
export function validateEntry(d) {
  const title = String(d.title ?? '').trim();
  const username = String(d.username ?? '').trim();
  const password = String(d.password ?? '');
  const notes = String(d.notes ?? '');
  if (!title) throw new Error('need_title');
  if (title.length > LIMITS.title || hidden(title)) throw new Error('bad_title');
  if (username.length > LIMITS.username || hidden(username) || /[\s<>"`\\]/.test(username)) throw new Error('bad_username_field');
  if (!password) throw new Error('need_password');
  if (password.length > LIMITS.password || hidden(password)) throw new Error('bad_password');
  if (password !== password.trim()) throw new Error('password_spaces');
  if (notes.length > LIMITS.notes || hiddenNotes(notes)) throw new Error('bad_notes');
  return { title, username, password, url: normalizeUrl(d.url), notes };
}

// Everything read from the server, the device copy or a backup file passes through here:
// unknown fields are dropped, text is cleaned and cut to length, unsafe addresses are blanked.
export function sanitizeItems(items) {
  const out = [];
  const seen = new Set();
  const text = (v, max, src = HIDDEN_SRC) => (typeof v === 'string' ? v.replace(new RegExp('[' + src + ']', 'g'), '').slice(0, max) : '');
  const time = (v) => (Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);
  for (const it of Array.isArray(items) ? items : []) {
    if (!it || typeof it !== 'object' || typeof it.id !== 'string' || !/^[A-Za-z0-9_+/=-]{1,64}$/.test(it.id) || seen.has(it.id)) continue;
    seen.add(it.id);
    if (it.deleted === true) { out.push({ id: it.id, deleted: true, updatedAt: time(it.updatedAt) }); continue; }
    let url = '';
    try { url = normalizeUrl(it.url); } catch { /* blank it */ }
    out.push({
      id: it.id,
      title: text(it.title, LIMITS.title).trim(),
      username: text(it.username, LIMITS.username).trim(),
      password: text(it.password, LIMITS.password),
      url,
      notes: text(it.notes, LIMITS.notes, NOTES_SRC),
      createdAt: time(it.createdAt),
      updatedAt: time(it.updatedAt),
      deleted: false,
    });
  }
  return out;
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

/* ---------- Access log helpers ---------- */

// Turns a browser's user-agent text into something readable, such as "iPhone · Safari".
export function describeDevice(ua) {
  const s = String(ua || '');
  const device = /iPhone/.test(s) ? 'iPhone' : /iPad/.test(s) ? 'iPad' : /Android/.test(s) ? 'Android'
    : /Macintosh|Mac OS X/.test(s) ? 'Mac' : /Windows/.test(s) ? 'Windows PC' : /CrOS/.test(s) ? 'Chromebook'
      : /Linux/.test(s) ? 'Linux' : 'Unknown device';
  const browser = /Edg\//.test(s) ? 'Edge' : /OPR\//.test(s) ? 'Opera' : /Firefox\/|FxiOS/.test(s) ? 'Firefox'
    : /CriOS|Chrome\//.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari'
      : /curl|python|wget|bot|http/i.test(s) ? 'Script or tool' : 'Unknown browser';
  return device + ' · ' + browser;
}

// kind: ok (normal), fail (someone got it wrong), change (a security setting changed), save (vault edits)
export const LOG_EVENTS = Object.freeze({
  register: ['Account created', 'change'],
  login_ok: ['Signed in with master password', 'ok'],
  login_fail: ['Failed sign-in: wrong master password', 'fail'],
  logout: ['Signed out', 'ok'],
  pin_ok: ['Unlocked with PIN', 'ok'],
  pin_fail: ['Wrong PIN entered', 'fail'],
  pin_locked: ['PIN turned off after 3 wrong tries', 'fail'],
  pin_set: ['PIN unlock turned on', 'change'],
  pin_clear: ['PIN unlock turned off', 'change'],
  bio_ok: ['Unlocked with Face ID or Touch ID', 'ok'],
  bio_on: ['Face ID or Touch ID turned on', 'change'],
  bio_off: ['Face ID or Touch ID turned off', 'change'],
  rekey: ['Master password changed', 'change'],
  recovery_set: ['Recovery key created', 'change'],
  recovery_clear: ['Recovery key removed', 'change'],
  recover_ok: ['Account recovered with the recovery key', 'change'],
  recover_fail: ['Failed recovery attempt: wrong recovery key', 'fail'],
  save: ['Vault changes saved', 'save'],
});

// type: all | signin | fail | change | save.  days: 0 means no time limit.
export function filterLog(entries, { type = 'all', days = 0, text = '', now = Date.now() } = {}) {
  const q = text.trim().toLowerCase();
  const since = days > 0 ? now / 1000 - days * 86400 : 0;
  return entries.filter((en) => {
    const [label, kind] = LOG_EVENTS[en.e] || ['Other activity', 'ok'];
    if (type === 'signin' && !['login_ok', 'pin_ok', 'bio_ok', 'logout', 'register'].includes(en.e)) return false;
    if (type !== 'all' && type !== 'signin' && kind !== type) return false;
    if (en.t < since) return false;
    return !q || [label, en.ip, describeDevice(en.ua), en.ua].some((v) => String(v).toLowerCase().includes(q));
  });
}
