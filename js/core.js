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
  const out = { alg: kdf.alg, m: kdf.m, t: kdf.t, p: kdf.p };
  if (kdf.sk === 1) out.sk = 1; // the account also needs its secret key
  return out;
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
//
// With a secret key on the account (kdf.sk), the Argon2id output is mixed with that key before the split.
// The secret key is random, lives only on the person's devices and on paper, and never reaches the server.
// So neither a stolen copy of the server's files nor a stolen master password is enough by itself:
// guessing passwords against the server's data is pointless without the 125 random bits.
export async function deriveKeys(password, saltB64, kdfIn, secretKey = null) {
  const kdf = checkKdf(kdfIn);
  const salt = b64.dec(saltB64);
  if (salt.length < 16) throw new Error('Bad salt.');
  let sk = null;
  if (kdf.sk) {
    if (!secretKey) throw new Error('need_secret_key');
    sk = te.encode('vault-secret-key-v1|' + normalizeSecretKey(secretKey));
  }
  let master = await argon2idImpl({
    password: password.normalize('NFKC'),
    salt,
    parallelism: kdf.p,
    iterations: kdf.t,
    memorySize: kdf.m,
    hashLength: 32,
    outputType: 'binary',
  });
  if (sk) {
    const mac = await crypto.subtle.importKey('raw', sk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mixed = new Uint8Array(await crypto.subtle.sign('HMAC', mac, master));
    master.fill(0);
    master = mixed;
  }
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

// The secret key: 25 characters, 125 random bits, shown in groups of five.
export function generateSecretKey() {
  const bytes = randomBytes(16);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < 125; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out.match(/.{5}/g).join('-');
}
export function normalizeSecretKey(input) {
  const s = String(input).toUpperCase().replace(/[^0-9A-Z]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (s.length !== 25 || [...s].some((c) => !B32.includes(c))) throw new Error('bad_secret_key');
  return s;
}
export const formatSecretKey = (input) => normalizeSecretKey(input).match(/.{5}/g).join('-');

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

// Raised whenever entries gain a field that an older copy of the app would silently drop.
// A device running older code then refuses to open (and overwrite) a newer vault and asks for a reload.
export const VAULT_FORMAT = 4;

export async function encryptVault(encKey, username, items) {
  const iv = randomBytes(12); // fresh nonce on every save
  const pt = te.encode(JSON.stringify({ fmt: VAULT_FORMAT, items }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(username) }, encKey, pt);
  return JSON.stringify({ v: 1, iv: b64.enc(iv), ct: b64.enc(new Uint8Array(ct)) });
}

export async function decryptVault(encKey, username, blob) {
  const o = JSON.parse(blob);
  if (o.v !== 1) throw new Error('Unknown vault version.');
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64.dec(o.iv), additionalData: aad(username) }, encKey, b64.dec(o.ct));
  const data = JSON.parse(td.decode(pt));
  if (Number.isInteger(data.fmt) && data.fmt > VAULT_FORMAT) throw new Error('newer_format');
  return sanitizeItems(data.items);
}

/* ---------- Authenticator codes stored in entries (TOTP, RFC 6238) ---------- */

const B32_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Accepts the key a website shows during two-factor setup, or the otpauth:// link behind its QR code.
// Returns the bare key in upper case, or '' for empty input.
export function normalizeTotp(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return '';
  let key = raw;
  if (/^otpauth:/i.test(raw)) {
    if (!/^otpauth:\/\/totp\//i.test(raw)) throw new Error('totp_unsupported');
    const param = (name) => {
      const m = raw.match(new RegExp('[?&]' + name + '=([^&#]*)', 'i'));
      return m ? decodeURIComponent(m[1]) : '';
    };
    key = param('secret');
    // Only the settings nearly every site uses are supported: SHA-1, 6 digits, 30 seconds.
    if ((param('algorithm') || 'SHA1').toUpperCase() !== 'SHA1' || (param('digits') || '6') !== '6' || (param('period') || '30') !== '30') {
      throw new Error('totp_unsupported');
    }
  }
  key = key.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  if (!/^[A-Z2-7]{16,128}$/.test(key)) throw new Error('bad_totp_secret');
  return key;
}

function b32Bytes(key) {
  let bits = '';
  for (const c of key) bits += B32_STD.indexOf(c).toString(2).padStart(5, '0');
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}

// The current 6-digit code and how many seconds it stays valid.
export async function totpNow(key, nowMs = Date.now()) {
  const step = Math.floor(nowMs / 30000);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setUint32(4, step >>> 0);
  new DataView(msg.buffer).setUint32(0, Math.floor(step / 0x100000000));
  const k = await crypto.subtle.importKey('raw', b32Bytes(normalizeTotp(key)), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  const o = h[19] & 0x0f;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000;
  return { code: String(n).padStart(6, '0'), left: 30 - Math.floor((nowMs / 1000) % 30) };
}

/* ---------- List order ---------- */

// Favourites first, then the entries used most recently on this device, then everything else by name.
// recents maps entry id to the time it was last used here. Returns [{ label, items }] with empty groups left out.
export function groupForList(items, recents = {}, maxRecent = 5) {
  const byName = (a, b) => (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' });
  const favs = items.filter((it) => it.fav).sort(byName);
  const rest = items.filter((it) => !it.fav);
  const recent = rest.filter((it) => recents[it.id] > 0).sort((a, b) => recents[b.id] - recents[a.id]).slice(0, maxRecent);
  const inRecent = new Set(recent.map((it) => it.id));
  const others = rest.filter((it) => !inRecent.has(it.id)).sort(byName);
  return [
    { label: 'Favourites', items: favs },
    { label: 'Recently used', items: recent },
    { label: favs.length || recent.length ? 'All passwords' : '', items: others },
  ].filter((g) => g.items.length);
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
/* ---------- Tags ---------- */

export const TAG_MAX = 6;     // per entry
export const TAG_LEN = 24;    // characters per tag
// Accepts what was typed ("Work, Banking") or a stored list. Returns a clean list: trimmed, single spaces,
// no repeats (ignoring upper and lower case). strict = true refuses what does not fit instead of trimming it.
export function normalizeTags(input, strict = false) {
  const parts = Array.isArray(input) ? input : String(input ?? '').split(/[,;\n]/);
  const out = [];
  const seen = new Set();
  for (const raw of parts) {
    if (typeof raw !== 'string') continue;
    let tag = raw.replace(new RegExp('[' + HIDDEN_SRC + '<>]', 'g'), ' ').replace(/\s+/g, ' ').trim();
    if (!tag) continue;
    if ([...tag].length > TAG_LEN) {
      if (strict) throw new Error('bad_tags');
      tag = [...tag].slice(0, TAG_LEN).join('').trim();
    }
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  if (out.length > TAG_MAX) {
    if (strict) throw new Error('too_many_tags');
    out.length = TAG_MAX;
  }
  return out;
}
// Every tag in use on live entries with how many entries carry it, A to Z. Spelling follows the first entry seen.
export function allTags(items) {
  const map = new Map();
  for (const it of items) {
    if (it.deleted || it.trashedAt) continue;
    for (const tag of it.tags || []) {
      const key = tag.toLowerCase();
      if (!map.has(key)) map.set(key, { tag, count: 0 });
      map.get(key).count++;
    }
  }
  return [...map.values()].sort((a, b) => a.tag.localeCompare(b.tag, undefined, { sensitivity: 'base' }));
}
export const hasTag = (it, tag) => (it.tags || []).some((t) => t.toLowerCase() === String(tag).toLowerCase());

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
  const out = { title, username, password, url: normalizeUrl(d.url), notes };
  const totp = normalizeTotp(d.totp);
  if (totp) out.totp = totp;
  const tags = normalizeTags(d.tags, true);
  if (tags.length) out.tags = tags;
  return out;
}

// Everything read from the server, the device copy or a backup file passes through here:
// unknown fields are dropped, text is cleaned and cut to length, unsafe addresses are blanked.
// How many earlier passwords an entry remembers. They live inside the encrypted entry like everything else.
export const PW_HISTORY = 5;
// The history an entry should carry once its password has been replaced: the outgoing password goes on top.
// Changing a password to itself, or to and from blank, adds nothing.
export function pushPasswordHistory(prev, nextPassword) {
  const hist = Array.isArray(prev.hist) ? prev.hist : [];
  if (!prev.password || prev.password === nextPassword) return hist;
  const at = prev.pwAt || prev.updatedAt || 0;
  return [{ p: prev.password, at }, ...hist.filter((h) => h.p !== prev.password)].slice(0, PW_HISTORY);
}

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
    const clean = {
      id: it.id,
      title: text(it.title, LIMITS.title).trim(),
      username: text(it.username, LIMITS.username).trim(),
      password: text(it.password, LIMITS.password),
      url,
      notes: text(it.notes, LIMITS.notes, NOTES_SRC),
      createdAt: time(it.createdAt),
      updatedAt: time(it.updatedAt),
      deleted: false,
    };
    // Optional fields are present only when set, so older entries keep their exact shape.
    if (it.fav === true) clean.fav = true;
    if (time(it.trashedAt)) clean.trashedAt = time(it.trashedAt); // in Recently deleted since this time
    if (time(it.pwAt)) clean.pwAt = time(it.pwAt);                // when the password itself was last set
    try { const key = normalizeTotp(it.totp); if (key) clean.totp = key; } catch { /* drop an unusable key */ }
    const tags = normalizeTags(Array.isArray(it.tags) ? it.tags : []);
    if (tags.length) clean.tags = tags;
    // Earlier passwords of this entry, newest first: { p: the password, at: when it was set }.
    const hist = (Array.isArray(it.hist) ? it.hist : [])
      .filter((h) => h && typeof h === 'object')
      .map((h) => ({ p: text(h.p, LIMITS.password), at: time(h.at) }))
      .filter((h) => h.p)
      .slice(0, PW_HISTORY);
    if (hist.length) clean.hist = hist;
    out.push(clean);
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
    if (it.deleted || it.trashedAt || !it.password) continue;
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
  login_renew: ['Session renewed by the app (no password typed)', 'ok'],
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
  restore: ['Vault restored from a device after the server copy went backwards', 'change'],
  rollback_seen: ['A device found an older or swapped vault copy on the server', 'fail'],
  totp_on: ['Two-factor sign-in turned on', 'change'],
  totp_off: ['Two-factor sign-in turned off', 'change'],
  totp_fail: ['Wrong authenticator code after a correct master password', 'fail'],
  device_trusted: ['New device approved with an authenticator code', 'change'],
  device_off: ['A device was signed out from another device', 'change'],
  device_new: ['Signed in on a new device', 'change'],
  backup_used: ['Signed in with a two-factor backup code', 'change'],
  backup_new: ['New two-factor backup codes created', 'change'],
  sk_on: ['Secret key turned on', 'change'],
  sk_off: ['Secret key turned off', 'change'],
  key_add: ['Security key added', 'change'],
  key_remove: ['Security key removed', 'change'],
  key_used: ['New device approved with a security key', 'ok'],
  key_fail: ['Security key check failed', 'fail'],
  history_restore: ['Vault restored to an earlier version', 'change'],
  device_refused: ['A signed-out device tried to connect and was refused', 'fail'],
  login_blocked: ['Sign-in blocked for 15 minutes after 5 wrong tries', 'fail'],
  recover_blocked: ['Recovery blocked for 15 minutes after 5 wrong tries', 'fail'],
  // The lines below reach only the server owner: attempts on names that do not exist or on other accounts.
  login_fail_unknown: ['Failed sign-in: no account with that username', 'fail'],
  login_blocked_unknown: ['Sign-in blocked for 15 minutes: repeated tries on a username that does not exist', 'fail'],
  login_bad_name: ['Failed sign-in: text that cannot be a username', 'fail'],
  recover_fail_unknown: ['Failed recovery attempt: no recovery key for that username', 'fail'],
  recover_blocked_unknown: ['Recovery blocked for 15 minutes: repeated tries on an unknown username', 'fail'],
  register_bad_invite: ['Sign-up attempt with a wrong invite code', 'fail'],
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
    return !q || [label, en.ip, describeDevice(en.ua), en.ua, en.u || '', en.where || ''].some((v) => String(v).toLowerCase().includes(q));
  });
}

/* ---------- Import from other password managers (CSV) ---------- */

// Reads CSV text into rows of cells. Handles quoted cells, doubled quotes, commas and line breaks inside quotes.
export function parseCsv(text) {
  const src = String(text).replace(/^﻿/, '');
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"') {
        if (src[i + 1] === '"') { cell += '"'; i++; } else quoted = false;
      } else cell += c;
    } else if (c === '"' && cell === '') quoted = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(cell);
      cell = '';
      if (row.some((v) => v !== '')) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some((v) => v !== '')) rows.push(row);
  return rows;
}

// Column names used by Google/Chrome, Safari and iCloud, Firefox, Edge, Bitwarden, 1Password, LastPass, Dashlane and NordPass.
const CSV_COLUMNS = {
  title: ['name', 'title', 'account', 'item name', 'site name'],
  url: ['url', 'website', 'login_uri', 'web site', 'uri', 'login url', 'site', 'origin'],
  username: ['username', 'login_username', 'user name', 'login', 'email', 'user', 'login name'],
  password: ['password', 'login_password', 'pass'],
  notes: ['note', 'notes', 'extra', 'comment', 'comments'],
  totp: ['login_totp', 'otpauth', 'totp', 'otp', 'one-time password'],
  tags: ['folder', 'grouping', 'group', 'tags', 'tag', 'category'],
};

// Turns an export file into entries. existing = entries already in the vault, used to skip duplicates.
// Returns { items, duplicates, skipped: [{ line, reason }] } and throws 'csv_no_password_column' for a file it cannot read.
export function importCsv(text, existing = []) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error('csv_empty');
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = {};
  for (const [field, names] of Object.entries(CSV_COLUMNS)) col[field] = header.findIndex((h) => names.includes(h));
  if (col.password < 0) throw new Error('csv_no_password_column');
  if (rows.length > 5001) throw new Error('csv_too_big');
  const keyOf = (it) => [it.url || it.title.toLowerCase(), it.username.toLowerCase(), it.password].join('\u0001');
  const seen = new Set(existing.filter((it) => !it.deleted && !it.trashedAt).map(keyOf));
  const items = [];
  const skipped = [];
  let duplicates = 0;
  const now = Date.now();
  rows.slice(1).forEach((r, n) => {
    const get = (f) => (col[f] >= 0 ? String(r[col[f]] ?? '') : '');
    const password = get('password');
    if (!password.trim()) { skipped.push({ line: n + 2, reason: 'no password' }); return; }
    if (password.length > LIMITS.password) { skipped.push({ line: n + 2, reason: 'password longer than 256 characters' }); return; }
    let url = '';
    try { url = normalizeUrl(get('url')); } catch { /* app links such as android:// have no web address */ }
    let title = get('title').trim();
    if (!title && url) title = new URL(url).hostname.replace(/^www\./, '');
    if (!title) title = get('username').trim() || 'Imported entry';
    // sanitizeItems applies the same cleaning as every other data source.
    const [clean] = sanitizeItems([{
      id: newId(), title, username: get('username'), password, url, notes: get('notes'), totp: get('totp'), tags: normalizeTags(get('tags').replace(/[\\/]/g, ',')), createdAt: now, updatedAt: now,
    }]);
    if (!clean.password) { skipped.push({ line: n + 2, reason: 'no usable password' }); return; }
    const key = keyOf(clean);
    if (seen.has(key)) { duplicates++; return; }
    seen.add(key);
    items.push(clean);
  });
  return { items, duplicates, skipped };
}

/* ---------- Rollback detection ---------- */

export async function sha256Hex(text) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Compares what this device last saw with what the server now offers.
// 'older'   the server's version number went backwards (an old copy was put back)
// 'swapped' same version number, different content
// null      normal: the server copy is the same or newer
export function checkRollback(localRev, localHash, remoteRev, remoteHash) {
  if (remoteRev < localRev) return 'older';
  if (remoteRev === localRev && localHash && remoteHash !== localHash) return 'swapped';
  return null;
}

/* ---------- Two-factor sign-in ---------- */

const B32_RFC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// A new 160-bit authenticator secret, in the base32 form authenticator apps expect.
export function newTotpSecret() {
  let bits = '';
  for (const b of randomBytes(20)) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < 160; i += 5) out += B32_RFC[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

// The address a QR code or "add to authenticator" link carries.
export function otpauthUri(secret, username, issuer = 'Vault') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

/* ---------- Recently deleted ---------- */

export const TRASH_DAYS = 30;
const DAY = 86400000;

// Entries that have sat in Recently deleted for 30 days are removed for good. What remains is a small
// marker (id and time) so the removal reaches the other devices.
export function purgeTrash(items, now = Date.now()) {
  let purged = 0;
  const out = items.map((it) => {
    if (it.deleted || !it.trashedAt || now - it.trashedAt < TRASH_DAYS * DAY) return it;
    purged++;
    return { id: it.id, deleted: true, updatedAt: now };
  });
  return { items: out, purged };
}
export const trashDaysLeft = (it, now = Date.now()) => Math.max(0, Math.ceil((it.trashedAt + TRASH_DAYS * DAY - now) / DAY));

/* ---------- Health summary ---------- */

export const OLD_DAYS = 365;

// Everything the Health tab can say without contacting anyone. breach = results of the last breach check
// kept on this device as { id: [timesSeen, updatedAtWhenChecked] }; a result is ignored once its entry has been edited.
export function healthFindings(items, breach = {}, now = Date.now()) {
  const liveItems = items.filter((it) => !it.deleted && !it.trashedAt && it.password);
  const leaked = liveItems.filter((it) => Array.isArray(breach[it.id]) && breach[it.id][0] > 0 && breach[it.id][1] === it.updatedAt)
    .map((it) => ({ it, count: breach[it.id][0] }));
  const reused = findReused(liveItems);
  const weak = liveItems.filter((it) => isWeak(it.password));
  const old = liveItems.filter((it) => it.pwAt > 0 && now - it.pwAt > OLD_DAYS * DAY);
  const ids = new Set([...leaked.map((x) => x.it.id), ...reused.flat().map((it) => it.id), ...weak.map((it) => it.id), ...old.map((it) => it.id)]);
  return { leaked, reused, weak, old, total: ids.size, checked: liveItems.length };
}

/* ---------- Version history ---------- */

// What going back to an earlier copy would do, without doing it.
// returns: entries that would come back or revert, and entries added since that would move to Recently deleted.
export function snapshotDiff(current, snapshot) {
  const alive = (list) => list.filter((it) => !it.deleted && !it.trashedAt);
  const now = new Map(alive(current).map((it) => [it.id, it]));
  const then = new Map(alive(snapshot).map((it) => [it.id, it]));
  const same = (a, b) => ['title', 'username', 'password', 'url', 'notes', 'totp'].every((k) => (a[k] || '') === (b[k] || ''))
    && !!a.fav === !!b.fav && (a.tags || []).join('\n') === (b.tags || []).join('\n');
  let back = 0, changed = 0, removed = 0;
  for (const [id, it] of then) { if (!now.has(id)) back++; else if (!same(it, now.get(id))) changed++; }
  for (const id of now.keys()) if (!then.has(id)) removed++;
  return { total: then.size, back, changed, removed };
}
// Goes back to an earlier copy. Every entry of that copy returns exactly as it was, stamped with the present time so
// it wins on the other devices. Entries added since are not destroyed: they move to Recently deleted.
export function restoreSnapshot(current, snapshot, now = Date.now()) {
  const then = new Map(snapshot.filter((it) => !it.deleted).map((it) => [it.id, it]));
  const out = [];
  const seen = new Set();
  for (const it of current) {
    seen.add(it.id);
    if (then.has(it.id)) out.push({ ...then.get(it.id), updatedAt: now });
    else if (it.deleted || it.trashedAt) out.push(it);
    else out.push({ ...it, trashedAt: now, updatedAt: now });
  }
  for (const [id, it] of then) if (!seen.has(id)) out.push({ ...it, updatedAt: now });
  return out;
}
