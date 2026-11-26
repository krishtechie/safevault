import * as core from './core.js';

core.setArgon2(globalThis.hashwasm.argon2id);

const $ = (id) => document.getElementById(id);
const API = 'api/index.php';

// The page and this script are published together. Right after an update a browser can hold one of them from
// before; the missing parts would then stop the app from starting. When they do not match, fetch fresh copies
// and reload, once.
const BUILD = '23';
{
  const page = document.querySelector('meta[name="vault-build"]');
  let tried = false;
  try {
    if (page && page.content === BUILD) sessionStorage.removeItem('rebuilt');
    else { tried = sessionStorage.getItem('rebuilt') === BUILD; sessionStorage.setItem('rebuilt', BUILD); }
  } catch { tried = true; /* storage blocked: do not risk a reload loop */ }
  if ((!page || page.content !== BUILD) && !tried) {
    await Promise.all(['./', 'js/app.js', 'js/core.js', 'style.css'].map((u) => fetch(u, { cache: 'reload' }).catch(() => {})));
    location.reload();
    await new Promise(() => {}); // nothing below runs; the reload takes over
  }
}

// Everything sensitive lives only in this object, in memory, while unlocked.
// encKey is the vault key (non-extractable). wrap is that key locked with the master password key.
const S = { username: null, encKey: null, auth: null, salt: null, kdf: null, wrap: null, hasRecovery: false, totp: false, hash: '', rollback: null, items: [], rev: 0, dirty: false, changes: 0 };

/* ---------- Small helpers ---------- */

const store = {
  open() {
    return new Promise((res, rej) => {
      const r = indexedDB.open('vault', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  },
  async run(mode, fn) {
    const db = await this.open();
    return new Promise((res, rej) => {
      const q = fn(db.transaction('kv', mode).objectStore('kv'));
      q.onsuccess = () => { res(q.result); db.close(); };
      q.onerror = () => { rej(q.error); db.close(); };
    });
  },
  get(k) { return this.run('readonly', (s) => s.get(k)); },
  set(k, v) { return this.run('readwrite', (s) => s.put(v, k)); },
  del(k) { return this.run('readwrite', (s) => s.delete(k)); },
};

// A random id this browser chose for itself, so the account can list its devices and sign one out from another.
let did = null;
async function newDid() {
  did = core.b64.enc(core.randomBytes(16));
  await store.set('device', { id: did }).catch(() => {});
}
const didReady = (async () => {
  try { const d = await store.get('device'); if (d && typeof d.id === 'string') { did = d.id; return; } } catch { /* storage unavailable */ }
  await newDid();
})();

// The second sign-in step takes a 6-digit authenticator code, or one of the backup codes.
let backupMode = false;
let notice = '';
function setBackupMode(on) {
  backupMode = on;
  const i = $('aTotp');
  i.value = '';
  i.maxLength = on ? 11 : 6;
  i.inputMode = on ? 'text' : 'numeric';
  i.autocomplete = on ? 'off' : 'one-time-code';
  i.placeholder = on ? 'xxxxx-xxxxx' : '';
  i.classList.toggle('code-text', on);
  $('totpLabel').textContent = on ? 'Backup code' : 'Authenticator code';
  $('totpAlt').textContent = on ? 'Use the authenticator code instead' : 'Use a backup code instead';
}
const typedCode = () => (backupMode ? $('aTotp').value.trim().toLowerCase() : $('aTotp').value.replace(/\D/g, ''));
// A security key can pass the second step instead of a code. The server offers a one-time challenge for it
// along with "code needed"; the key's signed answer rides on the next sign-in request.
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (str) => Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
};
const keysUsable = () => !!(window.PublicKeyCredential && navigator.credentials);
let keyOffer = null;  // { challenge, ids } from the server
let keyAnswer = null; // the key's answer, used once
function setKeyOffer(offer) {
  keyOffer = offer && keysUsable() ? offer : null;
  $('keyBtn').hidden = !keyOffer;
}

async function api(action, body, query = '') {
  await didReady;
  const opt = { method: body ? 'POST' : 'GET', headers: { 'X-Vault-Client': '1', 'X-Vault-Device': did }, credentials: 'same-origin', cache: 'no-store' };
  if (body) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(`${API}?a=${action}${query}`, opt); }
  catch { const e = new Error('offline'); e.offline = true; throw e; }
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (data.error === 'device_revoked') await wipeDevice(ERRORS.device_revoked);
  if (!res.ok && res.status !== 409) { const e = new Error(data.error || 'http_' + res.status); e.status = res.status; e.data = data; throw e; }
  data.status = res.status;
  return data;
}

// This device was signed out from another one: erase everything kept here and go back to the sign-in screen.
async function wipeDevice(message) {
  quick = null;
  trust = null;
  recents.clear();
  breach.clear();
  for (const k of ['quick', 'trust', 'state', 'unlock']) await store.del(k).catch(() => {});
  await newDid();
  if (S.encKey) lock(message);
  else { setAuthMode('unlock'); $('authMsg').textContent = message; }
}

let toastTimer;
function toast(text, action = null) {
  const t = $('toast');
  t.textContent = text;
  t.classList.toggle('has-action', !!action);
  if (action) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = action.label;
    b.addEventListener('click', () => { t.classList.remove('show', 'has-action'); action.run(); });
    t.append(b);
  }
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show', 'has-action'), action ? 7000 : 2200);
}

let clipTimer;
async function copy(text, label = 'Copied') {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast(label + '. Clipboard clears in 30s');
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000);
  } catch { toast('Could not copy'); }
}

const ERRORS = {
  bad_credentials: 'Wrong username or master password.',
  device_revoked: 'This device was signed out from another device, and its copy of the vault was erased. Sign in again with your master password to use it here.',
  bad_tags: 'A tag can be up to 24 characters.',
  too_many_tags: 'Up to 6 tags per entry.',
  bad_device_name: 'Name: 1 to 40 characters.',
  newer_format: 'Your vault was saved by a newer version of the app. Reload this page to update, then unlock again.',
  bad_invite: 'That invite code is not valid.',
  username_taken: 'That username is already taken.',
  bad_username: 'Username: 3 to 32 characters, letters, numbers, dot, dash or underscore.',
  registration_closed: 'Sign-ups are closed on this server.',
  slow_down: 'Too many attempts. Wait 15 minutes and try again.',
  not_configured: 'The server is not set up yet. See the README.',
  data_dir_inside_web_root: 'Server setup problem: the data folder must be outside the web root.',
  offline: 'No connection. This needs internet.',
  changed_elsewhere: 'Your master password was changed on another device. Unlock with the new one.',
  bad_recovery_code: 'That recovery key is not valid. It has 32 letters and numbers.',
  bad_recovery: 'Wrong username or recovery key.',
  bad_current: 'The current master password is wrong.',
  need_current: 'Enter your current master password first.',
  weak: 'Master password is too weak. Use at least 12 characters; a 5 or 6 word passphrase works well.',
  mismatch: 'The two passwords do not match.',
  need_username: 'Enter your username.',
  pin_format: 'A PIN is exactly 6 digits.',
  pin_simple: 'That PIN is too easy to guess. Avoid repeats and sequences such as 111111 or 123456.',
  pin_mismatch: 'The two PINs do not match.',
  pin_offline: 'PIN unlock needs internet. Use your master password while offline.',
  pin_locked: 'Too many wrong PINs, so the PIN is turned off. Enter your master password. You can set a new PIN afterwards.',
  pin_gone: 'The PIN on this device is no longer valid. Enter your master password.',
  need_master: 'Enter your master password on this device first.',
  too_many_devices: 'PIN unlock is already on for 10 devices. Turn it off on one first.',
  csv_empty: 'That file has no entries in it.',
  csv_no_password_column: 'That does not look like a password export. It needs a header row with a "password" column.',
  csv_too_big: 'That file has more than 5,000 rows. Split it and import in parts.',
  csv_none: 'Choose a CSV file first.',
  bio_unsupported: 'This browser or device does not support Face ID or Touch ID unlock for web apps.',
  bio_failed: 'Face ID or Touch ID did not complete. Try again, or use your master password.',
  totp_required: 'Enter the 6-digit code from your authenticator app.',
  bad_totp: 'That code is not right, or it was already used. Wait for the next code and try again.',
  bad_backup: 'That backup code is not right, or it was already used.',
  totp_off: 'Two-factor sign-in is off, so there are no backup codes to make.',
  totp_or_key: 'Enter the 6-digit code from your authenticator app, or use your security key.',
  bad_key: 'The security key was not accepted. Try it again, or enter a code instead.',
  key_cancelled: 'The security key check was cancelled or timed out. Try again, or enter a code instead.',
  key_needs_totp: 'Turn on two-factor sign-in first. Security keys are added on top of it.',
  key_limit: 'An account can hold up to 5 security keys. Remove one first.',
  key_exists: 'That security key is already on this account.',
  key_expired: 'That took too long. Tap Add a security key and try again.',
  bad_key_name: 'Give the key a name of up to 40 characters.',
  key_unsupported: 'This browser cannot use security keys.',
  key_failed: 'No key was added. It was cancelled, it timed out, or this key is already on the account.',
  no_key: 'That security key is no longer on the account.',
  bad_secret: 'Could not set up the authenticator. Start the setup again.',
  totp_lost: 'This device needs your authenticator code again. Unlock with your master password.',
  bad_totp_secret: 'That authenticator key is not valid. Paste the key the site shows during two-factor setup, or its otpauth:// link.',
  totp_unsupported: 'That authenticator setup uses non-standard settings. Only 6-digit, 30-second codes are supported.',
  need_title: 'Give this entry a name.',
  bad_title: 'The name is too long or contains hidden characters. Retype it.',
  bad_username_field: 'A username or email cannot contain spaces, double quotes, angle brackets or hidden characters.',
  need_password: 'Enter a password, or tap Generate.',
  bad_password: 'The password is too long (256 max) or contains hidden characters such as a line break. Retype or paste it again.',
  password_spaces: 'The password starts or ends with a space. Remove it, since most sites do not accept that.',
  bad_url: 'That is not a valid website address. Use something like https://example.com, or leave it empty.',
  bad_notes: 'The notes are too long or contain hidden characters.',
};
const explain = (e) => ERRORS[e.message] || e.message || 'Something went wrong.';

/* ---------- Unlock, register, recover, lock ---------- */

let mode = 'unlock'; // 'unlock' | 'register' | 'recover'

// Quick unlock settings for this device: { username, auth (sealed), pin?: {deviceId, kdev, wrap}, bio?: {credId, salt, wrap} }
let quick = null;
const quickFor = (name) => (quick && quick.username === name ? quick : null);
const bioName = /iPhone|iPad|iPod/.test(navigator.userAgent) ? 'Face ID' : /Macintosh/.test(navigator.userAgent) ? 'Touch ID' : 'device unlock';

function setAuthMode(m) {
  mode = m;
  const q = quickFor($('aUser').value.trim().toLowerCase());
  $('userField').hidden = m === 'pin';
  $('passField').hidden = m === 'pin';
  $('pinField').hidden = m !== 'pin';
  $('recField').hidden = m !== 'recover';
  $('recDropField').hidden = m !== 'recover';
  $('confirmField').hidden = m !== 'register' && m !== 'recover';
  $('inviteField').hidden = m !== 'register';
  $('regNote').hidden = m !== 'register';
  $('aPassLabel').textContent = m === 'recover' ? 'New master password' : 'Master password';
  $('authBtn').textContent = { unlock: 'Unlock', pin: 'Unlock', register: 'Create account', recover: 'Set new master password' }[m];
  $('authLead').textContent = {
    unlock: 'Unlock with your master password.',
    pin: 'Enter your PIN to unlock.',
    register: 'Choose a master password you will remember.',
    recover: 'Enter your recovery key and choose a new master password.',
  }[m];
  $('bioBtn').hidden = !(q && q.bio && (m === 'unlock' || m === 'pin'));
  $('bioBtn').textContent = 'Unlock with ' + bioName;
  $('authSwitch').hidden = !(q && q.pin && (m === 'unlock' || m === 'pin'));
  $('authSwitch').textContent = m === 'pin' ? 'Use master password' : 'Use PIN';
  $('authToggle').hidden = m === 'pin';
  $('authToggle').textContent = m === 'unlock' ? 'Create an account' : 'Back to unlock';
  $('authForgot').hidden = m !== 'unlock';
  $('authMsg').textContent = '';
  $('aPin').value = '';
  $('totpField').hidden = true;
  setBackupMode(false);
  setKeyOffer(null);
  keyAnswer = null;
  $('aTotp').value = '';
  const focus = { pin: 'aPin', unlock: $('aUser').value ? 'aPass' : 'aUser' }[m];
  if (focus && !$('auth').hidden) $(focus).focus();
}
// The unlock screen opens on the PIN when one is set for the remembered user.
const restingMode = () => (quickFor($('aUser').value.trim().toLowerCase())?.pin ? 'pin' : 'unlock');

const cacheRecord = (blob) => ({
  username: S.username, salt: S.salt, kdf: S.kdf, wrap: S.wrap, recovery: S.hasRecovery, totp: S.totp, hash: S.hash,
  blob, rev: S.rev, dirty: S.dirty,
});
async function cacheState(blob) { await store.set('state', cacheRecord(blob)); }
// Update account fields in the device copy without touching the encrypted vault stored there.
async function patchCache() {
  const c = await store.get('state');
  if (c && c.username === S.username) await store.set('state', { ...cacheRecord(c.blob), rev: c.rev, dirty: c.dirty });
}

const newSalt = () => core.b64.enc(core.randomBytes(16));
const checkStrength = (pw, pw2) => {
  if (pw !== pw2) throw new Error('mismatch');
  if (pw.length < 12 || core.estimateBits(pw) < 60) throw new Error('weak');
};

// Signs in to the server and returns the raw vault key. Accounts created before key
// wrapping existed are upgraded here: their existing key is wrapped and stored, and the vault is left as is.
// A device that has passed the authenticator check holds a random token, so it is not asked again.
let trust = null; // { username, token }
const loginBody = (username, auth, code = '', key = null) => {
  const body = { username, auth };
  if (trust && trust.username === username) body.trust = trust.token;
  if (key) body.key = key;
  else if (code) body.totp = code;
  return body;
};
async function keepTrust(username, token) {
  if (!token) return;
  trust = { username, token };
  await store.set('trust', trust).catch(() => {});
}
// Signs in again with what is in memory (session expired). Never has a code to offer.
// Several requests can find the session expired at the same moment; they share one sign-in.
let reloginBusy = null;
const relogin = () => {
  if (!reloginBusy) {
    reloginBusy = api('login', { ...loginBody(S.username, S.auth), auto: true }).finally(() => { reloginBusy = null; });
  }
  return reloginBusy;
};

async function signIn(username, keys) {
  const answer = keyAnswer;
  keyAnswer = null;
  const r = await api('login', loginBody(username, keys.auth, $('totpField').hidden ? '' : typedCode(), answer));
  if (typeof r.backupLeft === 'number') notice = `Backup code used. ${r.backupLeft} left` + (r.backupLeft < 3 ? '. Create new ones in Settings' : '');
  await keepTrust(username, r.trust);
  const vkRaw = r.wrap ? await core.unwrapKey(keys.kek, username, r.wrap) : keys.legacyRaw;
  // If the upgrade call fails (for example mid-deploy), carry on; it is retried at the next unlock.
  const wrap = r.wrap || await api('setwrap', { wrap: await core.wrapKey(keys.kek, username, vkRaw) }).then((x) => x.wrap, () => null);
  return { vkRaw, wrap, rev: r.rev, recovery: !!r.recovery, totp: !!r.totp };
}

// Changes made on this device that never reached the server survive a password change,
// because the vault key stays the same.
async function unsyncedLocal(cached, username, vk) {
  if (!cached || cached.username !== username || !cached.dirty) return [];
  try { return await core.decryptVault(vk, username, cached.blob); } catch { return []; }
}

async function unlock(username, password) {
  const cached = await store.get('state');
  let stale = false; // the device copy opened with this password but the server refused it
  if (cached && cached.username === username) {
    // Known device: open the local encrypted copy first (works offline), then check in with the server.
    const keys = await core.deriveKeys(password, cached.salt, cached.kdf);
    let local = null;
    try {
      const raw = cached.wrap ? await core.unwrapKey(keys.kek, username, cached.wrap) : keys.legacyRaw;
      const vk = await core.importVaultKey(raw);
      local = { vk, items: await core.decryptVault(vk, username, cached.blob) };
    } catch { /* wrong password, or the password was changed elsewhere: try the server below */ }
    if (local) {
      let wrap = cached.wrap || null;
      let recovery = !!cached.recovery;
      let totp = !!cached.totp;
      try {
        const r = await signIn(username, keys);
        wrap = r.wrap;
        recovery = r.recovery;
        totp = r.totp;
      } catch (e) {
        // The server refused the sign-in this device knows. The password may still be right: a change or a
        // recovery on another device gives the account a new salt even when the same password is kept.
        if (e.message === 'bad_credentials') local = null;
        if (e.message === 'device_revoked') throw e; // signed out remotely: the local copy is already erased
        if (['totp_required', 'bad_totp', 'bad_key'].includes(e.message)) throw e; // the server wants the second step
        // offline or busy: carry on with the device copy
      }
      if (local) {
        S.totp = totp;
        S.hash = cached.hash || '';
        Object.assign(S, {
          username, encKey: local.vk, auth: keys.auth, salt: cached.salt, kdf: cached.kdf, wrap, hasRecovery: recovery,
          items: local.items, rev: cached.rev, dirty: !!cached.dirty,
        });
        await patchCache();
        return;
      }
      stale = true;
    }
  }
  // New device, or the device copy did not open: fetch salt, derive keys, sign in, download and decrypt.
  let pre;
  try { pre = await api('prelogin', { username }); }
  catch (e) { throw cached && e.offline ? new Error('bad_credentials') : e; }
  const keys = await core.deriveKeys(password, pre.salt, pre.kdf);
  let r;
  try { r = await signIn(username, keys); }
  catch (e) { throw stale && e.message === 'bad_credentials' ? new Error('changed_elsewhere') : e; }
  const vk = await core.importVaultKey(r.vkRaw);
  const v = await api('vault');
  const remote = await core.decryptVault(vk, username, v.blob);
  const extra = await unsyncedLocal(cached, username, vk);
  Object.assign(S, {
    username, encKey: vk, auth: keys.auth, salt: pre.salt, kdf: core.checkKdf(pre.kdf), wrap: r.wrap, hasRecovery: r.recovery,
    items: core.mergeItems(extra, remote), rev: v.rev, dirty: extra.length > 0,
  });
  S.totp = r.totp;
  S.hash = await core.sha256Hex(v.blob);
  await cacheState(extra.length ? await core.encryptVault(vk, username, S.items) : v.blob);
}

async function register(username, password, invite) {
  const salt = newSalt();
  const kdf = { ...core.KDF_DEFAULT };
  const keys = await core.deriveKeys(password, salt, kdf);
  const vkRaw = core.newVaultKeyRaw();
  const wrap = await core.wrapKey(keys.kek, username, vkRaw);
  const vk = await core.importVaultKey(vkRaw);
  const blob = await core.encryptVault(vk, username, []);
  const r = await api('register', { username, salt, kdf, auth: keys.auth, wrap, invite, blob });
  Object.assign(S, { username, encKey: vk, auth: keys.auth, salt, kdf, wrap, hasRecovery: false, totp: false, items: [], rev: r.rev, dirty: false });
  S.hash = await core.sha256Hex(blob);
  await cacheState(blob);
}

// Forgotten master password: the recovery key unlocks the vault key, which is then
// locked again under the new master password. The vault data is not rewritten.
async function recover(username, code, password) {
  const rec = await core.deriveRecoveryKeys(code, username);
  let start;
  try { start = await api('recover_start', { username, recAuth: rec.auth }); }
  catch (e) { throw e.message === 'bad_credentials' ? new Error('bad_recovery') : e; }
  const vkRaw = await core.unwrapKey(rec.kek, username, start.recWrap, 'rec');
  const salt = newSalt();
  const kdf = { ...core.KDF_DEFAULT };
  const keys = await core.deriveKeys(password, salt, kdf);
  const wrap = await core.wrapKey(keys.kek, username, vkRaw);
  const dropTotp = $('aRecDrop').checked;
  const done = await api('recover_finish', {
    username, recAuth: rec.auth, newAuth: keys.auth, salt, kdf, wrap, dropTotp,
    trust: trust && trust.username === username ? trust.token : undefined,
  });
  if (quick) delete quick.pin; // the server turned PINs off for this account
  const vk = await core.importVaultKey(vkRaw);
  const v = await api('vault');
  const remote = await core.decryptVault(vk, username, v.blob);
  const extra = await unsyncedLocal(await store.get('state'), username, vk);
  Object.assign(S, {
    username, encKey: vk, auth: keys.auth, salt, kdf, wrap, hasRecovery: true, totp: !!done.totp,
    items: core.mergeItems(extra, remote), rev: v.rev, dirty: extra.length > 0,
  });
  S.hash = await core.sha256Hex(v.blob);
  if (!done.totp) { // two-factor sign-in is off on the server, so the saved device pass means nothing
    trust = null;
    await store.del('trust').catch(() => {});
  }
  $('aRecDrop').checked = false;
  await cacheState(extra.length ? await core.encryptVault(vk, username, S.items) : v.blob);
}

/* ---------- Quick unlock: PIN and Face ID / Touch ID ---------- */

async function saveQuick() {
  if (quick && !quick.pin && !quick.bio) quick = null;
  if (quick) await store.set('quick', quick); else await store.del('quick');
  renderAccount();
}

// Both quick-unlock paths end here with the raw vault key in hand.
async function openWithVaultKey(q, vkRaw) {
  const cached = await store.get('state');
  if (!cached || cached.username !== q.username) throw new Error('need_master');
  const vk = await core.importVaultKey(vkRaw);
  vkRaw.fill(0);
  const items = await core.decryptVault(vk, q.username, cached.blob);
  const auth = await core.openText(vk, q.auth);
  Object.assign(S, {
    username: q.username, encKey: vk, auth, salt: cached.salt, kdf: cached.kdf, wrap: cached.wrap || null,
    hasRecovery: !!cached.recovery, totp: !!cached.totp, hash: cached.hash || '', items, rev: cached.rev, dirty: !!cached.dirty,
  });
  sealedAuth = q.auth;
}

async function unlockWithPin(pin) {
  const q = quick;
  if (!q || !q.pin) throw new Error('pin_gone');
  if (!/^\d{6}$/.test(pin)) throw new Error('pin_format');
  const pinAuth = await core.derivePinAuth(pin, q.pin.kdev);
  let r;
  try {
    r = await api('pin_unlock', { deviceId: q.pin.deviceId, pinAuth });
  } catch (e) {
    if (e.offline) throw new Error('pin_offline');
    if (e.message === 'pin_locked' || e.message === 'pin_gone') { delete quick.pin; await saveQuick(); }
    if (e.message === 'bad_pin') {
      const left = e.data && e.data.left;
      throw new Error(`Wrong PIN. ${left} ${left === 1 ? 'try' : 'tries'} left before the master password is required.`);
    }
    throw e;
  }
  const kek = await core.pinKek(q.pin.kdev, core.b64.dec(r.ksrv));
  await openWithVaultKey(q, await core.unwrapKey(kek, q.username, q.pin.wrap, 'pin'));
}

const rnd = (n) => core.randomBytes(n);

// Asks the device for the Face ID / Touch ID protected secret tied to this vault.
async function bioSecret(bio) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: rnd(32), rpId: location.hostname, userVerification: 'required', timeout: 60000,
    allowCredentials: [{ type: 'public-key', id: core.b64.dec(bio.credId), transports: ['internal', 'hybrid'] }],
    extensions: { prf: { eval: { first: core.b64.dec(bio.salt) } } },
  } });
  const out = a.getClientExtensionResults().prf;
  if (!out || !out.results || !out.results.first) throw new Error('bio_unsupported');
  return out.results.first;
}

async function unlockWithBio() {
  const q = quick;
  if (!q || !q.bio) throw new Error('need_master');
  let secret;
  try { secret = await bioSecret(q.bio); }
  catch (e) { throw new Error(e.message === 'bio_unsupported' ? 'bio_unsupported' : 'bio_failed'); }
  const kek = await core.bioKek(secret);
  let vkRaw;
  try { vkRaw = await core.unwrapKey(kek, q.username, q.bio.wrap, 'bio'); }
  catch { throw new Error('bio_failed'); }
  await openWithVaultKey(q, vkRaw);
}

let bioBusy = false;
// quiet = started by the app itself (on launch or on return), so a refusal shows no error:
// some browsers only allow Face ID after a tap, and the button is right there.
async function runBio(quiet) {
  if (bioBusy || S.encKey || !quick || !quick.bio) return;
  bioBusy = true;
  const btn = $('bioBtn');
  if (!quiet) $('authMsg').textContent = '';
  btn.disabled = true;
  try {
    await unlockWithBio();
    enterApp();
    authed(() => api('note', { e: 'bio_ok' })).catch(() => {});
  } catch (e) {
    if (!quiet) $('authMsg').textContent = explain(e);
  } finally {
    btn.disabled = false;
    bioBusy = false;
  }
}
$('bioBtn').addEventListener('click', () => runBio(false));
// Coming back to a locked app: offer Face ID straight away.
document.addEventListener('visibilitychange', () => { if (!document.hidden && !S.encKey && (mode === 'unlock' || mode === 'pin')) runBio(true); });

$('authSwitch').addEventListener('click', () => setAuthMode(mode === 'pin' ? 'unlock' : 'pin'));
$('authToggle').addEventListener('click', () => setAuthMode(mode === 'unlock' ? 'register' : 'unlock'));
$('authForgot').addEventListener('click', () => setAuthMode('recover'));
// Six digits typed: submit without needing the button.
$('aPin').addEventListener('input', () => {
  $('aPin').value = $('aPin').value.replace(/\D/g, '').slice(0, 6);
  if ($('aPin').value.length === 6 && !$('authBtn').disabled) $('authForm').requestSubmit();
});

$('authForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const username = $('aUser').value.trim().toLowerCase();
  const password = $('aPass').value;
  const msg = $('authMsg');
  const started = mode;
  msg.textContent = '';
  const btn = $('authBtn');
  try {
    if (started !== 'pin' && !username) throw new Error('need_username');
    if (started === 'register' || started === 'recover') checkStrength(password, $('aPass2').value);
    btn.disabled = true;
    btn.textContent = 'Working';
    if (started === 'pin') await unlockWithPin($('aPin').value);
    else if (started === 'register') await register(username, password, $('aInvite').value);
    else if (started === 'recover') await recover(username, $('aRec').value, password);
    else await unlock(username, password);
    for (const id of ['aPass', 'aPass2', 'aInvite', 'aRec', 'aPin', 'aTotp']) $(id).value = '';
    $('totpField').hidden = true;
    setBackupMode(false);
    setKeyOffer(null);
    enterApp();
    if (started === 'recover') toast(S.totp ? 'New master password set. Two-factor sign-in is still on' : 'New master password set');
    else if (notice) toast(notice);
    notice = '';
  } catch (e) {
    $('aPin').value = '';
    if (started === 'pin' && ['pin_locked', 'pin_gone', 'need_master'].includes(e.message)) setAuthMode('unlock');
    if (['totp_required', 'bad_totp', 'bad_key'].includes(e.message)) { // right master password, new device: second step
      $('totpField').hidden = false;
      $('aTotp').value = '';
      if (e.data && e.data.key) setKeyOffer(e.data.key);
      else if (e.message !== 'bad_totp') setKeyOffer(null);
      $('aTotp').focus();
    }
    msg.textContent = e.message === 'bad_totp' && backupMode ? ERRORS.bad_backup
      : e.message === 'totp_required' && keyOffer ? ERRORS.totp_or_key : explain(e);
  } finally {
    btn.disabled = false;
    setAuthModeLabel();
  }
});
function setAuthModeLabel() { $('authBtn').textContent = { unlock: 'Unlock', pin: 'Unlock', register: 'Create account', recover: 'Set new master password' }[mode]; }

function enterApp(activeAt = Date.now()) {
  try { sessionStorage.setItem('vaultOpen', '1'); } catch { /* storage blocked */ }
  $('auth').hidden = true;
  $('app').hidden = false;
  $('whoami').textContent = S.username;
  lastActive = activeAt;
  showView('vault');
  renderList();
  regenerate();
  renderAccount();
  rememberUnlock();
  refreshQuick();
  if (sweepTrash()) persist(); else sync();
}

// After any unlock, make sure the quick-unlock record belongs to this user and holds the current sign-in key.
async function refreshQuick() {
  try {
    if (!quick) return;
    if (quick.username !== S.username) { quick = null; await saveQuick(); return; }
    if (!sealedAuth) sealedAuth = await core.sealText(S.encKey, S.auth);
    quick.auth = sealedAuth;
    await saveQuick();
  } catch { /* storage unavailable */ }
}

function lock(message = '') {
  if (!S.encKey) return;
  const user = S.username;
  Object.assign(S, { username: null, encKey: null, auth: null, salt: null, kdf: null, wrap: null, hasRecovery: false, items: [], rev: 0, dirty: false });
  S.totp = false;
  S.hash = '';
  S.rollback = null;
  S.outdated = false;
  $('rollbackBar').hidden = true;
  $('updateBar').hidden = true;
  if ($('trashDlg').open) $('trashDlg').close();
  for (const d of document.querySelectorAll('details.fold')) d.open = false; // settings sections fold shut again
  $('trashList').replaceChildren();
  $('trashOpen').hidden = true;
  activeTag = '';
  $('tagBar').replaceChildren();
  $('tagBar').hidden = true;
  $('tagPick').replaceChildren();
  $('devList').replaceChildren();
  $('devMsg').textContent = '';
  $('histList').replaceChildren();
  $('histMsg').textContent = '';
  histOpen = null;
  backupList = null;
  $('backupCodes').textContent = '';
  $('backupShow').hidden = true;
  $('backupMsg').textContent = '';
  $('backupStatus').textContent = '';
  S.keys = [];
  $('keyList').replaceChildren();
  $('keyMsg').textContent = '';
  $('keyName').value = '';
  $('healthBadge').hidden = true;
  $('healthSum').textContent = '';
  $('toast').classList.remove('show', 'has-action');
  $('toast').textContent = '';
  sealedAuth = null;
  // Cleared synchronously, so a reload right after Lock can never reopen the vault
  // even if the stored key has not finished being removed yet.
  try { sessionStorage.removeItem('vaultOpen'); } catch { /* storage blocked */ }
  store.del('unlock').catch(() => {});
  if ($('itemDlg').open) $('itemDlg').close();
  for (const id of ['fTitle', 'fUser', 'fPass', 'fUrl', 'fNotes', 'fTotp', 'fTags', 'search', 'importPass', 'cpCur', 'cpNew', 'cpNew2', 'recPass', 'qPass', 'qPin', 'qPin2', 'tfaPass', 'tfaCode']) $(id).value = '';
  $('tfaSetup').hidden = true;
  tfaPending = null;
  for (const id of ['healthMsg', 'healthNote', 'fAge', 'cpMsg', 'recMsg', 'recCode', 'pinMsg', 'bioMsg', 'csvMsg', 'tfaMsg', 'tfaKey']) $(id).textContent = '';
  $('csvFile').value = '';
  $('recOut').hidden = true;
  $('list').replaceChildren();
  $('logList').replaceChildren();
  logEntries = [];
  $('logCount').textContent = '';
  $('healthOut').replaceChildren();
  $('genOut').textContent = '';
  $('app').hidden = true;
  $('auth').hidden = false;
  $('aUser').value = user || '';
  setAuthMode(message ? 'unlock' : restingMode());
  $('authMsg').textContent = message;
}

$('lockBtn').addEventListener('click', () => lock());
$('lockBtnM').addEventListener('click', () => lock());

// Auto-lock after inactivity (also checked when the tab becomes visible again).
let lastActive = Date.now();
const lockMs = () => (parseInt(localStorage.getItem('lockMin'), 10) || 5) * 60000;
for (const ev of ['pointerdown', 'keydown', 'input']) addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true });
const idleCheck = () => {
  if (!S.encKey) return;
  if (Date.now() - lastActive > lockMs()) lock();
  else if (lastActive !== rememberedAt) rememberUnlock();
};
setInterval(idleCheck, 5000);
document.addEventListener('visibilitychange', () => { idleCheck(); if (!document.hidden && S.encKey) sync(); });

/* ---------- Stay unlocked across a page reload ---------- */

// The vault key is kept in the browser's key store as a non-extractable key: page scripts can use it
// but cannot read its bytes. It is removed on Lock, on sign out, and once the auto-lock time has passed.
const stayOn = () => localStorage.getItem('stayUnlocked') !== '0';
let sealedAuth = null;
let rememberedAt = 0;

async function rememberUnlock() {
  try {
    if (!S.encKey || !stayOn()) { await store.del('unlock'); return; }
    if (!sealedAuth) sealedAuth = await core.sealText(S.encKey, S.auth);
    rememberedAt = lastActive;
    await store.set('unlock', { username: S.username, key: S.encKey, auth: sealedAuth, lastActive });
  } catch { /* private browsing or storage blocked: the app simply asks for the password after a reload */ }
}

async function tryRestore() {
  const u = await store.get('unlock');
  if (!u) return false;
  const cached = await store.get('state');
  // Session storage survives a reload but not closing the app or tab, so a fresh launch always asks again.
  let sameSession = false;
  try { sameSession = sessionStorage.getItem('vaultOpen') === '1'; } catch { /* storage blocked */ }
  const fresh = sameSession && stayOn() && cached && cached.username === u.username && Date.now() - u.lastActive <= lockMs();
  try {
    if (!fresh) throw new Error('expired');
    const items = await core.decryptVault(u.key, u.username, cached.blob);
    const auth = await core.openText(u.key, u.auth);
    Object.assign(S, {
      username: u.username, encKey: u.key, auth, salt: cached.salt, kdf: cached.kdf, wrap: cached.wrap || null,
      hasRecovery: !!cached.recovery, totp: !!cached.totp, hash: cached.hash || '', items, rev: cached.rev, dirty: !!cached.dirty,
    });
    sealedAuth = u.auth;
    enterApp(u.lastActive); // a reload does not count as activity
    return true;
  } catch {
    await store.del('unlock');
    return false;
  }
}

/* ---------- Sync ---------- */

let lastStatus = '';
function setStatus(state) {
  const text = {
    synced: 'Synced', syncing: 'Syncing', pending: 'Changes waiting to sync',
    offline: 'Offline. Saved on this device', error: 'Sync problem. Tap to retry',
  }[state];
  for (const s of ['', 'M']) {
    $('syncDot' + s).className = 'dot ' + state;
    $('syncText' + s).textContent = text;
  }
  if (state === 'offline') wasOffline = true;
  $('offlineBar').hidden = state !== 'offline' && !(wasOffline && state === 'syncing');
  if (state === 'synced' && wasOffline) { wasOffline = false; toast('Back online. Everything is synced'); }
  lastStatus = state;
}
let wasOffline = false;

let syncing = null;
let syncAgain = false;
function sync() {
  if (!S.encKey) return Promise.resolve();
  if (syncing) { syncAgain = true; return syncing; }
  syncing = doSync().finally(() => {
    syncing = null;
    if (syncAgain) { syncAgain = false; sync(); }
  });
  return syncing;
}

async function mergeRemote(blob, rev) {
  const remote = await core.decryptVault(S.encKey, S.username, blob);
  S.items = core.mergeItems(S.items, remote);
  S.rev = rev;
  S.hash = await core.sha256Hex(blob);
  if (sweepTrash()) { S.dirty = true; S.changes++; }
  if (!S.dirty) await cacheState(blob);
  renderList();
}

// The server offered a copy older than (or different from) what this device has already seen.
// Nothing is merged or overwritten until the user decides.
function raiseRollback(kind, serverRev, blob) {
  const first = !S.rollback;
  S.rollback = { kind, serverRev, blob };
  $('rollbackText').textContent = {
    older: `The server returned an older copy of your vault (version ${serverRev}; this device has seen version ${S.rev}). `,
    swapped: `The server returned a different vault under the same version number (${serverRev}). `,
    missing: 'Your vault is missing from the server. ',
  }[kind] + 'This happens when a server is restored from a backup, and it can also mean someone tampered with it. Your passwords on this device are untouched and nothing was overwritten.';
  $('rollbackBar').hidden = false;
  setStatus('error');
  if (first) authed(() => api('note', { e: 'rollback_seen' })).catch(() => {});
}

// Entries that have been in Recently deleted for 30 days are removed for good. True when anything changed.
function sweepTrash() {
  const { items, purged } = core.purgeTrash(S.items);
  if (purged) S.items = items;
  return purged > 0;
}

async function doSync() {
  if (S.rollback || S.outdated) { setStatus('error'); return; } // paused until the user restores or reloads
  setStatus('syncing');
  try {
    for (let attempt = 0; attempt < 6 && S.encKey; attempt++) {
      let remote;
      try {
        remote = await api('vault', null, '&rev=' + S.rev + (S.hash ? '&h=' + S.hash : ''));
      } catch (e) {
        if (e.message === 'no_vault' && S.rev > 0) { raiseRollback('missing', 0, null); return; }
        if (e.status !== 401) throw e;
        try {
          await relogin(); // session expired, sign in again
        } catch (e2) {
          if (e2.message !== 'bad_credentials' && e2.message !== 'totp_required') throw e2;
          quick = null; // quick unlock on this device holds a sign-in that no longer works
          await store.del('quick').catch(() => {});
          lock(e2.message === 'totp_required' ? ERRORS.totp_lost : ERRORS.changed_elsewhere);
          return;
        }
        continue;
      }
      if (!remote.unchanged) {
        const verdict = core.checkRollback(S.rev, S.hash, remote.rev, await core.sha256Hex(remote.blob));
        if (verdict) { raiseRollback(verdict, remote.rev, remote.blob); return; }
        await mergeRemote(remote.blob, remote.rev);
      }
      if (!S.dirty) break;

      const mark = S.changes;
      const blob = await core.encryptVault(S.encKey, S.username, S.items);
      const saved = await api('save', { blob, baseRev: S.rev });
      if (saved.status === 409) { // another device saved first, or the server went backwards
        if (saved.rev < S.rev) { raiseRollback('older', saved.rev, saved.blob); return; }
        await mergeRemote(saved.blob, saved.rev);
        continue;
      }
      S.rev = saved.rev;
      S.hash = await core.sha256Hex(blob);
      if (S.changes === mark) S.dirty = false;
      await cacheState(blob);
      if (!S.dirty) break;
    }
    if (S.encKey) setStatus(S.dirty ? 'pending' : 'synced');
  } catch (e) {
    if (e.message === 'newer_format' && S.encKey) {
      // Another device runs a newer version of the app. Saving from here could drop what it added, so stop and ask for a reload.
      S.outdated = true;
      $('updateBar').hidden = false;
    }
    if (S.encKey) setStatus(e.offline ? 'offline' : 'error');
  }
}
$('updateReload').addEventListener('click', () => location.reload());

// Puts this device's newer copy back on the server, keeping anything the server copy has that this device lacks.
$('rollbackFix').addEventListener('click', async () => {
  const rb = S.rollback;
  if (!rb) return;
  const btn = $('rollbackFix');
  btn.disabled = true;
  try {
    let items = S.items;
    if (rb.blob) {
      try { items = core.mergeItems(S.items, await core.decryptVault(S.encKey, S.username, rb.blob)); } catch { /* unreadable copy: keep ours */ }
    }
    const blob = await core.encryptVault(S.encKey, S.username, items);
    const r = await authed(() => api('save', { blob, baseRev: rb.serverRev, restoreRev: S.rev }));
    S.rollback = null;
    $('rollbackBar').hidden = true;
    if (r.status !== 409) {
      S.items = items;
      S.rev = r.rev;
      S.hash = await core.sha256Hex(blob);
      S.dirty = false;
      await cacheState(blob);
      renderList();
      toast('Vault restored to the server from this device');
    }
    sync(); // on a conflict the server moved again: look afresh
  } catch (e) {
    toast(e.offline ? 'Restoring needs internet' : 'Could not restore. Try again');
  } finally {
    btn.disabled = false;
  }
});

// Called after every local change: encrypt, save on this device, then push.
async function persist() {
  S.dirty = true;
  S.changes++;
  setStatus('pending'); // never show Synced while a change is still on its way
  await cacheState(await core.encryptVault(S.encKey, S.username, S.items));
  renderList();
  sync();
}

$('syncBtn').addEventListener('click', sync);
$('syncBtnM').addEventListener('click', sync);
addEventListener('online', sync);
addEventListener('offline', () => { if (S.encKey) setStatus('offline'); });
// While offline, keep trying quietly so syncing resumes even if the browser never reports the reconnect.
setInterval(() => { if (S.encKey && lastStatus === 'offline' && !document.hidden) sync(); }, 15000);
setInterval(() => { if (S.encKey && !document.hidden) sync(); }, 60000);

/* ---------- Views ---------- */

function showView(name) {
  for (const v of ['vault', 'generator', 'health', 'settings']) $('view-' + v).hidden = v !== name;
  if (name === 'vault' && wideScreen() && !$('itemDlg').open) setTimeout(() => $('search').focus(), 0);
  for (const t of document.querySelectorAll('.tab')) t.classList.toggle('active', t.dataset.view === name);
}
for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => { showView(t.dataset.view); if (t.dataset.view === 'settings') { loadLog(); loadDevices(); loadAccountInfo(); } if (t.dataset.view === 'health') refreshHealth(); });

const live = () => S.items.filter((it) => !it.deleted && !it.trashedAt);
const trashed = () => S.items.filter((it) => !it.deleted && it.trashedAt).sort((a, b) => b.trashedAt - a.trashedAt);

// Which entries were used last on this device. Only ids and times are kept, never names or passwords,
// and it stays on the device so that using an entry does not rewrite the vault.
const recents = {
  read() { try { return JSON.parse(localStorage.getItem('recent') || '{}') || {}; } catch { return {}; } },
  touch(id) {
    if (!id) return;
    const all = this.read();
    all[id] = Date.now();
    const keep = Object.entries(all).sort((x, y) => y[1] - x[1]).slice(0, 30);
    try { localStorage.setItem('recent', JSON.stringify(Object.fromEntries(keep))); } catch { /* storage blocked */ }
  },
  clear() { try { localStorage.removeItem('recent'); } catch { /* storage blocked */ } },
};

const ICON = {
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.500 20a7.500 7.500 0 0 1 15 0',
  key: 'M15 9a3 3 0 1 1-6 0 3 3 0 0 1 6 0zM12 12v8M12 16h3M12 20h2',
};
function iconButton(kind, label, onClick) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'row-btn';
  b.setAttribute('aria-label', label);
  b.title = label;
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', ICON[kind]);
  svg.append(path);
  b.append(svg);
  b.addEventListener('click', onClick);
  return b;
}

function entryRow(it) {
  const li = document.createElement('li');
  li.className = 'item';
  const main = document.createElement('button');
  main.type = 'button';
  main.className = 'item-main';
  const av = document.createElement('span');
  const name = it.title || '?';
  av.className = 'avatar av' + ([...name.toLowerCase()].reduce((n, c) => (n * 31 + c.codePointAt(0)) >>> 0, 7) % 6);
  av.textContent = [...name][0];
  av.setAttribute('aria-hidden', 'true');
  const text = document.createElement('span');
  text.className = 'item-text';
  const t = document.createElement('div');
  t.className = 'item-title';
  t.textContent = it.title || '(no name)';
  const s = document.createElement('div');
  s.className = 'item-sub';
  s.textContent = it.username || (it.url || '').replace(/^https?:\/\//, '').replace(/\/$/, '') || '';
  text.append(t, s);
  main.append(av, text);
  main.addEventListener('click', () => openItem(it.id));
  li.append(main);
  const what = it.title || 'entry';
  if (it.username) {
    li.append(iconButton('user', 'Copy username for ' + what, () => { recents.touch(it.id); copy(it.username, 'Username copied'); }));
  }
  li.append(iconButton('key', 'Copy password for ' + what, () => { recents.touch(it.id); copy(it.password, 'Password copied'); }));
  return li;
}

// Tag chips above the list. Tapping one shows only the entries that carry it.
let activeTag = '';
function tagChip(label, count, pressed, onTap) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'chip';
  b.setAttribute('aria-pressed', String(pressed));
  b.textContent = label;
  if (count !== null) {
    const n = document.createElement('span');
    n.className = 'n';
    n.textContent = String(count);
    b.append(n);
  }
  b.addEventListener('click', onTap);
  return b;
}
function renderTags() {
  const tags = core.allTags(S.items);
  if (activeTag && !tags.some((t) => t.tag.toLowerCase() === activeTag.toLowerCase())) activeTag = '';
  $('tagBar').hidden = tags.length === 0;
  const at = $('tagBar').scrollLeft; // keep the row where the user scrolled it
  $('tagBar').replaceChildren(
    tagChip('All', live().length, !activeTag, () => { activeTag = ''; renderList(); }),
    ...tags.map((t) => tagChip(t.tag, t.count, activeTag.toLowerCase() === t.tag.toLowerCase(), () => { activeTag = activeTag.toLowerCase() === t.tag.toLowerCase() ? '' : t.tag; renderList(); })),
  );
  $('tagBar').scrollLeft = at;
}

function renderList() {
  if (!S.encKey) return;
  const q = $('search').value.trim().toLowerCase();
  renderTags();
  const rows = live().filter((it) => (!activeTag || core.hasTag(it, activeTag))
    && (!q || [it.title, it.username, it.url, ...(it.tags || [])].some((f) => (f || '').toLowerCase().includes(q))));
  // While searching, show one flat list of matches. Otherwise group: favourites, recently used, the rest.
  const groups = q
    ? [{ label: '', items: rows.sort((a, b) => (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' })) }].filter((g) => g.items.length)
    : core.groupForList(rows, recents.read());
  const frag = document.createDocumentFragment();
  for (const g of groups) {
    if (g.label) {
      const h = document.createElement('h3');
      h.className = 'list-head';
      h.textContent = g.label;
      frag.append(h);
    }
    const ul = document.createElement('ul');
    ul.className = 'list';
    for (const it of g.items) ul.append(entryRow(it));
    frag.append(ul);
  }
  $('list').replaceChildren(frag);
  $('empty').hidden = rows.length > 0;
  $('empty').textContent = q ? 'No matches.' : 'Nothing here yet. Tap Add to save your first password.';
  const gone = trashed().length;
  $('trashOpen').hidden = !gone || !!q;
  $('trashOpen').textContent = `Recently deleted (${gone})`;
  if ($('trashDlg').open) renderTrash();
  refreshHealth();
}
$('search').addEventListener('input', renderList);
const wideScreen = () => matchMedia('(min-width: 761px) and (pointer: fine)').matches;
addEventListener('keydown', (ev) => {
  // "/" jumps to search from anywhere in the app, as long as nothing is being typed
  if (ev.key !== '/' || !S.encKey || $('itemDlg').open || /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) return;
  ev.preventDefault();
  showView('vault');
  $('search').focus();
});

/* ---------- Entry editor ---------- */

const FIELD_IDS = ['fTitle', 'fUser', 'fPass', 'fUrl', 'fNotes', 'fTotp', 'fTags'];
const FIELD_OF = { need_title: 'fTitle', bad_title: 'fTitle', bad_username_field: 'fUser', need_password: 'fPass', bad_password: 'fPass', password_spaces: 'fPass', bad_url: 'fUrl', bad_notes: 'fNotes', bad_totp_secret: 'fTotp', totp_unsupported: 'fTotp', bad_tags: 'fTags', too_many_tags: 'fTags' };
let editingId = null;
let fixing = false;

function siteLink(url) {
  try { return core.normalizeUrl(url) || null; } catch { return null; }
}

// `why` is set when opened from the Health tab: shows the reason and the steps to fix it.
function openItem(id, why = '') {
  const it = id ? S.items.find((x) => x.id === id) : null;
  $('fixBox').hidden = !why;
  $('fixWhy').textContent = why;
  const link = why ? siteLink(it?.url) : null;
  $('fixOpen').hidden = !link;
  if (link) $('fixOpen').href = link; else $('fixOpen').removeAttribute('href');
  fixing = !!why;
  editingId = it ? it.id : null;
  $('itemTitle').textContent = it ? 'Edit password' : 'New password';
  $('fTitle').value = it?.title || '';
  $('fUser').value = it?.username || '';
  $('fPass').value = it?.password || '';
  $('fUrl').value = it?.url || '';
  $('fNotes').value = it?.notes || '';
  $('fTotp').value = it?.totp || '';
  $('fFav').checked = !!it?.fav;
  $('fTags').value = (it?.tags || []).join(', ');
  renderTagPick();
  refreshGo();
  startCode();
  $('fPass').type = 'password';
  $('fShow').textContent = 'Show';
  $('fDelete').hidden = !it;
  $('fAge').textContent = it?.pwAt ? 'Password last changed ' + ago(it.pwAt) : '';
  $('itemMsg').textContent = '';
  for (const id of FIELD_IDS) $(id).classList.remove('bad');
  $('itemDlg').showModal();
  $('itemDlg').scrollTop = 0;
  if (why) $('fixBox').scrollIntoView({ block: 'start' });
}

// Existing tags shown under the Tags field: tap to add one to the entry or take it off.
function renderTagPick() {
  const tags = core.allTags(S.items);
  const mine = core.normalizeTags($('fTags').value);
  $('tagPick').hidden = tags.length === 0;
  $('tagPick').replaceChildren(...tags.map((t) => {
    const on = mine.some((m) => m.toLowerCase() === t.tag.toLowerCase());
    return tagChip(t.tag, null, on, () => {
      const now = core.normalizeTags($('fTags').value);
      const next = on ? now.filter((m) => m.toLowerCase() !== t.tag.toLowerCase()) : [...now, t.tag];
      $('fTags').value = next.join(', ');
      $('fTags').classList.remove('bad');
      renderTagPick();
    });
  }));
}
$('fTags').addEventListener('input', renderTagPick);

$('addBtn').addEventListener('click', () => { openItem(null); if (activeTag) { $('fTags').value = activeTag; renderTagPick(); } });
$('fCancel').addEventListener('click', () => $('itemDlg').close());
$('fUserCopy').addEventListener('click', () => { recents.touch(editingId); copy($('fUser').value, 'Username copied'); });
$('fPassCopy').addEventListener('click', () => { recents.touch(editingId); copy($('fPass').value, 'Password copied'); });

// "Copy password and open website": the link itself opens the site, the click also copies.
function refreshGo() {
  const link = siteLink($('fUrl').value);
  $('fGo').hidden = !link || !$('fPass').value;
  if (link) $('fGo').href = link; else $('fGo').removeAttribute('href');
}
$('fUrl').addEventListener('input', refreshGo);
$('fPass').addEventListener('input', refreshGo);
$('fGo').addEventListener('click', () => { recents.touch(editingId); copy($('fPass').value, 'Password copied. Opening the site'); });

// Live authenticator code for the key in the field, refreshed every second while the editor is open.
let codeTimer = null;
async function showCode() {
  let key = '';
  try { key = core.normalizeTotp($('fTotp').value); } catch { /* not a usable key yet */ }
  if (!key || !$('itemDlg').open) { $('codeBox').hidden = true; $('codeNow').textContent = ''; return; }
  const { code, left } = await core.totpNow(key);
  $('codeNow').textContent = code.slice(0, 3) + ' ' + code.slice(3);
  $('codeLeft').textContent = `changes in ${left}s`;
  $('codeBox').hidden = false;
}
function startCode() {
  clearInterval(codeTimer);
  codeTimer = setInterval(showCode, 1000);
  setTimeout(showCode, 0);
}
$('fTotp').addEventListener('input', showCode);
// A field marked as wrong goes back to normal as soon as it is edited.
for (const id of FIELD_IDS) $(id).addEventListener('input', () => $(id).classList.remove('bad'));
$('codeCopy').addEventListener('click', () => { recents.touch(editingId); copy($('codeNow').textContent.replace(/\s/g, ''), 'Code copied'); });
$('itemDlg').addEventListener('close', () => { clearInterval(codeTimer); $('codeBox').hidden = true; $('codeNow').textContent = ''; $('fTotp').value = ''; });
$('fShow').addEventListener('click', () => {
  const show = $('fPass').type === 'password';
  $('fPass').type = show ? 'text' : 'password';
  $('fShow').textContent = show ? 'Hide' : 'Show';
});
$('fGen').addEventListener('click', () => {
  $('fPass').value = currentGenerated().value;
  $('fPass').type = 'text';
  $('fShow').textContent = 'Hide';
});

$('itemForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  for (const id of FIELD_IDS) $(id).classList.remove('bad');
  let clean;
  try {
    clean = core.validateEntry({
      title: $('fTitle').value, username: $('fUser').value, password: $('fPass').value, url: $('fUrl').value, notes: $('fNotes').value,
      totp: $('fTotp').value, tags: $('fTags').value,
    });
  } catch (e) {
    $('itemMsg').textContent = explain(e);
    const field = $(FIELD_OF[e.message] || 'fTitle');
    field.classList.add('bad');
    field.focus();
    return;
  }
  const data = { ...clean, updatedAt: Date.now(), deleted: false };
  if ($('fFav').checked) data.fav = true;
  if (editingId) {
    const i = S.items.findIndex((x) => x.id === editingId);
    const { fav, totp, tags, ...kept } = S.items[i]; // optional fields come only from the form
    // The password's age restarts only when the password itself changes.
    if (kept.password !== data.password) data.pwAt = data.updatedAt;
    else breach.carry(editingId, kept.updatedAt, data.updatedAt);
    S.items[i] = { ...kept, ...data };
  } else {
    S.items.push({ id: core.newId(), createdAt: Date.now(), ...data, pwAt: data.updatedAt });
  }
  $('itemDlg').close();
  await persist();
  if (fixing) $('healthMsg').textContent = 'Saved. Run the check again to confirm it is fixed.';
  toast('Saved');
});

// Delete moves the entry to Recently deleted, where it stays for 30 days, and offers Undo straight away.
$('fDelete').addEventListener('click', async () => {
  const id = editingId;
  const i = S.items.findIndex((x) => x.id === id);
  if (i < 0) return;
  const now = Date.now();
  S.items[i] = { ...S.items[i], trashedAt: now, updatedAt: now };
  $('itemDlg').close();
  await persist();
  toast('Entry deleted', { label: 'Undo', run: () => restoreEntry(id) });
});

/* ---------- Recently deleted ---------- */

async function restoreEntry(id) {
  const i = S.items.findIndex((x) => x.id === id && !x.deleted && x.trashedAt);
  if (i < 0 || !S.encKey) return;
  const { trashedAt, ...kept } = S.items[i];
  S.items[i] = { ...kept, updatedAt: Date.now() };
  await persist();
  toast('Restored');
}
// Removes entries for good. Only a marker (id and time) stays, so the removal reaches the other devices.
async function eraseEntries(ids) {
  const now = Date.now();
  S.items = S.items.map((it) => (ids.includes(it.id) ? { id: it.id, deleted: true, updatedAt: now } : it));
  await persist();
}
function armed(btn, label, run) {
  btn.addEventListener('click', () => {
    if (btn.dataset.armed) { delete btn.dataset.armed; btn.textContent = label; run(); return; }
    btn.dataset.armed = '1';
    btn.textContent = 'Tap again to confirm';
    setTimeout(() => { if (btn.dataset.armed) { delete btn.dataset.armed; btn.textContent = label; } }, 4000);
  });
}
function renderTrash() {
  const rows = trashed();
  const frag = document.createDocumentFragment();
  for (const it of rows) {
    const row = document.createElement('div');
    row.className = 'trash-row';
    const main = document.createElement('div');
    main.className = 'log-main';
    const name = document.createElement('strong');
    name.textContent = it.title || '(no name)';
    const sub = document.createElement('div');
    sub.className = 'muted';
    const left = core.trashDaysLeft(it);
    sub.textContent = [it.username, left === 1 ? '1 day left' : `${left} days left`].filter(Boolean).join(' · ');
    main.append(name, sub);
    const back = document.createElement('button');
    back.type = 'button';
    back.className = 'btn small';
    back.textContent = 'Restore';
    back.setAttribute('aria-label', 'Restore ' + (it.title || 'entry'));
    back.addEventListener('click', () => restoreEntry(it.id));
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'btn small danger';
    del.textContent = 'Delete';
    del.setAttribute('aria-label', 'Delete ' + (it.title || 'entry') + ' for good');
    armed(del, 'Delete', async () => { await eraseEntries([it.id]); toast('Deleted for good'); });
    row.append(main, back, del);
    frag.append(row);
  }
  $('trashList').replaceChildren(frag);
  $('trashEmpty').hidden = rows.length > 0;
  $('trashEmptyBtn').hidden = rows.length === 0;
}
$('trashOpen').addEventListener('click', () => { renderTrash(); $('trashDlg').showModal(); });
$('trashClose').addEventListener('click', () => $('trashDlg').close());
armed($('trashEmptyBtn'), 'Delete all now', async () => { await eraseEntries(trashed().map((it) => it.id)); toast('Recently deleted is now empty'); });

/* ---------- Generator ---------- */

let genMode = 'random';
function currentGenerated() {
  return genMode === 'random'
    ? core.generatePassword({
      length: +$('gLen').value, lower: $('gLower').checked, upper: $('gUpper').checked,
      digits: $('gDigits').checked, symbols: $('gSymbols').checked,
    })
    : core.generatePassphrase({ words: +$('gWords').value, capitalize: $('gCap').checked, number: $('gNum').checked });
}
function regenerate() {
  $('lenVal').textContent = $('gLen').value;
  $('wordsVal').textContent = $('gWords').value;
  const g = currentGenerated();
  $('genOut').textContent = g.value;
  const grade = g.bits >= 100 ? 'excellent' : g.bits >= 75 ? 'strong' : g.bits >= 60 ? 'fair' : 'weak';
  $('genBits').textContent = `About ${g.bits} bits of entropy (${grade})`;
}
function setMode(mode) {
  genMode = mode;
  $('modeRandom').classList.toggle('active', mode === 'random');
  $('modeWords').classList.toggle('active', mode === 'words');
  $('optRandom').hidden = mode !== 'random';
  $('optWords').hidden = mode !== 'words';
  regenerate();
}
$('modeRandom').addEventListener('click', () => setMode('random'));
$('modeWords').addEventListener('click', () => setMode('words'));
for (const id of ['gLen', 'gLower', 'gUpper', 'gDigits', 'gSymbols', 'gWords', 'gCap', 'gNum']) $(id).addEventListener('input', regenerate);
$('genNew').addEventListener('click', regenerate);
$('genCopy').addEventListener('click', () => copy($('genOut').textContent, 'Password copied'));

/* ---------- Health check ---------- */

function healthGroup(title, tone, note, rows) {
  const card = document.createElement('div');
  card.className = 'card h-group';
  const h = document.createElement('h3');
  h.textContent = title + ' ';
  const b = document.createElement('span');
  b.className = 'badge ' + (rows.length ? tone : 'good');
  b.textContent = String(rows.length);
  h.append(b);
  card.append(h);
  if (rows.length) {
    const n = document.createElement('p');
    n.className = 'h-note';
    n.textContent = note;
    card.append(n);
  }
  for (const [it, detail, why] of rows) {
    const row = document.createElement('div');
    row.className = 'h-row';
    const info = document.createElement('div');
    info.className = 'h-info';
    const name = document.createElement('span');
    name.className = 'h-name';
    name.textContent = it.title || '(no name)';
    const d = document.createElement('span');
    d.textContent = [it.username, detail].filter(Boolean).join(' · ');
    info.append(name, d);
    const fix = document.createElement('button');
    fix.type = 'button';
    fix.className = 'h-fix';
    fix.textContent = 'Fix';
    fix.setAttribute('aria-label', 'Fix ' + (it.title || 'entry'));
    fix.addEventListener('click', () => openItem(it.id, why));
    row.append(info, fix);
    card.append(row);
  }
  return card;
}

// Results of the last breach check, kept on this device only: entry ids, how often each password was seen,
// and when each entry was last edited at the time. No names and no passwords. Removed on sign out.
const breach = {
  read() {
    try { const v = JSON.parse(localStorage.getItem('health') || 'null'); return v && typeof v.r === 'object' && v.r ? v : null; } catch { return null; }
  },
  write(v) { try { localStorage.setItem('health', JSON.stringify(v)); } catch { /* storage blocked */ } },
  // An edit that leaves the password alone keeps its result.
  carry(id, from, to) { const v = this.read(); if (v && Array.isArray(v.r[id]) && v.r[id][1] === from) { v.r[id][1] = to; this.write(v); } },
  clear() { try { localStorage.removeItem('health'); } catch { /* storage blocked */ } },
};

function ago(t) {
  const days = Math.floor((Date.now() - t) / 86400000);
  if (days < 1) return 'today';
  if (days < 60) return days === 1 ? 'yesterday' : `${days} days ago`;
  if (days < 730) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

// Works out what needs attention from what is already on this device (nothing is sent anywhere),
// updates the count on the Health tab and, when that tab is showing, the lists.
function refreshHealth() {
  if (!S.encKey) return;
  const saved = breach.read();
  const f = core.healthFindings(S.items, saved ? saved.r : {});
  $('healthBadge').hidden = f.total === 0;
  $('healthBadge').textContent = f.total > 99 ? '99+' : String(f.total);
  $('healthBadge').setAttribute('aria-label', `${f.total} need attention`);
  if ($('view-health').hidden || $('healthBtn').disabled) return;

  $('healthSum').classList.toggle('clear', f.total === 0 && f.checked > 0);
  $('healthSum').textContent = !f.checked ? '' : f.total ? `${f.total} of ${f.checked} entries need attention` : `No issues found in ${f.checked} entries`;
  $('healthBtn').textContent = saved ? 'Check for breaches again' : 'Check for breaches';
  $('healthNote').textContent = saved ? 'Breach check last run on this device ' + ago(saved.at) + '.' : 'Breach check not run on this device yet. Reused, weak and old passwords are found without it.';

  const leaked = f.leaked.map(({ it, count }) => [it, `seen ${count.toLocaleString()} times in breaches`,
    `This exact password appears ${count.toLocaleString()} times in leaked password lists, so attackers try it early. The lists hold passwords only and do not record which website or account they came from. It cannot be removed from those lists; changing it makes the leaked one useless.`]);
  const reused = f.reused.flatMap((g) => g.map((it) => [it, `shared by ${g.length} entries`,
    `This password is used by ${g.length} entries (${g.map((x) => x.title || 'no name').join(', ')}). If one of those sites is breached, the others are exposed too. Give each one its own password.`]));
  const weak = f.weak.map((it) => [it, 'short or simple',
    'This password is short or simple enough to be guessed quickly. Replace it with a generated one.']);
  const old = f.old.map((it) => [it, 'changed ' + ago(it.pwAt),
    `This password was last changed ${ago(it.pwAt)}. Age alone is not a fault, so there is no rush if it is strong and used only here. Change it if the account matters a lot or the site has had a breach.`]);
  const groups = [];
  if (saved) groups.push(healthGroup('Found in data breaches', 'bad', 'These exact passwords are in leaked password lists. Change them first, on every site where you use them.', leaked));
  groups.push(
    healthGroup('Reused', 'warn', 'The same password protects more than one account. Give each account its own.', reused),
    healthGroup('Weak', 'warn', 'Short or simple passwords that are quick to guess.', weak),
    healthGroup('Older than a year', 'warn', 'Passwords not changed for over a year. Imported entries are not listed until their password is changed here, because their age is unknown.', old),
  );
  $('healthOut').replaceChildren(...groups);
}

$('healthBtn').addEventListener('click', async () => {
  const btn = $('healthBtn');
  const msg = $('healthMsg');
  const items = live().filter((it) => it.password);
  btn.disabled = true;

  // One lookup per distinct password, a few at a time.
  const unique = [...new Set(items.map((it) => it.password))];
  const counts = new Map();
  let done = 0;
  let failed = false;
  const worker = async () => {
    while (unique.length && !failed && S.encKey) {
      const pw = unique.pop();
      try { counts.set(pw, await core.pwnedCount(pw)); }
      catch { failed = true; }
      msg.textContent = `Checked ${++done} passwords`;
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  btn.disabled = false;
  if (!S.encKey) return;

  if (failed) msg.textContent = 'Could not reach the leak check service. Reused, weak and old results are still shown. Try again when online.';
  else {
    const r = {};
    for (const it of items) if (counts.get(it.password) > 0) r[it.id] = [counts.get(it.password), it.updatedAt];
    breach.write({ at: Date.now(), r });
    const total = core.healthFindings(S.items, r).total;
    msg.textContent = `Checked ${items.length} entries. ${total ? 'Tap Fix on each one below.' : 'All clear.'}`;
  }
  refreshHealth();
});

/* ---------- Settings ---------- */

$('lockMin').value = String(parseInt(localStorage.getItem('lockMin'), 10) || 5);
$('lockMin').addEventListener('change', () => localStorage.setItem('lockMin', $('lockMin').value));

$('stayUnlocked').checked = stayOn();
$('stayUnlocked').addEventListener('change', () => {
  localStorage.setItem('stayUnlocked', $('stayUnlocked').checked ? '1' : '0');
  rememberUnlock();
});

function renderAccount() {
  $('recStatus').textContent = S.hasRecovery
    ? 'A recovery key is set for this account. Creating a new one replaces it.'
    : 'No recovery key yet. Without one, a forgotten master password cannot be reset by anyone.';
  $('recBtn').textContent = S.hasRecovery ? 'Replace recovery key' : 'Create recovery key';
  $('tfaStatus').textContent = S.totp
    ? 'Two-factor sign-in is on. A new device needs your master password and a code from your authenticator app.'
    : 'Off. Anyone who learns your master password could sign in from their own device.';
  $('tfaBegin').hidden = S.totp;
  $('tfaOff').hidden = !S.totp;
  renderBackup();
  renderKeys();
  const q = quickFor(S.username);
  $('pinBtn').textContent = q && q.pin ? 'Change PIN' : 'Set PIN';
  $('pinOff').hidden = !(q && q.pin);
  $('bioOn').textContent = 'Turn on ' + bioName;
  $('bioOff').textContent = 'Turn off ' + bioName;
  $('bioOn').hidden = !!(q && q.bio);
  $('bioOff').hidden = !(q && q.bio);
}

// Runs a signed-in request, signing in again first if the server session has expired.
async function authed(fn) {
  try { return await fn(); }
  catch (e) {
    if (e.message !== 'signed_out') throw e;
    await relogin();
    return fn();
  }
}

// Re-enter the current master password before any sensitive change. Returns its keys and the raw vault key.
async function confirmMaster(password) {
  if (!password) throw new Error('need_current');
  const keys = await core.deriveKeys(password, S.salt, S.kdf);
  if (keys.auth !== S.auth) throw new Error('bad_current');
  if (!S.wrap) { // account not upgraded yet (this device was offline since the update)
    const r = await signIn(S.username, keys);
    S.wrap = r.wrap;
    await patchCache();
    return { keys, vkRaw: r.vkRaw };
  }
  return { keys, vkRaw: await core.unwrapKey(keys.kek, S.username, S.wrap) };
}

async function withButton(btn, msg, fn) {
  msg.className = 'msg';
  msg.textContent = '';
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Working';
  try {
    const done = await fn();
    msg.className = 'msg ok';
    msg.textContent = done;
  } catch (e) {
    msg.textContent = explain(e);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
    renderAccount();
  }
}

$('cpBtn').addEventListener('click', () => withButton($('cpBtn'), $('cpMsg'), async () => {
  const next = $('cpNew').value;
  checkStrength(next, $('cpNew2').value);
  const { keys: cur, vkRaw } = await confirmMaster($('cpCur').value);
  const salt = newSalt();
  const kdf = { ...core.KDF_DEFAULT };
  const keys = await core.deriveKeys(next, salt, kdf);
  const wrap = await core.wrapKey(keys.kek, S.username, vkRaw);
  await authed(() => api('rekey', { auth: cur.auth, newAuth: keys.auth, salt, kdf, wrap, trust: trust && trust.username === S.username ? trust.token : undefined }));
  Object.assign(S, { auth: keys.auth, salt, kdf, wrap });
  sealedAuth = await core.sealText(S.encKey, S.auth);
  await patchCache();
  await rememberUnlock();
  const hadPin = !!(quick && quick.pin);
  if (quick) { delete quick.pin; quick.auth = sealedAuth; await saveQuick(); } // the server turned PINs off for this account
  for (const id of ['cpCur', 'cpNew', 'cpNew2']) $(id).value = '';
  return 'Master password changed. Your other devices are signed out and will ask for the new one.' + (hadPin ? ' PIN unlock was turned off, so set your PIN again.' : '');
}));

$('recBtn').addEventListener('click', () => withButton($('recBtn'), $('recMsg'), async () => {
  $('recOut').hidden = true;
  const { keys: cur, vkRaw } = await confirmMaster($('recPass').value);
  const code = core.generateRecoveryCode();
  const rec = await core.deriveRecoveryKeys(code, S.username);
  const recWrap = await core.wrapKey(rec.kek, S.username, vkRaw, 'rec');
  await authed(() => api('recovery_set', { auth: cur.auth, recAuth: rec.auth, recWrap }));
  S.hasRecovery = true;
  await patchCache();
  $('recPass').value = '';
  $('recCode').textContent = code;
  $('recOut').hidden = false;
  return 'Recovery key created. It is shown only this once.';
}));
$('recCopy').addEventListener('click', () => copy($('recCode').textContent, 'Recovery key copied'));
$('recHide').addEventListener('click', () => { $('recCode').textContent = ''; $('recOut').hidden = true; $('recMsg').textContent = ''; });

async function quickBase() {
  if (!sealedAuth) sealedAuth = await core.sealText(S.encKey, S.auth);
  return quickFor(S.username) || { username: S.username, auth: sealedAuth };
}

$('pinBtn').addEventListener('click', () => withButton($('pinBtn'), $('pinMsg'), async () => {
  const pin = $('qPin').value;
  core.checkPin(pin);
  if (pin !== $('qPin2').value) throw new Error('pin_mismatch');
  const { keys: cur, vkRaw } = await confirmMaster($('qPass').value);
  const deviceId = core.b64.enc(rnd(16));
  const kdev = rnd(32);
  const ksrv = rnd(32);
  const wrap = await core.wrapKey(await core.pinKek(kdev, ksrv), S.username, vkRaw, 'pin');
  const pinAuth = await core.derivePinAuth(pin, kdev);
  await authed(() => api('pin_set', { auth: cur.auth, deviceId, pinAuth, ksrv: core.b64.enc(ksrv) }));
  ksrv.fill(0); // only the server keeps this half
  const q = await quickBase();
  const old = q.pin && q.pin.deviceId;
  q.pin = { deviceId, kdev, wrap };
  quick = q;
  await saveQuick();
  if (old) api('pin_clear', { deviceId: old }).catch(() => {});
  for (const id of ['qPass', 'qPin', 'qPin2']) $(id).value = '';
  return 'PIN is on for this device. Three wrong tries turn it off.';
}));

$('pinOff').addEventListener('click', () => withButton($('pinOff'), $('pinMsg'), async () => {
  const q = quickFor(S.username);
  if (q && q.pin) {
    await authed(() => api('pin_clear', { deviceId: q.pin.deviceId })).catch(() => {});
    delete q.pin;
    await saveQuick();
  }
  return 'PIN is off for this device.';
}));

$('bioOn').addEventListener('click', () => withButton($('bioOn'), $('bioMsg'), async () => {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('bio_unsupported');
  const { vkRaw } = await confirmMaster($('qPass').value);
  const salt = rnd(32);
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: {
      challenge: rnd(32),
      rp: { name: 'Vault', id: location.hostname },
      user: { id: rnd(16), name: S.username, displayName: 'Vault: ' + S.username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
      timeout: 60000, attestation: 'none',
      extensions: { prf: { eval: { first: salt } } },
    } });
  } catch { throw new Error('bio_failed'); }
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) throw new Error('bio_unsupported');
  const bio = { credId: core.b64.enc(new Uint8Array(cred.rawId)), salt: core.b64.enc(salt) };
  // Some browsers hand back the secret straight away; others need one more face or fingerprint check.
  let secret = ext.results && ext.results.first;
  if (!secret) {
    try { secret = await bioSecret(bio); }
    catch (e) { throw new Error(e.message === 'bio_unsupported' ? 'bio_unsupported' : 'bio_failed'); }
  }
  bio.wrap = await core.wrapKey(await core.bioKek(secret), S.username, vkRaw, 'bio');
  const q = await quickBase();
  q.bio = bio;
  quick = q;
  await saveQuick();
  $('qPass').value = '';
  authed(() => api('note', { e: 'bio_on' })).catch(() => {});
  return bioName + ' unlock is on for this device. Opening the app will now ask for it.';
}));

$('bioOff').addEventListener('click', () => withButton($('bioOff'), $('bioMsg'), async () => {
  const q = quickFor(S.username);
  if (q) { delete q.bio; await saveQuick(); authed(() => api('note', { e: 'bio_off' })).catch(() => {}); }
  return bioName + ' unlock is off for this device. You can also delete the "Vault" passkey in your device password settings.';
}));

/* ---------- Two-factor sign-in ---------- */

let tfaPending = null; // { auth, secret } between "Set up" and "Turn on"

function drawQr(target, text) {
  const qr = globalThis.qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${n + 8} ${n + 8}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'QR code for your authenticator app');
  const bg = document.createElementNS(NS, 'rect');
  bg.setAttribute('width', n + 8);
  bg.setAttribute('height', n + 8);
  bg.setAttribute('fill', '#fff');
  svg.append(bg);
  let d = '';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', d);
  path.setAttribute('fill', '#000');
  svg.append(path);
  target.replaceChildren(svg);
}

$('tfaBegin').addEventListener('click', () => withButton($('tfaBegin'), $('tfaMsg'), async () => {
  const { keys } = await confirmMaster($('tfaPass').value);
  const secret = core.newTotpSecret();
  tfaPending = { auth: keys.auth, secret };
  const uri = core.otpauthUri(secret, S.username);
  drawQr($('tfaQr'), uri);
  $('tfaKey').textContent = secret.match(/.{4}/g).join(' ');
  $('tfaLink').href = uri;
  $('tfaSetup').hidden = false;
  $('tfaPass').value = '';
  $('tfaCode').focus();
  return 'Add the key to your authenticator app, then enter the code it shows.';
}));

$('tfaOn').addEventListener('click', () => withButton($('tfaOn'), $('tfaMsg'), async () => {
  if (!tfaPending) throw new Error('bad_secret');
  const code = $('tfaCode').value.replace(/\D/g, '');
  if (code.length !== 6) throw new Error('bad_totp');
  const r = await authed(() => api('totp_enable', { auth: tfaPending.auth, secret: tfaPending.secret, code }));
  await keepTrust(S.username, r.trust);
  S.totp = true;
  tfaPending = null;
  await patchCache();
  $('tfaSetup').hidden = true;
  $('tfaCode').value = '';
  $('tfaKey').textContent = '';
  $('tfaQr').replaceChildren();
  S.backup = 0;
  renderAccount();
  return 'Two-factor sign-in is on. This device stays signed in; any other device will need a code once. Create backup codes below in case you lose the authenticator.';
}));

$('tfaOff').addEventListener('click', () => withButton($('tfaOff'), $('tfaMsg'), async () => {
  const { keys } = await confirmMaster($('tfaPass').value);
  await authed(() => api('totp_disable', { auth: keys.auth }));
  S.totp = false;
  S.backup = 0;
  S.keys = [];
  trust = null;
  await store.del('trust').catch(() => {});
  await patchCache();
  $('tfaPass').value = '';
  renderAccount();
  return 'Two-factor sign-in is off.';
}));
$('tfaCopy').addEventListener('click', () => copy($('tfaKey').textContent.replace(/\s/g, ''), 'Key copied'));

/* ---------- Import from CSV ---------- */

$('csvBtn').addEventListener('click', () => withButton($('csvBtn'), $('csvMsg'), async () => {
  const file = $('csvFile').files[0];
  if (!file) throw new Error('csv_none');
  if (file.size > 5 * 1024 * 1024) throw new Error('csv_too_big');
  const { items, duplicates, skipped } = core.importCsv(await file.text(), S.items);
  if (items.length) {
    S.items = S.items.concat(items);
    await persist();
  }
  $('csvFile').value = '';
  const parts = [`Imported ${items.length} ${items.length === 1 ? 'entry' : 'entries'}.`];
  if (duplicates) parts.push(`${duplicates} already in the vault, skipped.`);
  if (skipped.length) {
    const lines = skipped.slice(0, 8).map((x) => `line ${x.line} (${x.reason})`).join(', ');
    parts.push(`${skipped.length} not imported: ${lines}${skipped.length > 8 ? ' and more' : ''}.`);
  }
  parts.push('Now delete the CSV file from this device.');
  return parts.join(' ');
}));

/* ---------- Access log ---------- */

let logEntries = [];
let logIp = '';

function renderLog() {
  const rows = core.filterLog(logEntries, { type: $('logType').value, days: +$('logDays').value, text: $('logSearch').value });
  const frag = document.createDocumentFragment();
  for (const en of rows.slice(0, 200)) {
    const [label, kind] = core.LOG_EVENTS[en.e] || ['Other activity', 'ok'];
    const row = document.createElement('div');
    row.className = 'log-row ' + kind;
    const dot = document.createElement('span');
    dot.className = 'log-dot ' + kind;
    const main = document.createElement('div');
    main.className = 'log-main';
    const title = document.createElement('div');
    title.className = 'log-title';
    title.textContent = label;
    if (en.ip === logIp && en.ua === navigator.userAgent) {
      const tag = document.createElement('span');
      tag.className = 'log-tag';
      tag.textContent = 'This device';
      title.append(tag);
    }
    const sub = document.createElement('div');
    sub.className = 'log-sub';
    const when = new Date(en.t * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    sub.textContent = `${when} · ${core.describeDevice(en.ua)} · ${en.ip}${en.where ? ' · ' + en.where : ''}`;
    main.append(title, sub);
    if (en.u !== undefined && en.u !== S.username) {
      const who = document.createElement('div');
      who.className = 'log-sub log-who';
      who.textContent = en.u ? 'Username tried: ' + en.u : 'No username was given';
      main.append(who);
    }
    row.append(dot, main);
    frag.append(row);
  }
  $('logList').replaceChildren(frag);
  $('logCount').textContent = rows.length
    ? `${Math.min(rows.length, 200)} of ${rows.length} matching events`
    : (logEntries.length ? 'No events match these filters.' : '');
}

async function loadLog() {
  const msg = $('logMsg');
  msg.textContent = '';
  try {
    const r = await authed(() => api('log'));
    const where = r.where && typeof r.where === 'object' ? r.where : {};
    logEntries = (Array.isArray(r.entries) ? r.entries : []).map((en) => ({ ...en, where: typeof where[en.ip] === 'string' ? where[en.ip] : '' }));
    logIp = r.ip || '';
    const notes = [];
    if (r.owner) notes.push('You are the owner of this server, so this also lists failed attempts on usernames that do not exist and on other accounts.');
    if (r.geo === 'failed') notes.push('City lookup did not return anything just now. The lookup service may be busy, or your hosting may block outgoing requests. It is tried again within the hour.');
    if (r.geo === 'off') notes.push('City lookup is switched off in the server settings.');
    $('logScope').textContent = notes.join(' ');
    renderLog();
  } catch (e) {
    msg.textContent = e.offline ? 'The access log needs internet.' : explain(e);
  }
}
for (const id of ['logType', 'logDays']) $(id).addEventListener('change', renderLog);
$('logSearch').addEventListener('input', renderLog);
$('logRefresh').addEventListener('click', loadLog);

$('exportBtn').addEventListener('click', async () => {
  const blob = await core.encryptVault(S.encKey, S.username, S.items);
  const file = new Blob([JSON.stringify({ format: 'vault-backup-v2', username: S.username, salt: S.salt, kdf: S.kdf, wrap: S.wrap, blob })], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(file);
  a.download = `vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  toast('Encrypted backup downloaded');
});

$('importBtn').addEventListener('click', async () => {
  const msg = $('importMsg');
  msg.className = 'msg';
  msg.textContent = '';
  const file = $('importFile').files[0];
  if (!file || !$('importPass').value) { msg.textContent = 'Choose a backup file and enter its master password.'; return; }
  $('importBtn').disabled = true;
  try {
    const b = JSON.parse(await file.text());
    if (b.format !== 'vault-backup-v1' && b.format !== 'vault-backup-v2') throw new Error('format');
    // A backup opens with the master password that was in use when it was made.
    const keys = await core.deriveKeys($('importPass').value, b.salt, b.kdf);
    const raw = b.wrap ? await core.unwrapKey(keys.kek, b.username, b.wrap) : keys.legacyRaw;
    const items = await core.decryptVault(await core.importVaultKey(raw), b.username, b.blob);
    S.items = core.mergeItems(S.items, items);
    await persist();
    msg.className = 'msg ok';
    msg.textContent = `Merged ${items.filter((it) => !it.deleted && !it.trashedAt).length} entries from the backup.`;
  } catch {
    msg.textContent = 'Could not open that backup. Check the file and the master password it was made with.';
  } finally {
    $('importPass').value = '';
    $('importBtn').disabled = false;
  }
});

let signOutArmed = false;
$('signOutBtn').addEventListener('click', async () => {
  if (S.dirty && !signOutArmed) {
    signOutArmed = true;
    $('signOutBtn').textContent = 'Unsynced changes will be lost. Tap again';
    return;
  }
  signOutArmed = false;
  $('signOutBtn').textContent = 'Sign out of this device';
  if (quick && quick.pin) await api('pin_clear', { deviceId: quick.pin.deviceId }).catch(() => {});
  try { await api('logout', {}); } catch { /* offline is fine */ }
  quick = null;
  trust = null;
  recents.clear();
  breach.clear();
  await store.del('quick').catch(() => {});
  await store.del('trust').catch(() => {});
  await store.del('state');
  await newDid(); // the server has forgotten this device; it starts afresh next time
  lock();
  $('aUser').value = '';
});

$('totpAlt').addEventListener('click', () => { setBackupMode(!backupMode); $('authMsg').textContent = ''; $('aTotp').focus(); });
// Second step with a security key: the key signs the server's challenge, then the form is sent again with it.
$('keyBtn').addEventListener('click', async () => {
  if (!keyOffer || $('authBtn').disabled) return;
  const msg = $('authMsg');
  msg.textContent = '';
  let a;
  try {
    a = await navigator.credentials.get({ publicKey: {
      challenge: b64u.dec(keyOffer.challenge),
      rpId: location.hostname,
      allowCredentials: (keyOffer.list || keyOffer.ids.map((id) => ({ id }))).map((k) => {
        const c = { type: 'public-key', id: b64u.dec(k.id) };
        if (k.tr && k.tr.length) c.transports = k.tr;
        return c;
      }),
      userVerification: 'discouraged', timeout: 60000,
    } });
  } catch { msg.textContent = ERRORS.key_cancelled; return; }
  keyAnswer = {
    id: b64u.enc(a.rawId), clientData: b64u.enc(a.response.clientDataJSON),
    authData: b64u.enc(a.response.authenticatorData), sig: b64u.enc(a.response.signature),
  };
  $('authForm').requestSubmit();
});

/* ---------- Two-factor backup codes ---------- */

let backupList = null; // the codes just created, held only until the user says they are saved
function renderBackup() {
  $('tfaBackup').hidden = !S.totp;
  if (!S.totp) { backupList = null; $('backupShow').hidden = true; $('backupCodes').textContent = ''; return; }
  const n = S.backup;
  $('backupStatus').textContent = n === undefined ? '' : n === 0 ? 'No backup codes yet. Without them, losing your authenticator means using the recovery key.'
    : n === 1 ? '1 backup code left. Create new ones soon.' : `${n} backup codes left.`;
  $('backupNew').textContent = n ? 'Replace backup codes' : 'Create backup codes';
}
async function loadAccountInfo() {
  if (!S.encKey) return;
  try {
    const r = await authed(() => api('account'));
    if (!S.encKey) return;
    S.backup = r.backup;
    S.keys = Array.isArray(r.keys) ? r.keys : [];
    renderBackup();
    renderKeys();
  } catch { /* offline: the count simply stays as it was */ }
}
$('backupNew').addEventListener('click', () => withButton($('backupNew'), $('backupMsg'), async () => {
  const { keys } = await confirmMaster($('tfaPass').value);
  const r = await authed(() => api('totp_backup', { auth: keys.auth }));
  backupList = r.codes;
  S.backup = r.codes.length;
  $('tfaPass').value = '';
  $('backupCodes').textContent = r.codes.join('\n');
  $('backupShow').hidden = false;
  renderBackup();
  return 'New backup codes created. Any earlier ones no longer work.';
}));
$('backupCopy').addEventListener('click', () => { if (backupList) copy(backupList.join('\n'), 'Backup codes copied'); });
$('backupSave').addEventListener('click', () => {
  if (!backupList) return;
  const text = `Vault two-factor backup codes for ${S.username}\nCreated ${new Date().toISOString().slice(0, 10)}. Each code works once.\n\n${backupList.join('\n')}\n`;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  a.download = 'vault-backup-codes.txt';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('Backup codes downloaded');
});
$('backupHide').addEventListener('click', () => { backupList = null; $('backupCodes').textContent = ''; $('backupShow').hidden = true; $('backupMsg').textContent = ''; });

/* ---------- Security keys ---------- */

function renderKeys() {
  $('tfaKeys').hidden = !S.totp;
  const list = S.totp ? S.keys || [] : [];
  $('keyStatus').textContent = !keysUsable() ? 'This browser cannot use security keys.'
    : list.length ? '' : 'No security keys yet.';
  $('keyAdd').disabled = !keysUsable();
  const frag = document.createDocumentFragment();
  for (const k of list) {
    const row = document.createElement('div');
    row.className = 'dev-row';
    const top = document.createElement('div');
    top.className = 'dev-top';
    const name = document.createElement('strong');
    name.textContent = k.name;
    top.append(name);
    const sub = document.createElement('p');
    sub.className = 'muted';
    sub.textContent = 'Added ' + since(k.at) + ' · ' + (k.last ? 'last used ' + since(k.last) : 'not used yet');
    const acts = document.createElement('div');
    acts.className = 'dev-acts';
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn small danger';
    b.textContent = 'Remove';
    b.setAttribute('aria-label', 'Remove security key ' + k.name);
    b.addEventListener('click', () => withButton(b, $('keyMsg'), async () => {
      const { keys } = await confirmMaster($('tfaPass').value);
      const r = await authed(() => api('key_remove', { auth: keys.auth, id: k.id }));
      S.keys = r.keys;
      $('tfaPass').value = '';
      return 'Security key removed.';
    }));
    acts.append(b);
    row.append(top, sub, acts);
    frag.append(row);
  }
  $('keyList').replaceChildren(frag);
}
$('keyAdd').addEventListener('click', () => withButton($('keyAdd'), $('keyMsg'), async () => {
  if (!keysUsable()) throw new Error('key_unsupported');
  const name = $('keyName').value.trim();
  if (!name || name.length > 40) throw new Error('bad_key_name');
  const { keys } = await confirmMaster($('tfaPass').value);
  const g = await authed(() => api('key_begin', { auth: keys.auth }));
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: {
      challenge: b64u.dec(g.challenge),
      rp: { name: 'Vault', id: location.hostname },
      user: { id: b64u.dec(g.user), name: S.username, displayName: 'Vault sign-in: ' + S.username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      excludeCredentials: g.ids.map((id) => ({ type: 'public-key', id: b64u.dec(id) })),
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'discouraged' },
      timeout: 60000, attestation: 'none',
    } });
  } catch { throw new Error('key_failed'); }
  const res = cred.response;
  const pk = res.getPublicKey ? res.getPublicKey() : null;
  if (!pk || !res.getAuthenticatorData) throw new Error('key_unsupported');
  const r = await authed(() => api('key_add', {
    name, id: b64u.enc(cred.rawId), clientData: b64u.enc(res.clientDataJSON),
    authData: b64u.enc(res.getAuthenticatorData()), pk: b64u.enc(pk), alg: res.getPublicKeyAlgorithm(),
    transports: res.getTransports ? res.getTransports() : [],
  }));
  S.keys = r.keys;
  $('keyName').value = '';
  $('tfaPass').value = '';
  return 'Security key added. On a new device you can now use it instead of typing a code.';
}));

/* ---------- Devices ---------- */

function since(sec) {
  const min = Math.floor((Date.now() - sec * 1000) / 60000);
  if (min < 2) return 'just now';
  if (min < 60) return `${min} min ago`;
  if (min < 1440) return min < 120 ? '1 hour ago' : `${Math.floor(min / 60)} hours ago`;
  return ago(sec * 1000);
}
let devRenaming = null;
function renderDevices(list) {
  const frag = document.createDocumentFragment();
  for (const d of list) {
    const kind = core.describeDevice(d.ua);
    const row = document.createElement('div');
    row.className = 'dev-row';
    const top = document.createElement('div');
    top.className = 'dev-top';
    const name = document.createElement('strong');
    name.textContent = d.name || kind;
    top.append(name);
    if (d.current) {
      const here = document.createElement('span');
      here.className = 'badge here';
      here.textContent = 'This device';
      top.append(here);
    }
    const sub = document.createElement('p');
    sub.className = 'muted';
    sub.textContent = [d.name ? kind : '', 'Active ' + since(d.last), d.pin ? 'PIN on' : ''].filter(Boolean).join(' · ');
    const acts = document.createElement('div');
    acts.className = 'dev-acts';
    const button = (label, cls, aria) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn small' + cls;
      b.textContent = label;
      b.setAttribute('aria-label', aria);
      return b;
    };
    if (devRenaming === d.id) {
      const input = document.createElement('input');
      input.type = 'text';
      input.maxLength = 40;
      input.value = d.name || kind;
      input.autocomplete = 'off';
      input.setAttribute('aria-label', 'Device name');
      const save = button('Save', ' primary', 'Save device name');
      const cancel = button('Cancel', '', 'Cancel renaming');
      const done = async () => {
        try {
          await authed(() => api('device_name', { id: d.id, name: input.value }));
          devRenaming = null;
          await loadDevices();
        } catch (e) { $('devMsg').textContent = e.offline ? 'Renaming needs internet.' : explain(e); }
      };
      save.addEventListener('click', done);
      input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); done(); } });
      cancel.addEventListener('click', () => { devRenaming = null; renderDevices(list); });
      acts.append(input, save, cancel);
      setTimeout(() => input.select(), 0);
    } else {
      const ren = button('Rename', '', 'Rename ' + (d.name || kind));
      ren.addEventListener('click', () => { devRenaming = d.id; $('devMsg').textContent = ''; renderDevices(list); });
      acts.append(ren);
      if (!d.current) {
        const off = button('Sign out', ' danger', 'Sign out ' + (d.name || kind));
        armed(off, 'Sign out', async () => {
          try {
            await authed(() => api('device_off', { id: d.id }));
            toast('Signed out. It erases its copy when it next connects');
            await loadDevices();
          } catch (e) { $('devMsg').textContent = e.offline ? 'Signing a device out needs internet.' : 'Could not sign that device out. Try again.'; }
        });
        acts.append(off);
      }
    }
    row.append(top, sub, acts);
    frag.append(row);
  }
  $('devList').replaceChildren(frag);
}
async function loadDevices() {
  if (!S.encKey) return;
  try {
    let r = await authed(() => api('devices'));
    // A session that began before devices were tracked is not on the list yet: renew it once so it is.
    if (S.encKey && !(r.devices || []).some((d) => d.current)) {
      await relogin();
      r = await api('devices');
    }
    if (!S.encKey) return;
    $('devMsg').textContent = '';
    renderDevices(r.devices || []);
  } catch (e) {
    if (S.encKey) $('devMsg').textContent = e.offline ? 'The device list needs internet.' : 'Could not load the device list.';
  }
}
$('devFold').addEventListener('toggle', () => { if ($('devFold').open) loadDevices(); });

/* ---------- Version history ---------- */

let histOpen = null; // { rev, items } of the copy being looked at
function renderHistory(versions) {
  const frag = document.createDocumentFragment();
  for (const v of versions) {
    const row = document.createElement('div');
    row.className = 'hist-row';
    const main = document.createElement('div');
    main.className = 'log-main';
    const when = document.createElement('strong');
    when.textContent = new Date(v.at * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    const sub = document.createElement('p');
    sub.className = 'muted';
    sub.textContent = `${since(v.at)} · ${Math.max(1, Math.round(v.size / 1024))} KB`;
    main.append(when, sub);
    const view = document.createElement('button');
    view.type = 'button';
    view.className = 'btn small';
    view.textContent = histOpen && histOpen.rev === v.rev ? 'Close' : 'View';
    view.setAttribute('aria-label', (histOpen && histOpen.rev === v.rev ? 'Close copy from ' : 'View copy from ') + when.textContent);
    view.addEventListener('click', async () => {
      $('histMsg').textContent = '';
      if (histOpen && histOpen.rev === v.rev) { histOpen = null; renderHistory(versions); return; }
      view.disabled = true;
      try {
        const r = await authed(() => api('history_get', null, '&rev=' + v.rev));
        if (!S.encKey) return;
        // Opened with the vault key on this device. The server only ever held the encrypted copy.
        histOpen = { rev: v.rev, items: await core.decryptVault(S.encKey, S.username, r.blob) };
      } catch (e) {
        histOpen = null;
        $('histMsg').textContent = e.offline ? 'Opening a copy needs internet.' : e.message === 'newer_format' ? ERRORS.newer_format : 'That copy could not be opened.';
      }
      renderHistory(versions);
    });
    row.append(main, view);
    if (histOpen && histOpen.rev === v.rev) {
      const d = core.snapshotDiff(S.items, histOpen.items);
      const box = document.createElement('div');
      box.className = 'hist-detail';
      const p = document.createElement('p');
      const n = (k, one, many) => (k === 1 ? `1 ${one}` : `${k} ${many}`);
      const parts = [];
      if (d.back) parts.push(n(d.back, 'entry would come back', 'entries would come back'));
      if (d.changed) parts.push(n(d.changed, 'entry would return to how it was', 'entries would return to how they were'));
      if (d.removed) parts.push(n(d.removed, 'newer entry would move to Recently deleted', 'newer entries would move to Recently deleted'));
      p.textContent = `This copy holds ${n(d.total, 'entry', 'entries')}. ` + (parts.length ? parts.join(', ') + '.' : 'It matches your vault as it is now.');
      box.append(p);
      if (parts.length) {
        const go = document.createElement('button');
        go.type = 'button';
        go.className = 'btn small danger';
        go.textContent = 'Go back to this copy';
        armed(go, 'Go back to this copy', async () => {
          S.items = core.restoreSnapshot(S.items, histOpen.items);
          histOpen = null;
          await persist();
          authed(() => api('note', { e: 'history_restore' })).catch(() => {});
          toast('Vault restored to that copy');
          loadHistory();
        });
        box.append(go);
      }
      row.append(box);
    }
    frag.append(row);
  }
  $('histList').replaceChildren(frag);
  if (!versions.length) $('histMsg').textContent = 'No earlier copies yet. One is kept each time your vault changes.';
}
async function loadHistory() {
  if (!S.encKey) return;
  try {
    const r = await authed(() => api('history'));
    if (!S.encKey) return;
    $('histMsg').textContent = '';
    renderHistory(r.versions || []);
  } catch (e) {
    if (S.encKey) $('histMsg').textContent = e.offline ? 'Version history needs internet.' : 'Could not load version history.';
  }
}
$('histFold').addEventListener('toggle', () => { if ($('histFold').open) loadHistory(); else histOpen = null; });

/* ---------- Startup ---------- */

setAuthMode('unlock');
(async () => {
  quick = await store.get('quick').catch(() => null) || null;
  trust = await store.get('trust').catch(() => null) || null;
  if (await tryRestore().catch(() => false)) return;
  const c = await store.get('state').catch(() => null);
  if (c?.username) $('aUser').value = c.username;
  setAuthMode(restingMode());
  runBio(true); // opening the app asks for Face ID at once when it is turned on
})();
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
