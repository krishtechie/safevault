import * as core from './core.js';

core.setArgon2(globalThis.hashwasm.argon2id);

const $ = (id) => document.getElementById(id);
const API = 'api/index.php';

// Everything sensitive lives only in this object, in memory, while unlocked.
// encKey is the vault key (non-extractable). wrap is that key locked with the master password key.
const S = { username: null, encKey: null, auth: null, salt: null, kdf: null, wrap: null, hasRecovery: false, items: [], rev: 0, dirty: false, changes: 0 };

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

async function api(action, body, query = '') {
  const opt = { method: body ? 'POST' : 'GET', headers: { 'X-Vault-Client': '1' }, credentials: 'same-origin', cache: 'no-store' };
  if (body) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(`${API}?a=${action}${query}`, opt); }
  catch { const e = new Error('offline'); e.offline = true; throw e; }
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok && res.status !== 409) { const e = new Error(data.error || 'http_' + res.status); e.status = res.status; e.data = data; throw e; }
  data.status = res.status;
  return data;
}

let toastTimer;
function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
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
  bio_unsupported: 'This browser or device does not support Face ID or Touch ID unlock for web apps.',
  bio_failed: 'Face ID or Touch ID did not complete. Try again, or use your master password.',
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
  const focus = { pin: 'aPin', unlock: $('aUser').value ? 'aPass' : 'aUser' }[m];
  if (focus && !$('auth').hidden) $(focus).focus();
}
// The unlock screen opens on the PIN when one is set for the remembered user.
const restingMode = () => (quickFor($('aUser').value.trim().toLowerCase())?.pin ? 'pin' : 'unlock');

const cacheRecord = (blob) => ({
  username: S.username, salt: S.salt, kdf: S.kdf, wrap: S.wrap, recovery: S.hasRecovery, blob, rev: S.rev, dirty: S.dirty,
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
async function signIn(username, keys) {
  const r = await api('login', { username, auth: keys.auth });
  const vkRaw = r.wrap ? await core.unwrapKey(keys.kek, username, r.wrap) : keys.legacyRaw;
  // If the upgrade call fails (for example mid-deploy), carry on; it is retried at the next unlock.
  const wrap = r.wrap || await api('setwrap', { wrap: await core.wrapKey(keys.kek, username, vkRaw) }).then((x) => x.wrap, () => null);
  return { vkRaw, wrap, rev: r.rev, recovery: !!r.recovery };
}

// Changes made on this device that never reached the server survive a password change,
// because the vault key stays the same.
async function unsyncedLocal(cached, username, vk) {
  if (!cached || cached.username !== username || !cached.dirty) return [];
  try { return await core.decryptVault(vk, username, cached.blob); } catch { return []; }
}

async function unlock(username, password) {
  const cached = await store.get('state');
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
      try {
        const r = await signIn(username, keys);
        wrap = r.wrap;
        recovery = r.recovery;
      } catch (e) {
        if (e.message === 'bad_credentials') throw new Error('changed_elsewhere');
        // offline or busy: carry on with the device copy
      }
      Object.assign(S, {
        username, encKey: local.vk, auth: keys.auth, salt: cached.salt, kdf: cached.kdf, wrap, hasRecovery: recovery,
        items: local.items, rev: cached.rev, dirty: !!cached.dirty,
      });
      await patchCache();
      return;
    }
  }
  // New device, or the device copy did not open: fetch salt, derive keys, sign in, download and decrypt.
  let pre;
  try { pre = await api('prelogin', { username }); }
  catch (e) { throw cached && e.offline ? new Error('bad_credentials') : e; }
  const keys = await core.deriveKeys(password, pre.salt, pre.kdf);
  const r = await signIn(username, keys);
  const vk = await core.importVaultKey(r.vkRaw);
  const v = await api('vault');
  const remote = await core.decryptVault(vk, username, v.blob);
  const extra = await unsyncedLocal(cached, username, vk);
  Object.assign(S, {
    username, encKey: vk, auth: keys.auth, salt: pre.salt, kdf: core.checkKdf(pre.kdf), wrap: r.wrap, hasRecovery: r.recovery,
    items: core.mergeItems(extra, remote), rev: v.rev, dirty: extra.length > 0,
  });
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
  Object.assign(S, { username, encKey: vk, auth: keys.auth, salt, kdf, wrap, hasRecovery: false, items: [], rev: r.rev, dirty: false });
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
  await api('recover_finish', { username, recAuth: rec.auth, newAuth: keys.auth, salt, kdf, wrap });
  if (quick) delete quick.pin; // the server turned PINs off for this account
  const vk = await core.importVaultKey(vkRaw);
  const v = await api('vault');
  const remote = await core.decryptVault(vk, username, v.blob);
  const extra = await unsyncedLocal(await store.get('state'), username, vk);
  Object.assign(S, {
    username, encKey: vk, auth: keys.auth, salt, kdf, wrap, hasRecovery: true,
    items: core.mergeItems(extra, remote), rev: v.rev, dirty: extra.length > 0,
  });
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
    hasRecovery: !!cached.recovery, items, rev: cached.rev, dirty: !!cached.dirty,
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

$('bioBtn').addEventListener('click', async () => {
  const btn = $('bioBtn');
  $('authMsg').textContent = '';
  btn.disabled = true;
  try {
    await unlockWithBio();
    enterApp();
  } catch (e) {
    $('authMsg').textContent = explain(e);
  } finally {
    btn.disabled = false;
  }
});

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
    for (const id of ['aPass', 'aPass2', 'aInvite', 'aRec', 'aPin']) $(id).value = '';
    enterApp();
    if (started === 'recover') toast('New master password set');
  } catch (e) {
    $('aPin').value = '';
    if (started === 'pin' && ['pin_locked', 'pin_gone', 'need_master'].includes(e.message)) setAuthMode('unlock');
    msg.textContent = explain(e);
  } finally {
    btn.disabled = false;
    setAuthModeLabel();
  }
});
function setAuthModeLabel() { $('authBtn').textContent = { unlock: 'Unlock', pin: 'Unlock', register: 'Create account', recover: 'Set new master password' }[mode]; }

function enterApp(activeAt = Date.now()) {
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
  sync();
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
  sealedAuth = null;
  store.del('unlock').catch(() => {});
  if ($('itemDlg').open) $('itemDlg').close();
  for (const id of ['fTitle', 'fUser', 'fPass', 'fUrl', 'fNotes', 'search', 'importPass', 'cpCur', 'cpNew', 'cpNew2', 'recPass', 'qPass', 'qPin', 'qPin2']) $(id).value = '';
  for (const id of ['healthMsg', 'cpMsg', 'recMsg', 'recCode', 'pinMsg', 'bioMsg']) $(id).textContent = '';
  $('recOut').hidden = true;
  $('list').replaceChildren();
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
  const fresh = stayOn() && cached && cached.username === u.username && Date.now() - u.lastActive <= lockMs();
  try {
    if (!fresh) throw new Error('expired');
    const items = await core.decryptVault(u.key, u.username, cached.blob);
    const auth = await core.openText(u.key, u.auth);
    Object.assign(S, {
      username: u.username, encKey: u.key, auth, salt: cached.salt, kdf: cached.kdf, wrap: cached.wrap || null,
      hasRecovery: !!cached.recovery, items, rev: cached.rev, dirty: !!cached.dirty,
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
  if (!S.dirty) await cacheState(blob);
  renderList();
}

async function doSync() {
  setStatus('syncing');
  try {
    for (let attempt = 0; attempt < 6 && S.encKey; attempt++) {
      let remote;
      try {
        remote = await api('vault', null, '&rev=' + S.rev);
      } catch (e) {
        if (e.status !== 401) throw e;
        try {
          await api('login', { username: S.username, auth: S.auth }); // session expired, sign in again
        } catch (e2) {
          if (e2.message !== 'bad_credentials') throw e2;
          quick = null; // quick unlock on this device holds the old sign-in key
          await store.del('quick').catch(() => {});
          lock(ERRORS.changed_elsewhere); // the sign-in key no longer works
          return;
        }
        continue;
      }
      if (!remote.unchanged) await mergeRemote(remote.blob, remote.rev);
      if (!S.dirty) break;

      const mark = S.changes;
      const blob = await core.encryptVault(S.encKey, S.username, S.items);
      const saved = await api('save', { blob, baseRev: S.rev });
      if (saved.status === 409) { await mergeRemote(saved.blob, saved.rev); continue; } // another device saved first
      S.rev = saved.rev;
      if (S.changes === mark) S.dirty = false;
      await cacheState(blob);
      if (!S.dirty) break;
    }
    if (S.encKey) setStatus(S.dirty ? 'pending' : 'synced');
  } catch (e) {
    if (S.encKey) setStatus(e.offline ? 'offline' : 'error');
  }
}

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
  for (const t of document.querySelectorAll('.tab')) t.classList.toggle('active', t.dataset.view === name);
}
for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => showView(t.dataset.view));

const live = () => S.items.filter((it) => !it.deleted);

function renderList() {
  if (!S.encKey) return;
  const q = $('search').value.trim().toLowerCase();
  const rows = live()
    .filter((it) => !q || [it.title, it.username, it.url].some((f) => (f || '').toLowerCase().includes(q)))
    .sort((a, b) => (a.title || '').localeCompare(b.title || '', undefined, { sensitivity: 'base' }));
  const frag = document.createDocumentFragment();
  for (const it of rows) {
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
    const cp = document.createElement('button');
    cp.type = 'button';
    cp.className = 'btn small';
    cp.textContent = 'Copy';
    cp.setAttribute('aria-label', 'Copy password for ' + (it.title || 'entry'));
    cp.addEventListener('click', () => copy(it.password, 'Password copied'));
    li.append(main, cp);
    frag.append(li);
  }
  $('list').replaceChildren(frag);
  $('empty').hidden = rows.length > 0;
  $('empty').textContent = q ? 'No matches.' : 'Nothing here yet. Tap Add to save your first password.';
}
$('search').addEventListener('input', renderList);

/* ---------- Entry editor ---------- */

const FIELD_IDS = ['fTitle', 'fUser', 'fPass', 'fUrl', 'fNotes'];
const FIELD_OF = { need_title: 'fTitle', bad_title: 'fTitle', bad_username_field: 'fUser', need_password: 'fPass', bad_password: 'fPass', password_spaces: 'fPass', bad_url: 'fUrl', bad_notes: 'fNotes' };
let editingId = null;
let deleteArmed = false;
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
  $('fPass').type = 'password';
  $('fShow').textContent = 'Show';
  $('fDelete').hidden = !it;
  $('fDelete').textContent = 'Delete';
  $('itemMsg').textContent = '';
  for (const id of FIELD_IDS) $(id).classList.remove('bad');
  deleteArmed = false;
  $('itemDlg').showModal();
  $('itemDlg').scrollTop = 0;
  if (why) $('fixBox').scrollIntoView({ block: 'start' });
}

$('addBtn').addEventListener('click', () => openItem(null));
$('fCancel').addEventListener('click', () => $('itemDlg').close());
$('fUserCopy').addEventListener('click', () => copy($('fUser').value, 'Username copied'));
$('fPassCopy').addEventListener('click', () => copy($('fPass').value, 'Password copied'));
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
    });
  } catch (e) {
    $('itemMsg').textContent = explain(e);
    const field = $(FIELD_OF[e.message] || 'fTitle');
    field.classList.add('bad');
    field.focus();
    return;
  }
  const data = { ...clean, updatedAt: Date.now(), deleted: false };
  if (editingId) {
    const i = S.items.findIndex((x) => x.id === editingId);
    S.items[i] = { ...S.items[i], ...data };
  } else {
    S.items.push({ id: core.newId(), createdAt: Date.now(), ...data });
  }
  $('itemDlg').close();
  await persist();
  if (fixing) {
    $('healthOut').replaceChildren();
    $('healthMsg').textContent = 'Saved. Run the check again to confirm it is fixed.';
  }
  toast('Saved');
});

$('fDelete').addEventListener('click', async () => {
  if (!deleteArmed) { deleteArmed = true; $('fDelete').textContent = 'Tap again to delete'; return; }
  const i = S.items.findIndex((x) => x.id === editingId);
  // Keep a tombstone (id and time only) so the deletion reaches other devices.
  S.items[i] = { id: editingId, deleted: true, updatedAt: Date.now() };
  $('itemDlg').close();
  await persist();
  toast('Deleted');
});

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

$('healthBtn').addEventListener('click', async () => {
  const btn = $('healthBtn');
  const msg = $('healthMsg');
  const items = live().filter((it) => it.password);
  btn.disabled = true;
  $('healthOut').replaceChildren();

  const reused = core.findReused(items).flatMap((g) => g.map((it) => [it, `shared by ${g.length} entries`,
    `This password is used by ${g.length} entries (${g.map((x) => x.title || 'no name').join(', ')}). If one of those sites is breached, the others are exposed too. Give each one its own password.`]));
  const weak = items.filter((it) => core.isWeak(it.password)).map((it) => [it, 'short or simple',
    'This password is short or simple enough to be guessed quickly. Replace it with a generated one.']);

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
  if (!S.encKey) return;

  const leaked = items.filter((it) => counts.get(it.password) > 0)
    .map((it) => [it, `seen ${counts.get(it.password).toLocaleString()} times in breaches`,
      `This exact password appears ${counts.get(it.password).toLocaleString()} times in leaked password lists, so attackers try it early. The lists hold passwords only and do not record which website or account they came from. It cannot be removed from those lists; changing it makes the leaked one useless.`]);
  const out = $('healthOut');
  if (failed) msg.textContent = 'Could not reach the leak check service. Reused and weak results are still shown. Try again when online.';
  else {
    msg.textContent = `Checked ${items.length} entries. ${leaked.length + reused.length + weak.length ? 'Tap Fix on each one below.' : 'All clear.'}`;
    out.append(healthGroup('Found in data breaches', 'bad', 'These exact passwords are in leaked password lists. Change them first, on every site where you use them.', leaked));
  }
  out.append(
    healthGroup('Reused', 'warn', 'The same password protects more than one account. Give each account its own.', reused),
    healthGroup('Weak', 'warn', 'Short or simple passwords that are quick to guess.', weak),
  );
  btn.disabled = false;
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
    await api('login', { username: S.username, auth: S.auth });
    return fn();
  }
}

// Re-enter the current master password before any sensitive change. Returns its keys and the raw vault key.
async function confirmMaster(password) {
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
  await authed(() => api('rekey', { auth: cur.auth, newAuth: keys.auth, salt, kdf, wrap }));
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
  return bioName + ' unlock is on for this device.';
}));

$('bioOff').addEventListener('click', () => withButton($('bioOff'), $('bioMsg'), async () => {
  const q = quickFor(S.username);
  if (q) { delete q.bio; await saveQuick(); }
  return bioName + ' unlock is off for this device. You can also delete the "Vault" passkey in your device password settings.';
}));

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
    msg.textContent = `Merged ${items.filter((it) => !it.deleted).length} entries from the backup.`;
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
  await store.del('quick').catch(() => {});
  await store.del('state');
  lock();
  $('aUser').value = '';
});

/* ---------- Startup ---------- */

setAuthMode('unlock');
(async () => {
  quick = await store.get('quick').catch(() => null) || null;
  if (await tryRestore().catch(() => false)) return;
  const c = await store.get('state').catch(() => null);
  if (c?.username) $('aUser').value = c.username;
  setAuthMode(restingMode());
})();
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
