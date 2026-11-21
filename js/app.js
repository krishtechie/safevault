import * as core from './core.js';

core.setArgon2(globalThis.hashwasm.argon2id);

const $ = (id) => document.getElementById(id);
const API = 'api/index.php';

// Everything sensitive lives only in this object, in memory, while unlocked.
const S = { username: null, encKey: null, auth: null, salt: null, kdf: null, items: [], rev: 0, dirty: false, changes: 0 };

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
  if (!res.ok && res.status !== 409) { const e = new Error(data.error || 'http_' + res.status); e.status = res.status; throw e; }
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
  offline: 'No connection. This device has no saved vault yet, so it needs internet for the first sign-in.',
};
const explain = (e) => ERRORS[e.message] || e.message || 'Something went wrong.';

/* ---------- Unlock, register, lock ---------- */

let registering = false;

function setRegistering(on) {
  registering = on;
  $('regFields').hidden = !on;
  $('authBtn').textContent = on ? 'Create account' : 'Unlock';
  $('authLead').textContent = on ? 'Choose a master password you will remember.' : 'Unlock with your master password.';
  $('authToggle').textContent = on ? 'I already have an account' : 'Create an account';
  $('authMsg').textContent = '';
}

async function cacheState(blob) {
  await store.set('state', { username: S.username, salt: S.salt, kdf: S.kdf, blob, rev: S.rev, dirty: S.dirty });
}

async function unlock(username, password) {
  const cached = await store.get('state');
  if (cached && cached.username === username) {
    // Known device: open the local encrypted copy first (works offline), then sync.
    const keys = await core.deriveKeys(password, cached.salt, cached.kdf);
    let items;
    try { items = await core.decryptVault(keys.encKey, username, cached.blob); }
    catch { throw new Error('bad_credentials'); }
    Object.assign(S, { username, ...keys, salt: cached.salt, kdf: cached.kdf, items, rev: cached.rev, dirty: !!cached.dirty });
    return;
  }
  // New device: fetch salt, derive keys, sign in, download and decrypt.
  const pre = await api('prelogin', { username });
  const keys = await core.deriveKeys(password, pre.salt, pre.kdf);
  await api('login', { username, auth: keys.auth });
  const v = await api('vault');
  const items = await core.decryptVault(keys.encKey, username, v.blob);
  Object.assign(S, { username, ...keys, salt: pre.salt, kdf: core.checkKdf(pre.kdf), items, rev: v.rev, dirty: false });
  await cacheState(v.blob);
}

async function register(username, password, invite) {
  const salt = core.b64.enc(core.randomBytes(16));
  const kdf = { ...core.KDF_DEFAULT };
  const keys = await core.deriveKeys(password, salt, kdf);
  const blob = await core.encryptVault(keys.encKey, username, []);
  const r = await api('register', { username, salt, kdf, auth: keys.auth, invite, blob });
  Object.assign(S, { username, ...keys, salt, kdf, items: [], rev: r.rev, dirty: false });
  await cacheState(blob);
}

$('authToggle').addEventListener('click', () => setRegistering(!registering));

$('authForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const username = $('aUser').value.trim().toLowerCase();
  const password = $('aPass').value;
  const msg = $('authMsg');
  msg.textContent = '';
  if (registering) {
    if (password !== $('aPass2').value) { msg.textContent = 'The two passwords do not match.'; return; }
    if (password.length < 12 || core.estimateBits(password) < 60) {
      msg.textContent = 'Master password is too weak. Use at least 12 characters; a 5 or 6 word passphrase works well.';
      return;
    }
  }
  const btn = $('authBtn');
  btn.disabled = true;
  btn.textContent = 'Working';
  try {
    if (registering) await register(username, password, $('aInvite').value);
    else await unlock(username, password);
    for (const id of ['aPass', 'aPass2', 'aInvite']) $(id).value = '';
    enterApp();
  } catch (e) {
    msg.textContent = explain(e);
  } finally {
    btn.disabled = false;
    btn.textContent = registering ? 'Create account' : 'Unlock';
  }
});

function enterApp() {
  $('auth').hidden = true;
  $('app').hidden = false;
  $('whoami').textContent = S.username;
  lastActive = Date.now();
  showView('vault');
  renderList();
  regenerate();
  sync();
}

function lock() {
  if (!S.encKey) return;
  const user = S.username;
  Object.assign(S, { username: null, encKey: null, auth: null, salt: null, kdf: null, items: [], rev: 0, dirty: false });
  if ($('itemDlg').open) $('itemDlg').close();
  for (const id of ['fTitle', 'fUser', 'fPass', 'fUrl', 'fNotes', 'search', 'importPass']) $(id).value = '';
  $('healthMsg').textContent = '';
  $('list').replaceChildren();
  $('healthOut').replaceChildren();
  $('genOut').textContent = '';
  $('app').hidden = true;
  $('auth').hidden = false;
  setRegistering(false);
  $('aUser').value = user || '';
  $('aPass').focus();
}

$('lockBtn').addEventListener('click', lock);
$('lockBtnM').addEventListener('click', lock);

// Auto-lock after inactivity (also checked when the tab becomes visible again).
let lastActive = Date.now();
const lockMs = () => (parseInt(localStorage.getItem('lockMin'), 10) || 5) * 60000;
for (const ev of ['pointerdown', 'keydown', 'input']) addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true });
const idleCheck = () => { if (S.encKey && Date.now() - lastActive > lockMs()) lock(); };
setInterval(idleCheck, 5000);
document.addEventListener('visibilitychange', () => { idleCheck(); if (!document.hidden && S.encKey) sync(); });

/* ---------- Sync ---------- */

function setStatus(state) {
  const text = {
    synced: 'Synced', syncing: 'Syncing', pending: 'Changes waiting to sync',
    offline: 'Offline. Saved on this device', error: 'Sync problem. Tap to retry',
  }[state];
  for (const s of ['', 'M']) {
    $('syncDot' + s).className = 'dot ' + state;
    $('syncText' + s).textContent = text;
  }
}

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
        await api('login', { username: S.username, auth: S.auth }); // session expired, sign in again
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
    const t = document.createElement('div');
    t.className = 'item-title';
    t.textContent = it.title || '(no name)';
    const s = document.createElement('div');
    s.className = 'item-sub';
    s.textContent = it.username || it.url || '';
    main.append(t, s);
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

let editingId = null;
let deleteArmed = false;
let fixing = false;

function siteLink(url) {
  if (!url) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : 'https://' + url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch { return null; }
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
  const data = {
    title: $('fTitle').value.trim(), username: $('fUser').value.trim(), password: $('fPass').value,
    url: $('fUrl').value.trim(), notes: $('fNotes').value, updatedAt: Date.now(), deleted: false,
  };
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

$('exportBtn').addEventListener('click', async () => {
  const blob = await core.encryptVault(S.encKey, S.username, S.items);
  const file = new Blob([JSON.stringify({ format: 'vault-backup-v1', username: S.username, salt: S.salt, kdf: S.kdf, blob })], { type: 'application/json' });
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
    if (b.format !== 'vault-backup-v1') throw new Error('format');
    const keys = await core.deriveKeys($('importPass').value, b.salt, b.kdf);
    const items = await core.decryptVault(keys.encKey, b.username, b.blob);
    S.items = core.mergeItems(S.items, items);
    await persist();
    msg.className = 'msg ok';
    msg.textContent = `Merged ${items.filter((it) => !it.deleted).length} entries from the backup.`;
  } catch {
    msg.textContent = 'Could not open that backup. Check the file and the master password.';
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
  try { await api('logout', {}); } catch { /* offline is fine */ }
  await store.del('state');
  lock();
  $('aUser').value = '';
});

/* ---------- Startup ---------- */

store.get('state').then((c) => { if (c?.username) { $('aUser').value = c.username; $('aPass').focus(); } }).catch(() => {});
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
