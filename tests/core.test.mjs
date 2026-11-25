// Run with: node --test tests/core.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as core from '../js/core.js';

const require = createRequire(import.meta.url);
core.setArgon2(require('../vendor/argon2.umd.min.js').argon2id);
const salt = core.b64.enc(core.randomBytes(16));
const kdf = { alg: 'argon2id', m: 19456, t: 2, p: 1 }; // minimum allowed, keeps tests fast

test('Argon2id output matches libsodium for the app default settings', async () => {
  // Expected value produced independently with libsodium (PHP sodium_crypto_pwhash, ARGON2ID13, t=3, m=64 MiB).
  const hex = await require('../vendor/argon2.umd.min.js').argon2id({
    password: 'correct horse battery staple', salt: new Uint8Array(16).fill(2),
    parallelism: 1, iterations: 3, memorySize: 65536, hashLength: 32, outputType: 'hex',
  });
  assert.equal(hex, '1096810449d933301800a640fd5cade6dfa0a9d07987e909a9fde0235baa5309');
});

test('same password and salt give the same keys, different password does not', async () => {
  const a = await core.deriveKeys('correct horse battery staple', salt, kdf);
  const b = await core.deriveKeys('correct horse battery staple', salt, kdf);
  const c = await core.deriveKeys('correct horse battery stapl3', salt, kdf);
  assert.equal(a.auth, b.auth);
  assert.notEqual(a.auth, c.auth);
  assert.deepEqual(a.legacyRaw, b.legacyRaw);
  assert.equal(core.b64.dec(a.auth).length, 32);
  assert.equal(a.kek.extractable, false);
  assert.notEqual(core.b64.enc(a.legacyRaw), a.auth); // sign-in key and vault key are unrelated
});

test('vault round trip, wrong key, wrong user and tampering all behave', async () => {
  const a = await core.importVaultKey(core.newVaultKeyRaw());
  const b = await core.importVaultKey(core.newVaultKeyRaw());
  assert.equal(a.extractable, false);
  const items = core.sanitizeItems([{ id: '1', title: 'Bank', password: 'p@ss ünïcode 🔑', updatedAt: 1 }]);
  const blob = await core.encryptVault(a, 'user', items);
  assert.ok(!blob.includes('Bank'));
  assert.deepEqual(await core.decryptVault(a, 'user', blob), items);
  await assert.rejects(core.decryptVault(b, 'user', blob));
  await assert.rejects(core.decryptVault(a, 'other', blob));
  const o = JSON.parse(blob); const ct = core.b64.dec(o.ct); ct[0] ^= 1; o.ct = core.b64.enc(ct);
  await assert.rejects(core.decryptVault(a, 'user', JSON.stringify(o)));
  const blob2 = await core.encryptVault(a, 'user', items);
  assert.notEqual(JSON.parse(blob).iv, JSON.parse(blob2).iv); // fresh nonce each save
});

test('vaults made before key wrapping still open (same key bytes as the old derivation)', async () => {
  // The first release derived the vault key directly with HKDF deriveKey. Rebuild that here.
  const master = await require('../vendor/argon2.umd.min.js').argon2id({
    password: 'old account password', salt: core.b64.dec(salt), parallelism: 1, iterations: 2, memorySize: 19456, hashLength: 32, outputType: 'binary',
  });
  const hk = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  const oldKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('vault-enc-v1') },
    hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const items = core.sanitizeItems([{ id: 'x', title: 'From v1', updatedAt: 5 }]);
  const oldBlob = await core.encryptVault(oldKey, 'user', items);
  const keys = await core.deriveKeys('old account password', salt, kdf);
  assert.deepEqual(await core.decryptVault(await core.importVaultKey(keys.legacyRaw), 'user', oldBlob), items);
});

test('key wrapping: password change and recovery re-wrap the same vault key', async () => {
  const vkRaw = core.newVaultKeyRaw();
  const blob = await core.encryptVault(await core.importVaultKey(vkRaw), 'user', [{ id: '1', updatedAt: 1 }]);
  const oldPw = await core.deriveKeys('old master password!', salt, kdf);
  const wrap = await core.wrapKey(oldPw.kek, 'user', vkRaw);
  assert.ok(!wrap.includes(core.b64.enc(vkRaw)));
  assert.deepEqual(await core.unwrapKey(oldPw.kek, 'user', wrap), vkRaw);
  // change password: new salt and key, same vault key, vault blob untouched
  const salt2 = core.b64.enc(core.randomBytes(16));
  const newPw = await core.deriveKeys('new master password!', salt2, kdf);
  const wrap2 = await core.wrapKey(newPw.kek, 'user', await core.unwrapKey(oldPw.kek, 'user', wrap));
  await assert.rejects(core.unwrapKey(oldPw.kek, 'user', wrap2));
  await assert.rejects(core.unwrapKey(newPw.kek, 'other', wrap2));
  await assert.rejects(core.unwrapKey(newPw.kek, 'user', wrap2, 'rec')); // a password wrap cannot pass as a recovery wrap
  const vk2 = await core.importVaultKey(await core.unwrapKey(newPw.kek, 'user', wrap2));
  assert.equal((await core.decryptVault(vk2, 'user', blob)).length, 1);
});

test('recovery key: format, tolerant entry, and independent keys', async () => {
  const code = core.generateRecoveryCode();
  assert.match(code, /^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.notEqual(code, core.generateRecoveryCode());
  const a = await core.deriveRecoveryKeys(code, 'user');
  const b = await core.deriveRecoveryKeys(' ' + code.toLowerCase().replaceAll('-', ' ') + ' ', 'user');
  assert.equal(a.auth, b.auth);
  assert.notEqual(a.auth, (await core.deriveRecoveryKeys(code, 'other')).auth);
  assert.equal(core.normalizeRecoveryCode('oOiIlL' + '0'.repeat(26)), '001111' + '0'.repeat(26));
  await assert.rejects(core.deriveRecoveryKeys('too-short', 'user'));
  await assert.rejects(core.deriveRecoveryKeys('U'.repeat(32), 'user'));
  const vkRaw = core.newVaultKeyRaw();
  const recWrap = await core.wrapKey(a.kek, 'user', vkRaw, 'rec');
  assert.deepEqual(await core.unwrapKey(b.kek, 'user', recWrap, 'rec'), vkRaw);
  const wrong = await core.deriveRecoveryKeys(core.generateRecoveryCode(), 'user');
  await assert.rejects(core.unwrapKey(wrong.kek, 'user', recWrap, 'rec'));
});

test('sealed text round trip', async () => {
  const k = await core.importVaultKey(core.newVaultKeyRaw());
  const sealed = await core.sealText(k, 'sign-in-key');
  assert.equal(await core.openText(k, sealed), 'sign-in-key');
  await assert.rejects(core.openText(await core.importVaultKey(core.newVaultKeyRaw()), sealed));
});

test('weak KDF settings from a server are refused', async () => {
  await assert.rejects(core.deriveKeys('x', salt, { alg: 'argon2id', m: 8, t: 1, p: 1 }));
  await assert.rejects(core.deriveKeys('x', salt, { alg: 'pbkdf2', m: 65536, t: 3, p: 1 }));
  await assert.rejects(core.deriveKeys('x', core.b64.enc(new Uint8Array(4)), kdf));
});

test('merge keeps the newest version of each entry and syncs deletions', () => {
  const local = [{ id: 'a', title: 'old', updatedAt: 1 }, { id: 'b', title: 'mine', updatedAt: 9 }, { id: 'd', deleted: true, updatedAt: 8 }];
  const remote = [{ id: 'a', title: 'new', updatedAt: 5 }, { id: 'c', title: 'theirs', updatedAt: 2 }, { id: 'd', title: 'alive', updatedAt: 3 }];
  const m = Object.fromEntries(core.mergeItems(local, remote).map((i) => [i.id, i]));
  assert.equal(m.a.title, 'new'); assert.equal(m.b.title, 'mine'); assert.equal(m.c.title, 'theirs'); assert.equal(m.d.deleted, true);
  assert.equal(Object.keys(m).length, 4);
});

test('generator honours options and randomInt is in range and roughly uniform', () => {
  for (let i = 0; i < 300; i++) {
    const { value, bits } = core.generatePassword({ length: 20 });
    assert.equal(value.length, 20); assert.ok(bits >= 125);
    for (const set of Object.values(core.CHARSETS)) assert.ok([...value].some((c) => set.includes(c)));
  }
  assert.match(core.generatePassword({ length: 16, upper: false, symbols: false, lower: false }).value, /^[0-9]{16}$/);
  const p = core.generatePassphrase({ words: 6 });
  assert.equal(p.value.split('-').length, 6); assert.equal(p.bits, 78);
  assert.match(core.generatePassphrase({ words: 4, capitalize: true, number: true }).value, /^([A-Z][a-z-]*-){4}[0-9]$/);
  const seen = new Set(); for (let i = 0; i < 200; i++) seen.add(core.generatePassword().value); assert.equal(seen.size, 200);
  const buckets = new Array(6).fill(0); for (let i = 0; i < 60000; i++) buckets[core.randomInt(6)]++;
  for (const b of buckets) assert.ok(b > 9400 && b < 10600, 'bucket ' + b);
});

test('leak check sends only a 5 character hash prefix and reads the count', async () => {
  assert.equal(await core.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  let asked;
  const fake = async (url) => { asked = url; return { ok: true, text: async () => '0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179\r\n' }; };
  assert.equal(await core.pwnedCount('password', fake), 52256179);
  assert.equal(asked, 'https://api.pwnedpasswords.com/range/5BAA6');
  assert.equal(await core.pwnedCount('some-other-password', fake), 0);
  await assert.rejects(core.pwnedCount('x', async () => ({ ok: false, status: 503 })));
});

test('weak and reused detection', () => {
  assert.ok(core.isWeak('summer2024')); assert.ok(core.isWeak('aaaaaaaaaaaaaaaaaaaa')); assert.ok(!core.isWeak(core.generatePassword().value));
  const groups = core.findReused([{ id: 1, password: 'x' }, { id: 2, password: 'x' }, { id: 3, password: 'y' }, { id: 4, password: 'x', deleted: true }]);
  assert.equal(groups.length, 1); assert.equal(groups[0].length, 2);
});

test('entry form rules: each field accepts only what belongs in it', () => {
  const ok = { title: ' Bank ', username: " o'brien+tag@example.com ", password: 'correct horse battery', url: 'example.com/login', notes: 'line one\nline two\ttabbed' };
  assert.deepEqual(core.validateEntry(ok), { title: 'Bank', username: "o'brien+tag@example.com", password: 'correct horse battery', url: 'https://example.com/login', notes: 'line one\nline two\ttabbed' });
  const bad = (patch, code) => assert.throws(() => core.validateEntry({ ...ok, ...patch }), { message: code });
  bad({ title: '   ' }, 'need_title');
  bad({ title: 'x'.repeat(101) }, 'bad_title');
  bad({ title: 'Bank‮gnp.exe' }, 'bad_title'); // right-to-left override used to disguise text
  bad({ username: 'two words' }, 'bad_username_field');
  bad({ username: '<script>alert(1)</script>' }, 'bad_username_field');
  bad({ username: 'a​b@example.com' }, 'bad_username_field'); // zero-width space
  bad({ password: '' }, 'need_password');
  bad({ password: 'has\nnewline' }, 'bad_password');
  bad({ password: 'x'.repeat(257) }, 'bad_password');
  bad({ password: ' padded ' }, 'password_spaces');
  bad({ notes: 'null\u0000byte' }, 'bad_notes');
  for (const u of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>alert(1)</script>', 'file:///etc/passwd', 'vbscript:x', 'https://user:pw@example.com', 'https://exa mple.com', 'localhost', 'ftp://example.com']) bad({ url: u }, 'bad_url');
  assert.equal(core.validateEntry({ ...ok, url: '' }).url, '');
  assert.equal(core.validateEntry({ ...ok, url: 'HTTP://Example.COM' }).url, 'http://example.com/');
});

test('incoming data is cleaned: unknown fields dropped, hidden characters removed, unsafe links blanked', () => {
  const dirty = [
    { id: 'a1', title: '<img src=x onerror=alert(1)>', username: 'me\u0000@x.com', password: 'p​w', url: 'javascript:alert(1)', notes: 'ok\nline\u0007', updatedAt: 5.9, evil: { nested: true }, __proto__: { polluted: 1 } },
    { id: 'a1', title: 'duplicate id is dropped' },
    { id: '../../etc', title: 'bad id is dropped' },
    { id: 'b2', deleted: true, updatedAt: 9, title: 'tombstones keep no content', password: 'x' },
    { id: 'c3', title: 'T'.repeat(500), password: 42, url: 'example.com' },
    null, 'string', 7, { title: 'no id' },
  ];
  const clean = core.sanitizeItems(dirty);
  assert.equal(clean.length, 3);
  assert.deepEqual(clean[0], { id: 'a1', title: '<img src=x onerror=alert(1)>', username: 'me@x.com', password: 'pw', url: '', notes: 'ok\nline', createdAt: 0, updatedAt: 5, deleted: false });
  assert.deepEqual(clean[1], { id: 'b2', deleted: true, updatedAt: 9 });
  assert.equal(clean[2].title.length, 100); assert.equal(clean[2].password, ''); assert.equal(clean[2].url, 'https://example.com/');
  assert.equal({}.polluted, undefined);
  assert.deepEqual(core.sanitizeItems('not an array'), []);
});

test('PIN rules and PIN unlock keys', async () => {
  assert.equal(core.checkPin('284951'), '284951');
  for (const p of ['12345', '1234567', 'abcdef', '', '12 456']) assert.throws(() => core.checkPin(p), { message: 'pin_format' });
  for (const p of ['000000', '777777', '123456', '456789', '987654', '890123']) assert.throws(() => core.checkPin(p), { message: 'pin_simple' });
  const kdev = core.randomBytes(32); const ksrv = core.randomBytes(32);
  const a = await core.derivePinAuth('284951', kdev);
  assert.equal(a, await core.derivePinAuth('284951', kdev));
  assert.notEqual(a, await core.derivePinAuth('284952', kdev));
  assert.notEqual(a, await core.derivePinAuth('284951', core.randomBytes(32))); // useless without the device half
  assert.equal(core.b64.dec(a).length, 32);
  const vkRaw = core.newVaultKeyRaw();
  const wrap = await core.wrapKey(await core.pinKek(kdev, ksrv), 'user', vkRaw, 'pin');
  assert.deepEqual(await core.unwrapKey(await core.pinKek(kdev, ksrv), 'user', wrap, 'pin'), vkRaw);
  await assert.rejects(async () => core.unwrapKey(await core.pinKek(kdev, core.randomBytes(32)), 'user', wrap, 'pin')); // server half missing
  await assert.rejects(async () => core.unwrapKey(await core.pinKek(core.randomBytes(32), ksrv), 'user', wrap, 'pin')); // device half missing
  await assert.rejects(async () => core.unwrapKey(await core.pinKek(kdev, ksrv), 'user', wrap, 'pw'));
  await assert.rejects(core.pinKek(kdev, new Uint8Array(8)));
});

test('Face ID key: same device secret opens, a different one does not', async () => {
  const secret = core.randomBytes(32).buffer; const vkRaw = core.newVaultKeyRaw();
  const wrap = await core.wrapKey(await core.bioKek(secret), 'user', vkRaw, 'bio');
  assert.deepEqual(await core.unwrapKey(await core.bioKek(secret), 'user', wrap, 'bio'), vkRaw);
  await assert.rejects(async () => core.unwrapKey(await core.bioKek(core.randomBytes(32).buffer), 'user', wrap, 'bio'));
  await assert.rejects(core.bioKek(new Uint8Array(4).buffer));
});

test('access log: readable device names and filters', () => {
  assert.equal(core.describeDevice('Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1'), 'iPhone · Safari');
  assert.equal(core.describeDevice('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'), 'Mac · Chrome');
  assert.equal(core.describeDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0'), 'Windows PC · Edge');
  assert.equal(core.describeDevice('python-requests/2.32'), 'Unknown device · Script or tool');
  assert.equal(core.describeDevice(''), 'Unknown device · Unknown browser');
  const now = 1_800_000_000_000; const sec = now / 1000;
  const log = [
    { t: sec - 60, e: 'login_ok', ip: '203.0.113.5', ua: 'iPhone Safari/604' },
    { t: sec - 3600, e: 'login_fail', ip: '198.51.100.9', ua: 'python-requests/2.32' },
    { t: sec - 2 * 86400, e: 'pin_locked', ip: '203.0.113.5', ua: 'iPhone Safari/604' },
    { t: sec - 10 * 86400, e: 'rekey', ip: '203.0.113.5', ua: 'Macintosh Chrome/140' },
    { t: sec - 40 * 86400, e: 'save', ip: '203.0.113.5', ua: 'Macintosh Chrome/140' },
    { t: sec - 30, e: 'something_new', ip: '203.0.113.5', ua: '' },
  ];
  const f = (o) => core.filterLog(log, { now, ...o }).map((x) => x.e);
  assert.deepEqual(f({}), log.map((x) => x.e));
  assert.deepEqual(f({ days: 1 }), ['login_ok', 'login_fail', 'something_new']);
  assert.deepEqual(f({ days: 7 }), ['login_ok', 'login_fail', 'pin_locked', 'something_new']);
  assert.deepEqual(f({ type: 'fail' }), ['login_fail', 'pin_locked']);
  assert.deepEqual(f({ type: 'change' }), ['rekey']);
  assert.deepEqual(f({ type: 'save' }), ['save']);
  assert.deepEqual(f({ type: 'signin' }), ['login_ok']);
  assert.deepEqual(f({ text: '198.51' }), ['login_fail']);
  assert.deepEqual(f({ text: 'script' }), ['login_fail']);
  assert.deepEqual(f({ text: 'wrong pin' }), []);
  assert.deepEqual(f({ text: 'MASTER PASSWORD CHANGED' }), ['rekey']);
  assert.deepEqual(f({ type: 'fail', days: 1, text: 'python' }), ['login_fail']);
  const owner = [
    { t: sec - 5, e: 'login_fail_unknown', ip: '198.51.100.9', ua: 'x', u: 'admin', where: 'Lagos, Nigeria' },
    { t: sec - 6, e: 'login_blocked', ip: '198.51.100.9', ua: 'x', where: '' },
    { t: sec - 7, e: 'register_bad_invite', ip: '203.0.113.5', ua: 'x', u: 'mallory', where: 'Toronto, Ontario, Canada' },
  ];
  const g = (o) => core.filterLog(owner, { now, ...o }).map((x) => x.e);
  assert.deepEqual(g({ type: 'fail' }), ['login_fail_unknown', 'login_blocked', 'register_bad_invite']);
  assert.deepEqual(g({ text: 'ADMIN' }), ['login_fail_unknown']);
  assert.deepEqual(g({ text: 'toronto' }), ['register_bad_invite']);
  assert.deepEqual(g({ text: '15 minutes' }), ['login_blocked']);
  for (const k of ['login_fail_unknown', 'login_blocked_unknown', 'login_bad_name', 'recover_fail_unknown', 'recover_blocked', 'recover_blocked_unknown', 'register_bad_invite', 'login_blocked']) assert.equal(core.LOG_EVENTS[k][1], 'fail');
});

test('CSV parser: quotes, commas, line breaks, doubled quotes, BOM, blank lines', () => {
  const csv = '﻿name,url,note\r\n"Smith, John",https://a.com,"line one\nline two"\r\n\r\nplain,"say ""hi""",\n';
  assert.deepEqual(core.parseCsv(csv), [['name', 'url', 'note'], ['Smith, John', 'https://a.com', 'line one\nline two'], ['plain', 'say "hi"', '']]);
  assert.deepEqual(core.parseCsv(''), []);
  assert.deepEqual(core.parseCsv('a,b'), [['a', 'b']]);
});

test('CSV import: Google, Safari, Bitwarden, LastPass and Firefox layouts', () => {
  const pick = (r) => r.items.map((i) => [i.title, i.username, i.password, i.url, i.notes]);
  const google = 'name,url,username,password,note\nexample.com,https://example.com/login,me@example.com,"p,ass""word",my note\n,https://shop.test/,bob,secret123,\nandroid app,android://abc==@com.app.x/,me,apppass,\n';
  assert.deepEqual(pick(core.importCsv(google)), [
    ['example.com', 'me@example.com', 'p,ass"word', 'https://example.com/login', 'my note'],
    ['shop.test', 'bob', 'secret123', 'https://shop.test/', ''],
    ['android app', 'me', 'apppass', '', ''],
  ]);
  const safari = 'Title,URL,Username,Password,Notes,OTPAuth\nBank (me),https://bank.test/,me,Tr0ub4dor,,\n';
  assert.deepEqual(pick(core.importCsv(safari)), [['Bank (me)', 'me', 'Tr0ub4dor', 'https://bank.test/', '']]);
  const bitwarden = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Mail,hello,,0,https://mail.test,me@x.com,pw1,\n';
  assert.deepEqual(pick(core.importCsv(bitwarden)), [['Mail', 'me@x.com', 'pw1', 'https://mail.test/', 'hello']]);
  const lastpass = 'url,username,password,totp,extra,name,grouping,fav\nhttps://lp.test,u,pw2,,note here,LP Site,,0\n';
  assert.deepEqual(pick(core.importCsv(lastpass)), [['LP Site', 'u', 'pw2', 'https://lp.test/', 'note here']]);
  const firefox = '"url","username","password","httpRealm","formActionOrigin","guid"\n"https://ff.test","u","pw3",,"https://ff.test","{x}"\n';
  assert.deepEqual(pick(core.importCsv(firefox)), [['ff.test', 'u', 'pw3', 'https://ff.test/', '']]);
});

test('CSV import: skips, duplicates, cleaning and bad files', () => {
  const csv = 'name,url,username,password,note\nA,https://a.test,me,pw-a,\nA,https://a.test,ME,pw-a,\nNoPw,https://b.test,me,,\nBig,https://c.test,me,' + 'x'.repeat(300) + ',\n<img src=x onerror=alert(1)>,javascript:alert(1),me​,pw\u0000d,\nExisting,https://e.test,me,pw-e,\n';
  const existing = core.sanitizeItems([{ id: 'e1', title: 'Old name', username: 'me', password: 'pw-e', url: 'https://e.test', updatedAt: 1 }, { id: 'e2', deleted: true, updatedAt: 2 }]);
  const r = core.importCsv(csv, existing);
  assert.equal(r.items.length, 2);
  assert.equal(r.duplicates, 2); // same site and password twice in the file, and one already in the vault
  assert.deepEqual(r.skipped, [{ line: 4, reason: 'no password' }, { line: 5, reason: 'password longer than 256 characters' }]);
  const evil = r.items[1];
  assert.equal(evil.title, '<img src=x onerror=alert(1)>'); // kept as text, shown as text
  assert.equal(evil.url, ''); assert.equal(evil.username, 'me'); assert.equal(evil.password, 'pwd');
  assert.ok(r.items.every((i) => /^[A-Za-z0-9-]{8,64}$/.test(i.id) && i.updatedAt > 0 && i.deleted === false));
  assert.equal(new Set(r.items.map((i) => i.id)).size, 2);
  assert.equal(core.importCsv(csv, existing.concat(r.items)).items.length, 0); // importing the same file twice adds nothing
  assert.throws(() => core.importCsv('just some text'), { message: 'csv_empty' });
  assert.throws(() => core.importCsv('a,b\n1,2\n'), { message: 'csv_no_password_column' });
  assert.throws(() => core.importCsv('password\n' + 'x\n'.repeat(5001)), { message: 'csv_too_big' });
});

test('rollback detection: older and swapped copies are flagged, normal updates are not', async () => {
  assert.equal(core.checkRollback(7, 'aa', 8, 'bb'), null);   // newer copy from another device
  assert.equal(core.checkRollback(7, 'aa', 7, 'aa'), null);   // nothing changed
  assert.equal(core.checkRollback(7, 'aa', 6, 'cc'), 'older');
  assert.equal(core.checkRollback(7, 'aa', 0, ''), 'older');
  assert.equal(core.checkRollback(7, 'aa', 7, 'zz'), 'swapped');
  assert.equal(core.checkRollback(7, '', 7, 'zz'), null);     // a device upgraded from an older release has no fingerprint yet
  assert.equal(core.checkRollback(0, '', 1, 'aa'), null);     // a brand new device has nothing to compare
  assert.equal(await core.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('two-factor setup: secret format and authenticator link', () => {
  const a = core.newTotpSecret();
  assert.match(a, /^[A-Z2-7]{32}$/);
  assert.notEqual(a, core.newTotpSecret());
  assert.equal(core.otpauthUri('JBSWY3DPEHPK3PXP', 'me@x'), 'otpauth://totp/Vault:me%40x?secret=JBSWY3DPEHPK3PXP&issuer=Vault&algorithm=SHA1&digits=6&period=30');
  for (const k of ['totp_on', 'totp_off', 'totp_fail', 'device_trusted', 'restore', 'rollback_seen']) assert.ok(core.LOG_EVENTS[k]);
});

test('authenticator codes in entries: key formats and the RFC 6238 reference values', async () => {
  const KEY = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
  assert.equal(core.normalizeTotp(''), '');
  assert.equal(core.normalizeTotp(' gezd gnbv-gy3t qojq gezd gnbv gy3t qojq== '), KEY);
  assert.equal(core.normalizeTotp('otpauth://totp/Example:me%40x.com?secret=' + KEY.toLowerCase() + '&issuer=Example'), KEY);
  assert.equal(core.normalizeTotp('otpauth://totp/x?issuer=A&secret=' + KEY + '&algorithm=SHA1&digits=6&period=30'), KEY);
  for (const bad of ['short', 'not base32 !!!!!!!!!!!!', '1111111111111111', 'otpauth://totp/x?issuer=A']) assert.throws(() => core.normalizeTotp(bad), { message: 'bad_totp_secret' });
  for (const odd of ['otpauth://hotp/x?secret=' + KEY, 'otpauth://totp/x?secret=' + KEY + '&digits=8', 'otpauth://totp/x?secret=' + KEY + '&period=60', 'otpauth://totp/x?secret=' + KEY + '&algorithm=SHA256']) assert.throws(() => core.normalizeTotp(odd), { message: 'totp_unsupported' });
  // RFC 6238 appendix B (SHA-1), last six digits of each published value
  for (const [t, code] of [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']]) {
    assert.equal((await core.totpNow(KEY, t * 1000)).code, code);
  }
  assert.equal((await core.totpNow(KEY, 59 * 1000)).left, 1);
  assert.equal((await core.totpNow(KEY, 60 * 1000)).left, 30);
  await assert.rejects(core.totpNow('nonsense'));
});

test('entries keep favourite and authenticator key through cleaning, and old entries keep their shape', () => {
  const KEY = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const [a, b, c] = core.sanitizeItems([
    { id: 'a', title: 'A', password: 'p', fav: true, totp: KEY.toLowerCase(), updatedAt: 1 },
    { id: 'b', title: 'B', password: 'p', fav: 'yes', totp: '<script>', updatedAt: 1 },
    { id: 'c', title: 'C', password: 'p', updatedAt: 1 },
  ]);
  assert.equal(a.fav, true); assert.equal(a.totp, KEY);
  assert.ok(!('fav' in b) && !('totp' in b));
  assert.deepEqual(Object.keys(c), ['id', 'title', 'username', 'password', 'url', 'notes', 'createdAt', 'updatedAt', 'deleted']);
  const ok = { title: 'T', username: 'u', password: 'pw', url: '', notes: '' };
  assert.equal(core.validateEntry({ ...ok, totp: 'gezd gnbv gy3t qojq' }).totp, 'GEZDGNBVGY3TQOJQ');
  assert.ok(!('totp' in core.validateEntry({ ...ok, totp: '  ' })));
  assert.throws(() => core.validateEntry({ ...ok, totp: 'abc' }), { message: 'bad_totp_secret' });
  const csv = 'name,url,username,password,note,otpauth\nSite,https://s.test,u,pw,,otpauth://totp/Site:u?secret=' + KEY + '\nOther,https://o.test,u,pw2,,garbage\n';
  const r = core.importCsv(csv);
  assert.equal(r.items[0].totp, KEY); assert.ok(!('totp' in r.items[1])); assert.equal(r.items.length, 2);
});

test('list order: favourites, then recently used on this device, then the rest by name', () => {
  const items = ['delta', 'Alpha', 'charlie', 'Bravo', 'echo', 'foxtrot'].map((t, i) => ({ id: 'i' + i, title: t }));
  items[4].fav = true; items[1].fav = true; // echo, Alpha
  const shape = (g) => g.map((x) => [x.label, x.items.map((i) => i.title)]);
  assert.deepEqual(shape(core.groupForList(items, { i0: 50, i3: 90, i4: 99, gone: 5 })), [
    ['Favourites', ['Alpha', 'echo']],
    ['Recently used', ['Bravo', 'delta']],
    ['All passwords', ['charlie', 'foxtrot']],
  ]);
  assert.deepEqual(shape(core.groupForList(items.filter((i) => !i.fav))), [['', ['Bravo', 'charlie', 'delta', 'foxtrot']]]);
  assert.deepEqual(shape(core.groupForList(items.filter((i) => !i.fav), { i0: 1, i2: 2, i3: 3, i5: 4 }, 2)), [['Recently used', ['foxtrot', 'Bravo']], ['All passwords', ['charlie', 'delta']]]);
  assert.deepEqual(core.groupForList([]), []);
  const flat = core.groupForList(items, { i0: 1 }).flatMap((g) => g.items); assert.equal(new Set(flat).size, items.length); // every entry appears exactly once
});

test('recently deleted: entries keep their content for 30 days, then become removal markers', () => {
  const DAY = 86400000, now = 1800000000000;
  const items = core.sanitizeItems([
    { id: 'a', title: 'Fresh', password: 'pw-a', updatedAt: 5, trashedAt: now - 29 * DAY },
    { id: 'b', title: 'Expired', password: 'pw-b', updatedAt: 5, trashedAt: now - 30 * DAY },
    { id: 'c', title: 'Live', password: 'pw-c', updatedAt: 5, trashedAt: 'soon', pwAt: -4 },
    { id: 'd', deleted: true, updatedAt: 9, trashedAt: 3 },
  ]);
  assert.equal(items[0].trashedAt, now - 29 * DAY);
  assert.equal(items[0].password, 'pw-a'); // content kept while in the trash
  assert.ok(!('trashedAt' in items[2]) && !('pwAt' in items[2])); // malformed values dropped
  assert.deepEqual(items[3], { id: 'd', deleted: true, updatedAt: 9 });
  const { items: out, purged } = core.purgeTrash(items, now);
  assert.equal(purged, 1);
  assert.deepEqual(out[1], { id: 'b', deleted: true, updatedAt: now }); // nothing of the entry is left
  assert.equal(out[0], items[0]);
  assert.equal(out[2], items[2]);
  assert.equal(core.purgeTrash(out, now).purged, 0);
  assert.equal(core.trashDaysLeft(items[0], now), 1);
  assert.equal(core.trashDaysLeft({ trashedAt: now }, now), 30);
  // A trashed entry does not count as reused, and does not block importing the same login again.
  assert.deepEqual(core.findReused([{ id: 'x', password: 'same' }, { id: 'y', password: 'same', trashedAt: 1 }]), []);
  const csv = 'name,url,username,password\nFresh,,,pw-a\n';
  assert.equal(core.importCsv(csv, items).items.length, 1);
  // Deleting on one device and restoring on another: the later action wins.
  const trashed = { id: 'm', title: 'M', password: 'p', updatedAt: 10, trashedAt: 10 };
  const restored = { id: 'm', title: 'M', password: 'p', updatedAt: 20 };
  assert.ok(!core.mergeItems([trashed], [restored])[0].trashedAt);
  assert.ok(!core.mergeItems([restored], [trashed])[0].trashedAt);
  assert.equal(core.mergeItems([restored], [{ ...trashed, updatedAt: 30, trashedAt: 30 }])[0].trashedAt, 30);
});

test('health summary: counts each entry once and ignores trashed, deleted and edited entries', () => {
  const DAY = 86400000, now = 1800000000000;
  const strong = (n) => `Zq7!vK2#mX9$pL4@-${n}`;
  const items = [
    { id: 'leak', title: 'Leaked', password: strong(1), updatedAt: 100 },
    { id: 'edited', title: 'Edited since check', password: strong(2), updatedAt: 200 },
    { id: 'r1', title: 'Reuse 1', password: strong(3), updatedAt: 1 },
    { id: 'r2', title: 'Reuse 2', password: strong(3), updatedAt: 1 },
    { id: 'weakold', title: 'Weak and old', password: 'abc123', updatedAt: 1, pwAt: now - 400 * DAY },
    { id: 'young', title: 'Young', password: strong(4), updatedAt: 1, pwAt: now - 364 * DAY },
    { id: 'noage', title: 'Imported, age unknown', password: strong(5), updatedAt: 1 },
    { id: 'bin', title: 'In trash', password: 'abc123', updatedAt: 100, trashedAt: 5, pwAt: 1 },
    { id: 'gone', deleted: true, updatedAt: 1 },
  ];
  const breach = { leak: [1010, 100], edited: [5, 100], bin: [9, 100], young: [0, 1] };
  const f = core.healthFindings(items, breach, now);
  assert.deepEqual(f.leaked.map((x) => [x.it.id, x.count]), [['leak', 1010]]);
  assert.deepEqual(f.reused.map((g) => g.map((it) => it.id)), [['r1', 'r2']]);
  assert.deepEqual(f.weak.map((it) => it.id), ['weakold']);
  assert.deepEqual(f.old.map((it) => it.id), ['weakold']);
  assert.equal(f.total, 4); // leak, r1, r2, weakold (weak and old, counted once)
  assert.equal(f.checked, 7);
  assert.equal(core.healthFindings(items.slice(5, 7), {}, now).total, 0);
  assert.equal(core.healthFindings([], undefined, now).total, 0);
});

test('vault format: a copy written by a newer app version is refused instead of being opened and trimmed', async () => {
  const key = await core.importVaultKey(core.randomBytes(32));
  const blob = await core.encryptVault(key, 'u', [{ id: '1', title: 'A', password: 'p', updatedAt: 1, trashedAt: 7, pwAt: 3 }]);
  const back = await core.decryptVault(key, 'u', blob);
  assert.equal(back[0].trashedAt, 7);
  assert.equal(back[0].pwAt, 3);
  // Build a blob the way a future version would, with a higher format number.
  const seal = async (obj) => {
    const iv = core.randomBytes(12);
    const k = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('vault-v1|u') }, k, new TextEncoder().encode(JSON.stringify(obj)));
    return JSON.stringify({ v: 1, iv: core.b64.enc(iv), ct: core.b64.enc(new Uint8Array(ct)) });
  };
  const raw = core.randomBytes(32);
  const k2 = await core.importVaultKey(raw.slice());
  await assert.rejects(core.decryptVault(k2, 'u', await seal({ fmt: core.VAULT_FORMAT + 1, items: [] })), /newer_format/);
  assert.deepEqual(await core.decryptVault(k2, 'u', await seal({ items: [{ id: 'o', title: 'Old format', updatedAt: 1 }] })), core.sanitizeItems([{ id: 'o', title: 'Old format', updatedAt: 1 }]));
});

test('tags: cleaned, limited, matched without regard to case, and kept through encrypt and import', async () => {
  assert.deepEqual(core.normalizeTags(' Work ,banking;  work , Side   project\n​Hidden<b> '), ['Work', 'banking', 'Side project', 'Hidden b']);
  assert.deepEqual(core.normalizeTags(''), []);
  assert.deepEqual(core.normalizeTags(undefined), []);
  assert.deepEqual(core.normalizeTags(['ok', 7, null, { a: 1 }, 'OK', 'two']), ['ok', 'two']);
  assert.equal(core.normalizeTags('x'.repeat(40))[0].length, core.TAG_LEN);
  assert.throws(() => core.normalizeTags('x'.repeat(25), true), /bad_tags/);
  assert.equal(core.normalizeTags('a,b,c,d,e,f,g,h').length, core.TAG_MAX);
  assert.throws(() => core.normalizeTags('a,b,c,d,e,f,g', true), /too_many_tags/);
  const base = { title: 'T', username: '', password: 'pw-123456', url: '', notes: '' };
  assert.deepEqual(core.validateEntry({ ...base, tags: 'Work, Banking' }).tags, ['Work', 'Banking']);
  assert.ok(!('tags' in core.validateEntry(base)));
  assert.throws(() => core.validateEntry({ ...base, tags: 'y'.repeat(30) }), /bad_tags/);
  const items = core.sanitizeItems([
    { id: '1', title: 'A', password: 'p', updatedAt: 1, tags: ['Work', '<img src=x>', 'work', 5] },
    { id: '2', title: 'B', password: 'p2', updatedAt: 1, tags: 'not a list' },
    { id: '3', title: 'C', password: 'p3', updatedAt: 1, tags: ['WORK', 'Bank'] },
    { id: '4', title: 'D', password: 'p4', updatedAt: 1, tags: ['Bank'], trashedAt: 9 },
  ]);
  assert.deepEqual(items[0].tags, ['Work', 'img src=x']);
  assert.ok(!('tags' in items[1]));
  assert.deepEqual(core.allTags(items), [{ tag: 'Bank', count: 1 }, { tag: 'img src=x', count: 1 }, { tag: 'Work', count: 2 }]);
  assert.ok(core.hasTag(items[2], 'work') && !core.hasTag(items[1], 'work'));
  const key = await core.importVaultKey(core.randomBytes(32));
  assert.deepEqual((await core.decryptVault(key, 'u', await core.encryptVault(key, 'u', items)))[2].tags, ['WORK', 'Bank']);
  const bw = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork/Clients,,login,Acme,,,0,https://acme.test,me,pw-acme-1,\n,,login,Plain,,,0,,me,pw-plain-1,\n';
  const got = core.importCsv(bw, []).items;
  assert.deepEqual(got[0].tags, ['Work', 'Clients']);
  assert.ok(!('tags' in got[1]));
  assert.ok(!('tags' in core.importCsv('name,url,username,password,note\nG,https://g.test,me,pw-g-12345,\n', []).items[0])); // Google export has no folders
});

test('version history: going back restores the old copy and moves newer entries to Recently deleted', () => {
  const e = (id, title, extra = {}) => ({ id, title, username: '', password: 'pw-' + title, url: '', notes: '', createdAt: 1, updatedAt: 5, deleted: false, ...extra });
  const snapshot = [e('a', 'Alpha'), e('b', 'Bravo', { tags: ['Work'] }), e('c', 'Charlie'), e('t', 'Was in trash', { trashedAt: 3 }), { id: 'x', deleted: true, updatedAt: 2 }];
  const current = [
    e('a', 'Alpha'),                               // untouched
    e('b', 'Bravo', { password: 'changed', updatedAt: 50 }), // edited since
    { id: 'c', deleted: true, updatedAt: 60 },     // deleted for good since
    e('n', 'New since'),                           // added since
    e('g', 'Already in trash', { trashedAt: 40 }),
    { id: 'z', deleted: true, updatedAt: 9 },
  ];
  assert.deepEqual(core.snapshotDiff(current, snapshot), { total: 3, back: 1, changed: 1, removed: 1 });
  assert.deepEqual(core.snapshotDiff(snapshot, snapshot), { total: 3, back: 0, changed: 0, removed: 0 });
  const now = 1000;
  const out = core.restoreSnapshot(current, snapshot, now);
  const by = Object.fromEntries(out.map((it) => [it.id, it]));
  assert.equal(new Set(out.map((it) => it.id)).size, out.length);
  assert.equal(by.b.password, 'pw-Bravo'); assert.deepEqual(by.b.tags, ['Work']); assert.equal(by.b.updatedAt, now);
  assert.ok(!by.c.deleted && by.c.title === 'Charlie' && by.c.updatedAt === now); // back from permanent deletion
  assert.equal(by.n.trashedAt, now); assert.equal(by.n.title, 'New since');           // kept, recoverable
  assert.equal(by.g.trashedAt, 40);                                                   // left alone
  assert.deepEqual(by.z, { id: 'z', deleted: true, updatedAt: 9 });
  assert.equal(by.t.trashedAt, 3);                                                    // as it was in the old copy
  assert.ok(!('x' in by)); // an old removal marker for something this device never had is not brought back
  // The restored state wins over what any other device still holds.
  const merged = core.mergeItems(current, out);
  assert.equal(merged.find((it) => it.id === 'b').password, 'pw-Bravo');
  assert.equal(core.snapshotDiff(out, snapshot).back + core.snapshotDiff(out, snapshot).changed + core.snapshotDiff(out, snapshot).removed, 0);
  assert.deepEqual(core.restoreSnapshot([], [], now), []);
});
