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
  assert.equal(core.b64.dec(a.auth).length, 32);
  assert.equal(a.encKey.extractable, false);
});

test('vault round trip, wrong key, wrong user and tampering all behave', async () => {
  const a = await core.deriveKeys('pw-one-long-enough', salt, kdf);
  const b = await core.deriveKeys('pw-two-long-enough', salt, kdf);
  const items = [{ id: '1', title: 'Bank', password: 'p@ss ünïcode 🔑', updatedAt: 1 }];
  const blob = await core.encryptVault(a.encKey, 'user', items);
  assert.ok(!blob.includes('Bank'));
  assert.deepEqual(await core.decryptVault(a.encKey, 'user', blob), items);
  await assert.rejects(core.decryptVault(b.encKey, 'user', blob));
  await assert.rejects(core.decryptVault(a.encKey, 'other', blob));
  const o = JSON.parse(blob); const ct = core.b64.dec(o.ct); ct[0] ^= 1; o.ct = core.b64.enc(ct);
  await assert.rejects(core.decryptVault(a.encKey, 'user', JSON.stringify(o)));
  const blob2 = await core.encryptVault(a.encKey, 'user', items);
  assert.notEqual(JSON.parse(blob).iv, JSON.parse(blob2).iv); // fresh nonce each save
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
