// Compares the files the live site serves with the files in this repository.
//
// Why this runs on GitHub and not inside the app: if someone changed the app's code on the web host, the
// changed code could simply skip or fake any check built into it. A check has to come from outside the
// thing being checked. GitHub fetches the site the way a visitor's browser would and compares every file
// the app loads, byte for byte, with the copy that was committed here.
//
// Usage: node tests/check-live.mjs https://vault.example.com [--wait=minutes]
// On GitHub the address comes from the SITE_URL secret, so it never appears in this public repository or its logs.
// Exits 0 when everything matches, 1 when something differs, 2 when the site could not be checked.

import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// What a browser loads to run the app. Server-side code (api/) cannot be read from outside, and by design
// it only ever sees encrypted data, so the files that matter for your secrets are these.
const SHIPPED_FILES = ['index.html', 'style.css', 'sw.js', 'manifest.webmanifest'];
const SHIPPED_DIRS = ['js', 'vendor', 'icons'];
// What must never be readable from the web.
const HIDDEN = ['.git/HEAD', '.git/config', '.htaccess', '.gitignore', 'api/config.php~', 'tests/core.test.mjs'];

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

async function walk(dir) {
  const out = [];
  for (const e of await readdir(join(ROOT, dir), { withFileTypes: true })) {
    if (e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...await walk(p));
    else if (e.isFile()) out.push(p.split(sep).join('/'));
  }
  return out;
}

export async function shippedFiles() {
  const list = [...SHIPPED_FILES];
  for (const d of SHIPPED_DIRS) list.push(...await walk(d));
  return list.sort();
}

async function get(url) {
  const res = await fetch(url, {
    redirect: 'manual', cache: 'no-store',
    headers: { 'User-Agent': 'vault-integrity-check (GitHub Actions)', 'Cache-Control': 'no-cache' },
    signal: AbortSignal.timeout(30000),
  });
  return { status: res.status, type: res.headers.get('content-type') || '', csp: res.headers.get('content-security-policy') || '', body: Buffer.from(await res.arrayBuffer()) };
}

// One pass over the site. Returns a list of problems, each a short sentence.
export async function check(base, root = ROOT) {
  const site = base.replace(/\/+$/, '');
  const problems = [];
  const files = await shippedFiles();
  const stamp = Date.now();
  for (const f of files) {
    const want = await readFile(join(root, f));
    let got;
    try { got = await get(`${site}/${f}?integrity=${stamp}`); }
    catch (e) { problems.push(`${f}: could not be fetched (${e.name})`); continue; }
    if (got.status !== 200) problems.push(`${f}: the site answered ${got.status}, expected 200`);
    else if (sha256(got.body) !== sha256(want)) {
      problems.push(`${f}: DIFFERENT from the repository (served ${got.body.length} bytes as ${got.type || 'unknown type'}, sha256 ${sha256(got.body).slice(0, 16)}; expected ${want.length} bytes, sha256 ${sha256(want).slice(0, 16)})`);
    }
  }
  // The page at the bare address must be the same index.html.
  try {
    const home = await get(`${site}/?integrity=${stamp}`);
    if (home.status !== 200 || sha256(home.body) !== sha256(await readFile(join(root, 'index.html')))) problems.push('/: the home page is not the repository index.html');
    if (!/default-src 'none'/.test(home.csp) || /unsafe-inline|unsafe-eval'/.test(home.csp.replace("'wasm-unsafe-eval'", ''))) {
      problems.push(`/: the Content-Security-Policy header is missing or weakened (${home.csp || 'none sent'})`);
    }
  } catch (e) { problems.push(`/: could not be fetched (${e.name})`); }
  for (const h of HIDDEN) {
    try {
      const r = await get(`${site}/${h}`);
      if (r.status === 200) problems.push(`${h}: is readable from the web and must not be`);
    } catch { /* unreachable is as good as hidden */ }
  }
  return { files: files.length, problems };
}

async function main() {
  const arg = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '';
  const base = (arg || process.env.SITE_URL || '').trim();
  if (!/^https?:\/\//.test(base)) {
    console.error('No site address. On GitHub, add a repository secret named SITE_URL holding the full address of the site');
    console.error('(Settings, Secrets and variables, Actions, New repository secret). On a computer, pass it as the first argument.');
    process.exit(2);
  }
  const wait = Number((process.argv.find((a) => a.startsWith('--wait=')) || '--wait=0').slice(7)) || 0;
  const until = Date.now() + wait * 60000;
  let result;
  for (;;) {
    result = await check(base);
    if (!result.problems.length || Date.now() >= until) break;
    // A push takes a few minutes to reach the host. Until then the old files are still being served.
    console.log(`${result.problems.length} difference(s). The site may still be updating. Checking again in a minute.`);
    await new Promise((r) => setTimeout(r, 60000));
  }
  if (!result.problems.length) {
    console.log(`OK. All ${result.files} files the app loads match this repository, and the hidden paths are hidden.`);
    return;
  }
  console.error(`MISMATCH. The live site does not match this repository:\n`);
  for (const p of result.problems) console.error('  - ' + p);
  console.error(`\nIf you pushed in the last few minutes and the host has not updated yet, run this check again.`);
  console.error('If not, treat the site as tampered with: do not sign in, check the host, and redeploy from this repository.');
  process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch((e) => { console.error('The check itself failed:', e); process.exit(2); });
