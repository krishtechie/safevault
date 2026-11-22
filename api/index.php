<?php
declare(strict_types=1);

/*
 * Vault sync API.
 * The server never sees the master password or the encryption key. It stores:
 *   - a hash of the client-derived auth key (to sign in)
 *   - the encrypted vault blob (opaque to the server)
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function out(int $code, array $data): never {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}
function fail(int $code, string $error): never { out($code, ['error' => $error]); }

/* ---------- Config ---------- */

$cfgFile = __DIR__ . '/config.php';
if (!is_file($cfgFile)) fail(500, 'not_configured');
$cfg = require $cfgFile;

$dataDir = rtrim((string)($cfg['data_dir'] ?? ''), '/');
$secret  = (string)($cfg['server_secret'] ?? '');
$invite  = (string)($cfg['invite_code'] ?? '');
if ($dataDir === '' || strlen($secret) < 32 || str_contains($secret, 'CHANGE_ME')
    || strlen($invite) < 12 || str_contains($invite, 'CHANGE_ME')) {
    fail(500, 'not_configured');
}
foreach (['', '/users', '/vaults', '/throttle', '/sessions', '/pins'] as $sub) {
    if (!is_dir($dataDir . $sub) && !@mkdir($dataDir . $sub, 0700, true)) fail(500, 'data_dir_unwritable');
}
// The data folder must live outside the web root.
$realData = realpath($dataDir);
$docRoot  = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: '';
if ($realData === false || ($docRoot !== '' && str_starts_with($realData . '/', $docRoot . '/'))) {
    fail(500, 'data_dir_inside_web_root');
}

/* ---------- Request checks ---------- */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = (string)($_GET['a'] ?? '');
$ip     = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

// A custom header cannot be sent cross-site without a CORS preflight, and this API never approves one.
if (($_SERVER['HTTP_X_VAULT_CLIENT'] ?? '') !== '1') fail(400, 'bad_request');
if (!in_array($method, ['GET', 'POST'], true)) fail(405, 'method_not_allowed');
$origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
if ($origin !== '') {
    $host = (string)($_SERVER['HTTP_HOST'] ?? '');
    if (parse_url($origin, PHP_URL_HOST) . (parse_url($origin, PHP_URL_PORT) ? ':' . parse_url($origin, PHP_URL_PORT) : '') !== $host) {
        fail(403, 'bad_origin');
    }
}

$body = [];
if ($method === 'POST') {
    if (!str_starts_with(strtolower((string)($_SERVER['CONTENT_TYPE'] ?? '')), 'application/json')) fail(415, 'json_only');
    $raw = file_get_contents('php://input', false, null, 0, 6 * 1024 * 1024 + 1);
    if ($raw === false || strlen($raw) > 6 * 1024 * 1024) fail(413, 'too_large');
    $body = json_decode($raw, true);
    if (!is_array($body)) fail(400, 'bad_json');
}

/* ---------- Helpers ---------- */

function valid_username(mixed $u): ?string {
    if (!is_string($u)) return null;
    $u = strtolower(trim($u));
    return preg_match('/^[a-z0-9][a-z0-9._-]{2,31}$/', $u) ? $u : null;
}
function b64_len(mixed $s): int {
    if (!is_string($s) || $s === '') return -1;
    $d = base64_decode($s, true);
    return $d === false ? -1 : strlen($d);
}
function valid_kdf(mixed $k): ?array {
    if (!is_array($k) || ($k['alg'] ?? '') !== 'argon2id') return null;
    foreach (['m' => [19456, 1048576], 't' => [2, 20], 'p' => [1, 4]] as $f => [$lo, $hi]) {
        if (!is_int($k[$f] ?? null) || $k[$f] < $lo || $k[$f] > $hi) return null;
    }
    return ['alg' => 'argon2id', 'm' => $k['m'], 't' => $k['t'], 'p' => $k['p']];
}
function valid_blob(mixed $b): bool {
    if (!is_string($b) || strlen($b) > 5 * 1024 * 1024) return false;
    $o = json_decode($b, true);
    return is_array($o) && ($o['v'] ?? null) === 1 && b64_len($o['iv'] ?? null) === 12 && b64_len($o['ct'] ?? null) >= 16;
}
function read_json(string $file): ?array {
    if (!is_file($file)) return null;
    $d = json_decode((string)file_get_contents($file), true);
    return is_array($d) ? $d : null;
}
function write_json(string $file, array $data): void {
    $tmp = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
    if (file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES), LOCK_EX) === false || !rename($tmp, $file)) {
        @unlink($tmp);
        fail(500, 'write_failed');
    }
    @chmod($file, 0600);
}
function with_lock(string $lockFile, callable $fn): mixed {
    $h = fopen($lockFile, 'c');
    if (!$h || !flock($h, LOCK_EX)) fail(500, 'lock_failed');
    try { return $fn(); } finally { flock($h, LOCK_UN); fclose($h); }
}

/* ---------- Throttling (failed attempts in a sliding window) ---------- */

function throttle_file(string $key): string {
    global $dataDir;
    return $dataDir . '/throttle/' . hash('sha256', $key) . '.json';
}
function throttle_count(string $key, int $window): int {
    $now = time();
    $hits = array_filter(read_json(throttle_file($key)) ?? [], fn($t) => is_int($t) && $t > $now - $window);
    return count($hits);
}
function throttle_hit(string $key, int $window): void {
    $f = throttle_file($key);
    with_lock($f . '.lock', function () use ($f, $window) {
        $now = time();
        $hits = array_values(array_filter(read_json($f) ?? [], fn($t) => is_int($t) && $t > $now - $window));
        $hits[] = $now;
        write_json($f, $hits);
    });
}
function throttle_clear(string $key): void { @unlink(throttle_file($key)); }

/* ---------- Session ---------- */

const IDLE_SECONDS = 1800;

function start_session(): void {
    global $dataDir, $https;
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', (string)IDLE_SECONDS);
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '50');
    session_save_path($dataDir . '/sessions');
    session_name('vsid');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/api/index.php')), '/') . '/',
        'secure'   => $https,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}
function current_user(): ?string {
    global $dataDir;
    start_session();
    $u = $_SESSION['u'] ?? null;
    if (!is_string($u) || (time() - (int)($_SESSION['t'] ?? 0)) > IDLE_SECONDS) {
        $_SESSION = [];
        return null;
    }
    // A password change or recovery bumps the account generation, which signs out every other device.
    $user = read_json("$dataDir/users/$u.json");
    if (!$user || (int)($user['gen'] ?? 0) !== (int)($_SESSION['g'] ?? 0)) {
        $_SESSION = [];
        return null;
    }
    $_SESSION['t'] = time();
    return $u;
}
function require_user(): string {
    $u = current_user();
    if ($u === null) fail(401, 'signed_out');
    return $u;
}
function sign_in(string $u, int $gen): void {
    start_session();
    session_regenerate_id(true);
    $_SESSION = ['u' => $u, 't' => time(), 'g' => $gen];
}
// A wrapped key is a small encrypted blob: the vault key locked with a password key or a recovery key.
function valid_wrap(mixed $w): bool {
    return is_string($w) && strlen($w) <= 1024 && valid_blob($w);
}

const DUMMY_HASH = '$2y$10$nHYP29y/FHhGZsklg8tTnOhhQCqOj3m25uhIv9MBJYchFv.hAECve';

$userFile  = fn(string $u) => "$dataDir/users/$u.json";
$vaultFile = fn(string $u) => "$dataDir/vaults/$u.json";

// Checks a secret against a stored hash with throttling. Unknown users get a dummy hash so timing reveals nothing.
$verify = function (string $kind, string $u, mixed $secretIn, ?string $hash) use ($ip): bool {
    $keyPair = "$kind:$ip|$u";
    $keyIp   = "$kind-ip:$ip";
    if (throttle_count($keyPair, 900) >= 5 || throttle_count($keyIp, 900) >= 30) fail(429, 'slow_down');
    $ok = b64_len($secretIn) === 32 && password_verify((string)$secretIn, $hash ?? DUMMY_HASH) && $hash !== null;
    if (!$ok) {
        throttle_hit($keyPair, 900);
        throttle_hit($keyIp, 900);
        return false;
    }
    throttle_clear($keyPair);
    return true;
};
$updateUser = function (string $u, callable $fn) use ($userFile): array {
    $file = $userFile($u);
    return with_lock($file . '.lock', function () use ($file, $fn) {
        $user = read_json($file) ?? fail(404, 'no_account');
        $user = $fn($user);
        write_json($file, $user);
        return $user;
    });
};

// PIN unlock records, one per device. The server holds half of the key needed to open the
// vault on that device and releases it only for the right PIN, at most three wrong tries.
$pinFile = function (mixed $deviceId) use ($dataDir): string {
    if (b64_len($deviceId) !== 16) fail(400, 'bad_device');
    return $dataDir . '/pins/' . bin2hex(base64_decode($deviceId, true)) . '.json';
};
$clearPins = function (string $u) use ($dataDir): void {
    foreach (glob($dataDir . '/pins/*.json') ?: [] as $f) {
        $rec = read_json($f);
        if (($rec['user'] ?? null) === $u) { @unlink($f); @unlink($f . '.lock'); }
    }
};
const PIN_TRIES = 3;

/* ---------- Actions ---------- */

switch ($method . ' ' . $action) {

case 'POST prelogin': {
    // Returns the salt and KDF settings needed to derive keys on a new device.
    // Unknown usernames get a stable fake salt so accounts cannot be enumerated.
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    if (throttle_count("pre-ip:$ip", 900) >= 60) fail(429, 'slow_down');
    throttle_hit("pre-ip:$ip", 900);
    $user = read_json($userFile($u));
    if ($user) out(200, ['salt' => $user['salt'], 'kdf' => $user['kdf']]);
    $fake = substr(hash_hmac('sha256', 'salt|' . $u, $secret, true), 0, 16);
    out(200, ['salt' => base64_encode($fake), 'kdf' => ['alg' => 'argon2id', 'm' => 65536, 't' => 3, 'p' => 1]]);
}

case 'POST register': {
    if (empty($cfg['allow_registration'])) fail(403, 'registration_closed');
    if (throttle_count("reg-ip:$ip", 3600) >= 5) fail(429, 'slow_down');
    if (!hash_equals($invite, (string)($body['invite'] ?? ''))) {
        throttle_hit("reg-ip:$ip", 3600);
        fail(403, 'bad_invite');
    }
    $u   = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $kdf = valid_kdf($body['kdf'] ?? null) ?? fail(400, 'bad_kdf');
    if (b64_len($body['salt'] ?? null) !== 16) fail(400, 'bad_salt');
    if (b64_len($body['auth'] ?? null) !== 32) fail(400, 'bad_auth');
    if (!valid_wrap($body['wrap'] ?? null)) fail(400, 'bad_wrap');
    if (!valid_blob($body['blob'] ?? null)) fail(400, 'bad_blob');

    $h = @fopen($userFile($u), 'x'); // atomic: fails if the account already exists
    if (!$h) fail(409, 'username_taken');
    fwrite($h, json_encode([
        'salt' => $body['salt'], 'kdf' => $kdf,
        'auth_hash' => password_hash($body['auth'], PASSWORD_DEFAULT),
        'wrap' => $body['wrap'], 'rec' => null, 'gen' => 0,
        'created' => time(),
    ], JSON_UNESCAPED_SLASHES));
    fclose($h);
    @chmod($userFile($u), 0600);
    write_json($vaultFile($u), ['rev' => 1, 'blob' => $body['blob'], 'updated' => time()]);
    sign_in($u, 0);
    out(200, ['rev' => 1]);
}

case 'POST login': {
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $user = read_json($userFile($u));
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    sign_in($u, (int)($user['gen'] ?? 0));
    $v = read_json($vaultFile($u));
    out(200, ['rev' => (int)($v['rev'] ?? 0), 'wrap' => $user['wrap'] ?? null, 'recovery' => !empty($user['rec'])]);
}

case 'POST logout': {
    start_session();
    $_SESSION = [];
    session_destroy();
    out(200, ['ok' => true]);
}

case 'GET account': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    out(200, ['wrap' => $user['wrap'] ?? null, 'recovery' => !empty($user['rec'])]);
}

case 'POST setwrap': {
    // One-time upgrade for accounts created before key wrapping existed. Never overwrites an existing wrap.
    $u = require_user();
    if (!valid_wrap($body['wrap'] ?? null)) fail(400, 'bad_wrap');
    $user = $updateUser($u, function (array $user) use ($body) {
        if (!empty($user['wrap'])) out(200, ['wrap' => $user['wrap']]);
        $user['wrap'] = $body['wrap'];
        return $user;
    });
    out(200, ['wrap' => $user['wrap']]);
}

case 'POST rekey': {
    // Change master password. The current sign-in key is checked again even though a session exists.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $kdf = valid_kdf($body['kdf'] ?? null) ?? fail(400, 'bad_kdf');
    if (b64_len($body['salt'] ?? null) !== 16) fail(400, 'bad_salt');
    if (b64_len($body['newAuth'] ?? null) !== 32) fail(400, 'bad_auth');
    if (!valid_wrap($body['wrap'] ?? null)) fail(400, 'bad_wrap');
    $user = $updateUser($u, function (array $user) use ($body, $kdf) {
        $user['salt'] = $body['salt'];
        $user['kdf'] = $kdf;
        $user['auth_hash'] = password_hash($body['newAuth'], PASSWORD_DEFAULT);
        $user['wrap'] = $body['wrap'];
        $user['gen'] = (int)($user['gen'] ?? 0) + 1;
        return $user;
    });
    $clearPins($u); // PINs on every device stop working until set again
    sign_in($u, $user['gen']);
    out(200, ['ok' => true]);
}

case 'POST recovery_set': {
    // Create or replace the recovery key. Needs the current sign-in key again.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    if (b64_len($body['recAuth'] ?? null) !== 32) fail(400, 'bad_auth');
    if (!valid_wrap($body['recWrap'] ?? null)) fail(400, 'bad_wrap');
    $updateUser($u, function (array $user) use ($body) {
        $user['rec'] = ['auth_hash' => password_hash($body['recAuth'], PASSWORD_DEFAULT), 'wrap' => $body['recWrap'], 'created' => time()];
        return $user;
    });
    out(200, ['recovery' => true]);
}

case 'POST recovery_clear': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $updateUser($u, function (array $user) { $user['rec'] = null; return $user; });
    out(200, ['recovery' => false]);
}

case 'POST recover_start': {
    // Forgotten master password, step 1: prove knowledge of the recovery key, receive the wrapped vault key.
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $user = read_json($userFile($u));
    if (!$verify('recover', $u, $body['recAuth'] ?? null, $user['rec']['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    out(200, ['recWrap' => $user['rec']['wrap']]);
}

case 'POST recover_finish': {
    // Step 2: set a new master password. The vault itself is not touched.
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $user = read_json($userFile($u));
    if (!$verify('recover', $u, $body['recAuth'] ?? null, $user['rec']['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $kdf = valid_kdf($body['kdf'] ?? null) ?? fail(400, 'bad_kdf');
    if (b64_len($body['salt'] ?? null) !== 16) fail(400, 'bad_salt');
    if (b64_len($body['newAuth'] ?? null) !== 32) fail(400, 'bad_auth');
    if (!valid_wrap($body['wrap'] ?? null)) fail(400, 'bad_wrap');
    $user = $updateUser($u, function (array $user) use ($body, $kdf) {
        $user['salt'] = $body['salt'];
        $user['kdf'] = $kdf;
        $user['auth_hash'] = password_hash($body['newAuth'], PASSWORD_DEFAULT);
        $user['wrap'] = $body['wrap'];
        $user['gen'] = (int)($user['gen'] ?? 0) + 1;
        return $user;
    });
    $clearPins($u);
    sign_in($u, $user['gen']);
    $v = read_json($vaultFile($u));
    out(200, ['rev' => (int)($v['rev'] ?? 0)]);
}

case 'POST pin_set': {
    // Turn on PIN unlock for one device. Needs the current sign-in key again.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $file = $pinFile($body['deviceId'] ?? null);
    if (b64_len($body['pinAuth'] ?? null) !== 32 || b64_len($body['ksrv'] ?? null) !== 32) fail(400, 'bad_pin_data');
    $mine = 0;
    foreach (glob($dataDir . '/pins/*.json') ?: [] as $f) {
        if ($f !== $file && ((read_json($f)['user'] ?? null) === $u)) $mine++;
    }
    if ($mine >= 10) fail(409, 'too_many_devices');
    write_json($file, [
        'user' => $u, 'hash' => password_hash($body['pinAuth'], PASSWORD_DEFAULT), 'ksrv' => $body['ksrv'],
        'fails' => 0, 'created' => time(),
    ]);
    out(200, ['ok' => true]);
}

case 'POST pin_unlock': {
    // No session needed: the device id is a 128-bit random value known only to that device.
    $file = $pinFile($body['deviceId'] ?? null);
    if (throttle_count("pin-ip:$ip", 900) >= 30) fail(429, 'slow_down');
    with_lock($file . '.lock', function () use ($file, $body, $ip) {
        $rec = read_json($file);
        if (!$rec) { @unlink($file . '.lock'); fail(404, 'pin_gone'); }
        $ok = b64_len($body['pinAuth'] ?? null) === 32 && password_verify((string)$body['pinAuth'], (string)$rec['hash']);
        if ($ok) {
            if ((int)$rec['fails'] !== 0) { $rec['fails'] = 0; write_json($file, $rec); }
            out(200, ['ksrv' => $rec['ksrv']]);
        }
        throttle_hit("pin-ip:$ip", 900);
        $rec['fails'] = (int)$rec['fails'] + 1;
        if ($rec['fails'] >= PIN_TRIES) {
            @unlink($file); // the key half is destroyed: only the master password opens this device now
            fail(403, 'pin_locked');
        }
        write_json($file, $rec);
        out(401, ['error' => 'bad_pin', 'left' => PIN_TRIES - $rec['fails']]);
    });
}

case 'POST pin_clear': {
    $u = require_user();
    $file = $pinFile($body['deviceId'] ?? null);
    $rec = read_json($file);
    if ($rec && ($rec['user'] ?? null) === $u) { @unlink($file); @unlink($file . '.lock'); }
    out(200, ['ok' => true]);
}

case 'GET vault': {
    $u = require_user();
    $v = read_json($vaultFile($u)) ?? fail(404, 'no_vault');
    if (isset($_GET['rev']) && (int)$_GET['rev'] === (int)$v['rev']) out(200, ['rev' => (int)$v['rev'], 'unchanged' => true]);
    out(200, ['rev' => (int)$v['rev'], 'blob' => $v['blob']]);
}

case 'POST save': {
    $u = require_user();
    if (!valid_blob($body['blob'] ?? null)) fail(400, 'bad_blob');
    if (!is_int($body['baseRev'] ?? null)) fail(400, 'bad_rev');
    $file = $vaultFile($u);
    with_lock($file . '.lock', function () use ($file, $body) {
        $v = read_json($file) ?? ['rev' => 0, 'blob' => null];
        // Another device saved first: hand back the newer copy so the client can merge and retry.
        if ((int)$v['rev'] !== $body['baseRev']) out(409, ['error' => 'conflict', 'rev' => (int)$v['rev'], 'blob' => $v['blob']]);
        if ($v['blob'] !== null) @copy($file, $file . '.prev'); // keep one previous version
        $rev = (int)$v['rev'] + 1;
        write_json($file, ['rev' => $rev, 'blob' => $body['blob'], 'updated' => time()]);
        out(200, ['rev' => $rev]);
    });
}

default:
    fail(404, 'unknown_action');
}
