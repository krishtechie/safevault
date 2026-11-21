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
foreach (['', '/users', '/vaults', '/throttle', '/sessions'] as $sub) {
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
    start_session();
    $u = $_SESSION['u'] ?? null;
    if (!is_string($u) || (time() - (int)($_SESSION['t'] ?? 0)) > IDLE_SECONDS) {
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
function sign_in(string $u): void {
    start_session();
    session_regenerate_id(true);
    $_SESSION = ['u' => $u, 't' => time()];
}

$userFile  = fn(string $u) => "$dataDir/users/$u.json";
$vaultFile = fn(string $u) => "$dataDir/vaults/$u.json";

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
    if (!valid_blob($body['blob'] ?? null)) fail(400, 'bad_blob');

    $h = @fopen($userFile($u), 'x'); // atomic: fails if the account already exists
    if (!$h) fail(409, 'username_taken');
    fwrite($h, json_encode([
        'salt' => $body['salt'], 'kdf' => $kdf,
        'auth_hash' => password_hash($body['auth'], PASSWORD_DEFAULT),
        'created' => time(),
    ]));
    fclose($h);
    @chmod($userFile($u), 0600);
    write_json($vaultFile($u), ['rev' => 1, 'blob' => $body['blob'], 'updated' => time()]);
    sign_in($u);
    out(200, ['rev' => 1]);
}

case 'POST login': {
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $keyPair = "login:$ip|$u";
    $keyIp   = "login-ip:$ip";
    if (throttle_count($keyPair, 900) >= 5 || throttle_count($keyIp, 900) >= 30) fail(429, 'slow_down');
    $user = read_json($userFile($u));
    // Verify against a dummy hash for unknown users so timing does not reveal who exists.
    $hash = $user['auth_hash'] ?? '$2y$10$nHYP29y/FHhGZsklg8tTnOhhQCqOj3m25uhIv9MBJYchFv.hAECve';
    $ok = b64_len($body['auth'] ?? null) === 32 && password_verify((string)$body['auth'], $hash) && $user;
    if (!$ok) {
        throttle_hit($keyPair, 900);
        throttle_hit($keyIp, 900);
        fail(401, 'bad_credentials');
    }
    throttle_clear($keyPair);
    sign_in($u);
    $v = read_json($vaultFile($u));
    out(200, ['rev' => (int)($v['rev'] ?? 0)]);
}

case 'POST logout': {
    start_session();
    $_SESSION = [];
    session_destroy();
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
