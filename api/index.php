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
foreach (['', '/users', '/vaults', '/throttle', '/sessions', '/pins', '/logs', '/geo'] as $sub) {
    if (!is_dir($dataDir . $sub) && !@mkdir($dataDir . $sub, 0700, true)) fail(500, 'data_dir_unwritable');
}
// Housekeeping, on roughly one request in forty: remove attempt counters and location answers that have
// expired, so the data folder cannot grow without limit under a flood of junk sign-in attempts.
if (random_int(1, 40) === 1) {
    foreach (['throttle' => 7200, 'geo' => 32 * 86400] as $sub => $maxAge) {
        foreach (glob("$dataDir/$sub/*") ?: [] as $old) {
            if ((int)@filemtime($old) < time() - $maxAge) @unlink($old);
        }
    }
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

// Access log: one line per event, per account. Kept to the most recent 500 events.
$audit = function (string $u, string $event, ?string $typed = null) use ($dataDir, $ip): void {
    // $u = '_server' is the server-wide log of attempts that belong to no account (or to someone else's).
    $file = "$dataDir/logs/$u.log";
    $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
    $row = ['t' => time(), 'e' => $event, 'ip' => $ip, 'ua' => $ua];
    if ($typed !== null) $row['u'] = substr((string)preg_replace('/[^\x21-\x7E]/', '', $typed), 0, 40);
    $line = json_encode($row, JSON_UNESCAPED_SLASHES) . "\n";
    $new = !is_file($file);
    @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    if ($new) @chmod($file, 0600);
    clearstatcache(true, $file);
    if ((int)@filesize($file) > 160000) {
        with_lock($file . '.lock', function () use ($file) {
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            file_put_contents($file, implode("\n", array_slice($lines, -500)) . "\n", LOCK_EX);
        });
    }
};

// Failed and blocked attempts are also copied to the server-wide log with the username that was typed,
// so the owner sees attempts against names that do not exist and against other accounts.
$auditFail = function (string $typed, string $event, bool $exists) use ($audit): void {
    $name = valid_username($typed) ?? '';
    if ($exists && $name !== '') $audit($name, $event);
    $audit('_server', $exists ? $event : $event . '_unknown', $typed);
};
// The owner is the account named in config ('owner'), or else the first account created on this server.
$isOwner = function (string $u) use ($cfg, $dataDir): bool {
    if (!empty($cfg['owner'])) return strtolower((string)$cfg['owner']) === $u;
    $first = null;
    $firstAt = PHP_INT_MAX;
    foreach (glob($dataDir . '/users/*.json') ?: [] as $f) {
        $at = (int)(read_json($f)['created'] ?? PHP_INT_MAX);
        if ($at < $firstAt) { $firstAt = $at; $first = basename($f, '.json'); }
    }
    return $first === $u;
};
// City and country for an address, looked up only when the log is viewed and cached for 30 days.
// Set 'geo_url' => false in config.php to switch this off (addresses are then never sent anywhere).
$geo = function (array $ips) use ($cfg, $dataDir): array {
    $tpl = array_key_exists('geo_url', $cfg) ? $cfg['geo_url'] : 'https://free.freeipapi.com/api/v1/json/{ip}';
    $out = [];
    $tried = 0;
    $found = 0;
    $deadline = microtime(true) + 6;
    $fetched = 0;
    foreach (array_unique($ips) as $addr) {
        if (!filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;
        $file = $dataDir . '/geo/' . hash('sha256', $addr) . '.json';
        $hit = read_json($file);
        if ($hit && ($hit['v'] ?? 0) === 3 && (int)($hit['until'] ?? 0) > time()) {
            if (($hit['where'] ?? '') !== '') $out[$addr] = $hit['where'];
            continue;
        }
        // The free service allows 10 lookups per 10 seconds, so a single view asks for at most 8 new ones.
        if (!is_string($tpl) || $tpl === '' || $fetched >= 8 || microtime(true) > $deadline) continue;
        $fetched++;
        $url = str_replace('{ip}', rawurlencode($addr), $tpl);
        $raw = false;
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2, CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => 'Vault-access-log/1.0',
                CURLOPT_HTTPHEADER => ['Accept: application/json']]);
            $raw = curl_exec($ch);
        } elseif (ini_get('allow_url_fopen')) {
            $raw = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 2, 'header' => "Accept: application/json\r\nUser-Agent: Vault-access-log/1.0\r\n"]]), 0, 20000);
        }
        $j = is_string($raw) ? json_decode(substr($raw, 0, 20000), true) : null;
        $parts = [];
        if (is_array($j)) {
            foreach ([['city', 'cityName'], ['region', 'regionName', 'region_name'], ['country', 'countryName', 'country_name']] as $keys) {
                foreach ($keys as $k) {
                    if (is_string($j[$k] ?? null) && trim($j[$k]) !== '') {
                        $v = mb_substr(trim((string)preg_replace('/[\x00-\x1f\x7f<>]/u', '', $j[$k])), 0, 60);
                        if ($v !== '' && $v !== '-' && !in_array($v, $parts, true)) $parts[] = $v;
                        break;
                    }
                }
            }
        }
        $where = implode(', ', $parts);
        // Relay and VPN addresses (Apple Private Relay runs on Cloudflare, Akamai and Fastly) belong to the
        // relay company, so the city on record for them says nothing about where the person is.
        if (is_array($j)) {
            $org = '';
            foreach (['asnOrganization', 'org', 'isp', 'asn_org'] as $k) {
                if (is_string($j[$k] ?? null) && trim($j[$k]) !== '') {
                    $org = mb_substr(trim((string)preg_replace('/[\x00-\x1f\x7f<>]/u', '', $j[$k])), 0, 40);
                    break;
                }
            }
            $proxy = ($j['isProxy'] ?? false) === true || ($j['proxy'] ?? false) === true;
            if ($proxy || preg_match('/cloudflare|akamai|fastly|private relay|icloud|vpn|proxy/i', $org)) {
                $where = 'Private relay or VPN' . ($org !== '' ? " ($org)" : '') . ', real location hidden';
            }
        }
        // A failed lookup is retried after an hour, a good one is kept for 30 days.
        write_json($file, ['v' => 3, 'where' => $where, 'until' => time() + ($where === '' ? 3600 : 30 * 86400)]);
        $tried++;
        if ($where !== '') { $out[$addr] = $where; $found++; }
    }
    // 'off' = switched off in config, 'failed' = every new lookup in this view came back empty.
    $state = (!is_string($tpl) || $tpl === '') ? 'off' : (($tried > 0 && $found === 0) ? 'failed' : 'ok');
    return ['where' => $out, 'state' => $state];
};

// Checks a secret against a stored hash with throttling. Unknown users get a dummy hash so timing reveals nothing.
$verify = function (string $kind, string $u, mixed $secretIn, ?string $hash) use ($ip, $auditFail): bool {
    $keyPair = "$kind:$ip|$u";
    $keyIp   = "$kind-ip:$ip";
    if (throttle_count($keyPair, 900) >= 5 || throttle_count($keyIp, 900) >= 30) {
        if (throttle_count("blocknote:$keyPair", 900) === 0) { // one log line per lockout, not one per blocked try
            throttle_hit("blocknote:$keyPair", 900);
            $auditFail($u, $kind === 'recover' ? 'recover_blocked' : 'login_blocked', $hash !== null);
        }
        fail(429, 'slow_down');
    }
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

/* ---------- Two-factor sign-in (authenticator app codes, RFC 6238) ---------- */

function b32_decode(string $in): ?string {
    $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
    $in = strtoupper((string)preg_replace('/[\s=-]/', '', $in));
    if ($in === '' || preg_match('/[^A-Z2-7]/', $in)) return null;
    $bits = '';
    foreach (str_split($in) as $c) $bits .= str_pad(decbin($map[$c]), 5, '0', STR_PAD_LEFT);
    $out = '';
    foreach (str_split(substr($bits, 0, intdiv(strlen($bits), 8) * 8), 8) as $byte) $out .= chr(bindec($byte));
    return $out;
}
function totp_code(string $key, int $counter): string {
    $h = hash_hmac('sha1', pack('J', $counter), $key, true);
    $o = ord($h[19]) & 0x0f;
    $n = ((ord($h[$o]) & 0x7f) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]);
    return str_pad((string)($n % 1000000), 6, '0', STR_PAD_LEFT);
}
// Returns the matching time step (so a code cannot be used twice) or null. Accepts one step either side for clock drift.
function totp_match(string $key, mixed $code, int $lastStep): ?int {
    if (!is_string($code) || !preg_match('/^\d{6}$/', $code)) return null;
    $now = intdiv(time(), 30);
    foreach ([0, -1, 1] as $d) {
        $step = $now + $d;
        if ($step > $lastStep && hash_equals(totp_code($key, $step), $code)) return $step;
    }
    return null;
}
// The authenticator secret is stored encrypted with a key derived from the server secret in config.php,
// so the data folder alone does not reveal it.
$totpKey = hash_hmac('sha256', 'totp-storage-v1', $secret, true);
$totpSeal = function (string $raw) use ($totpKey): string {
    $iv = random_bytes(12);
    $ct = openssl_encrypt($raw, 'aes-256-gcm', $totpKey, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ct === false) fail(500, 'crypto_unavailable');
    return base64_encode($iv . $tag . $ct);
};
$totpOpen = function (mixed $sealed) use ($totpKey): ?string {
    $bin = is_string($sealed) ? base64_decode($sealed, true) : false;
    if ($bin === false || strlen($bin) < 29) return null;
    $raw = openssl_decrypt(substr($bin, 28), 'aes-256-gcm', $totpKey, OPENSSL_RAW_DATA, substr($bin, 0, 12), substr($bin, 12, 16));
    return $raw === false ? null : $raw;
};
// A device that has passed the code check once gets a random token. Only its hash is stored.
$trustHash = fn(mixed $t): ?string => b64_len($t) === 32 ? hash('sha256', (string)base64_decode($t, true)) : null;
$isTrusted = function (array $user, mixed $token) use ($trustHash): bool {
    $h = $trustHash($token);
    if ($h === null) return false;
    foreach ($user['trusted'] ?? [] as $t) if (hash_equals((string)($t['h'] ?? ''), $h)) return true;
    return false;
};

/* ---------- Actions ---------- */

switch ($method . ' ' . $action) {

case 'POST prelogin': {
    // Returns the salt and KDF settings needed to derive keys on a new device.
    // Unknown usernames get a stable fake salt so accounts cannot be enumerated.
    $u = valid_username($body['username'] ?? null);
    if ($u === null) {
        if (throttle_count("badname-ip:$ip", 900) < 20) { // bounded, so junk cannot flood the log
            throttle_hit("badname-ip:$ip", 900);
            $audit('_server', 'login_bad_name', is_string($body['username'] ?? null) ? $body['username'] : '');
        }
        fail(400, 'bad_username');
    }
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
        $audit('_server', 'register_bad_invite', is_string($body['username'] ?? null) ? $body['username'] : '');
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
    $audit($u, 'register');
    out(200, ['rev' => 1]);
}

case 'POST login': {
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $user = read_json($userFile($u));
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) {
        $auditFail($u, 'login_fail', (bool)$user);
        fail(401, 'bad_credentials');
    }
    $newTrust = null;
    if (!empty($user['totp']) && !$isTrusted($user, $body['trust'] ?? null)) {
        // Right master password on a device that has not passed the code check: ask for the code.
        if (!isset($body['totp']) || $body['totp'] === '') out(401, ['error' => 'totp_required']);
        $tk = "totp:$ip|$u";
        if (throttle_count($tk, 900) >= 5) fail(429, 'slow_down');
        $key = $totpOpen($user['totp']['secret'] ?? null) ?? fail(500, 'totp_unreadable');
        $newTrust = base64_encode(random_bytes(32));
        $step = null;
        $updateUser($u, function (array $fresh) use ($key, $body, &$step, $newTrust, $trustHash) {
            $step = totp_match($key, $body['totp'], (int)($fresh['totp']['last'] ?? 0));
            if ($step === null) return $fresh;
            $fresh['totp']['last'] = $step;
            $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
            $fresh['trusted'] = array_slice(array_merge($fresh['trusted'] ?? [], [['h' => $trustHash($newTrust), 'at' => time(), 'ua' => $ua]]), -10);
            return $fresh;
        });
        if ($step === null) {
            throttle_hit($tk, 900);
            $audit($u, 'totp_fail');
            $audit('_server', 'totp_fail', $u);
            out(401, ['error' => 'bad_totp']);
        }
        throttle_clear($tk);
        $audit($u, 'device_trusted');
    }
    sign_in($u, (int)($user['gen'] ?? 0));
    // 'auto' marks the app renewing its own session after a Face ID or PIN unlock, with no password typed.
    // It only changes the wording in the log. The same key and the same checks are required either way.
    $audit($u, ($body['auto'] ?? false) === true ? 'login_renew' : 'login_ok');
    $v = read_json($vaultFile($u));
    $res = ['rev' => (int)($v['rev'] ?? 0), 'wrap' => $user['wrap'] ?? null, 'recovery' => !empty($user['rec']), 'totp' => !empty($user['totp'])];
    if ($newTrust !== null) $res['trust'] = $newTrust;
    out(200, $res);
}

case 'POST totp_enable': {
    // Turn on two-factor sign-in. Needs the current sign-in key and a valid code from the new authenticator entry.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $key = b32_decode((string)($body['secret'] ?? ''));
    if ($key === null || strlen($key) < 20 || strlen($key) > 64) fail(400, 'bad_secret');
    $step = totp_match($key, $body['code'] ?? null, 0);
    if ($step === null) fail(400, 'bad_totp');
    $trust = base64_encode(random_bytes(32));
    $updateUser($u, function (array $fresh) use ($key, $step, $trust, $totpSeal, $trustHash) {
        $fresh['totp'] = ['secret' => $totpSeal($key), 'last' => $step, 'at' => time()];
        $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
        $fresh['trusted'] = [['h' => $trustHash($trust), 'at' => time(), 'ua' => $ua]]; // only this device starts out trusted
        return $fresh;
    });
    $audit($u, 'totp_on');
    out(200, ['totp' => true, 'trust' => $trust]);
}

case 'POST totp_disable': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $updateUser($u, function (array $fresh) { unset($fresh['totp'], $fresh['trusted']); return $fresh; });
    $audit($u, 'totp_off');
    out(200, ['totp' => false]);
}

case 'POST logout': {
    $who = current_user();
    if ($who !== null) $audit($who, 'logout');
    $_SESSION = [];
    session_destroy();
    out(200, ['ok' => true]);
}

case 'GET account': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    out(200, ['wrap' => $user['wrap'] ?? null, 'recovery' => !empty($user['rec']), 'totp' => !empty($user['totp'])]);
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
    $user = $updateUser($u, function (array $user) use ($body, $kdf, $trustHash) {
        $user['salt'] = $body['salt'];
        $user['kdf'] = $kdf;
        $user['auth_hash'] = password_hash($body['newAuth'], PASSWORD_DEFAULT);
        $user['wrap'] = $body['wrap'];
        $user['gen'] = (int)($user['gen'] ?? 0) + 1;
        // Only the device making the change stays trusted for two-factor sign-in.
        if (isset($user['trusted'])) {
            $mine = $trustHash($body['trust'] ?? null);
            $user['trusted'] = array_values(array_filter($user['trusted'], fn($t) => $mine !== null && hash_equals((string)($t['h'] ?? ''), $mine)));
        }
        return $user;
    });
    $clearPins($u); // PINs on every device stop working until set again
    sign_in($u, $user['gen']);
    $audit($u, 'rekey');
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
    $audit($u, 'recovery_set');
    out(200, ['recovery' => true]);
}

case 'POST recovery_clear': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $updateUser($u, function (array $user) { $user['rec'] = null; return $user; });
    $audit($u, 'recovery_clear');
    out(200, ['recovery' => false]);
}

case 'POST recover_start': {
    // Forgotten master password, step 1: prove knowledge of the recovery key, receive the wrapped vault key.
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $user = read_json($userFile($u));
    if (!$verify('recover', $u, $body['recAuth'] ?? null, $user['rec']['auth_hash'] ?? null)) {
        $auditFail($u, 'recover_fail', (bool)$user);
        fail(401, 'bad_credentials');
    }
    out(200, ['recWrap' => $user['rec']['wrap']]);
}

case 'POST recover_finish': {
    // Step 2: set a new master password. The vault itself is not touched.
    $u = valid_username($body['username'] ?? null) ?? fail(400, 'bad_username');
    $user = read_json($userFile($u));
    if (!$verify('recover', $u, $body['recAuth'] ?? null, $user['rec']['auth_hash'] ?? null)) {
        $auditFail($u, 'recover_fail', (bool)$user);
        fail(401, 'bad_credentials');
    }
    $kdf = valid_kdf($body['kdf'] ?? null) ?? fail(400, 'bad_kdf');
    if (b64_len($body['salt'] ?? null) !== 16) fail(400, 'bad_salt');
    if (b64_len($body['newAuth'] ?? null) !== 32) fail(400, 'bad_auth');
    if (!valid_wrap($body['wrap'] ?? null)) fail(400, 'bad_wrap');
    $hadTotp = false;
    $user = $updateUser($u, function (array $user) use ($body, $kdf, &$hadTotp) {
        $user['salt'] = $body['salt'];
        $user['kdf'] = $kdf;
        $user['auth_hash'] = password_hash($body['newAuth'], PASSWORD_DEFAULT);
        $user['wrap'] = $body['wrap'];
        $user['gen'] = (int)($user['gen'] ?? 0) + 1;
        $hadTotp = !empty($user['totp']);
        unset($user['totp'], $user['trusted']); // the recovery key is also the way back in after losing the authenticator
        return $user;
    });
    $clearPins($u);
    sign_in($u, $user['gen']);
    $audit($u, 'recover_ok');
    if ($hadTotp) $audit($u, 'totp_off');
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
    $audit($u, 'pin_set');
    out(200, ['ok' => true]);
}

case 'POST pin_unlock': {
    // No session needed: the device id is a 128-bit random value known only to that device.
    $file = $pinFile($body['deviceId'] ?? null);
    if (throttle_count("pin-ip:$ip", 900) >= 30) fail(429, 'slow_down');
    with_lock($file . '.lock', function () use ($file, $body, $ip, $audit) {
        $rec = read_json($file);
        if (!$rec) { @unlink($file . '.lock'); fail(404, 'pin_gone'); }
        $ok = b64_len($body['pinAuth'] ?? null) === 32 && password_verify((string)$body['pinAuth'], (string)$rec['hash']);
        if ($ok) {
            if ((int)$rec['fails'] !== 0) { $rec['fails'] = 0; write_json($file, $rec); }
            $audit((string)$rec['user'], 'pin_ok');
            out(200, ['ksrv' => $rec['ksrv']]);
        }
        throttle_hit("pin-ip:$ip", 900);
        $rec['fails'] = (int)$rec['fails'] + 1;
        if ($rec['fails'] >= PIN_TRIES) {
            @unlink($file); // the key half is destroyed: only the master password opens this device now
            $audit((string)$rec['user'], 'pin_locked');
            fail(403, 'pin_locked');
        }
        write_json($file, $rec);
        $audit((string)$rec['user'], 'pin_fail');
        out(401, ['error' => 'bad_pin', 'left' => PIN_TRIES - $rec['fails']]);
    });
}

case 'POST pin_clear': {
    $u = require_user();
    $file = $pinFile($body['deviceId'] ?? null);
    $rec = read_json($file);
    if ($rec && ($rec['user'] ?? null) === $u) { @unlink($file); @unlink($file . '.lock'); $audit($u, 'pin_clear'); }
    out(200, ['ok' => true]);
}

case 'GET log': {
    // The account's access log, newest first. The owner also gets the server-wide failed attempts.
    $u = require_user();
    $read = function (string $name) use ($dataDir): array {
        $file = "$dataDir/logs/$name.log";
        $rows = [];
        foreach (array_slice(is_file($file) ? (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []) : [], -500) as $line) {
            $row = json_decode($line, true);
            if (is_array($row) && is_int($row['t'] ?? null) && is_string($row['e'] ?? null)) {
                $e = ['t' => $row['t'], 'e' => $row['e'], 'ip' => (string)($row['ip'] ?? ''), 'ua' => (string)($row['ua'] ?? '')];
                if (isset($row['u'])) $e['u'] = (string)$row['u'];
                $rows[] = $e;
            }
        }
        return $rows;
    };
    $entries = $read($u);
    $owner = $isOwner($u);
    if ($owner) {
        // Attempts on this account are already in its own log; add everything aimed at other names.
        foreach ($read('_server') as $row) if (($row['u'] ?? '') !== $u) $entries[] = $row;
    }
    // Newest first; events in the same second keep the order they were written in.
    foreach ($entries as $i => $row) $entries[$i]['i'] = $i;
    usort($entries, fn($x, $y) => [$y['t'], $y['i']] <=> [$x['t'], $x['i']]);
    $entries = array_map(function ($row) { unset($row['i']); return $row; }, array_slice($entries, 0, 500));
    $places = $geo(array_column($entries, 'ip'));
    out(200, ['entries' => $entries, 'ip' => $ip, 'owner' => $owner, 'where' => (object)$places['where'], 'geo' => $places['state']]);
}

case 'POST note': {
    // Events that happen only on the device (Face ID) are reported here so they appear in the log.
    $u = require_user();
    $e = (string)($body['e'] ?? '');
    if (!in_array($e, ['bio_ok', 'bio_on', 'bio_off', 'rollback_seen'], true)) fail(400, 'bad_event');
    $audit($u, $e);
    out(200, ['ok' => true]);
}

case 'GET vault': {
    $u = require_user();
    $v = read_json($vaultFile($u)) ?? fail(404, 'no_vault');
    $same = isset($_GET['rev']) && (int)$_GET['rev'] === (int)$v['rev'];
    // The device may also send a fingerprint of the copy it holds. A different copy under the same version number is sent back in full.
    if ($same && isset($_GET['h']) && !hash_equals(hash('sha256', (string)$v['blob']), (string)$_GET['h'])) $same = false;
    if ($same) out(200, ['rev' => (int)$v['rev'], 'unchanged' => true]);
    out(200, ['rev' => (int)$v['rev'], 'blob' => $v['blob']]);
}

case 'POST save': {
    $u = require_user();
    if (!valid_blob($body['blob'] ?? null)) fail(400, 'bad_blob');
    if (!is_int($body['baseRev'] ?? null)) fail(400, 'bad_rev');
    $file = $vaultFile($u);
    with_lock($file . '.lock', function () use ($file, $body, $audit, $u) {
        $v = read_json($file) ?? ['rev' => 0, 'blob' => null];
        // Another device saved first: hand back the newer copy so the client can merge and retry.
        if ((int)$v['rev'] !== $body['baseRev']) out(409, ['error' => 'conflict', 'rev' => (int)$v['rev'], 'blob' => $v['blob']]);
        if ($v['blob'] !== null) @copy($file, $file . '.prev'); // keep one previous version
        $rev = (int)$v['rev'] + 1;
        // After a rollback, a device restores its newer copy and lifts the version past the one it had seen.
        $restore = is_int($body['restoreRev'] ?? null) && $body['restoreRev'] >= $rev && $body['restoreRev'] < $rev + 1000000;
        if ($restore) $rev = $body['restoreRev'] + 1;
        write_json($file, ['rev' => $rev, 'blob' => $body['blob'], 'updated' => time()]);
        $audit($u, $restore ? 'restore' : 'save');
        out(200, ['rev' => $rev]);
    });
}

default:
    fail(404, 'unknown_action');
}
