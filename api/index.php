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

// Preferred place: a folder named vault-data beside the website folder, which the web server never serves.
// The old place, next to this file, still works so an existing install keeps running until its file is moved.
$cfgFile = dirname(__DIR__, 2) . '/vault-data/config.php';
if (!is_file($cfgFile)) $cfgFile = __DIR__ . '/config.php';
if (!is_file($cfgFile)) fail(500, 'not_configured');
$cfg = require $cfgFile;
if (!is_array($cfg)) fail(500, 'not_configured');

$dataDir = rtrim((string)($cfg['data_dir'] ?? ''), '/');
$secret  = (string)($cfg['server_secret'] ?? '');
$invite  = (string)($cfg['invite_code'] ?? '');
if ($dataDir === '' || strlen($secret) < 32 || str_contains($secret, 'CHANGE_ME')
    || strlen($invite) < 12 || str_contains($invite, 'CHANGE_ME')) {
    fail(500, 'not_configured');
}
foreach (['', '/users', '/vaults', '/throttle', '/sessions', '/pins', '/logs', '/geo', '/history'] as $sub) {
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
// Each browser picks a random id for itself and sends it with every request. Only a hash of it is stored.
// It is what lets the account list its devices and sign one of them out from another.
$didRaw = base64_decode((string)($_SERVER['HTTP_X_VAULT_DEVICE'] ?? ''), true);
$dh     = ($didRaw !== false && strlen($didRaw) === 16) ? substr(hash('sha256', $didRaw), 0, 32) : null;

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
    // A device that was signed out from another device loses its session at once.
    $d = $_SESSION['d'] ?? null;
    if (is_string($d) && (!isset($user['devices'][$d]) || !empty($user['devices'][$d]['off']))) {
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
    global $dh;
    $_SESSION = ['u' => $u, 't' => time(), 'g' => $gen];
    if ($dh !== null) $_SESSION['d'] = $dh;
}
// A wrapped key is a small encrypted blob: the vault key locked with a password key or a recovery key.
function valid_wrap(mixed $w): bool {
    return is_string($w) && strlen($w) <= 1024 && valid_blob($w);
}

const DUMMY_HASH = '$2y$10$nHYP29y/FHhGZsklg8tTnOhhQCqOj3m25uhIv9MBJYchFv.hAECve';

$userFile  = fn(string $u) => "$dataDir/users/$u.json";
$vaultFile = fn(string $u) => "$dataDir/vaults/$u.json";

// Access log: one line per event, per account. Kept to the most recent 500 events.
// Email alerts for the events worth knowing about straight away. Off unless 'alert_email' is set in config.php.
const ALERT_EVENTS = [
    'login_ok'       => 'You signed in to your vault',
    'login_fail'     => 'A sign-in attempt on your vault failed',
    'pin_fail'       => 'A wrong PIN was entered',
    'totp_fail'      => 'A wrong authenticator code was entered',
    'recover_fail'   => 'An account recovery attempt failed',
    'recover_blocked' => 'Account recovery was blocked after 5 wrong attempts',
    'totp_on'        => 'Two-factor sign-in was turned on',
    'backup_used'    => 'A backup code was used to sign in',
    'backup_new'     => 'New backup codes were created',
    'recovery_set'   => 'A recovery key was created',
    'device_new'     => 'Your vault was opened on a new device',
    'device_refused' => 'A signed-out device tried to connect and was refused',
    'device_off'     => 'A device was signed out from another device',
    'login_blocked'  => 'Sign-in was blocked after 5 wrong attempts',
    'pin_locked'     => 'A PIN was turned off after 3 wrong tries',
    'rekey'          => 'Your sign-in details were changed',
    'recover_ok'     => 'Your account was recovered with the recovery key',
    'recovery_clear' => 'Your recovery key was removed',
    'totp_off'       => 'Two-factor sign-in was turned off',
    'history_restore' => 'Your vault was restored to an earlier version',
    'key_add'        => 'A security key was added',
    'key_remove'     => 'A security key was removed',
    'key_used'       => 'A new device was approved with a security key',
    'key_fail'       => 'A security key check failed',
];
const ALERT_SMART = ['device_new', 'rekey', 'recover_ok', 'totp_off', 'recovery_clear', 'login_blocked', 'recover_blocked'];
// Which colour the notice carries: green for a normal sign-in, red for a failed or refused attempt, amber for a change.
const ALERT_TONES = [
    'login_ok' => 'ok', 'device_new' => 'new', 'backup_used' => 'fail',
    'login_fail' => 'fail', 'pin_fail' => 'fail', 'totp_fail' => 'fail', 'recover_fail' => 'fail', 'recover_blocked' => 'fail',
    'login_blocked' => 'fail', 'pin_locked' => 'fail', 'device_refused' => 'fail', 'key_fail' => 'fail',
];
// "Chrome on macOS" from a browser's user agent line.
function ua_label(string $ua): string {
    $os = 'an unknown system';
    foreach (['iPhone' => 'iPhone', 'iPad' => 'iPad', 'Android' => 'Android', 'Mac OS X' => 'macOS', 'Windows' => 'Windows', 'CrOS' => 'ChromeOS', 'Linux' => 'Linux'] as $needle => $name) {
        if (strpos($ua, $needle) !== false) { $os = $name; break; }
    }
    $br = 'Unknown browser';
    foreach (['Edg' => 'Edge', 'OPR/' => 'Opera', 'FxiOS' => 'Firefox', 'Firefox/' => 'Firefox', 'CriOS' => 'Chrome', 'Chrome/' => 'Chrome', 'Safari/' => 'Safari'] as $needle => $name) {
        if (strpos($ua, $needle) !== false) { $br = $name; break; }
    }
    return "$br on $os";
}
// The notice as a designed card: a navy header with the logo, a colour bar for the kind of event, the account,
// the details, and an optional button. Tables and inline styles only, because that is what mail apps render
// reliably. The only remote content is the logo, and only when a site address is set in config. Every value is escaped.
// What each emailed event means, in one plain sentence. Events without a line here use their title.
const ALERT_BODY = [
    'device_new'      => 'Your vault was just opened on a device it has not seen before.',
    'rekey'           => 'The details you use to sign in to your vault were just changed. Your other devices were signed out and will ask for the new ones.',
    'recover_ok'      => 'Your account was just recovered with the recovery key, and new sign-in details were set.',
    'totp_off'        => 'Two-factor sign-in was just turned off. A new device no longer needs an authenticator code.',
    'recovery_clear'  => 'The recovery key for your vault was just removed. The old key no longer works.',
    'login_blocked'   => 'Wrong sign-in details were entered 5 times in a row, so sign-in from that network is paused for 15 minutes.',
    'recover_blocked' => 'A wrong recovery key was entered 5 times in a row, so recovery from that network is paused for 15 minutes.',
];

// The notice as a letter: logo, a large headline, a short colour bar, a greeting, what happened, the facts,
// what to do, then a quiet footer. One white column with dark text, so a mail app in dark mode can flip it
// cleanly; the logo and the button are pictures, which mail apps leave alone.
function alert_html(string $title, string $tone, array $rows, string $foot, ?string $link = null, string $lead = ''): string {
    $e = fn(string $v) => htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $bar = $tone === 'fail' ? '#d92d20' : '#1f6bff';
    $font = "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
    $tbl = 'role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"';
    $account = (string)($rows['Account'] ?? '');
    unset($rows['Account']);
    $pad = 'padding-left:32px;padding-right:32px;';
    if ($link !== null) {
        $icon = "<img src=\"" . $e(rtrim($link, '/') . '/icons/email-logo.png') . "\" width=\"44\" height=\"44\" alt=\"\" style=\"display:block;border:0;width:44px;height:44px;\">";
    } else {
        $icon = "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td width=\"44\" height=\"44\" align=\"center\" valign=\"middle\" bgcolor=\"#1f6bff\" "
            . "style=\"background:#1f6bff;border-radius:11px;{$font}font-size:22px;line-height:44px;font-weight:700;color:#ffffff;\">V</td></tr></table>";
    }
    $out = "<!doctype html>\r\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        . "<title>" . $e($title) . "</title></head>\r\n"
        . "<body style=\"margin:0;padding:0;background:#f3f5f9;\">\r\n"
        . "<table $tbl style=\"background:#f3f5f9;\"><tr><td align=\"center\" style=\"padding:24px 10px;\">\r\n"
        . "<table $tbl bgcolor=\"#ffffff\" style=\"max-width:520px;background:#ffffff;\">\r\n"
        // logo
        . "<tr><td style=\"padding-top:34px;$pad\"><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>"
        . "<td width=\"44\" valign=\"middle\">$icon</td>\r\n"
        . "<td valign=\"middle\" style=\"padding-left:12px;\"><div style=\"{$font}font-size:21px;line-height:24px;font-weight:800;letter-spacing:6px;color:#0a1433;\">VAULT</div>"
        . "<div style=\"{$font}font-size:9px;line-height:13px;font-weight:600;letter-spacing:2.2px;color:#6b7a90;padding-top:2px;\">PASSWORD MANAGER</div></td>"
        . "</tr></table></td></tr>\r\n"
        // headline and colour bar
        . "<tr><td style=\"{$font}font-size:29px;line-height:38px;font-weight:300;color:#0a1433;padding-top:34px;$pad\">" . $e($title) . "</td></tr>\r\n"
        . "<tr><td style=\"padding-top:20px;$pad\"><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>"
        . "<td width=\"64\" height=\"5\" bgcolor=\"$bar\" style=\"background:$bar;font-size:0;line-height:0;\">&nbsp;</td></tr></table></td></tr>\r\n";
    $text = "{$font}font-size:16px;line-height:26px;color:#27344a;";
    if ($account !== '') $out .= "<tr><td style=\"{$text}padding-top:26px;$pad\">Hi " . $e($account) . ",</td></tr>\r\n";
    if ($lead !== '') $out .= "<tr><td style=\"{$text}padding-top:16px;$pad\">" . $e($lead) . "</td></tr>\r\n";
    // the facts
    $out .= "<tr><td style=\"padding-top:20px;$pad\"><table $tbl>\r\n";
    foreach ($rows as $k => $v) {
        $out .= "<tr><td width=\"82\" valign=\"top\" style=\"{$font}font-size:13px;line-height:22px;color:#6b7a90;padding:9px 0;border-top:1px solid #e3e8ef;\">" . $e((string)$k) . "</td>"
            . "<td valign=\"top\" style=\"{$font}font-size:15px;line-height:22px;color:#0a1433;padding:9px 0;border-top:1px solid #e3e8ef;word-break:break-word;\">" . $e((string)$v) . "</td></tr>\r\n";
    }
    $out .= "</table></td></tr>\r\n"
        . "<tr><td style=\"{$text}padding-top:18px;$pad\">" . $e($foot) . "</td></tr>\r\n";
    if ($link !== null) {
        $out .= "<tr><td style=\"padding-top:22px;$pad\"><a href=\"" . $e($link) . "\" style=\"text-decoration:none;\">"
            . "<img src=\"" . $e(rtrim($link, '/') . '/icons/email-button.png') . "\" width=\"150\" height=\"44\" alt=\"Open Vault\" "
            . "style=\"display:block;border:0;{$font}font-size:15px;line-height:44px;font-weight:600;color:#1f6bff;\"></a></td></tr>\r\n"
            . "<tr><td style=\"{$font}font-size:12px;line-height:18px;color:#6b7a90;padding-top:10px;${pad}word-break:break-all;\">" . $e($link) . "</td></tr>\r\n";
    }
    $small = "{$font}font-size:12px;line-height:19px;color:#6b7a90;";
    $out .= "<tr><td style=\"padding-top:34px;$pad\"><table $tbl><tr><td height=\"2\" bgcolor=\"#e3e8ef\" style=\"background:#e3e8ef;font-size:0;line-height:0;\">&nbsp;</td></tr></table></td></tr>\r\n"
        . "<tr><td style=\"{$font}font-size:14px;line-height:22px;color:#27344a;padding-top:22px;$pad\">This is an automated message from your own Vault server. Please do not reply.</td></tr>\r\n"
        . "<tr><td style=\"{$small}padding-top:14px;$pad\">This notice holds no secrets. "
        . ($link === null ? 'It has no links.' : 'Its one link is the address shown above; check it before you sign in.') . "</td></tr>\r\n"
        . "<tr><td style=\"{$font}font-size:11px;line-height:18px;font-weight:600;letter-spacing:1.5px;color:#6b7a90;padding-top:14px;padding-bottom:34px;$pad\">STORE &nbsp;<span style=\"color:#1f6bff;\">&bull;</span>&nbsp; PROTECT &nbsp;<span style=\"color:#1f6bff;\">&bull;</span>&nbsp; ACCESS</td></tr>\r\n"
        . "</table></td></tr></table>\r\n</body></html>";
    return $out;
}

$alert = function (string $u, string $event) use ($cfg, $ip, $dh, $dataDir): void {
    $to = $cfg['alert_email'] ?? null;
    if (!is_string($to) || !filter_var($to, FILTER_VALIDATE_EMAIL) || !isset(ALERT_EVENTS[$event]) || $u === '_server') return;
    if (in_array($event, (array)($cfg['alert_skip'] ?? []), true)) return;
    // Which events are worth an email. The default, 'smart', works like a password manager: it emails only when
    // the vault is opened on a new device, when the way in changes (master password, recovery, two-factor turned
    // off, recovery key removed), and when sign-in or recovery is blocked after repeated wrong tries.
    // Everything else, such as wrong attempts, devices signed out, backup codes and PINs, is in the Access log only.
    // 'alert_level' => 'all' in config.php sends an email for every event.
    if (($cfg['alert_level'] ?? 'smart') !== 'all' && !in_array($event, ALERT_SMART, true)) return;
    // The one hard limit is 40 an hour, so a flood of attempts cannot bury the inbox or get the sending
    // address suspended. The Access log still records every event.
    if (throttle_count('mail-all', 3600) >= 40) return;
    throttle_hit('mail-all', 3600);
    $host = (string)($_SERVER['HTTP_HOST'] ?? '');
    $domain = preg_match('/^[A-Za-z0-9.-]{1,100}(:\d{1,5})?$/', $host) ? explode(':', $host)[0] : 'vault';
    $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
    // Kept short on purpose: no links, no images and no calls to change anything, which outgoing mail
    // filters read as phishing. The app's Access log has the detail.
    $title = ALERT_EVENTS[$event];
    $tz = 'UTC';
    if (is_string($cfg['alert_tz'] ?? null) && in_array($cfg['alert_tz'], timezone_identifiers_list(), true)) $tz = $cfg['alert_tz'];
    $now = new DateTime('now', new DateTimeZone($tz));
    $when = $now->format('D, j M Y, g:i A') . ' ' . ($tz === 'UTC' ? 'UTC' : $now->format('T'));
    $rows = ['Account' => $u, 'When' => $when, 'Device' => ua_label($ua), 'Address' => $ip];
    $lead = ALERT_BODY[$event] ?? '';
    $foot = in_array($event, ['login_blocked', 'recover_blocked'], true)
        ? 'If this was you, wait 15 minutes and try again. If it was not, nothing was opened: the block held. The full record is under Settings, Access log.'
        : 'If this was you, there is nothing to do. If it was not, open Settings, Devices and sign that device out. The full record is under Settings, Access log.';
    $text = $title . ".\r\n\r\n" . ($lead !== '' ? "$lead\r\n\r\n" : '');
    foreach ($rows as $k => $v) $text .= "$k: $v\r\n";
    // One optional link, to the vault itself. It comes only from config.php, never from the request, so nobody
    // can make these emails point somewhere else.
    $link = null;
    if (is_string($cfg['alert_link'] ?? null) && preg_match('~^https://[A-Za-z0-9.-]{1,100}(:\d{1,5})?(/[A-Za-z0-9._/-]{0,100})?$~', $cfg['alert_link'])) $link = $cfg['alert_link'];
    $text .= "\r\n$foot\r\n" . ($link !== null ? "\r\nOpen Vault: $link\r\n" : '');
    $html = alert_html($title, ALERT_TONES[$event] ?? 'change', $rows, $foot, $link, $lead);
    $boundary = 'vault-' . bin2hex(random_bytes(12));
    $body = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n$text\r\n"
        . "--$boundary\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n$html\r\n"
        . "--$boundary--\r\n";
    $from = is_string($cfg['alert_from'] ?? null) && filter_var($cfg['alert_from'], FILTER_VALIDATE_EMAIL) ? $cfg['alert_from'] : "vault@$domain";
    // Some hosts add their own X-PHP-Script header in front of these and run the first line into it,
    // which loses that line. A spare first header takes that hit so From always survives.
    $headers = "X-Vault-Notice: 1\r\nFrom: Vault <$from>\r\nReply-To: $from\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"$boundary\"\r\nX-Auto-Response-Suppress: All";
    // Name the sender on the envelope too. Without it the hosting account's own login is used, which
    // receiving mail servers see as a mismatch and tend to file as spam. If the host refuses that, send plainly.
    $sent = preg_match('/^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+$/', $from) && @mail($to, 'Vault notice: ' . ALERT_EVENTS[$event], $body, $headers, '-f' . $from);
    if (!$sent) @mail($to, 'Vault notice: ' . ALERT_EVENTS[$event], $body, $headers);
};

$audit = function (string $u, string $event, ?string $typed = null, bool $quiet = false) use ($dataDir, $ip, $alert): void {
    if (!$quiet) $alert($u, $event);
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

/* ---------- Devices ---------- */

const DEVICE_MAX = 20;
// Records this browser as one of the account's devices (or refreshes when it was last seen).
// $trustH: hash of the two-factor trust token this device just used, so the two can be removed together later.
$touchDevice = function (string $u, ?string $trustH = null) use ($updateUser, $dh): bool {
    if ($dh === null) return false;
    $isNew = false;
    $updateUser($u, function (array $user) use ($dh, $trustH, &$isNew) {
        $now = time();
        $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
        $devs = is_array($user['devices'] ?? null) ? $user['devices'] : [];
        $isNew = !isset($devs[$dh]);
        $devs[$dh] = ['name' => $devs[$dh]['name'] ?? null, 'ua' => $ua, 'first' => (int)($devs[$dh]['first'] ?? $now), 'last' => $now];
        // Signed-out devices are remembered for 60 days so they are refused if they come back, then forgotten.
        $devs = array_filter($devs, fn($d) => empty($d['off']) || (int)$d['off'] > $now - 60 * 86400);
        $live = array_filter($devs, fn($d) => empty($d['off']));
        if (count($live) > DEVICE_MAX) {
            uasort($live, fn($a, $b) => (int)$a['last'] <=> (int)$b['last']);
            foreach (array_slice(array_keys($live), 0, count($live) - DEVICE_MAX) as $old) unset($devs[$old]);
        }
        $user['devices'] = $devs;
        if ($trustH !== null) {
            foreach ($user['trusted'] ?? [] as $i => $t) {
                if (!isset($t['d']) && hash_equals((string)($t['h'] ?? ''), $trustH)) $user['trusted'][$i]['d'] = $dh;
            }
        }
        return $user;
    });
    return $isNew;
};
// Removes what a device could use to get back in quietly: its PIN record and its two-factor trust.
$forgetDevice = function (string $u, array $user, string $d) use ($dataDir): array {
    foreach (glob($dataDir . '/pins/*.json') ?: [] as $f) {
        $rec = read_json($f);
        if (($rec['user'] ?? null) === $u && ($rec['d'] ?? null) === $d) { @unlink($f); @unlink($f . '.lock'); }
    }
    if (isset($user['trusted'])) $user['trusted'] = array_values(array_filter($user['trusted'], fn($t) => ($t['d'] ?? null) !== $d));
    return $user;
};

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
// Backup codes: ten single-use codes for when the authenticator is not at hand. Only a keyed hash of each is stored,
// so the server file does not reveal them. Letters that are easy to confuse (i, l, o, 0, 1) are never used.
const BACKUP_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
function backup_clean(mixed $typed): ?string {
    if (!is_string($typed)) return null;
    $c = strtolower((string)preg_replace('/[\s-]/', '', $typed));
    return preg_match('/^[' . BACKUP_ALPHABET . ']{10}$/', $c) ? $c : null;
}

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
$backupHash = fn(string $code): string => hash_hmac('sha256', $code, $totpKey);
$isTrusted = function (array $user, mixed $token) use ($trustHash): bool {
    $h = $trustHash($token);
    if ($h === null) return false;
    foreach ($user['trusted'] ?? [] as $t) if (hash_equals((string)($t['h'] ?? ''), $h)) return true;
    return false;
};

/* ---------- Security keys (WebAuthn) as a second step ---------- */
// A security key, or a passkey held by a phone or laptop, can pass the second step instead of a typed code.
// The key signs a one-time challenge together with the address of the site it is talking to, so a code-stealing
// look-alike site gets nothing it can reuse. Only public keys are stored here.

const KEY_MAX = 5;
function b64u_enc(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function b64u_dec(mixed $s, int $max = 8192): ?string {
    if (!is_string($s) || $s === '' || strlen($s) > $max || !preg_match('/^[A-Za-z0-9_-]+$/', $s)) return null;
    $bin = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
    return $bin === false ? null : $bin;
}
// A challenge is random bytes, an expiry five minutes out, and a keyed checksum tying it to one account and one
// purpose. Nothing is stored until it is used, and then only a marker so that it cannot be used twice.
$keyChallenge = function (string $u, string $purpose) use ($secret): string {
    $raw = random_bytes(16) . pack('N', time() + 300);
    return b64u_enc($raw . substr(hash_hmac('sha256', "key-challenge-v1|$purpose|$u|" . $raw, $secret, true), 0, 16));
};
$keyChallengeOk = function (string $u, string $purpose, mixed $challenge) use ($secret): bool {
    $bin = b64u_dec($challenge, 64);
    if ($bin === null || strlen($bin) !== 36) return false;
    $raw = substr($bin, 0, 20);
    if (!hash_equals(substr(hash_hmac('sha256', "key-challenge-v1|$purpose|$u|" . $raw, $secret, true), 0, 16), substr($bin, 20))) return false;
    if (unpack('N', substr($raw, 16, 4))[1] < time()) return false;
    $used = 'key-challenge:' . bin2hex($bin);
    if (throttle_count($used, 600) > 0) return false;
    throttle_hit($used, 600);
    return true;
};
// What the browser says it did: which kind of request, for which challenge, on which site.
function key_client(string $json, string $type): ?array {
    $c = json_decode($json, true);
    if (!is_array($c) || ($c['type'] ?? null) !== $type || !is_string($c['challenge'] ?? null) || !is_string($c['origin'] ?? null)) return null;
    if (!empty($c['crossOrigin'])) return null;
    return ['challenge' => $c['challenge'], 'origin' => $c['origin']];
}
// The site a new key may be registered for is this one: the address the request came to, over HTTPS.
// Plain HTTP is accepted for localhost only, which is how browsers treat it too.
function key_site(string $origin): ?string {
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    if (!preg_match('~^(https?)://([a-z0-9.-]{1,100})(:\d{1,5})?$~', $origin, $m)) return null;
    if ($m[2] . ($m[3] ?? '') !== $host) return null;
    if ($m[1] !== 'https' && $m[2] !== 'localhost') return null;
    return $m[2];
}
function key_pem(string $der): string {
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}
$keyList = fn(array $user): array => array_map(
    fn($k) => ['id' => (string)$k['id'], 'name' => (string)($k['name'] ?? ''), 'at' => (int)($k['at'] ?? 0), 'last' => (int)($k['last'] ?? 0)],
    array_values($user['keys'] ?? [])
);
// Checks one signed answer from a key at sign-in. Returns the key's new use counter, or null if anything is off.
$keyVerify = function (string $u, array $rec, array $in) use ($keyChallengeOk): ?int {
    $cd = b64u_dec($in['clientData'] ?? null);
    $ad = b64u_dec($in['authData'] ?? null);
    $sig = b64u_dec($in['sig'] ?? null);
    if ($cd === null || $ad === null || $sig === null || strlen($ad) < 37) return null;
    $c = key_client($cd, 'webauthn.get');
    if ($c === null || !hash_equals((string)($rec['origin'] ?? ''), $c['origin'])) return null;
    if (!hash_equals(hash('sha256', (string)($rec['rp'] ?? ''), true), substr($ad, 0, 32))) return null;
    if ((ord($ad[32]) & 0x01) === 0) return null; // the person must have touched or confirmed the key
    $der = base64_decode((string)($rec['pk'] ?? ''), true);
    $pub = $der === false ? false : openssl_pkey_get_public(key_pem($der));
    if ($pub === false || openssl_verify($ad . hash('sha256', $cd, true), $sig, $pub, OPENSSL_ALGO_SHA256) !== 1) return null;
    // Keys that count their uses must always count upwards; going backwards means a copy exists.
    $count = unpack('N', substr($ad, 33, 4))[1];
    $before = (int)($rec['count'] ?? 0);
    if (($count !== 0 || $before !== 0) && $count <= $before) return null;
    // Last, so a failed attempt cannot use up a good challenge.
    if (!$keyChallengeOk($u, 'get', $c['challenge'])) return null;
    return $count;
};

/* ---------- Version history ---------- */

// Every save first files the copy it replaces. Kept: the 5 most recent, then older ones at least an hour apart,
// 35 in all. Each copy is the same encrypted blob the vault file held, so the server can read none of them.
const HISTORY_RECENT = 5;
const HISTORY_MAX = 35;
$historyDir = fn(string $u) => "$dataDir/history/$u";
$historyList = function (string $u) use ($historyDir): array {
    $out = [];
    foreach (glob($historyDir($u) . '/*.json') ?: [] as $f) {
        if (preg_match('~/(\d{1,12})\.json$~', $f, $m)) $out[] = ['rev' => (int)$m[1], 'at' => (int)@filemtime($f), 'size' => (int)@filesize($f), 'file' => $f];
    }
    usort($out, fn($a, $b) => $b['rev'] <=> $a['rev']);
    return $out;
};
$keepHistory = function (string $u, array $v) use ($historyDir, $historyList): void {
    $dir = $historyDir($u);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return; // history is a safety net; a save never fails because of it
    $file = $dir . '/' . (int)$v['rev'] . '.json';
    if (@file_put_contents($file, json_encode(['rev' => (int)$v['rev'], 'blob' => $v['blob'], 'updated' => (int)($v['updated'] ?? time())], JSON_UNESCAPED_SLASHES), LOCK_EX) === false) return;
    @chmod($file, 0600);
    @touch($file, (int)($v['updated'] ?? time()));
    $kept = 0;
    $lastAt = 0;
    foreach ($historyList($u) as $i => $h) {
        if ($i < HISTORY_RECENT) { $kept++; $lastAt = $h['at']; continue; }
        if ($kept < HISTORY_MAX && $lastAt - $h['at'] >= 3600) { $kept++; $lastAt = $h['at']; }
        else @unlink($h['file']);
    }
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
    $touchDevice($u);
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
    // The right master password from a device that was signed out remotely: refused, and the app on it erases its copy.
    if ($dh !== null && !empty($user['devices'][$dh]['off'])) {
        $audit($u, 'device_refused');
        out(401, ['error' => 'device_revoked']);
    }
    $newTrust = null;
    if (!empty($user['totp']) && !$isTrusted($user, $body['trust'] ?? null)) {
        // Right master password on a device that has not passed the second step: ask for the code,
        // and offer the security key check if the account has keys.
        $keyOffer = empty($user['keys']) ? [] : ['key' => ['ids' => array_column($user['keys'], 'id')]];
        $keyIn = is_array($body['key'] ?? null) ? $body['key'] : null;
        if ($keyIn === null && (!isset($body['totp']) || $body['totp'] === '')) {
            if ($keyOffer) $keyOffer['key']['challenge'] = $keyChallenge($u, 'get');
            out(401, ['error' => 'totp_required'] + $keyOffer);
        }
        $tk = "totp:$ip|$u";
        if (throttle_count($tk, 900) >= 5) fail(429, 'slow_down');
        if ($keyIn !== null) {
            $count = null;
            $kid = is_string($keyIn['id'] ?? null) ? $keyIn['id'] : '';
            foreach ($user['keys'] ?? [] as $rec) {
                if (hash_equals((string)$rec['id'], $kid)) { $count = $keyVerify($u, $rec, $keyIn); break; }
            }
            if ($count === null) {
                throttle_hit($tk, 900);
                $audit($u, 'key_fail');
                $audit('_server', 'key_fail', $u);
                if ($keyOffer) $keyOffer['key']['challenge'] = $keyChallenge($u, 'get');
                out(401, ['error' => 'bad_key'] + $keyOffer);
            }
            throttle_clear($tk);
            $newTrust = base64_encode(random_bytes(32));
            $updateUser($u, function (array $fresh) use ($kid, $count, $newTrust, $trustHash, $dh) {
                foreach ($fresh['keys'] ?? [] as $i => $k) {
                    if ($k['id'] === $kid) { $fresh['keys'][$i]['count'] = $count; $fresh['keys'][$i]['last'] = time(); }
                }
                $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
                $entry = ['h' => $trustHash($newTrust), 'at' => time(), 'ua' => $ua];
                if ($dh !== null) $entry['d'] = $dh;
                $fresh['trusted'] = array_slice(array_merge($fresh['trusted'] ?? [], [$entry]), -10);
                return $fresh;
            });
            $audit($u, 'key_used');
        } else {
        $key = $totpOpen($user['totp']['secret'] ?? null) ?? fail(500, 'totp_unreadable');
        $newTrust = base64_encode(random_bytes(32));
        $step = null;
        $usedBackup = false;
        $backupLeft = null;
        $updateUser($u, function (array $fresh) use ($key, $body, &$step, &$usedBackup, &$backupLeft, $newTrust, $trustHash, $dh, $backupHash) {
            $step = totp_match($key, $body['totp'], (int)($fresh['totp']['last'] ?? 0));
            if ($step === null && ($clean = backup_clean($body['totp'])) !== null) {
                // Not a 6-digit code: try it as a backup code. A match is removed, so each works once.
                $want = $backupHash($clean);
                foreach ($fresh['totp']['backup'] ?? [] as $i => $h) {
                    if (hash_equals((string)$h, $want)) {
                        array_splice($fresh['totp']['backup'], $i, 1);
                        $usedBackup = true;
                        $backupLeft = count($fresh['totp']['backup']);
                        $step = (int)($fresh['totp']['last'] ?? 0);
                        break;
                    }
                }
            }
            if ($step === null) return $fresh;
            $fresh['totp']['last'] = $step;
            $ua = substr((string)preg_replace('/[^\x20-\x7E]/', '', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 200);
            $entry = ['h' => $trustHash($newTrust), 'at' => time(), 'ua' => $ua];
            if ($dh !== null) $entry['d'] = $dh;
            $fresh['trusted'] = array_slice(array_merge($fresh['trusted'] ?? [], [$entry]), -10);
            return $fresh;
        });
        if ($step === null) {
            throttle_hit($tk, 900);
            $audit($u, 'totp_fail');
            $audit('_server', 'totp_fail', $u);
            out(401, ['error' => 'bad_totp']);
        }
        throttle_clear($tk);
        $audit($u, $usedBackup ? 'backup_used' : 'device_trusted');
        }
    }
    sign_in($u, (int)($user['gen'] ?? 0));
    $isNew = $touchDevice($u, $trustHash($body['trust'] ?? null));
    if ($isNew) $audit($u, 'device_new');
    // 'auto' marks the app renewing its own session after a Face ID or PIN unlock, with no password typed.
    // It only changes the wording in the log. The same key and the same checks are required either way.
    // A new device already sent its own notice just above, so the sign-in itself stays quiet that once.
    $audit($u, ($body['auto'] ?? false) === true ? 'login_renew' : 'login_ok', null, $isNew);
    $v = read_json($vaultFile($u));
    $res = ['rev' => (int)($v['rev'] ?? 0), 'wrap' => $user['wrap'] ?? null, 'recovery' => !empty($user['rec']), 'totp' => !empty($user['totp'])];
    if ($newTrust !== null) $res['trust'] = $newTrust;
    if (($backupLeft ?? null) !== null) $res['backupLeft'] = $backupLeft;
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

case 'POST totp_backup': {
    // Make ten new backup codes. Any earlier ones stop working. Shown once; only their hashes are kept.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    if (empty($user['totp'])) fail(400, 'totp_off');
    $codes = [];
    $n = strlen(BACKUP_ALPHABET);
    for ($i = 0; $i < 10; $i++) {
        $c = '';
        for ($j = 0; $j < 10; $j++) $c .= BACKUP_ALPHABET[random_int(0, $n - 1)];
        $codes[] = $c;
    }
    $hashes = array_map($backupHash, $codes);
    $ok = false;
    $updateUser($u, function (array $fresh) use ($hashes, &$ok) {
        if (empty($fresh['totp'])) return $fresh;
        $fresh['totp']['backup'] = $hashes;
        $ok = true;
        return $fresh;
    });
    if (!$ok) fail(400, 'totp_off');
    $audit($u, 'backup_new');
    out(200, ['codes' => array_map(fn($c) => substr($c, 0, 5) . '-' . substr($c, 5), $codes)]);
}

case 'POST totp_disable': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $updateUser($u, function (array $fresh) { unset($fresh['totp'], $fresh['trusted'], $fresh['keys']); return $fresh; });
    $audit($u, 'totp_off');
    out(200, ['totp' => false]);
}

case 'POST key_begin': {
    // First half of adding a security key: prove the master password, get a one-time challenge for the key to sign.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    if (empty($user['totp'])) fail(400, 'key_needs_totp');
    if (count($user['keys'] ?? []) >= KEY_MAX) fail(400, 'key_limit');
    out(200, [
        'challenge' => $keyChallenge($u, 'create'),
        'user' => b64u_enc(substr(hash_hmac('sha256', "key-user-v1|$u", $secret, true), 0, 16)),
        'ids' => array_column($user['keys'] ?? [], 'id'),
    ]);
}

case 'POST key_add': {
    // Second half: the browser hands over what the key produced. The challenge proves the master password
    // was given a moment ago in key_begin, so it is not asked for twice.
    $u = require_user();
    $name = is_string($body['name'] ?? null) ? trim((string)preg_replace('/[\x00-\x1F\x7F<>]|\xC2[\x80-\x9F]/', '', $body['name'])) : '';
    if ($name === '' || !mb_check_encoding($name, 'UTF-8') || mb_strlen($name, 'UTF-8') > 40) fail(400, 'bad_key_name');
    $id = b64u_dec($body['id'] ?? null, 1400);
    $cd = b64u_dec($body['clientData'] ?? null);
    $ad = b64u_dec($body['authData'] ?? null);
    $der = b64u_dec($body['pk'] ?? null, 2048);
    $alg = $body['alg'] ?? null;
    if ($id === null || $cd === null || $ad === null || $der === null || !in_array($alg, [-7, -257], true)) fail(400, 'bad_key');
    $c = key_client($cd, 'webauthn.create') ?? fail(400, 'bad_key');
    $rp = key_site($c['origin']) ?? fail(400, 'bad_key');
    // The key's own record: made for this site, with a person present, and carrying the same id the browser reported.
    if (strlen($ad) < 55 || !hash_equals(hash('sha256', $rp, true), substr($ad, 0, 32))) fail(400, 'bad_key');
    $flags = ord($ad[32]);
    if (($flags & 0x01) === 0 || ($flags & 0x40) === 0) fail(400, 'bad_key');
    $idLen = unpack('n', substr($ad, 53, 2))[1];
    if ($idLen < 1 || !hash_equals(substr($ad, 55, $idLen), $id)) fail(400, 'bad_key');
    // The public key must be the kind that was asked for, and must be the one inside the key's own record.
    $pub = openssl_pkey_get_public(key_pem($der));
    $d = $pub === false ? false : openssl_pkey_get_details($pub);
    if ($d === false) fail(400, 'bad_key');
    $rest = substr($ad, 55 + $idLen);
    if ($alg === -7) {
        if (($d['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($d['ec']['curve_name'] ?? '') !== 'prime256v1') fail(400, 'bad_key');
        $parts = [str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT), str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT)];
    } else {
        if (($d['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || (int)($d['bits'] ?? 0) < 2048) fail(400, 'bad_key');
        $parts = [ltrim($d['rsa']['n'], "\0")];
    }
    foreach ($parts as $part) if (!str_contains($rest, $part)) fail(400, 'bad_key');
    if (!$keyChallengeOk($u, 'create', $c['challenge'])) fail(400, 'key_expired');
    $kid = b64u_enc($id);
    $state = 'ok';
    $user = $updateUser($u, function (array $fresh) use ($kid, $der, $alg, $ad, $name, $rp, $c, &$state) {
        if (empty($fresh['totp'])) { $state = 'key_needs_totp'; return $fresh; }
        if (count($fresh['keys'] ?? []) >= KEY_MAX) { $state = 'key_limit'; return $fresh; }
        foreach ($fresh['keys'] ?? [] as $k) if ($k['id'] === $kid) { $state = 'key_exists'; return $fresh; }
        $fresh['keys'][] = [
            'id' => $kid, 'pk' => base64_encode($der), 'alg' => $alg, 'count' => unpack('N', substr($ad, 33, 4))[1],
            'name' => $name, 'at' => time(), 'last' => 0, 'rp' => $rp, 'origin' => $c['origin'],
        ];
        return $fresh;
    });
    if ($state !== 'ok') fail(400, $state);
    $audit($u, 'key_add');
    out(200, ['keys' => $keyList($user)]);
}

case 'POST key_remove': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    if (!$verify('login', $u, $body['auth'] ?? null, $user['auth_hash'] ?? null)) fail(401, 'bad_credentials');
    $kid = is_string($body['id'] ?? null) ? $body['id'] : '';
    $found = false;
    $user = $updateUser($u, function (array $fresh) use ($kid, &$found) {
        $keep = array_values(array_filter($fresh['keys'] ?? [], fn($k) => $k['id'] !== $kid));
        $found = count($keep) !== count($fresh['keys'] ?? []);
        if ($keep) $fresh['keys'] = $keep; else unset($fresh['keys']);
        return $fresh;
    });
    if (!$found) fail(404, 'no_key');
    $audit($u, 'key_remove');
    out(200, ['keys' => $keyList($user)]);
}

case 'POST logout': {
    $who = current_user();
    if ($who !== null) {
        $audit($who, 'logout');
        // Signing out removes this device from the account's list, with its PIN record and two-factor trust.
        $d = $_SESSION['d'] ?? null;
        if (is_string($d)) $updateUser($who, function (array $user) use ($who, $d, $forgetDevice) { unset($user['devices'][$d]); return $forgetDevice($who, $user, $d); });
    }
    $_SESSION = [];
    session_destroy();
    out(200, ['ok' => true]);
}

case 'GET account': {
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    out(200, ['wrap' => $user['wrap'] ?? null, 'recovery' => !empty($user['rec']), 'totp' => !empty($user['totp']), 'backup' => count($user['totp']['backup'] ?? []), 'keys' => $keyList($user)]);
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
    $touchDevice($u);
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
    // Two-factor sign-in stays on unless the person says the authenticator is lost too.
    // The recovery key is still the way back in after losing it, so asking is enough.
    $dropTotp = !empty($body['dropTotp']);
    $hadTotp = false;
    $user = $updateUser($u, function (array $user) use ($body, $kdf, $dropTotp, $trustHash, &$hadTotp) {
        $user['salt'] = $body['salt'];
        $user['kdf'] = $kdf;
        $user['auth_hash'] = password_hash($body['newAuth'], PASSWORD_DEFAULT);
        $user['wrap'] = $body['wrap'];
        $user['gen'] = (int)($user['gen'] ?? 0) + 1;
        $hadTotp = !empty($user['totp']);
        if ($dropTotp || !$hadTotp) {
            unset($user['totp'], $user['trusted'], $user['keys']);
        } else {
            // As with a password change, only the device doing the recovery stays trusted.
            $mine = $trustHash($body['trust'] ?? null);
            $user['trusted'] = array_values(array_filter($user['trusted'] ?? [], fn($t) => $mine !== null && hash_equals((string)($t['h'] ?? ''), $mine)));
        }
        return $user;
    });
    $clearPins($u);
    // Recovery also clears any remote sign-out, since the recovery key proves ownership.
    if ($dh !== null) $updateUser($u, function (array $fresh) use ($dh) { unset($fresh['devices'][$dh]['off']); return $fresh; });
    sign_in($u, $user['gen']);
    $touchDevice($u);
    $audit($u, 'recover_ok');
    if ($hadTotp && $dropTotp) $audit($u, 'totp_off');
    $v = read_json($vaultFile($u));
    out(200, ['rev' => (int)($v['rev'] ?? 0), 'totp' => !empty($user['totp'])]);
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
        'fails' => 0, 'created' => time(), 'd' => $dh,
    ]);
    $audit($u, 'pin_set');
    out(200, ['ok' => true]);
}

case 'POST pin_unlock': {
    // No session needed: the device id is a 128-bit random value known only to that device.
    $file = $pinFile($body['deviceId'] ?? null);
    if (throttle_count("pin-ip:$ip", 900) >= 30) fail(429, 'slow_down');
    with_lock($file . '.lock', function () use ($file, $body, $ip, $audit, $dh) {
        $rec = read_json($file);
        if (!$rec) { @unlink($file . '.lock'); fail(404, 'pin_gone'); }
        $ok = b64_len($body['pinAuth'] ?? null) === 32 && password_verify((string)$body['pinAuth'], (string)$rec['hash']);
        if ($ok) {
            $bind = $dh !== null && empty($rec['d']); // PINs set before devices were tracked get tied to their device here
            if ($bind) $rec['d'] = $dh;
            if ((int)$rec['fails'] !== 0 || $bind) { $rec['fails'] = 0; write_json($file, $rec); }
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

case 'GET devices': {
    // Where the account is signed in. Nothing here is secret: a name, the browser, and two times.
    $u = require_user();
    $user = read_json($userFile($u)) ?? fail(404, 'no_account');
    $withPin = [];
    foreach (glob($dataDir . '/pins/*.json') ?: [] as $f) {
        $rec = read_json($f);
        if (($rec['user'] ?? null) === $u && !empty($rec['d'])) $withPin[$rec['d']] = true;
    }
    $list = [];
    foreach ($user['devices'] ?? [] as $id => $d) {
        if (!empty($d['off'])) continue;
        $list[] = [
            'id' => (string)$id, 'name' => $d['name'] ?? null, 'ua' => (string)($d['ua'] ?? ''), 'first' => (int)($d['first'] ?? 0),
            'last' => (int)($d['last'] ?? 0), 'current' => $id === ($_SESSION['d'] ?? null), 'pin' => isset($withPin[$id]),
        ];
    }
    usort($list, fn($a, $b) => [$b['current'], $b['last']] <=> [$a['current'], $a['last']]);
    out(200, ['devices' => $list]);
}

case 'POST device_name': {
    $u = require_user();
    $id = $body['id'] ?? null;
    $name = is_string($body['name'] ?? null) ? trim((string)preg_replace('/[\x00-\x1F\x7F<>]|\xC2[\x80-\x9F]/', '', $body['name'])) : '';
    if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/', $id)) fail(400, 'bad_device');
    if ($name === '' || !mb_check_encoding($name, 'UTF-8') || mb_strlen($name, 'UTF-8') > 40) fail(400, 'bad_device_name');
    $found = false;
    $updateUser($u, function (array $user) use ($id, $name, &$found) {
        if (isset($user['devices'][$id]) && empty($user['devices'][$id]['off'])) { $user['devices'][$id]['name'] = $name; $found = true; }
        return $user;
    });
    if (!$found) fail(404, 'no_device');
    out(200, ['ok' => true, 'name' => $name]);
}

case 'POST device_off': {
    // Sign another device out. Its session ends at once, its PIN and two-factor trust are removed,
    // and the next time it connects it is refused and erases its own copy of the vault.
    $u = require_user();
    $id = $body['id'] ?? null;
    if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/', $id)) fail(400, 'bad_device');
    if ($id === ($_SESSION['d'] ?? null)) fail(400, 'is_this_device');
    $found = false;
    $updateUser($u, function (array $user) use ($u, $id, &$found, $forgetDevice) {
        if (!isset($user['devices'][$id]) || !empty($user['devices'][$id]['off'])) return $user;
        $found = true;
        $user['devices'][$id]['off'] = time();
        return $forgetDevice($u, $user, $id);
    });
    if (!$found) fail(404, 'no_device');
    $audit($u, 'device_off');
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
    if (!in_array($e, ['bio_ok', 'bio_on', 'bio_off', 'rollback_seen', 'history_restore'], true)) fail(400, 'bad_event');
    $audit($u, $e);
    out(200, ['ok' => true]);
}

case 'GET history': {
    $u = require_user();
    out(200, ['versions' => array_map(fn($h) => ['rev' => $h['rev'], 'at' => $h['at'], 'size' => $h['size']], $historyList($u))]);
}

case 'GET history_get': {
    $u = require_user();
    $rev = (string)($_GET['rev'] ?? '');
    if (!preg_match('/^\d{1,12}$/', $rev)) fail(400, 'bad_rev');
    $h = read_json($historyDir($u) . '/' . (int)$rev . '.json') ?? fail(404, 'no_version');
    out(200, ['rev' => (int)$h['rev'], 'blob' => $h['blob'], 'at' => (int)($h['updated'] ?? 0)]);
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
    with_lock($file . '.lock', function () use ($file, $body, $audit, $u, $keepHistory) {
        $v = read_json($file) ?? ['rev' => 0, 'blob' => null];
        // Another device saved first: hand back the newer copy so the client can merge and retry.
        if ((int)$v['rev'] !== $body['baseRev']) out(409, ['error' => 'conflict', 'rev' => (int)$v['rev'], 'blob' => $v['blob']]);
        if ($v['blob'] !== null) {
            @copy($file, $file . '.prev'); // keep one previous version
            $keepHistory($u, $v);
        }
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
