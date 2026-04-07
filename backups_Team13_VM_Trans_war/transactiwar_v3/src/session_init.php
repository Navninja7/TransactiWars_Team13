<?php
/**
 * session_init.php — Hardened Session Initialisation
 *
 * Included at the top of every page via require_once.
 * Configures the session, enforces timeouts, loads config.php,
 * sends security headers, and enforces POST content-type.
 *
 * ── Vulnerabilities fixed ────────────────────────────────────────────────────
 *
 *  [A] Session fixation after timeout restart
 *      After session_destroy() + session_start(), PHP may reuse the same
 *      session ID from the client's cookie. An attacker who captured the
 *      cookie before expiry could continue using it after the timeout reset.
 *      Fix: session_regenerate_id(true) is called immediately after every
 *      session_start() that follows a destroy. The full ini_set hardening
 *      block is re-applied before each restart so the new cookie is issued
 *      with identical security flags — previously the restart session_start()
 *      calls ran without those settings.
 *
 *  [B] Session cookie Secure flag absent over HTTP — hard block in production
 *      Previous behaviour: log a warning and continue, issuing the session
 *      cookie without the Secure flag. An intercepted cookie on any network
 *      path grants full authenticated access.
 *      Fix: the app now refuses to start an authenticated session over plain
 *      HTTP unless APP_ENV=development is explicitly set. In development mode
 *      it still warns loudly; in all other environments it returns 500 and
 *      exits rather than issue an insecure cookie.
 *
 *  [C] HTTPS detection did not account for reverse-proxy deployments
 *      Checking only $_SERVER['HTTPS'] misses the common case where a TLS-
 *      terminating proxy (nginx, Caddy, AWS ALB) forwards traffic over HTTP
 *      internally and sets X-Forwarded-Proto: https. In that configuration
 *      $isSecure was always false, blocking the app unnecessarily.
 *      Fix: X-Forwarded-Proto is trusted when the connection arrives from
 *      a loopback or RFC-1918 address (the only addresses a trusted internal
 *      proxy can originate from). Connections from public IPs ignore the
 *      header to prevent spoofing.
 *
 *  [D] ini_set hardening not re-applied before post-destroy session_start()
 *      The timeout restart paths called session_name() + session_start()
 *      without re-running the ini_set block, so the restarted session could
 *      be started with whatever PHP defaults were in effect (e.g. cookie_secure
 *      defaulting to 0 if not set globally in php.ini).
 *      Fix: hardening settings are extracted into a helper and called before
 *      every session_start().
 *
 *  ── Properties preserved ────────────────────────────────────────────────────
 *  [E] use_trans_sid = 0, use_only_cookies = 1  — session ID never in URL
 *  [F] cookie_httponly = 1                       — JS cannot read the cookie
 *  [G] cookie_samesite = Strict                  — CSRF via cross-site form
 *  [H] gc_maxlifetime = 1800                     — server-side GC window
 *  [I] cookie_lifetime = 0                       — session cookie, not persistent
 *  [J] sid_length = 64, sid_bits_per_character=6 — 384-bit session ID entropy
 *  [K] session_name('TWSESS')                    — hides PHPSESSID fingerprint
 *  [L] session_status() guard                    — no double session_start()
 *  [M] 30-min idle + 8-hour absolute timeouts
 *  [N] sendSecurityHeaders() on every request
 *  [O] Content-Type enforcement on POST          — rejects JSON body injection
 */

// ── HTTPS detection ───────────────────────────────────────────────────────────
// [C] Trust X-Forwarded-Proto only from loopback / RFC-1918 addresses
//     (i.e. a trusted internal reverse proxy). Public-IP connections are
//     never allowed to set this header.
(static function (): void {})(); // isolate scope — keep $isSecure available below

$_twRemoteIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

$_twIsPrivateIp = (static function (string $ip): bool {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    // Loopback (127.x, ::1) and RFC-1918 ranges are trusted proxy origins.
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
})($_twRemoteIp);

$isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || ($_twIsPrivateIp
        && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && strtolower(trim($_SERVER['HTTP_X_FORWARDED_PROTO'])) === 'https');

unset($_twRemoteIp, $_twIsPrivateIp);

// ── [B] Enforce HTTPS — refuse to run over plain HTTP in non-dev environments ─
$_twAppEnv = strtolower(trim(getenv('APP_ENV') ?: 'production'));

if (!$isSecure) {
    if ($_twAppEnv === 'development') {
        // Development only: warn but allow. Never acceptable in production.
        error_log(
            'session_init.php: WARNING — HTTPS not detected. ' .
            'Session cookie Secure flag is OFF. ' .
            'This is only permitted when APP_ENV=development. ' .
            'Deploy behind a TLS reverse proxy for production use.'
        );
    } else {
        // Production / staging: refuse to serve authenticated pages over HTTP.
        // An attacker intercepting traffic must not be handed a valid session cookie.
        http_response_code(500);
        error_log(
            'session_init.php: FATAL — HTTPS not detected in non-development environment. ' .
            'Refusing to start session without Secure cookie flag. ' .
            'Set APP_ENV=development to override (development only).'
        );
        exit('Secure connection required. Please contact the administrator.');
    }
}

unset($_twAppEnv);

// ── Session hardening helper ──────────────────────────────────────────────────
// [D] Extracted so the identical ini_set block runs before EVERY session_start(),
//     including the restart calls after timeout expiry. Previously the restart
//     paths skipped these settings entirely.
$_twApplySessionHardening = static function () use ($isSecure): void {
    ini_set('session.cookie_httponly',        1);      // [F] JS cannot read cookie
    ini_set('session.use_strict_mode',        1);      // Reject unrecognised IDs
    ini_set('session.cookie_samesite',        'Strict'); // [G] CSRF protection
    ini_set('session.use_only_cookies',       1);      // [E] No URL-based session IDs
    ini_set('session.use_trans_sid',          0);      // [E] Never embed ID in URLs
    ini_set('session.gc_maxlifetime',         1800);   // [H] 30-min server GC
    ini_set('session.cookie_lifetime',        0);      // [I] Session cookie only
    ini_set('session.cookie_secure',          $isSecure ? 1 : 0); // [B]
    ini_set('session.sid_length',             64);     // [J] High-entropy ID
    ini_set('session.sid_bits_per_character', 6);      // [J] 384-bit entropy total
    session_name('TWSESS');                            // [K] Hide PHPSESSID fingerprint
};

if (session_status() === PHP_SESSION_NONE) { // [L]

    $_twApplySessionHardening(); // [D] Apply before the first session_start()
    session_start();

    // ── Absolute session timeout: 8 hours ────────────────────────────────────
    // [M] If the session is older than 8 hours, destroy it and start fresh.
    // [A] Re-apply hardening + session_regenerate_id(true) after restart so the
    //     restarted session has all security flags and a brand-new ID.
    if (isset($_SESSION['session_start']) &&
        (time() - (int)$_SESSION['session_start']) > 28800) {

        session_unset();
        session_destroy();
        $_twApplySessionHardening(); // [D] Re-apply before restart session_start()
        session_start();
        session_regenerate_id(true); // [A] Issue brand-new session ID
        $_SESSION['session_start'] = time();
        $_SESSION['last_active']   = time();
    }

    // Initialise session_start timestamp for brand-new sessions.
    if (empty($_SESSION['session_start'])) {
        $_SESSION['session_start'] = time();
    }

    // ── Idle timeout: 30 minutes ──────────────────────────────────────────────
    // [M] If the session has been idle for more than 30 minutes, destroy it
    //     and start fresh.
    // [A] Same re-apply + session_regenerate_id(true) treatment as above.
    if (isset($_SESSION['last_active']) &&
        (time() - (int)$_SESSION['last_active']) > 1800) {

        session_unset();
        session_destroy();
        $_twApplySessionHardening(); // [D] Re-apply before restart session_start()
        session_start();
        session_regenerate_id(true); // [A] Issue brand-new session ID
        $_SESSION['session_start'] = time();
        $_SESSION['last_active']   = time();
    }

    // Refresh last-active timestamp on every request. [M]
    $_SESSION['last_active'] = time();
        // ── Session Hijacking Protection ─────────────────────────────────────────
    $currentIP     = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $currentUA     = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $currentUAHash = hash('sha256', $currentUA);

    if (!empty($_SESSION['user_id'])) {
        if (empty($_SESSION['bound_ip'])) {
            $_SESSION['bound_ip']      = $currentIP;
            $_SESSION['bound_ua_hash'] = $currentUAHash;
        } else {
            $ipMismatch = ($_SESSION['bound_ip'] !== $currentIP);
            $uaMismatch = ($_SESSION['bound_ua_hash'] !== $currentUAHash);

            if ($ipMismatch || $uaMismatch) {
                session_unset();
                session_destroy();
                $_twApplySessionHardening();
                session_start();
                session_regenerate_id(true);
                header('Location: /login.php?reason=security');
                exit;
            }
        }
    }

}

unset($_twApplySessionHardening);

// ── Load application config and send security headers ────────────────────────
// [N] config.php must be loaded before sendSecurityHeaders() because the
//     function is defined there. Headers must be sent before any output.
require_once __DIR__ . '/config.php';
sendSecurityHeaders(); // [N]

// ── POST Content-Type enforcement ─────────────────────────────────────────────
// [O] Only allow standard HTML form encodings on POST requests.
//     Rejects raw JSON body injections and automated tool attacks that send
//     non-standard content types to bypass input handling.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ct = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    if (!in_array($ct, ['application/x-www-form-urlencoded', 'multipart/form-data'], true)) {
        http_response_code(415);
        exit('Unsupported Media Type');
    }
}
