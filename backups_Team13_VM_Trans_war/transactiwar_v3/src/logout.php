<?php
/**
 * logout.php — Hardened Logout
 *
 * Fixes vs original:
 *  [A] startSecureSession() removed from config.php — replaced with correct
 *      inline restart + session_regenerate_id(true) for flash-message session
 *  [B] session_token cleared in DB on logout so requireLogin() immediately
 *      rejects any request using the old session cookie
 *
 * Preserved:
 *  [C] POST-only with CSRF token — prevents CSRF logout
 *  [D] GET shows confirmation form — no silent logout via link/image tag
 *  [E] Full cookie deletion — expires cookie in browser
 *  [F] logActivity() — audit trail
 *  [G] Redirect to login with flash message
 */

require_once 'session_init.php';

// [D] GET — show confirmation form so logout cannot be triggered by GET-based CSRF
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $pageTitle = 'Logout';
    include 'header.php';
    echo '<div class="auth-card card">';
    echo '<div class="card-title">Confirm Logout</div>';
    echo '<p style="color:#aaa;margin-bottom:1.5rem;">Are you sure you want to log out?</p>';
    echo '<form method="POST" action="/logout.php">';
    echo '<input type="hidden" name="csrf_token" value="' . h(generateCSRFToken()) . '">';
    echo '<button type="submit" class="btn btn-primary" style="width:100%;">Yes, Log Me Out</button>';
    echo '</form>';
    echo '<p style="margin-top:1rem;text-align:center;"><a href="/dashboard.php">Cancel</a></p>';
    echo '</div>';
    include 'footer.php';
    exit;
}

// [C] Validate CSRF before touching the session
if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
    redirect('/dashboard.php', 'Invalid logout request.', 'error');
}

// Capture identity before destroying session [F]
$userId   = (int)($_SESSION['user_id'] ?? 0);
$username = $_SESSION['username']      ?? 'guest';

logActivity('logout.php', $username); // [F]

// [B] Clear session_token in DB — requireLogin() now verifies this column.
//     Without this, a stolen session cookie could still pass the DB token
//     check until the next login overwrites it.
if ($userId > 0) {
    try {
        getDB()->prepare(
            "UPDATE users SET session_token = NULL WHERE id = ?"
        )->execute([$userId]);
    } catch (Exception $e) {
        error_log('logout.php: could not clear session_token in DB: ' . $e->getMessage());
    }
}

// [E] Wipe server-side session data
$_SESSION = [];

// [E] Expire session cookie in the browser immediately
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(), '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

session_destroy();

// [A] Restart minimal session for flash message only.
//     Re-apply all security settings, then immediately regenerate the ID
//     so the destroyed session's ID cannot be reused by anyone holding the
//     old cookie value.
// FIX: Use shared isHttps() from config.php (already loaded via session_init.php)
//      to correctly handle reverse-proxy deployments — the previous inline check
//      missed X-Forwarded-Proto from trusted private-IP proxies.
$isSecure = isHttps();
ini_set('session.cookie_httponly',        1);
ini_set('session.use_strict_mode',        1);
ini_set('session.cookie_samesite',        'Strict');
ini_set('session.use_only_cookies',       1);
ini_set('session.use_trans_sid',          0);
ini_set('session.gc_maxlifetime',         1800);
ini_set('session.cookie_lifetime',        0);
ini_set('session.cookie_secure',          $isSecure ? 1 : 0);
ini_set('session.sid_length',             64);
ini_set('session.sid_bits_per_character', 6);
session_name('TWSESS');
session_start();
session_regenerate_id(true); // [A] Fresh ID — old cookie is now dead

$_SESSION['session_start'] = time();
$_SESSION['last_active']   = time();

redirect('/login.php', 'You have been logged out.', 'info'); // [G]
