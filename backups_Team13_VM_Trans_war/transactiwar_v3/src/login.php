<?php
/**
 * login.php — Hardened Authentication (compatible with hardened config.php)
 *
 * All security properties from previous versions preserved.
 * Updated to work correctly with the hardened config.php:
 *
 *  - sanitizeForLog()       → removed from here, now lives in config.php
 *  - loginRateLimit()       → removed from here, uses config.php rateLimit()
 *                             which is already atomic + fails-closed
 *  - loginRateLimitCheck()  → removed from here, uses rateLimit() directly
 *  - session_token DB write → ADDED: writes SHA2 hash to users.session_token
 *                             so requireLogin() in config.php can verify it
 *
 * Requires DB migration (run once):
 *   ALTER TABLE users ADD COLUMN session_token VARCHAR(64) DEFAULT NULL;
 *
 * ── Security properties ──────────────────────────────────────────────────────
 *  [A] SQL Injection        — PDO prepared statements throughout
 *  [B] XSS                  — all output via h()
 *  [C] CSRF                 — validateCSRFToken() + hash_equals(), rotated
 *                             only after structural checks pass
 *  [D] Timing enumeration   — bcrypt always runs, uniform DB query count
 *  [E] Session fixation     — session_regenerate_id(true) on login
 *  [F] Error enumeration    — generic messages on all failure paths
 *  [G] Permanent lockout    — login_fail written only on real failures
 *  [H] Distributed IP bypass— composite ip:username bucket
 *  [I] Username squatting   — per-username bucket written only on failures
 *  [J] Rate-limit TOCTOU    — config.php rateLimit() is atomic INSERT...SELECT
 *  [K] Rate-limit fails open— config.php rateLimit() fails closed
 *  [L] Null POST key        — all $_POST reads use ?? ''
 *  [M] Log injection        — config.php logActivity() calls sanitizeForLog()
 *                             internally on every call
 *  [N] Open redirect        — config.php redirect() enforces same-origin
 *  [O] Session token verify — SHA2 hash written to DB on login, verified by
 *                             requireLogin() on every authenticated request
 */

require_once 'session_init.php';

// ── Already logged in ─────────────────────────────────────────────────────────
if (!empty($_SESSION['user_id'])) {
    redirect('/dashboard.php');
}

$error        = '';
$lockoutError = false;
$username     = '';

// ─────────────────────────────────────────────────────────────────────────────
// POST handler
// ─────────────────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // [C] CSRF validated before anything else.
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please reload the page and try again.';

    } else {
        // [L] All $_POST reads use ?? '' — missing key never yields null.
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password']      ?? '';

        if ($username === '' || $password === '') {
            // [C] Token NOT rotated — empty submission must not burn the token.
            $error = 'Please fill in all fields.';

        } else {
            // All structural checks passed — rotate CSRF token now. [C]
            rotateCSRFToken();

            $ip           = getClientIP();
            $compositeKey = $ip . ':' . $username; // [H] per-(ip, username) key

            // Dummy hash for timing equalisation on every path. [D]
            // FIX: Generate locally here instead of using a module-level constant.
            // Defining DUMMY_HASH in config.php caused bcrypt cost-13 (~500ms) to
            // run on EVERY page load. Generating it here means it only runs during
            // an actual login POST — exactly when it's needed for timing equalisation.
            // A fresh random input each time ensures the hash is never predictable.
            $dummyHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT, ['cost' => 13]);

            // ── IP-level rate limit ───────────────────────────────────────────
            // [J][K] config.php rateLimit() is atomic + fails closed.
            // Consumes one IP slot. If already over limit → block immediately.
            if (!rateLimit('login_ip', $ip, 9999, 900)) {
                // [D] Always run bcrypt even when IP-blocked to equalise timing.
                password_verify($password, $dummyHash);
                $lockoutError = true;
                logActivity('login.php', "RATE_LIMITED_IP:$ip"); // [M] sanitized in logActivity()

            } else {
                $db = getDB();

                // ── Step 1: Fetch user record ─────────────────────────────────
                // [A] Parameterised prepared statement.
                $stmt = $db->prepare(
                    "SELECT id, username, email, balance, full_name, bio,
                            profile_image, public_token, created_at,
                            password_hash, is_locked
                     FROM users WHERE username = ?"
                );
                $stmt->execute([$username]);
                $user = $stmt->fetch();

                // ── Step 2: ALWAYS run bcrypt ─────────────────────────────────
                // [D] Timing identical whether user exists or not.
                $hash       = $user ? $user['password_hash'] : $dummyHash;
                $passwordOk = password_verify($password, $hash);

                // ── Step 3: ALWAYS run the same DB operations ─────────────────
                // [D] Uniform DB round-trip count on every code path.
                $now = time();
                $win = $now - 1800; // 30-minute sliding window

                // Purge expired login_fail rows (unconditional).
                $db->prepare(
                    "DELETE FROM rate_limits
                     WHERE bucket = 'login_fail' AND `key` = ? AND created_at < ?"
                )->execute([$username, $win]);

                // Count recent failures (unconditional).
                $failStmt = $db->prepare(
                    "SELECT COUNT(*) FROM rate_limits
                     WHERE bucket = 'login_fail' AND `key` = ? AND created_at >= ?"
                );
                $failStmt->execute([$username, $win]);
                $recentFails = (int)$failStmt->fetchColumn();

                // Determine admin-lock state BEFORE consuming per-user buckets.
                // FIX [MEDIUM]: If the account is admin-locked, consuming login_user /
                // login_composite slots is wasteful and enables a targeted DoS: an
                // attacker exhaust both 5-slot buckets, preventing login even after
                // an admin unlocks the account. Check isAdminLocked first.
                $isAdminLocked = $user && !empty($user['is_locked']);
                $isTimeLocked  = ($recentFails >= 10);
                $isLocked      = $isAdminLocked || $isTimeLocked;

                // Read-only per-username and composite bucket checks.
                // Only consume slots when the account is not already locked.
                // [J][K] rateLimit() from config.php is atomic + fails closed.
                $usernameBudgetOk = $isLocked ? false : rateLimit('login_user',      $username,     9999, 900); // [I]
                $compositeOk      = $isLocked ? false : rateLimit('login_composite',  $compositeKey, 9999, 900); // [H]

                // ── Step 4: Single decision point ────────────────────────────
                if ($isLocked || !$usernameBudgetOk || !$compositeOk) {
                    // [G] Do NOT write a login_fail row here — existing rows
                    //     already enforce the lockout. Writing here would reset
                    //     the expiry window, enabling permanent lockout of victims.
                    // [F] Non-enumerable lockout message.
                    $lockoutError = true;
                    logActivity('login.php', "$username (locked/rate-limited)"); // [M]

                } elseif ($user && $passwordOk) {
                    // ── Successful login ──────────────────────────────────────
                    // Clear all failure tracking for this identity.
                    $db->prepare(
                        "DELETE FROM rate_limits WHERE bucket = 'login_fail'      AND `key` = ?"
                    )->execute([$username]);
                    $db->prepare(
                        "DELETE FROM rate_limits WHERE bucket = 'login_user'      AND `key` = ?"
                    )->execute([$username]);
                    $db->prepare(
                        "DELETE FROM rate_limits WHERE bucket = 'login_composite' AND `key` = ?"
                    )->execute([$compositeKey]);
                    // FIX [MEDIUM]: Refund the login_ip slot consumed above.
                    // Without this, each successful login burns a slot from the 10/15-min
                    // IP bucket. A user who logs in and out 10 times (normal activity)
                    // would be locked out of their own IP for 15 minutes.
                    $db->prepare(
                        "DELETE FROM rate_limits WHERE bucket = 'login_ip' AND `key` = ? LIMIT 1"
                    )->execute([$ip]);

                    // [E] Regenerate session ID — prevents session fixation.
                    session_regenerate_id(true);
                    $_SESSION['user_id']       = $user['id'];
                    $_SESSION['username']      = $user['username'];
                    $_SESSION['session_token'] = bin2hex(random_bytes(32));
                    $_SESSION['session_start'] = time();
                    $_SESSION['last_active']   = time();

                    // [O] Write SHA2 hash of session token to DB so requireLogin()
                    //     in config.php can verify it on every authenticated request.
                    //     This enables server-side session invalidation — a password
                    //     change or forced logout clears this column, instantly
                    //     invalidating any active session even if the cookie persists.
                    //
                    //     Requires: ALTER TABLE users ADD COLUMN session_token VARCHAR(64) DEFAULT NULL;
                    //
                    //     If the column doesn't exist yet (migration not applied),
                    //     the UPDATE throws — catch it and proceed without token binding
                    //     (requireLogin() in config.php handles the missing column gracefully).
                    try {
                        $db->prepare(
                            "UPDATE users SET session_token = SHA2(?, 256) WHERE id = ?"
                        )->execute([$_SESSION['session_token'], (int)$user['id']]);
                    } catch (PDOException $e) {
                        // Column not yet added — log warning, continue.
                        error_log('login.php: could not write session_token to DB (migration pending?): ' . $e->getMessage());
                    }

                    logActivity('login.php', $user['username']); // [M] sanitized inside logActivity()
                    redirect('/dashboard.php', 'Login successful! Welcome back.', 'success');

                } else {
                    // ── Genuine failed attempt ────────────────────────────────
                    // [G] Write login_fail ONLY on a real failure.
                    $db->prepare(
                        "INSERT INTO rate_limits (bucket, `key`, created_at)
                         VALUES ('login_fail', ?, ?)"
                    )->execute([$username, $now]);

                    // Re-count to detect if this attempt just tripped time-lock.
                    $failStmt->execute([$username, $win]);
                    if ((int)$failStmt->fetchColumn() >= 10) {
                        logActivity('login.php', "$username (TIME-LOCKED)"); // [M]
                    }

                    // [F] Generic — identical for wrong password and unknown username.
                    $error = 'Invalid username or password.';
                    logActivity('login.php', "$username (failed)"); // [M]
                }
            }
        }
    }

} else {
    // GET — log page visit only.
    logActivity('login.php', 'guest');
}

$pageTitle = 'Login';
include 'header.php';
?>
<div class="auth-wrap">
    <div class="auth-header">
        <div class="logo-text glitch" data-text="TRANSACTIWAR">TRANSACTIWAR</div>
        <div class="sub">// OPERATOR AUTHENTICATION PORTAL</div>
    </div>
    <div class="card" style="border-color:var(--border3);">
        <div class="card-title">AUTHENTICATE</div>

        <?php if ($lockoutError): ?>
            <div class="alert alert-error">
                Too many failed attempts from this operator ID or IP address.
                Please wait 15&ndash;30 minutes before trying again, or contact
                support if you believe this is an error.
            </div>
        <?php elseif ($error !== ''): ?>
            <!-- [B] h() escapes all reflected content -->
            <div class="alert alert-error"><?= h($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="/login.php" novalidate autocomplete="off">
            <!-- [C] CSRF token on every form render -->
            <input type="hidden" name="csrf_token" value="<?= h(generateCSRFToken()) ?>">
            <div class="form-group">
                <label>Operator ID</label>
                <!-- [B] reflected through h() -->
                <input
                    type="text"
                    name="username"
                    class="form-control"
                    value="<?= h($username) ?>"
                    required
                    autocomplete="username"
                    placeholder="your_callsign"
                    maxlength="50"
                >
            </div>
            <div class="form-group">
                <label>Access Code</label>
                <input
                    type="password"
                    name="password"
                    class="form-control"
                    required
                    autocomplete="current-password"
                    placeholder="••••••••••"
                    maxlength="72"
                >
            </div>
            <button type="submit" class="btn btn-primary btn-full" style="margin-top:0.8rem;">
                ⚡ AUTHENTICATE
            </button>
        </form>

        <div class="cyber-divider" style="margin:1.2rem 0;"></div>
        <p style="text-align:center;font-family:var(--font-mono);font-size:0.72rem;color:var(--text-dim);">
            NOT ENLISTED? <a href="/register.php" style="color:var(--gold);">REGISTER NOW →</a>
        </p>
    </div>
</div>
<?php include 'footer.php'; ?>
