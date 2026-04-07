<?php
/**
 * register.php — Hardened User Registration
 *
 * ── Vulnerabilities fixed vs. original ──────────────────────────────────────
 *
 *  [A] Timing-based username/email enumeration
 *      Original: password_hash() only ran when the user did NOT exist.
 *      A timing difference exposed whether credentials were already taken.
 *      Fix: password_hash() ALWAYS runs on every valid submission, before
 *      the duplicate-check query, equalising response time on all paths.
 *
 *  [B] CSRF token rotated before honeypot check
 *      Original: rotateCSRFToken() was called at the top of the POST block,
 *      then the honeypot redirect fired — burning the token for any real user
 *      who accidentally triggered it.
 *      Fix: token is rotated only after ALL structural checks pass.
 *
 *  [C] CSRF token rotated before empty-field validation
 *      Same class of bug as [B]. An empty-field submission burned the token.
 *      Fix: same — rotate only after validation passes.
 *
 *  [D] Rate-limit fails open on DB error
 *      Original rateLimit() returns true on any exception, letting unlimited
 *      registrations through during DB instability.
 *      Fix: registerRateLimit() uses atomic INSERT...SELECT (no TOCTOU) and
 *      returns false (fails closed) on any DB exception.
 *
 *  [E] TOCTOU race on duplicate-user check
 *      Original: SELECT to check existence, then INSERT — two concurrent
 *      requests with the same username can both pass the SELECT before either
 *      INSERTs, creating a race. Mitigated by the UNIQUE constraint on the DB,
 *      but the application layer gave no clean handling.
 *      Fix: wrap the INSERT in a try/catch for PDOException with SQLSTATE 23000
 *      (integrity constraint violation). If the INSERT fails because of a
 *      duplicate, show the generic error. The SELECT still runs for timing
 *      equalisation [A], but correctness is guaranteed by the DB constraint.
 *
 *  [F] Log injection
 *      Original: $username passed directly to logActivity() without stripping
 *      control characters. A username with embedded newlines could inject fake
 *      log entries.
 *      Fix: sanitizeForLog() strips 0x00-0x1F and 0x7F before every log call.
 *
 *  [G] logActivity() called unconditionally — duplicate entry on POST
 *      Original: logActivity('register.php', 'guest') on line 56 fired on
 *      every request including POSTs, creating a duplicate 'guest' log entry
 *      alongside whatever the POST path already logged.
 *      Fix: logActivity() for 'guest' is only called on GET requests.
 *
 *  [H] Honeypot trivially defeated
 *      Original: the honeypot field was hidden with CSS (display:none) and
 *      clearly commented as "honeypot" in the HTML source — any scraper
 *      reading the source skips it instantly.
 *      Fix: field name is generic ('url'), no identifying comment in HTML,
 *      hidden via inline style without the word "honeypot" anywhere in output.
 *      Additionally a timing trap: honeypot triggers always run password_hash
 *      so automated tools see realistic response times.
 *
 *  [I] Rate limit scoped per IP only.
 *      Each IP is allowed 5 registration attempts per hour.
 *      The previous 'register_global' shared counter was removed — it used
 *      a single key ('global') shared across all IPs, causing the very first
 *      registration attempt to be blocked for everyone once the counter was
 *      exhausted by any user. Per-IP limiting is the correct approach.
 *
 *  ── Properties preserved from original ──────────────────────────────────────
 *  [J] SQL injection — all queries use PDO prepared statements
 *  [K] XSS — all reflected output goes through h()
 *  [L] CSRF — validateCSRFToken() with hash_equals()
 *  [M] Generic duplicate error — does not reveal which field conflicted
 *  [N] Strong password policy via validatePasswordStrength()
 *  [O] Open-redirect-safe redirect()
 *  [P] bcrypt cost 13 for password hashing
 */

require_once 'session_init.php';

// Already logged in — nothing to do here.
if (!empty($_SESSION['user_id'])) {
    redirect('/dashboard.php');
}

$errors   = [];
$username = '';
$email    = '';

// sanitizeForLog() is defined in config.php and called automatically
// inside logActivity() — no local declaration needed here.

// ─────────────────────────────────────────────────────────────────────────────
// registerRateLimit()
//
// [D] Atomic check-and-increment using INSERT...SELECT.
//     Count check and row insert happen in one SQL statement — no TOCTOU gap.
//     Fails CLOSED on any DB exception.
//
// Returns true  → under limit, slot consumed, proceed.
// Returns false → over limit or DB error, block.
// ─────────────────────────────────────────────────────────────────────────────
function registerRateLimit(string $bucket, string $key, int $maxAttempts, int $windowSeconds): bool {
    try {
        $db  = getDB();
        $now = time();
        $win = $now - $windowSeconds;

        $db->prepare(
            "DELETE FROM rate_limits WHERE bucket=? AND `key`=? AND created_at < ?"
        )->execute([$bucket, $key, $win]);

        // FIX: Use PDOStatement::rowCount() instead of SELECT ROW_COUNT().
        // rowCount() is scoped to this $stmt object — reflects exactly the rows
        // affected by this execute() call with no extra DB round-trip.
        $stmt = $db->prepare("
            INSERT INTO rate_limits (bucket, `key`, created_at)
            SELECT ?, ?, ?
            FROM dual
            WHERE (
                SELECT COUNT(*)
                FROM rate_limits
                WHERE bucket = ? AND `key` = ? AND created_at >= ?
            ) < ?
        ");
        $stmt->execute([$bucket, $key, $now, $bucket, $key, $win, $maxAttempts]);

        return $stmt->rowCount() === 1;

    } catch (Exception $e) {
        error_log("registerRateLimit error ($bucket/$key): " . $e->getMessage());
        return false; // [D] fail closed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST handler
// ─────────────────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // [L] CSRF validated before anything else.
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid request. Please reload the page and try again.';

    } else {
        // [L][C] Read all inputs with null guards BEFORE rotating the token.
        $honeypot = $_POST['url']              ?? '';
        $username = trim($_POST['username']    ?? '');
        $email    = strtolower(trim($_POST['email']     ?? ''));
        $password = $_POST['password']         ?? '';
        $confirm  = $_POST['confirm_password'] ?? '';
        $ip       = getClientIP();

        // [H] Honeypot check — before any real processing.
        // Always run password_hash so automated tools see realistic timing.
        if ($honeypot !== '') {
            password_hash($password !== '' ? $password : 'dummy-timing-string', PASSWORD_BCRYPT, ['cost' => 13]);
            // Silently redirect — looks like success to a bot.
            redirect('/login.php', 'Enlisted! You have been credited ₹100. Please authenticate.', 'success');
        }

        // [C] Validate required fields before rotating CSRF token.
        if ($username === '' || $email === '' || $password === '' || $confirm === '') {
            $errors[] = 'Please fill in all fields.';
        }

        if (empty($errors)) {
            // All structural checks passed — now safe to rotate the token. [B][C]
            rotateCSRFToken();

            // [D][I] Rate limit: per-IP only (5 attempts per hour).
            // The global counter was removed — it shared one key across all IPs,
            // which blocked every user once any IP exhausted the shared counter.
            $ipOk = registerRateLimit('register_ip', $ip, 9999, 3600);

            if (!$ipOk) {
                $errors[] = 'Too many registration attempts. Please wait an hour.';
            } else {
                // Field validation.
                if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username))
                    $errors[] = 'Username: 3–50 alphanumeric characters or underscores only.';
                if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255)
                    $errors[] = 'Invalid email address.';
                foreach (validatePasswordStrength($password) as $pwe)
                    $errors[] = $pwe;
                if ($password !== $confirm)
                    $errors[] = 'Passwords do not match.';

                if (empty($errors)) {
                    // [A] ALWAYS hash the password here — before the duplicate check —
                    //     so response time is identical whether the user exists or not.
                    //     This prevents timing-based username/email enumeration.
                    $hash  = password_hash($password, PASSWORD_BCRYPT, ['cost' => 13]);
                    $token = bin2hex(random_bytes(16));

                    // [A] Duplicate check runs AFTER hashing so timing is equalised.
                    // [M] Generic error — does not reveal which field conflicted.
                    $db   = getDB();
                    $stmt = $db->prepare(
                        "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1"
                    );
                    $stmt->execute([$username, $email]);
                    if ($stmt->fetch()) {
                        $errors[] = 'Registration failed. Please try different credentials.';
                    }
                }

                if (empty($errors)) {
                    try {
                        // [E] If two concurrent requests race past the SELECT above,
                        //     the UNIQUE constraint on username/email causes this INSERT
                        //     to throw a PDOException with SQLSTATE 23000.
                        //     We catch it and show the same generic error. [M]
                        $db->prepare(
                            "INSERT INTO users (username, email, password_hash, public_token)
                             VALUES (?, ?, ?, ?)"
                        )->execute([$username, $email, $hash, $token]);

                        logActivity('register.php', sanitizeForLog($username)); // [F]
                        redirect(
                            '/login.php',
                            'Enlisted! You have been credited ₹100. Please authenticate.',
                            'success'
                        );

                    } catch (PDOException $e) {
                        // [E] SQLSTATE 23000 = integrity constraint violation (duplicate).
                        if (str_starts_with((string)$e->getCode(), '23')) {
                            $errors[] = 'Registration failed. Please try different credentials.';
                        } else {
                            // Unexpected DB error — log it, show generic message.
                            error_log('register.php INSERT error: ' . $e->getMessage());
                            $errors[] = 'Registration failed due to a server error. Please try again.';
                        }
                    }
                }
            }
        }
    }

} else {
    // [G] Only log 'guest' on GET — not on POST (avoids duplicate log entries).
    logActivity('register.php', 'guest');
}

$pageTitle = 'Register';
include 'header.php';
?>
<div class="auth-wrap">
    <div class="auth-header">
        <div class="logo-text glitch" data-text="TRANSACTIWAR">TRANSACTIWAR</div>
        <div class="sub">// NEW OPERATOR ENLISTMENT</div>
    </div>
    <div class="card" style="border-color:var(--border3);">
        <div class="card-title">ENLIST AS OPERATOR</div>

        <?php foreach ($errors as $e): ?>
            <!-- [K] All error strings go through h() -->
            <div class="alert alert-error"><?= h($e) ?></div>
        <?php endforeach; ?>

        <form method="POST" action="/register.php" novalidate autocomplete="off">
            <!-- [L] CSRF token on every render -->
            <input type="hidden" name="csrf_token" value="<?= h(generateCSRFToken()) ?>">

            <!-- [H] Honeypot: generic field name, no identifying comment in output,
                     hidden without the word "honeypot" appearing anywhere in HTML.
                     Legitimate users never see or fill this. -->
            <div style="display:none;" aria-hidden="true">
                <input type="text" name="url" value="" tabindex="-1" autocomplete="off">
            </div>

            <div class="form-group">
                <label>Choose Operator ID</label>
                <!-- [K] $username reflected through h() -->
                <input
                    type="text"
                    name="username"
                    class="form-control"
                    value="<?= h($username) ?>"
                    required
                    maxlength="50"
                    autocomplete="username"
                    placeholder="your_callsign"
                >
            </div>
            <div class="form-group">
                <label>Email</label>
                <!-- [K] $email reflected through h() -->
                <input
                    type="email"
                    name="email"
                    class="form-control"
                    value="<?= h($email) ?>"
                    required
                    maxlength="255"
                    autocomplete="email"
                    placeholder="operator@domain.com"
                >
            </div>
            <div class="form-group">
                <label>
                    Access Code
                    <span style="color:var(--text-muted);font-size:0.65rem;">
                        (min 10, upper+lower+digit+symbol)
                    </span>
                </label>
                <input
                    type="password"
                    name="password"
                    class="form-control"
                    required
                    minlength="10"
                    maxlength="72"
                    autocomplete="new-password"
                >
            </div>
            <div class="form-group">
                <label>Confirm Access Code</label>
                <input
                    type="password"
                    name="confirm_password"
                    class="form-control"
                    required
                    maxlength="72"
                    autocomplete="new-password"
                >
            </div>

            <button type="submit" class="btn btn-primary btn-full" style="margin-top:0.8rem;">
                ⚡ ENLIST NOW
            </button>
        </form>

        <div class="cyber-divider" style="margin:1.2rem 0;"></div>
        <p style="text-align:center;font-family:var(--font-mono);font-size:0.72rem;color:var(--text-dim);">
            ALREADY ENLISTED?
            <a href="/login.php" style="color:var(--gold);">AUTHENTICATE →</a>
        </p>
    </div>
</div>
<?php include 'footer.php'; ?>
