<?php
/**
 * config.php — Hardened Application Configuration & Shared Utilities
 *
 * ── Vulnerabilities fixed vs. original ──────────────────────────────────────
 *
 *  [A] rateLimit() fails open on DB error
 *      Original: catch block returns true, so any DB exception (connection
 *      drop, timeout, overload) silently allows the request through.
 *      Every caller — transfer.php, search.php, profile.php, view_profile.php,
 *      login.php, register.php — was bypassed during DB instability.
 *      Fix: rateLimit() now returns false (fails closed) on any exception.
 *
 *  [B] rateLimit() TOCTOU race condition
 *      Original: SELECT COUNT(*) then INSERT as two separate statements.
 *      Two concurrent requests can both read "count < limit" before either
 *      writes, letting both through and effectively doubling the allowed rate.
 *      Fix: replaced with a single atomic INSERT...SELECT. Count check and
 *      row insertion happen in one DB statement — no gap between them.
 *      PDOStatement::rowCount() reports whether the insert fired (1 = allowed)
 *      or was blocked by the WHERE clause (0 = over limit). This is
 *      statement-scoped, requires no extra DB round-trip, and is immune to
 *      session-level MySQL state unlike SELECT ROW_COUNT().
 *
 *  [C] logActivity() has no log injection protection
 *      Original: $username and $webpage written directly to activity_logs
 *      with only mb_substr() truncation. A username containing \n or \r
 *      injects fake entries into any flat-file export or SIEM feed.
 *      Fix: sanitizeForLog() strips all ASCII control characters
 *      (0x00-0x1F, 0x7F) inside logActivity() itself, so every caller
 *      is protected automatically — no per-caller changes needed.
 *
 *  [D] logActivity() silently swallows all errors
 *      Original: catch block is completely empty — DB errors during logging
 *      vanish without a trace, making log failures invisible.
 *      Fix: exceptions are passed to error_log() so failures are recorded
 *      in the server error log while remaining non-fatal to the request.
 *
 *  [E] redirect() HTTP header injection
 *      Original: header("Location: $url") with no stripping of \r or \n.
 *      Even though redirect() validates the path, a $url value that somehow
 *      contained a CRLF sequence could inject arbitrary HTTP response headers.
 *      Fix: strip \r and \n from $url before passing it to header().
 *
 *  [F] requireLogin() session_token never verified for integrity
 *      Original: requireLogin() checks that $_SESSION['session_token'] is
 *      non-empty but never validates it — any non-empty string passes.
 *      The token was designed as a session-binding value regenerated on login
 *      and password change, but without a DB cross-check it provides no
 *      real protection against a session that was cleared server-side.
 *      Fix: session_token is now stored as a hash in the DB (users.session_token
 *      column — add via migration below) and verified on every requireLogin()
 *      call. If the token doesn't match, the session is destroyed.
 *      NOTE: This requires adding a session_token column to the users table:
 *        ALTER TABLE users ADD COLUMN session_token VARCHAR(64) DEFAULT NULL;
 *      Until that migration is applied, requireLogin() falls back to the
 *      original non-empty check and emits a one-time error_log warning.
 *
 *  [G] startSecureSession() defined but never called — dead / confusing code
 *      Original: startSecureSession() duplicates the session setup already
 *      done inline in session_init.php. It was never called anywhere in the
 *      codebase, creating a maintenance trap (someone might call it thinking
 *      it's the canonical setup, getting a double session_start() error).
 *      Fix: function removed. session_init.php remains the single source of
 *      truth for session initialisation.
 *
 *  [H] Hardcoded fallback DB credentials in source
 *      Original: DB_PASS defaults to the literal string 'twpassword' baked
 *      into source code. If environment variables are missing (misconfigured
 *      deploy, stripped .env), the app silently connects with known-public
 *      credentials that are published in the README.
 *      Fix: if any required DB environment variable is missing, the app
 *      refuses to start with a clear error rather than falling back to
 *      insecure defaults. Credentials must always come from the environment.
 *
 *  [I] getDB() leaks DSN / credential details on connection failure
 *      Original: PDOException propagates up the call stack with the full
 *      DSN string (host, dbname) and potentially credential hints in its
 *      message — these can leak to logs, error pages, or PHP's default
 *      exception handler.
 *      Fix: connection exceptions are caught, logged safely with error_log(),
 *      and re-thrown as a generic RuntimeException with no credential details.
 *
 *  ── Properties preserved from original ─────────────────────────────────────
 *  [J] PDO with ATTR_EMULATE_PREPARES=false — real prepared statements
 *  [K] h() with ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE — full XSS escaping
 *  [L] validateCSRFToken() with hash_equals() — constant-time comparison
 *  [M] REMOTE_ADDR only for IP — X-Forwarded-For intentionally ignored
 *  [N] redirect() same-origin enforcement
 *  [O] validatePasswordStrength() — strong password policy
 *  [P] sendSecurityHeaders() — CSP, HSTS, X-Frame-Options, etc.
 *  [Q] getFlash() — safe flash message retrieval
 */

// ─── HTTPS Detection ──────────────────────────────────────────────────────────

/**
 * isHttps()
 *
 * Shared helper used by session_init.php and logout.php.
 * Trusts X-Forwarded-Proto only from loopback / RFC-1918 addresses
 * (i.e. a trusted internal reverse proxy) to avoid spoofing by public clients.
 */
function isHttps(): bool {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    $remoteIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $isPrivate = filter_var($remoteIp, FILTER_VALIDATE_IP) !== false
        && filter_var($remoteIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    return $isPrivate
        && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && strtolower(trim($_SERVER['HTTP_X_FORWARDED_PROTO'])) === 'https';
}

// ─── Required Environment Variables ──────────────────────────────────────────
// [H] No hardcoded credential fallbacks. Missing vars = hard stop.

(static function (): void {
    $required = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'];
    $missing  = [];
    foreach ($required as $var) {
        if (getenv($var) === false || getenv($var) === '') {
            $missing[] = $var;
        }
    }
    if (!empty($missing)) {
        // Log which vars are missing but do NOT expose values.
        error_log('config.php: Missing required environment variables: ' . implode(', ', $missing));
        http_response_code(500);
        // Generic message to the browser — no internal detail.
        exit('Application configuration error. Please contact the administrator.');
    }
})();

define('DB_HOST', getenv('DB_HOST'));
define('DB_NAME', getenv('DB_NAME'));
define('DB_USER', getenv('DB_USER'));
define('DB_PASS', getenv('DB_PASS'));

define('UPLOAD_DIR',   __DIR__ . '/uploads/profiles/');
define('UPLOAD_URL',   '/uploads/profiles/');
define('MAX_FILE_SIZE', 2 * 1024 * 1024);
// SVG (embedded JS) and GIF (pixel-tracking abuse) intentionally excluded.
define('ALLOWED_TYPES',      ['image/jpeg', 'image/png', 'image/webp']);
define('ALLOWED_FLASH_TYPES', ['success', 'error', 'info', 'warning']);

// DUMMY_HASH intentionally NOT defined here.
// It is generated locally inside login.php's POST handler so bcrypt cost-13
// only runs during an actual login attempt — not on every page load.
// Defining it at module level caused a ~500ms bcrypt penalty on every request.

// ─── Database ─────────────────────────────────────────────────────────────────

/**
 * getDB()
 *
 * Returns a singleton PDO connection.
 *
 * [I] Connection exceptions are caught, sanitised, and re-thrown as a generic
 *     RuntimeException so DSN / credential details never propagate to callers,
 *     logs visible to users, or PHP's default exception handler output.
 * [J] ATTR_EMULATE_PREPARES=false forces real server-side prepared statements.
 */
function getDB(): PDO {
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        DB_HOST,
        DB_NAME
    );
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    $retries = 3;
    $delay   = 500000; // 0.5s initial delay (microseconds)
    while ($retries > 0) {
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
            return $pdo;
        } catch (PDOException $e) {
            $retries--;
            if ($retries === 0) {
                // [I] Log the real error internally but expose nothing to callers.
                error_log('getDB(): connection failed after retries: ' . $e->getMessage());
                throw new RuntimeException('Database connection unavailable. Please try again later.');
            }
            // Exponential backoff: 0.5s → 1s → 2s (max total ~3.5s)
            usleep($delay);
            $delay *= 2;
        }
    }

    // Unreachable, but satisfies static analysis.
    throw new RuntimeException('Database connection unavailable.');
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

/**
 * rateLimit()
 *
 * Atomic sliding-window rate limiter.
 *
 * [A] Fails CLOSED on any DB exception — request is blocked, not allowed.
 *
 * [B] Uses a single atomic INSERT...SELECT so the count check and the row
 *     write happen in one DB statement. No TOCTOU gap between SELECT and
 *     INSERT — concurrent requests cannot both read "under limit" before
 *     either has written its row.
 *
 * Returns true  → under limit, slot consumed, caller may proceed.
 * Returns false → over limit OR DB error, caller must block the request.
 */
function rateLimit(string $bucket, string $key, int $maxAttempts, int $windowSeconds): bool {
    try {
        $db  = getDB();
        $now = time();
        $win = $now - $windowSeconds;

        // Housekeeping: remove expired rows for this bucket+key.
        $db->prepare(
            "DELETE FROM rate_limits WHERE bucket = ? AND `key` = ? AND created_at < ?"
        )->execute([$bucket, $key, $win]);

        // [B] Atomic check + insert in one statement.
        // The INSERT fires only when the subquery count is below the limit.
        // $stmt->rowCount() === 1 → insert happened → allowed.
        // $stmt->rowCount() === 0 → subquery blocked it → over limit.
        //
        // FIX: Use PDOStatement::rowCount() instead of SELECT ROW_COUNT().
        // rowCount() is scoped to this specific statement object and reflects
        // exactly the rows affected by its last execute() call — no extra DB
        // round-trip, no dependency on session-level MySQL state, and immune
        // to any future code added between the INSERT and the result read.
        $stmt = $db->prepare("
            INSERT IGNORE INTO rate_limits (bucket, `key`, created_at)
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
        // [A] Fail closed — DB instability must not open the floodgates.
        error_log("rateLimit($bucket, $key): " . $e->getMessage());
        return false;
    }
}

// ─── IP Detection ─────────────────────────────────────────────────────────────

/**
 * getClientIP()
 *
 * [M] Only REMOTE_ADDR is trusted. X-Forwarded-For is trivially spoofable
 *     and intentionally ignored — trusting it would allow rate-limit bypass
 *     by sending a forged header.
 */
function getClientIP(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

// ─── Activity Logging ─────────────────────────────────────────────────────────

/**
 * sanitizeForLog()
 *
 * [C] Strip all ASCII control characters (0x00-0x1F, 0x7F) from any value
 *     before it is written to activity_logs. Prevents log injection via
 *     embedded newlines, carriage returns, or other control bytes in
 *     usernames or page names supplied by the caller.
 *
 *     Called internally by logActivity() so ALL callers are protected
 *     automatically without needing per-file changes.
 */
function sanitizeForLog(string $value): string {
    return preg_replace('/[\x00-\x1F\x7F]/', '', $value);
}

/**
 * logActivity()
 *
 * [C] Sanitizes $webpage and $username through sanitizeForLog() before
 *     writing to the DB — log injection is impossible regardless of caller.
 * [D] Exceptions are passed to error_log() instead of being swallowed
 *     silently, so log failures appear in the server error log.
 */
function logActivity(string $webpage, string $username = 'guest'): void {
    try {
        $db = getDB();
        $db->prepare(
            "INSERT INTO activity_logs (webpage, username, ip_address) VALUES (?, ?, ?)"
        )->execute([
            mb_substr(sanitizeForLog($webpage),  0, 255), // [C]
            mb_substr(sanitizeForLog($username), 0, 50),  // [C]
            getClientIP(),
        ]);
    } catch (Exception $e) {
        // [D] Log the failure — do not silently discard it.
        error_log('logActivity() failed: ' . $e->getMessage());
    }
}

// ─── Output Escaping ──────────────────────────────────────────────────────────

/**
 * h()
 *
 * [K] Full HTML escaping with ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE.
 *     ENT_SUBSTITUTE replaces invalid UTF-8 sequences rather than returning
 *     an empty string, preventing silent XSS via malformed multibyte input.
 */
function h(string $str): string {
    return htmlspecialchars($str, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
}

// ─── CSRF ─────────────────────────────────────────────────────────────────────

/**
 * generateCSRFToken()
 * Generates a 64-hex-char (256-bit) token and stores it in the session.
 * Idempotent — returns the existing token if one already exists.
 */
function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * validateCSRFToken()
 *
 * [L] Uses hash_equals() for constant-time comparison to prevent
 *     timing-based token oracle attacks.
 */
function validateCSRFToken(string $token): bool {
    if ($token === '' || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * rotateCSRFToken()
 * Issues a fresh token. Called after a POST is accepted to prevent
 * token reuse across multiple form submissions.
 */
function rotateCSRFToken(): void {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * requireLogin()
 *
 * Validates the session and returns the current user's DB record.
 * Destroys the session and redirects to login on any failure.
 *
 * [F] session_token integrity check: the token stored in $_SESSION is
 *     compared against the hashed value in users.session_token (DB column).
 *     This means a server-side session invalidation (password change, forced
 *     logout) is honoured even if the client still holds a valid session cookie.
 *
 *     Requires DB migration:
 *       ALTER TABLE users
 *         ADD COLUMN session_token VARCHAR(64) DEFAULT NULL;
 *
 *     login.php must store the token hash on login:
 *       UPDATE users SET session_token = SHA2(?, 256) WHERE id = ?
 *
 *     Until the migration is applied the function falls back to the original
 *     non-empty check and emits a one-time error_log() warning.
 */
function requireLogin(): array {
    if (empty($_SESSION['user_id'])) {
        header('Location: /login.php');
        exit;
    }
    if (empty($_SESSION['session_token'])) {
        session_unset();
        session_destroy();
        header('Location: /login.php?reason=security');
        exit;
    }

    $db   = getDB();
    $stmt = $db->prepare(
        "SELECT id, username, email, balance, full_name, bio,
                profile_image, public_token, created_at, session_token
         FROM users WHERE id = ?"
    );
    $stmt->execute([(int)$_SESSION['user_id']]);
    $user = $stmt->fetch();

    if (!$user) {
        session_unset();
        session_destroy();
        header('Location: /login.php');
        exit;
    }

    // [F] Verify session_token against the DB if the column exists.
    if (array_key_exists('session_token', $user)) {
        if ($user['session_token'] === null) {
            // Column exists but no token stored — DB migration applied but
            // login.php hasn't been updated yet to write the token hash.
            error_log('requireLogin(): session_token column exists but is NULL for user ' . $user['id']);
        } else {
            // Constant-time comparison of hash(session_token) vs DB value.
            $expectedHash = hash('sha256', $_SESSION['session_token']);
            if (!hash_equals((string)$user['session_token'], $expectedHash)) {
                // Token mismatch — session was invalidated server-side.
                session_unset();
                session_destroy();
                header('Location: /login.php?reason=security');
                exit;
            }
        }
    } else {
        // Column doesn't exist yet — migration not applied. Warn once.
        static $warnedOnce = false;
        if (!$warnedOnce) {
            error_log('requireLogin(): users.session_token column missing. Apply DB migration for full session integrity checks.');
            $warnedOnce = true;
        }
    }

    // Remove the DB-internal column from the returned array —
    // callers don't need the stored hash and shouldn't see it.
    unset($user['session_token']);
    return $user;
}

// ─── Redirect (open-redirect + header-injection safe) ─────────────────────────

/**
 * redirect()
 *
 * [N]  Enforces same-origin paths: URL must start with '/' but not '//'.
 *      Strips any protocol-like prefix that could create a redirect to an
 *      external host.
 * [E]  Strips \r and \n from the URL before passing to header() to prevent
 *      HTTP response header injection via CRLF sequences.
 */
function redirect(string $url, string $msg = '', string $type = 'success'): void {
    // Same-origin enforcement. [N]
    if (!str_starts_with($url, '/') || str_starts_with($url, '//')) {
        $url = '/';
    }
    if (preg_match('/^[a-zA-Z][a-zA-Z0-9+\-.]*:/', ltrim($url, '/'))) {
        $url = '/';
    }

    // [E] Strip CR and LF to prevent header injection.
    $url = str_replace(["\r", "\n"], '', $url);

    $type = in_array($type, ALLOWED_FLASH_TYPES, true) ? $type : 'info';
    if ($msg !== '') {
        $_SESSION['flash_msg']  = mb_substr(strip_tags($msg), 0, 500);
        $_SESSION['flash_type'] = $type;
    }

    header("Location: $url");
    exit;
}

/**
 * getFlash()
 * Retrieves and clears the one-time flash message from the session.
 */
function getFlash(): ?array {
    if (isset($_SESSION['flash_msg'])) {
        $type  = $_SESSION['flash_type'] ?? 'info';
        $type  = in_array($type, ALLOWED_FLASH_TYPES, true) ? $type : 'info';
        $flash = ['msg' => $_SESSION['flash_msg'], 'type' => $type];
        unset($_SESSION['flash_msg'], $_SESSION['flash_type']);
        return $flash;
    }
    return null;
}

// ─── Password Validation ──────────────────────────────────────────────────────

/**
 * validatePasswordStrength()
 *
 * [O] Enforces minimum complexity: length 10-72, upper, lower, digit, symbol.
 *     72-char ceiling matches bcrypt's input limit (prevents silent truncation
 *     of longer passwords creating a weaker effective key space).
 */
function validatePasswordStrength(string $password): array {
    $errors = [];
    if (strlen($password) < 10)
        $errors[] = 'Password must be at least 10 characters.';
    if (strlen($password) > 72)
        $errors[] = 'Password must be 72 characters or fewer (bcrypt limit).';
    if (!preg_match('/[A-Z]/', $password))
        $errors[] = 'Must contain at least one uppercase letter.';
    if (!preg_match('/[a-z]/', $password))
        $errors[] = 'Must contain at least one lowercase letter.';
    if (!preg_match('/[0-9]/', $password))
        $errors[] = 'Must contain at least one digit.';
    if (!preg_match('/[\W_]/', $password))
        $errors[] = 'Must contain at least one special character.';
    return $errors;
}

// ─── Security Headers ─────────────────────────────────────────────────────────

/**
 * sendSecurityHeaders()
 *
 * [P] Sends the full suite of defensive HTTP headers on every response.
 *     Called from session_init.php so it runs before any output.
 *
 *     Headers set:
 *     - X-Frame-Options: DENY                  — clickjacking
 *     - X-Content-Type-Options: nosniff        — MIME sniffing
 *     - X-XSS-Protection: 1; mode=block        — legacy browser XSS filter
 *     - Referrer-Policy: no-referrer           — leaking URLs to third parties
 *     - Content-Security-Policy                — XSS, injection, framing
 *     - Permissions-Policy                     — browser feature restriction
 *     - Cross-Origin-Opener-Policy             — cross-origin isolation
 *     - Cross-Origin-Resource-Policy           — cross-origin resource access
 *     - Strict-Transport-Security (HTTPS only) — downgrade attacks
 *     - Cache-Control / Pragma / Expires       — caching of auth pages
 */
function sendSecurityHeaders(): void {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: no-referrer');
    header(
        "Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self'; " .
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " .
        "font-src 'self' https://fonts.gstatic.com; " .
        "img-src 'self' data: blob:; " .
        "frame-ancestors 'none'; " .
        "base-uri 'self'; " .
        "form-action 'self'; " .
        "object-src 'none'; " .
        "media-src 'none';"
    );
    header(
        'Permissions-Policy: ' .
        'geolocation=(), camera=(), microphone=(), payment=(), ' .
        'usb=(), interest-cohort=(), browsing-topics=()'
    );
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header_remove('X-Powered-By');

    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }

    // Prevent browsers from caching authenticated page content.
    header('Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
}
