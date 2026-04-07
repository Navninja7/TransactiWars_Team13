#!/usr/bin/env php
<?php
/**
 * create_accounts.php — CLI ONLY
 * V15 FIX: This file must be blocked from web access via Apache config:
 *   <Files "create_accounts.php">
 *       Require all denied
 *   </Files>
 * The php_sapi_name() check below is a defence-in-depth fallback only.
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('Forbidden');
}

require_once __DIR__ . '/config.php';

$accounts = [];
$db = getDB();

$output   = [];
$output[] = "TransactiWar – Creating Test Accounts";
$output[] = str_repeat('=', 50);

foreach ($accounts as $acc) {
    $stmt = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $stmt->execute([$acc['username'], $acc['email']]);
    if ($stmt->fetch()) {
        $output[] = "[SKIP] {$acc['username']} – already exists.";
        continue;
    }
    // V11 FIX: Use cost 13 — same as register.php — so timing is consistent
    //          across all account types and dummy hash in login.php matches
    $hash  = password_hash($acc['password'], PASSWORD_BCRYPT, ['cost' => 13]);
    $token = bin2hex(random_bytes(16));
    $stmt  = $db->prepare(
        "INSERT INTO users (username, email, password_hash, full_name, public_token) VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->execute([$acc['username'], $acc['email'], $hash, $acc['full_name'], $token]);
    $id       = $db->lastInsertId();
    $output[] = "[OK]   {$acc['username']} (ID #{$id}) – created.";
}

$output[] = str_repeat('=', 50);
$output[] = "Done! Each account starts with Rs.100.00 balance.";
echo implode("\n", $output) . "\n";
