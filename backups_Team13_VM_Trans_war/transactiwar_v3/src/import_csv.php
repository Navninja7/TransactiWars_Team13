#!/usr/bin/env php
<?php
if (php_sapi_name() !== 'cli') { http_response_code(403); die('Forbidden'); }
require_once __DIR__ . '/config.php';

$csvPath = __DIR__ . '/Phase2.csv';
if (!file_exists($csvPath)) { die("CSV not found at $csvPath\n"); }

$db = getDB();
$handle = fopen($csvPath, 'r');
$header = fgetcsv($handle);

$ok = 0; $skip = 0;
while (($row = fgetcsv($handle)) !== false) {
    [$username, $email, $full_name, $password] = $row;
    $chk = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $chk->execute([$username, $email]);
    if ($chk->fetch()) { echo "[SKIP] $username\n"; $skip++; continue; }
    $hash  = password_hash($password, PASSWORD_BCRYPT, ['cost' => 13]);
    $token = bin2hex(random_bytes(16));
    $stmt  = $db->prepare("INSERT INTO users (username, email, password_hash, full_name, public_token) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$username, $email, $hash, $full_name, $token]);
    echo "[OK]   $username (ID #" . $db->lastInsertId() . ")\n";
    $ok++;
}
fclose($handle);
echo "\nDone! Inserted: $ok, Skipped: $skip\n";
