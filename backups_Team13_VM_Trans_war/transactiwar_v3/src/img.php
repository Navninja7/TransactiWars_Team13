<?php
/**
 * Secure image proxy — serves uploaded profile images with correct headers.
 * SECURITY: Validates filename, enforces content-type, prevents path traversal,
 *           adds Content-Disposition: inline to prevent download-and-execute tricks.
 */
require_once 'session_init.php';
// SECURITY: Must be logged in to view any profile image
requireLogin();

$file = trim($_GET['f'] ?? '');

// SECURITY: Whitelist filename format — only hex string + .png (our GD re-encoded format)
if (!preg_match('/^[a-f0-9]{48}\.png$/', $file)) {
    http_response_code(404); exit;
}

$path = UPLOAD_DIR . $file;

// SECURITY: Confirm the resolved path is inside upload dir (belt & braces)
// FIX [LOW]: Use rtrim + DIRECTORY_SEPARATOR to ensure boundary is a dir separator,
// not just a string prefix (prevents e.g. /uploads/profiles matching /uploads/profiles2/).
$realUpload = realpath(UPLOAD_DIR);
$realPath   = realpath($path);
if ($realPath === false || !str_starts_with($realPath, rtrim($realUpload, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
    http_response_code(404); exit;
}

if (!file_exists($realPath)) {
    http_response_code(404); exit;
}

// SECURITY: Verify it's actually a valid PNG before serving
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($realPath);
if ($mime !== 'image/png') {
    http_response_code(403); exit;
}

// Serve with strict headers
header('Content-Type: image/png');
header('Content-Disposition: inline; filename="profile.png"');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, max-age=3600');
header('Content-Length: ' . filesize($realPath));
readfile($realPath);
exit;
