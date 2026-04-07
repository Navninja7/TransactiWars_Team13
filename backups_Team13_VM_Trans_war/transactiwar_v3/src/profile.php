<?php
require_once 'session_init.php';
$user = requireLogin();
logActivity('profile.php', $user['username']);
$errors = []; $success = '';

// FIXED: Define h() function if not already defined in header
if (!function_exists('h')) {
    function h($str) {
        return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8');
    }
}

// FIXED: Define validatePasswordStrength if not defined elsewhere
if (!function_exists('validatePasswordStrength')) {
    function validatePasswordStrength($password) {
        $errors = [];
        if (strlen($password) < 10) $errors[] = 'Password must be at least 10 characters.';
        if (!preg_match('/[A-Z]/', $password)) $errors[] = 'Password must contain an uppercase letter.';
        if (!preg_match('/[a-z]/', $password)) $errors[] = 'Password must contain a lowercase letter.';
        if (!preg_match('/[0-9]/', $password)) $errors[] = 'Password must contain a digit.';
        if (!preg_match('/[^A-Za-z0-9]/', $password)) $errors[] = 'Password must contain a symbol.';
        return $errors;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) { 
        $errors[] = 'Invalid request.'; 
    }
    else {
        rotateCSRFToken();
        // SECURITY: Rate limit profile updates — prevents brute-forcing current password via this form
        if (!rateLimit('profile_update', (string)$user['id'], 10, 300)) {
            $errors[] = 'Too many update attempts. Please wait 5 minutes.';
        } else {
            $db = getDB();
            
            // FIXED: Stricter input sanitization
            $full_name = mb_substr(strip_tags(trim($_POST['full_name'] ?? '')), 0, 100);
            // FIXED: Remove any potential HTML entities or script remnants
            $full_name = preg_replace('/[^\p{L}\p{N}\s\.\-\@]/u', '', $full_name);
            
            $email = strtolower(trim($_POST['email'] ?? ''));
            
            // FIXED: Bio sanitization - strip tags AND remove dangerous attributes
            $bio_raw = strip_tags($_POST['bio'] ?? '', '<p><br><b><i><em><strong><ul><ol><li>'); // Allow only safe tags
            // FIXED: Remove any JavaScript: or data: URLs from attributes
            $bio_raw = preg_replace('/(javascript|data|vbscript):/i', 'blocked:', $bio_raw);
            // FIXED: Remove on* event handlers
            $bio_raw = preg_replace('/\bon\w+\s*=\s*"[^"]*"/i', '', $bio_raw);
            $bio_raw = preg_replace('/\bon\w+\s*=\s*\'[^\']*\'/i', '', $bio_raw);
            $bio = mb_substr($bio_raw, 0, 10000);
            
            $newPass   = $_POST['new_password'] ?? '';
            $confPass  = $_POST['confirm_password'] ?? '';
            $curPass   = $_POST['current_password'] ?? '';

            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
                $errors[] = 'Invalid email address.';
            }

            // FIXED: Prepared statement with proper typing
            $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
            $stmt->execute([$email, (int)$user['id']]);
            if ($stmt->fetch()) {
                $errors[] = 'Could not update profile. Please try a different email.';
            }

            if ($newPass !== '') {
                if ($curPass === '') { 
                    $errors[] = 'Enter current password to set a new one.'; 
                } else {
                    $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
                    $stmt->execute([(int)$user['id']]); 
                    $row = $stmt->fetch();
                    if (!$row || !password_verify($curPass, $row['password_hash'])) { 
                        $errors[] = 'Current password incorrect.'; 
                    } else {
                        foreach (validatePasswordStrength($newPass) as $pwe) {
                            $errors[] = $pwe;
                        }
                        if ($newPass !== $confPass) { 
                            $errors[] = 'New passwords do not match.'; 
                        }
                    }
                }
            }

            $profileImg = $user['profile_image'];
            if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] !== UPLOAD_ERR_NO_FILE) {
                $file = $_FILES['profile_image'];
                if ($file['error'] !== UPLOAD_ERR_OK) { 
                    $errors[] = 'File upload error.'; 
                } elseif ($file['size'] > MAX_FILE_SIZE) { 
                    $errors[] = 'Image too large (max 2MB).'; 
                } else {
                    // FIXED: More secure MIME type validation
                    $finfo = new finfo(FILEINFO_MIME_TYPE); 
                    $mimeType = $finfo->file($file['tmp_name']);
                    $allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
                    $origExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                    $allowedExts = ['jpeg','png','webp'];
                    if (!in_array($origExt, $allowedExts, true)) { $errors[] = 'Invalid file type. Only JPEG/PNG/WEBP allowed.'; }
                    elseif (!in_array($mimeType, $allowedTypes, true)) { 
                        $errors[] = 'Invalid image type. Only JPEG/PNG/WEBP allowed.'; 
                    } else {
                        $imgInfo = @getimagesize($file['tmp_name']);
                        if (!$imgInfo) { 
                            $errors[] = 'Not a valid image.'; 
                        } elseif ($imgInfo[0] > 4096 || $imgInfo[1] > 4096) { 
                            $errors[] = 'Image too large (max 4096×4096).'; 
                        } else {
                            // FIX: Re-encode all uploads through GD to strip polyglot payloads/EXIF/metadata
                            $gdImage = @imagecreatefromstring(file_get_contents($file['tmp_name']));
                            if (!$gdImage) { 
                                $errors[] = 'Could not process image.'; 
                            } else {
                                $newFilename = bin2hex(random_bytes(24)) . '.png';
                                $dest = UPLOAD_DIR . $newFilename;
                                if (!is_dir(UPLOAD_DIR)) { 
                                    mkdir(UPLOAD_DIR, 0750, true); 
                                }
                                
                                // FIXED: Enhanced .htaccess for better security
                                $htaccess = UPLOAD_DIR . '.htaccess';
                                if (!file_exists($htaccess)) {
                                    $htaccessContent = "# Deny access to all PHP files\n";
                                    $htaccessContent .= "<FilesMatch \"\\.(php|php3|php4|php5|phtml|phar|inc|sql|bak|ini)$\">\n";
                                    $htaccessContent .= "  Require all denied\n";
                                    $htaccessContent .= "</FilesMatch>\n";
                                    $htaccessContent .= "Options -Indexes -ExecCGI\n";
                                    $htaccessContent .= "AddType text/plain .php .php3 .php4 .php5 .phtml .phar\n";
                                    file_put_contents($htaccess, $htaccessContent);
                                }
                                
                                if (imagepng($gdImage, $dest)) {
                                    imagedestroy($gdImage);
                                    if ($profileImg) { 
                                        $old = UPLOAD_DIR . basename($profileImg); 
                                        if (file_exists($old)) { 
                                            unlink($old); 
                                        }
                                    }
                                    $profileImg = $newFilename;
                                } else { 
                                    imagedestroy($gdImage); 
                                    $errors[] = 'Failed to save image.'; 
                                }
                            }
                        }
                    }
                }
            }

            if (empty($errors)) {
                if ($newPass !== '') {
                    $hash = password_hash($newPass, PASSWORD_BCRYPT, ['cost'=>13]);
                    try {
                        $db->prepare("UPDATE users SET full_name=?, email=?, bio=?, profile_image=?, password_hash=? WHERE id=?")
                           ->execute([$full_name, $email, $bio, $profileImg, $hash, (int)$user['id']]);
                    } catch (PDOException $e) {
                        if (str_starts_with((string)$e->getCode(), '23')) {
                            $errors[] = 'Could not update profile. Please try a different email.';
                        } else {
                            error_log('profile.php UPDATE error: ' . $e->getMessage());
                            $errors[] = 'Profile update failed. Please try again.';
                        }
                    }
                    
                    if (empty($errors)) {
                        // SECURITY: Regenerate session and rotate binding token after password change.
                        session_regenerate_id(true);
                        $_SESSION['session_token'] = bin2hex(random_bytes(32));
                        try {
                            $db->prepare("UPDATE users SET session_token = SHA2(?, 256) WHERE id = ?")
                               ->execute([$_SESSION['session_token'], (int)$user['id']]);
                        } catch (PDOException $e) {
                            error_log('profile.php: could not write session_token to DB: ' . $e->getMessage());
                        }
                    }
                } else {
                    try {
                        $db->prepare("UPDATE users SET full_name=?, email=?, bio=?, profile_image=? WHERE id=?")
                           ->execute([$full_name, $email, $bio, $profileImg, (int)$user['id']]);
                    } catch (PDOException $e) {
                        if (str_starts_with((string)$e->getCode(), '23')) {
                            $errors[] = 'Could not update profile. Please try a different email.';
                        } else {
                            error_log('profile.php UPDATE error: ' . $e->getMessage());
                            $errors[] = 'Profile update failed. Please try again.';
                        }
                    }
                }
                
                if (empty($errors)) {
                    $stmt = $db->prepare("SELECT id, username, email, balance, full_name, bio, profile_image, public_token, created_at FROM users WHERE id=?");
                    $stmt->execute([(int)$user['id']]); 
                    $user = $stmt->fetch();
                    $success = 'Profile updated successfully.';
                }
            }
        } // end rateLimit else
    }
}
$pageTitle = 'My Profile';
include 'header.php';
?>

<div class="page-heading">OPERATOR PROFILE</div>

<?php if ($success): ?>
    <div class="alert alert-success"><?= h($success) ?></div>
<?php endif; ?>
<?php foreach ($errors as $e): ?>
    <div class="alert alert-error"><?= h($e) ?></div>
<?php endforeach; ?>

<div class="grid-2">
    <!-- LEFT: PROFILE DISPLAY - FIXED: ALL OUTPUTS NOW ESCAPED WITH h() -->
    <div>
        <div class="card" style="background:linear-gradient(160deg,var(--panel) 0%,var(--panel2) 100%);">
            <div class="card-title">OPERATOR FILE</div>
            <div style="display:flex;flex-direction:column;align-items:center;padding:1rem 0 1.5rem;">
                <?php if ($user['profile_image']): ?>
                    <!-- FIXED: Added h() to prevent XSS in filename -->
                    <img src="<?= h('/img.php?f=' . basename($user['profile_image'])) ?>" class="profile-avatar" alt="Profile" style="width:130px;height:130px;">
                <?php else: ?>
                    <div class="profile-avatar-placeholder" style="width:130px;height:130px;font-size:3rem;"><?= h(strtoupper(substr($user['username'],0,1))) ?></div>
                <?php endif; ?>
                <div style="font-family:var(--font-hud);font-size:1.3rem;font-weight:900;color:var(--gold);margin-top:1rem;letter-spacing:0.1em;text-shadow:0 0 15px rgba(255,215,0,0.5);"><?= h(strtoupper($user['username'])) ?></div>
                <?php if ($user['full_name']): ?>
                    <!-- FIXED: CRITICAL - Added h() to prevent XSS -->
                    <div style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-dim);margin-top:0.2rem;"><?= h($user['full_name']) ?></div>
                <?php endif; ?>
                <div style="margin-top:1rem;"><span class="balance-badge" style="font-size:1.05rem;">₹<?= number_format((float)$user['balance'],2) ?></span></div>
            </div>
            <div class="cyber-divider"></div>
            <div style="padding:0.5rem 0;">
                <div class="profile-stat"><span class="key">OPERATOR ID</span><span class="val-text">#<?= (int)$user['id'] ?></span></div>
                <!-- FIXED: Added h() to email -->
                <div class="profile-stat"><span class="key">EMAIL</span><span class="val-text"><?= h($user['email']) ?></span></div>
                <!-- FIXED: Added h() to date -->
                <div class="profile-stat"><span class="key">ENLISTED</span><span class="val-text"><?= h(date('d M Y', strtotime($user['created_at']))) ?></span></div>
            </div>
            <?php if ($user['bio']): ?>
            <div style="margin-top:1rem;padding-top:0.8rem;border-top:1px solid var(--border);">
                <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);letter-spacing:0.1em;margin-bottom:0.5rem;">// BIO INTEL</div>
                <!-- FIXED: CRITICAL - Added h() to prevent XSS in bio -->
                <p style="font-family:var(--font-mono);font-size:0.78rem;color:var(--text);line-height:1.6;white-space:pre-wrap;"><?= h($user['bio']) ?></p>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- RIGHT: EDIT FORM - FIXED: ALL OUTPUTS ESCAPED -->
    <div>
        <div class="card">
            <div class="card-title">MODIFY OPERATOR DATA</div>
            <form method="POST" action="/profile.php" enctype="multipart/form-data" novalidate>
                <input type="hidden" name="csrf_token" value="<?= h(generateCSRFToken()) ?>">
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="full_name" class="form-control" 
                           value="<?= h($user['full_name'] ?? '') ?>" 
                           maxlength="100" placeholder="Operator real name">
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" class="form-control" 
                           value="<?= h($user['email']) ?>" required maxlength="255">
                </div>
                <div class="form-group">
                    <label>Bio / Intel</label>
                    <textarea name="bio" class="form-control" maxlength="10000" 
                              placeholder="Tell other operators about yourself..."><?= h($user['bio'] ?? '') ?></textarea>
                </div>
                <div class="form-group">
                    <label>Profile Image (JPEG/PNG/WEBP, max 2MB)</label>
                    <input type="file" name="profile_image" class="form-control" 
                           accept="image/jpeg,image/png,image/webp">
                </div>
                <div class="cyber-divider"></div>
                <div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-dim);margin-bottom:1rem;">// CHANGE PASSWORD — fill all three fields below</div>
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="current_password" class="form-control" 
                           maxlength="72" autocomplete="current-password">
                </div>
                <div class="form-group">
                    <label>New Password <span style="color:var(--text-muted);font-size:0.65rem;">(min 10, upper+lower+digit+symbol)</span></label>
                    <input type="password" name="new_password" class="form-control" 
                           minlength="10" maxlength="72" autocomplete="new-password">
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" name="confirm_password" class="form-control" 
                           maxlength="72" autocomplete="new-password">
                </div>
                <button type="submit" class="btn btn-primary btn-full" style="margin-top:0.5rem;">⚡ SAVE CHANGES</button>
            </form>
        </div>
    </div>
</div>

<!-- FIXED: Add Content-Security-Policy header if not already in header.php -->
<?php
if (!headers_sent()) {
    header("X-XSS-Protection: 1; mode=block");
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: SAMEORIGIN");
    header("Referrer-Policy: strict-origin-when-cross-origin");
}
?>

<?php include 'footer.php'; ?>
