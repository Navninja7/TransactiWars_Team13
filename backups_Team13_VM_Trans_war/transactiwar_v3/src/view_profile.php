<?php
require_once 'session_init.php';
$currentUser = requireLogin();
logActivity('view_profile.php', $currentUser['username']);
// FIX [INFO]: Key view_profile rate limit on user ID instead of IP,
// consistent with the search.php fix — avoids shared-NAT throttling.
if (!rateLimit('view_profile', (string)$currentUser['id'], 60, 60)) { http_response_code(429); include 'header.php'; echo '<div class="alert alert-error">Too many requests.</div>'; include 'footer.php'; exit; }
$db = getDB(); $token = trim($_GET['token'] ?? '');
if ($token === '') redirect('/search.php','Invalid profile link.','error');
if (!preg_match('/^[a-f0-9]{32}$|^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/', $token)) redirect('/search.php','Invalid profile link.','error');
$stmt = $db->prepare("SELECT id,username,full_name,bio,profile_image,created_at,public_token FROM users WHERE public_token=?");
$stmt->execute([$token]); $target = $stmt->fetch();
if (!$target) redirect('/search.php','User not found.','error');
$pageTitle = 'Profile: ' . preg_replace('/[^a-zA-Z0-9_\-]/', '', $target['username']);
include 'header.php';
?>
<div class="page-heading">
    OPERATOR PROFILE
    <?php if ($target['id'] == $currentUser['id']): ?>
        <span class="sub"><a href="/profile.php" style="color:var(--cyan);">← EDIT YOUR PROFILE</a></span>
    <?php endif; ?>
</div>
<div style="max-width:680px;">
    <div class="card" style="background:linear-gradient(160deg,var(--panel) 0%,var(--panel2) 100%);">
        <div style="display:flex;gap:1.5rem;align-items:flex-start;flex-wrap:wrap;margin-bottom:1.5rem;">
            <div>
                <?php if ($target['profile_image']): ?>
                    <img src="<?= h('/img.php?f=' . basename($target['profile_image'])) ?>" class="profile-avatar" alt="Profile" style="width:120px;height:120px;">
                <?php else: ?>
                    <div class="profile-avatar-placeholder" style="width:120px;height:120px;font-size:2.8rem;"><?= strtoupper(substr(h($target['username']),0,1)) ?></div>
                <?php endif; ?>
            </div>
            <div style="flex:1;">
                <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);letter-spacing:0.15em;margin-bottom:0.3rem;">// OPERATOR IDENTIFIED</div>
                <div style="font-family:var(--font-hud);font-size:1.5rem;font-weight:900;color:var(--gold);letter-spacing:0.1em;text-shadow:0 0 15px rgba(255,215,0,0.5);"><?= h(strtoupper($target['username'])) ?></div>
                <?php if ($target['full_name']): ?><div style="font-family:var(--font-mono);font-size:0.82rem;color:var(--text-dim);margin-top:0.3rem;"><?= h($target['full_name']) ?></div><?php endif; ?>
                <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);margin-top:0.5rem;">ENLISTED: <?= h(date('d M Y', strtotime($target['created_at']))) ?></div>
                <?php if ($target['id'] != $currentUser['id']): ?>
                    <div style="margin-top:1rem;"><a href="/transfer.php?to=<?= (int)$target['id'] ?>" class="btn btn-primary btn-sm">⚡ TRANSFER FUNDS</a></div>
                <?php endif; ?>
            </div>
        </div>
        <div class="cyber-divider"></div>
        <?php if ($target['bio']): ?>
            <div style="margin-top:1rem;">
                <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);letter-spacing:0.12em;margin-bottom:0.6rem;">// BIO INTEL</div>
                <p style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text);line-height:1.7;white-space:pre-wrap;"><?= h($target['bio']) ?></p>
            </div>
        <?php else: ?>
            <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);text-align:center;padding:1rem;">// NO BIO INTEL AVAILABLE</div>
        <?php endif; ?>
    </div>
</div>
<?php include 'footer.php'; ?>
