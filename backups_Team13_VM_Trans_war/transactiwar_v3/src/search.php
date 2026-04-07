<?php
require_once 'session_init.php';
$user = requireLogin();
logActivity('search.php', $user['username']);
// FIX [LOW]: Key search rate limit on user ID instead of IP.
// IP-keying throttles all users behind shared NAT (e.g. campus network) if
// one user searches heavily. Since search already requires authentication,
// per-user rate limiting is both fairer and more accurate.
if (!rateLimit('search', (string)$user['id'], 30, 60)) { http_response_code(429); include 'header.php'; echo '<div class="alert alert-error">Too many searches. Slow down.</div>'; include 'footer.php'; exit; }
$query = trim($_GET['q'] ?? '');
$results = [];
if (strlen($query) > 50) $query = substr($query, 0, 50);
if (mb_strlen($query) >= 2) {
    $db = getDB();
    if (ctype_digit($query)) { $stmt = $db->prepare("SELECT id,username,full_name,profile_image,public_token FROM users WHERE id=? LIMIT 20"); $stmt->execute([(int)$query]); }
    else {
        $escaped = str_replace(['\\','%','_'],['\\\\','\\%','\\_'],$query);
        $stmt = $db->prepare("SELECT id,username,full_name,profile_image,public_token FROM users WHERE username LIKE ? LIMIT 20");
        $stmt->execute(['%'.$escaped.'%']);
    }
    $results = $stmt->fetchAll();
}
$pageTitle = 'Recon';
include 'header.php';
?>
<div class="page-heading">OPERATOR RECON</div>
<div class="card">
    <div class="card-title">SEARCH DATABASE</div>
    <form method="GET" action="/search.php">
        <div style="display:flex;gap:1rem;">
            <input type="text" name="q" class="form-control" placeholder="// Search by username or operator ID..." value="<?= h($query) ?>" style="flex:1;">
            <button type="submit" class="btn btn-primary">SCAN</button>
        </div>
    </form>
</div>
<?php if ($query !== ''): ?>
<div class="card">
    <div class="card-title">SCAN RESULTS <?php if (!empty($results)): ?>(<?= (int)count($results) ?> FOUND)<?php endif; ?></div>
    <?php if (empty($results)): ?>
        <div style="text-align:center;padding:2rem;font-family:var(--font-mono);color:var(--text-dim);">
            <div style="font-size:2rem;margin-bottom:0.5rem;">📡</div>
            // NO OPERATORS FOUND FOR "<?= h(strtoupper($query)) ?>"
        </div>
    <?php else: ?>
        <?php foreach ($results as $r): ?>
        <div class="user-card">
            <div>
                <?php if ($r['profile_image']): ?>
                    <img src="<?= h('/img.php?f=' . basename($r['profile_image'])) ?>" class="profile-img-sm" alt="">
                <?php else: ?>
                    <div style="width:40px;height:40px;background:linear-gradient(135deg,var(--panel),var(--panel2));border:1px solid var(--border3);display:inline-flex;align-items:center;justify-content:center;font-family:var(--font-hud);font-size:1rem;color:var(--cyan);clip-path:polygon(4px 0%,100% 0%,100% calc(100% - 4px),calc(100% - 4px) 100%,0% 100%,0% 4px);"><?= h(strtoupper(substr($r['username'],0,1))) ?></div>
                <?php endif; ?>
            </div>
            <div class="info">
                <div class="uname"><?= h($r['username']) ?></div>
                <?php if ($r['full_name']): ?><div class="fname"><?= h($r['full_name']) ?></div><?php endif; ?>
                <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-top:0.2rem;">ID: #<?= (int)$r['id'] ?></div>
            </div>
            <div style="display:flex;gap:0.5rem;align-items:center;">
                <a href="/view_profile.php?token=<?= h($r['public_token']??'') ?>" class="btn btn-secondary btn-sm">PROFILE</a>
                <?php if ((int)$r['id'] !== (int)$user['id']): ?><a href="/transfer.php?to=<?= (int)$r['id'] ?>" class="btn btn-primary btn-sm">⚡ SEND</a><?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
    <?php endif; ?>
</div>
<?php endif; ?>
<?php include 'footer.php'; ?>
