<?php
require_once 'session_init.php';
$user = requireLogin();
logActivity('dashboard.php', $user['username']);
$db = getDB();

$stmt = $db->prepare("
    SELECT t.id, t.sender_id, t.receiver_id, t.amount, t.comment, t.created_at,
           s.username AS sender_name, s.public_token AS sender_token,
           r.username AS receiver_name, r.public_token AS receiver_token
    FROM transactions t
    JOIN users s ON t.sender_id = s.id
    JOIN users r ON t.receiver_id = r.id
    WHERE t.sender_id = ? OR t.receiver_id = ?
    ORDER BY t.created_at DESC LIMIT 10
");
$stmt->execute([$user['id'], $user['id']]);
$recentTx = $stmt->fetchAll();

$stmt = $db->prepare("SELECT COUNT(*) FROM transactions WHERE sender_id = ?");
$stmt->execute([$user['id']]); $sentCount = $stmt->fetchColumn();
$stmt = $db->prepare("SELECT COUNT(*) FROM transactions WHERE receiver_id = ?");
$stmt->execute([$user['id']]); $recvCount = $stmt->fetchColumn();
$stmt = $db->prepare("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE sender_id = ?");
$stmt->execute([$user['id']]); $totalSent = (float)$stmt->fetchColumn();
$stmt = $db->prepare("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE receiver_id = ?");
$stmt->execute([$user['id']]); $totalRecv = (float)$stmt->fetchColumn();

$pageTitle = 'Dashboard';
include 'header.php';
?>

<div class="page-heading">
    OPERATOR DASHBOARD
    <span class="sub">// <?= h(strtoupper($user['username'])) ?> &nbsp;|&nbsp; SESSION ACTIVE</span>
</div>

<!-- OPERATOR BANNER -->
<div class="card" style="margin-bottom:1.8rem;background:linear-gradient(135deg,var(--panel) 0%,var(--panel2) 100%);">
    <div style="display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap;">
        <div>
            <?php if ($user['profile_image']): ?>
                <img src="<?= h('/img.php?f=' . basename($user['profile_image'])) ?>" class="profile-avatar" alt="Avatar">
            <?php else: ?>
                <div class="profile-avatar-placeholder"><?= h(strtoupper(substr($user['username'],0,1))) ?></div>
            <?php endif; ?>
        </div>
        <div style="flex:1;">
            <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-dim);letter-spacing:0.15em;margin-bottom:0.3rem;">// OPERATOR IDENTIFIED</div>
            <div style="font-family:var(--font-hud);font-size:1.6rem;font-weight:900;color:var(--gold);letter-spacing:0.1em;text-shadow:0 0 20px rgba(255,215,0,0.5);">
                <?= h(strtoupper($user['username'])) ?>
            </div>
            <?php if ($user['full_name']): ?>
                <div style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-dim);margin-top:0.2rem;"><?= h($user['full_name']) ?></div>
            <?php endif; ?>
            <div style="margin-top:0.8rem;">
                <span class="balance-badge" style="font-size:1rem;">₹<?= number_format($user['balance'], 2) ?></span>
                <span style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-dim);margin-left:0.8rem;letter-spacing:0.1em;">AVAILABLE FUNDS</span>
            </div>
        </div>
        <div style="display:flex;gap:0.8rem;flex-wrap:wrap;">
            <a href="/transfer.php" class="btn btn-primary">⚡ TRANSFER</a>
            <a href="/profile.php" class="btn btn-secondary">EDIT PROFILE</a>
        </div>
    </div>
</div>

<!-- STATS -->
<div class="grid-3" style="margin-bottom:1.8rem;">
    <div class="stat-box">
        <div class="val"><?= (int)($sentCount + $recvCount) ?></div>
        <div class="lbl">Total Ops</div>
    </div>
    <div class="stat-box">
        <div class="val" style="color:var(--red);text-shadow:0 0 20px rgba(255,0,64,0.5);">₹<?= number_format($totalSent,0) ?></div>
        <div class="lbl">Total Sent</div>
    </div>
    <div class="stat-box">
        <div class="val" style="color:var(--green);text-shadow:0 0 20px rgba(0,255,136,0.5);">₹<?= number_format($totalRecv,0) ?></div>
        <div class="lbl">Total Received</div>
    </div>
</div>

<!-- RECENT TX -->
<div class="card">
    <div class="card-title">Recent Combat Ledger</div>
    <?php if (empty($recentTx)): ?>
        <div style="text-align:center;padding:2rem;font-family:var(--font-mono);color:var(--text-dim);">
            <div style="font-size:2rem;margin-bottom:0.5rem;">📡</div>
            // NO TRANSACTIONS FOUND &nbsp;&mdash;&nbsp;
            <a href="/transfer.php" style="color:var(--cyan);">INITIATE FIRST TRANSFER →</a>
        </div>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <thead><tr><th>Timestamp</th><th>From</th><th>To</th><th>Amount</th><th>Note</th></tr></thead>
            <tbody>
            <?php foreach ($recentTx as $tx): ?>
                <tr>
                    <td style="color:var(--text-dim);"><?= h(date('d M Y H:i', strtotime($tx['created_at']))) ?></td>
                    <td><?php if ((int)$tx['sender_id'] === (int)$user['id']): ?><span style="color:var(--cyan);font-family:var(--font-mono);">YOU</span><?php else: ?><a href="/view_profile.php?token=<?= h($tx['sender_token']??'') ?>"><?= h($tx['sender_name']) ?></a><?php endif; ?></td>
                    <td><?php if ((int)$tx['receiver_id'] === (int)$user['id']): ?><span style="color:var(--cyan);font-family:var(--font-mono);">YOU</span><?php else: ?><a href="/view_profile.php?token=<?= h($tx['receiver_token']??'') ?>"><?= h($tx['receiver_name']) ?></a><?php endif; ?></td>
                    <td><?php if ((int)$tx['sender_id'] === (int)$user['id']): ?><span class="tx-sent">-₹<?= number_format($tx['amount'],2) ?></span><?php else: ?><span class="tx-recv">+₹<?= number_format($tx['amount'],2) ?></span><?php endif; ?></td>
                    <td><?php if ($tx['comment']): ?><div class="comment-bubble"><?= h($tx['comment']) ?></div><?php else: ?><span style="color:var(--text-muted);">—</span><?php endif; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div style="margin-top:1rem;text-align:right;">
        <a href="/transactions.php" class="btn btn-secondary btn-sm">VIEW FULL LEDGER →</a>
    </div>
    <?php endif; ?>
</div>

<div style="display:flex;gap:1rem;flex-wrap:wrap;">
    <a href="/transfer.php" class="btn btn-primary">⚡ TRANSFER FUNDS</a>
    <a href="/transactions.php" class="btn btn-secondary">📋 FULL LEDGER</a>
    <a href="/search.php" class="btn btn-secondary">🔍 RECON</a>
</div>
<?php include 'footer.php'; ?>
