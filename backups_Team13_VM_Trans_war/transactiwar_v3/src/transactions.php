<?php
require_once 'session_init.php';
$user = requireLogin();
logActivity('transactions.php', $user['username']);
$db = getDB();
$perPage = 20;
$page = max(1, min((int)($_GET['page'] ?? 1), 10000));
$offset = ($page - 1) * $perPage;
$stmt = $db->prepare("SELECT COUNT(*) FROM transactions WHERE sender_id=? OR receiver_id=?");
$stmt->execute([$user['id'],$user['id']]); $total = (int)$stmt->fetchColumn();
$totalPages = min((int)ceil($total / $perPage), 500);
$stmt = $db->prepare("
    SELECT t.id,t.sender_id,t.receiver_id,t.amount,t.comment,t.created_at,
           s.username AS sender_name, s.public_token AS sender_token,
           r.username AS receiver_name, r.public_token AS receiver_token
    FROM transactions t
    JOIN users s ON t.sender_id=s.id JOIN users r ON t.receiver_id=r.id
    WHERE t.sender_id=? OR t.receiver_id=?
    ORDER BY t.created_at DESC LIMIT ? OFFSET ?
");
$stmt->execute([$user['id'],$user['id'],$perPage,$offset]);
$transactions = $stmt->fetchAll();
$pageTitle = 'Ledger';
include 'header.php';
?>
<div class="page-heading">COMBAT LEDGER <span class="sub">// <?= (int)$total ?> TOTAL OPS RECORDED</span></div>
<div class="card">
    <div class="card-title">TRANSACTION HISTORY</div>
    <?php if (empty($transactions)): ?>
        <div style="text-align:center;padding:2rem;font-family:var(--font-mono);color:var(--text-dim);">
            <div style="font-size:2rem;margin-bottom:0.5rem;">📡</div>
            // NO TRANSACTIONS RECORDED YET
        </div>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <thead><tr><th>#</th><th>Timestamp</th><th>From</th><th>To</th><th>Amount</th><th>Note</th></tr></thead>
            <tbody>
            <?php foreach ($transactions as $tx): ?>
                <tr>
                    <td style="color:var(--text-muted);"><?= (int)$tx['id'] ?></td>
                    <td style="color:var(--text-dim);"><?= h(date('d M Y H:i',strtotime($tx['created_at']))) ?></td>
                    <td><?php if ((int)$tx['sender_id']===(int)$user['id']): ?><span style="color:var(--cyan);font-family:var(--font-mono);">YOU</span><?php else: ?><a href="/view_profile.php?token=<?= h($tx['sender_token']??'') ?>"><?= h($tx['sender_name']) ?></a><?php endif; ?></td>
                    <td><?php if ((int)$tx['receiver_id']===(int)$user['id']): ?><span style="color:var(--cyan);font-family:var(--font-mono);">YOU</span><?php else: ?><a href="/view_profile.php?token=<?= h($tx['receiver_token']??'') ?>"><?= h($tx['receiver_name']) ?></a><?php endif; ?></td>
                    <td><?php if ((int)$tx['sender_id']===(int)$user['id']): ?><span class="tx-sent">-₹<?= number_format($tx['amount'],2) ?></span><?php else: ?><span class="tx-recv">+₹<?= number_format($tx['amount'],2) ?></span><?php endif; ?></td>
                    <td><?php if ($tx['comment']): ?><div class="comment-bubble"><?= h($tx['comment']) ?></div><?php else: ?><span style="color:var(--text-muted);">—</span><?php endif; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php if ($totalPages > 1): ?>
    <div style="display:flex;gap:0.4rem;margin-top:1.2rem;flex-wrap:wrap;align-items:center;">
        <?php if ($page > 1): ?><a href="?page=1" class="btn btn-secondary btn-sm">« FIRST</a><a href="?page=<?= (int)($page-1) ?>" class="btn btn-secondary btn-sm">‹ PREV</a><?php endif; ?>
        <?php for ($p=max(1,$page-4); $p<=min($totalPages,$page+4); $p++): ?><a href="?page=<?= (int)$p ?>" class="btn btn-<?= $p===$page?'primary':'secondary' ?> btn-sm"><?= (int)$p ?></a><?php endfor; ?>
        <?php if ($page < $totalPages): ?><a href="?page=<?= (int)($page+1) ?>" class="btn btn-secondary btn-sm">NEXT ›</a><a href="?page=<?= (int)$totalPages ?>" class="btn btn-secondary btn-sm">LAST »</a><?php endif; ?>
    </div>
    <?php endif; ?>
    <?php endif; ?>
</div>
<?php include 'footer.php'; ?>
