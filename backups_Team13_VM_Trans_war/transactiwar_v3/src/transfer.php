<?php
require_once 'session_init.php';
$user = requireLogin();
logActivity('transfer.php', $user['username']);
$errors = []; $success = '';
$prefilledId = filter_input(INPUT_GET, 'to', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid request.';
    } else {
        //rotateCSRFToken();

        if (!rateLimit('transfer', (string)$user['id'], 30, 3600)) {
            $errors[] = 'Transfer rate limit exceeded. Please try again later.';
        } else {
            $receiverId = filter_input(INPUT_POST, 'receiver_id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
            $amountRaw  = $_POST['amount'] ?? '';
            $comment    = trim($_POST['comment'] ?? '');

            if (!$receiverId || $receiverId <= 0) $errors[] = 'Invalid receiver ID.';
            if ($receiverId && (int)$receiverId === (int)$user['id']) $errors[] = 'Cannot transfer to yourself.';
            // SECURITY: Strict amount validation — no scientific notation, no negative
            if (!is_string($amountRaw) || !preg_match('/^\d+(\.\d{1,2})?$/', $amountRaw))
                $errors[] = 'Invalid amount format.';
            $amount = round((float)$amountRaw, 2);
            if ($amount <= 0 || $amount > 1000000)
                $errors[] = 'Amount must be between ₹0.01 and ₹10,00,000.';
            // SECURITY: Sanitize comment — strip tags, limit length
            $comment = mb_substr(strip_tags($comment), 0, 500);

            if (empty($errors)) {
                $db   = getDB();
                $stmt = $db->prepare("SELECT id, username FROM users WHERE id = ?");
                $stmt->execute([$receiverId]);
                $receiver = $stmt->fetch();
                if (!$receiver) $errors[] = 'Invalid receiver. Please check the operator ID.';
            }

            if (empty($errors)) {
                $db = getDB();
                // SECURITY: SERIALIZABLE isolation prevents phantom reads and race conditions
                $db->exec("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
                $db->beginTransaction();
                try {
                    // SECURITY: Lock both rows in consistent order by ID to prevent deadlock
                    $lowId  = min((int)$user['id'], (int)$receiverId);
                    $highId = max((int)$user['id'], (int)$receiverId);
                    $stmt   = $db->prepare(
                        "SELECT id, balance FROM users WHERE id IN (?, ?) ORDER BY id FOR UPDATE"
                    );
                    $stmt->execute([$lowId, $highId]);
                    $lockedRows  = $stmt->fetchAll();
                    $lockedById  = [];
                    foreach ($lockedRows as $row) $lockedById[(int)$row['id']] = $row;

                    if ((int)$user['id'] === (int)$receiverId) {
                        $db->rollBack(); $errors[] = 'Cannot transfer to yourself.';
                    } elseif (!isset($lockedById[(int)$user['id']]) || !isset($lockedById[(int)$receiverId])) {
                        $db->rollBack(); $errors[] = 'Transfer failed. Please try again.';
                    } else {
                        $senderBalance = (float)$lockedById[(int)$user['id']]['balance'];
                        // SECURITY: No balance leak — generic message only
                        if ($senderBalance < $amount) {
                            $db->rollBack();
                            $errors[] = 'Insufficient balance. Please check your available funds.';
                        } else {
                            // SECURITY: Double-check balance in UPDATE condition (defense in depth)
                            $db->prepare(
                                "UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?"
                            )->execute([$amount, (int)$user['id'], $amount]);
                            $db->prepare(
                                "UPDATE users SET balance = balance + ? WHERE id = ?"
                            )->execute([$amount, (int)$receiverId]);
                            $db->prepare(
                                "INSERT INTO transactions (sender_id, receiver_id, amount, comment) VALUES (?, ?, ?, ?)"
                            )->execute([(int)$user['id'], (int)$receiverId, $amount, $comment !== '' ? $comment : null]);
                            $db->commit();
                            rotateCSRFToken();
                            // Refresh user balance from DB
                            $stmt = $db->prepare(
                                "SELECT id, username, email, balance, full_name, bio,
                                        profile_image, public_token, created_at
                                 FROM users WHERE id = ?"
                            );
                            $stmt->execute([(int)$user['id']]);
                            $user    = $stmt->fetch();
                            // FIX [LOW]: Don't call h() here — $success is already
                            // output via h($success) in the template, so wrapping
                            // the username in h() here causes double-encoding.
                            $success = sprintf('Successfully transferred ₹%.2f to %s!', $amount, $receiver['username']);
                        }
                    }
                } catch (Exception $e) {
                    if ($db->inTransaction()) $db->rollBack();
                    $errors[] = 'Transfer failed. Please try again.';
                }
            }
        }
    }
}

$prefilledUser = null;
if ($prefilledId) {
    $db   = getDB();
    $stmt = $db->prepare("SELECT id, username, full_name FROM users WHERE id = ?");
    $stmt->execute([$prefilledId]);
    $prefilledUser = $stmt->fetch();
}
$pageTitle = 'Transfer';
include 'header.php';
?>
<div class="page-heading">FUND TRANSFER</div>
<div class="grid-2">
    <div>
        <?php if ($success): ?><div class="alert alert-success"><?= h($success) ?></div><?php endif; ?>
        <?php foreach ($errors as $e): ?><div class="alert alert-error"><?= h($e) ?></div><?php endforeach; ?>
        <div class="card">
            <div class="card-title">INITIATE TRANSFER</div>
            <form method="POST" action="/transfer.php" novalidate autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= h(generateCSRFToken()) ?>">
                <div class="form-group">
                    <label>Target Operator ID</label>
                    <input type="number" name="receiver_id" class="form-control"
                           value="<?= $prefilledUser ? (int)$prefilledUser['id'] : '' ?>"
                           placeholder="Enter user ID" required min="1" max="999999999">
                    <?php if ($prefilledUser): ?>
                        <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--green);margin-top:0.4rem;">
                            // TARGET: <?= h(strtoupper($prefilledUser['username'])) ?>
                            <?php if ($prefilledUser['full_name']): ?> — <?= h($prefilledUser['full_name']) ?><?php endif; ?>
                        </div>
                    <?php endif; ?>
                </div>
                <div class="form-group">
                    <label>Amount (₹)</label>
                    <input type="number" name="amount" class="form-control"
                           placeholder="0.00" step="0.01" min="0.01" max="1000000" required>
                </div>
                <div class="form-group">
                    <label>Mission Note <span style="color:var(--text-muted);font-size:0.65rem;">(optional)</span></label>
                    <textarea name="comment" class="form-control"
                              placeholder="Reason for transfer..." maxlength="500" rows="3"></textarea>
                </div>
                <button type="submit" class="btn btn-primary btn-full">⚡ EXECUTE TRANSFER</button>
            </form>
        </div>
    </div>
    <div>
        <div class="card" style="background:linear-gradient(135deg,var(--panel),var(--panel2));">
            <div class="card-title">OPERATOR STATUS</div>
            <div style="text-align:center;padding:1.5rem 0;">
                <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-dim);letter-spacing:0.15em;margin-bottom:0.5rem;">// AVAILABLE FUNDS</div>
                <div style="font-family:var(--font-hud);font-size:2.5rem;font-weight:900;color:var(--gold);text-shadow:0 0 30px rgba(255,215,0,0.5);">₹<?= number_format($user['balance'], 2) ?></div>
            </div>
        </div>
        <div class="card">
            <div class="card-title">FIND TARGET</div>
            <p style="font-family:var(--font-mono);font-size:0.76rem;color:var(--text-dim);margin-bottom:1rem;line-height:1.5;">// Use recon to find the receiver's operator ID before initiating transfer.</p>
            <a href="/search.php" class="btn btn-secondary btn-full">🔍 RECON OPERATORS</a>
        </div>
    </div>
</div>
<?php include 'footer.php'; ?>
