<?php
if (!isset($pageTitle)) $pageTitle = 'TransactiWar';
$loggedIn = !empty($_SESSION['user_id']);
$flash = getFlash();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= h($pageTitle) ?> — TRANSACTIWAR</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<div class="grid-bg"></div>
<nav class="navbar">
    <div class="nav-brand">
        <a href="/" class="glitch" data-text="TRANSACTIWAR">TRANSACTIWAR</a>
    </div>
    <div class="nav-links">
        <?php if ($loggedIn): ?>
            <a href="/dashboard.php">[ DASHBOARD ]</a>
            <a href="/transfer.php">[ TRANSFER ]</a>
            <a href="/transactions.php">[ LEDGER ]</a>
            <a href="/search.php">[ RECON ]</a>
            <a href="/profile.php">[ OPERATOR ]</a>
            <a href="/logout.php" class="nav-logout">[ DISCONNECT ]</a>
        <?php else: ?>
            <a href="/login.php">[ ACCESS ]</a>
            <a href="/register.php">[ ENLIST ]</a>
        <?php endif; ?>
    </div>
</nav>
<main class="container">
<?php if ($flash): ?>
    <div class="alert alert-<?= h($flash['type']) ?>"><?= h($flash['msg']) ?></div>
<?php endif; ?>
