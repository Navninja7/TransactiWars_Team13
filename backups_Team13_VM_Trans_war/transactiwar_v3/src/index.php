<?php
require_once 'session_init.php';
require_once 'config.php';
$loggedIn = !empty($_SESSION['user_id']);
if ($loggedIn) { redirect('/dashboard.php'); }
logActivity('index.php', 'guest');
$pageTitle = 'Welcome';
include 'header.php';
?>
<div class="hero">
    <div class="hero-eyebrow"><span>■</span> SYSTEM ONLINE <span>■</span></div>
    <h1 class="hero-title glitch" data-text="TRANSACTIWAR">TRANSACTIWAR</h1>
    <div class="hero-sub">DIGITAL FINANCIAL WARFARE</div>
    <div class="hero-tag">BATTLE FOR SUPREMACY &nbsp;<span>■</span>&nbsp; CS6903 NETWORK SECURITY &nbsp;<span>■</span>&nbsp; IIT HYDERABAD</div>
    <div style="display:flex;justify-content:center;gap:1.2rem;flex-wrap:wrap;margin-bottom:4rem;">
        <a href="/register.php" class="btn btn-primary">⚡ ENLIST NOW</a>
        <a href="/login.php" class="btn btn-secondary">⌨ AUTHENTICATE</a>
    </div>
    <div class="grid-3" style="max-width:720px;margin:0 auto;">
        <div class="stat-box" style="border-color:rgba(255,215,0,0.35);background:linear-gradient(160deg,rgba(255,215,0,0.07),var(--panel));">
            <div class="val" style="font-size:2rem;color:var(--gold);text-shadow:0 0 20px rgba(255,215,0,0.7);">₹</div>
            <div class="lbl" style="color:var(--gold);letter-spacing:0.16em;">Transfer Funds</div>
        </div>
        <div class="stat-box" style="border-color:rgba(255,0,64,0.35);background:linear-gradient(160deg,rgba(255,0,64,0.07),var(--panel));">
            <div class="val" style="font-size:2rem;color:var(--red);text-shadow:0 0 20px rgba(255,0,64,0.7);">⚔</div>
            <div class="lbl" style="color:var(--red);letter-spacing:0.16em;">Dominate Rivals</div>
        </div>
        <div class="stat-box" style="border-color:rgba(0,245,255,0.35);background:linear-gradient(160deg,rgba(0,245,255,0.07),var(--panel));">
            <div class="val" style="font-size:2rem;color:var(--cyan);text-shadow:0 0 20px rgba(0,245,255,0.7);">🛡</div>
            <div class="lbl" style="color:var(--cyan);letter-spacing:0.16em;">Secure Ops</div>
        </div>
    </div>
</div>
<?php include 'footer.php'; ?>
