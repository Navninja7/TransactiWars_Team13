# TransactiWar – Phase 1 Submission

**CS6903: Network Security, 2025-26**  
Department of Computer Science and Engineering  
Indian Institute of Technology Hyderabad  

---

## Overview

TransactiWar is a secure web application for peer-to-peer money transfers. It implements user authentication, session management, profile management, user search, and money transfers with comprehensive activity logging.

**Technologies Used:**
- Back-end: PHP 8.2 + MySQL 8.0
- Front-end: HTML5 / CSS3 / Vanilla JavaScript
- Containerization: Docker + Docker Compose

---

## Running with Docker

### Prerequisites
- Docker Engine 20.x+
- Docker Compose v2+

### Quick Start

```bash
# 1. Clone / extract the project
cd transactiwar

# 2. Build and start containers
docker compose up --build -d

# 3. Wait ~15 seconds for MySQL to initialize, then create test accounts
docker exec transactiwar_web php /var/www/html/create_accounts.php

# 4. Access the application
open http://localhost:8080
```

### Stopping

```bash
docker compose down        # stop containers
docker compose down -v     # stop and remove volumes (resets database)
```

### Rebuilding

```bash
docker compose up --build -d
```

---

## Application Access

| URL | Description |
|-----|-------------|
| `http://localhost:8080` | Landing page |
| `http://localhost:8080/register.php` | Register new account |
| `http://localhost:8080/login.php` | Login |
| `http://localhost:8080/dashboard.php` | Dashboard (authenticated) |
| `http://localhost:8080/transfer.php` | Transfer money |
| `http://localhost:8080/search.php` | Search users |
| `http://localhost:8080/profile.php` | Edit profile |
| `http://localhost:8080/transactions.php` | Transaction history |

---

## Test Accounts

Run `create_accounts.php` to seed the following accounts (each starts with ₹100):

| Username | Password      |
|----------|---------------|
| alice    | Alice@12345!   |
| bob      | Bob@12345!     |
| charlie  | Charlie@12345! |
| diana    | Diana@12345!   |
| eve      | Eve@12345!     |
| frank    | Frank@12345!   |
| grace    | Grace@12345!   |
| henry    | Henry@12345!   |
| iris     | Iris@12345!    |
| jack     | Jack@12345!    |

---

## Security Measures Implemented

### Authentication
- Passwords hashed with **bcrypt** (cost factor 13)
- Generic error messages to prevent username enumeration
- Session ID regenerated on login (prevents session fixation)

### Session Management
- `HttpOnly` cookie flag (mitigates XSS cookie theft)
- `SameSite=Strict` cookie flag (mitigates CSRF)
- Strict session mode enabled
- Session destroyed completely on logout

### CSRF Protection
- CSRF tokens on all state-changing forms
- `hash_equals()` for constant-time comparison

### SQL Injection Prevention
- All database queries use **PDO prepared statements** with parameterized queries
- No string interpolation in SQL

### XSS Prevention
- All output HTML-escaped with `htmlspecialchars()` (`ENT_QUOTES | ENT_HTML5`)
- Content-Security-Policy header set
- `X-Content-Type-Options: nosniff` header

### File Upload Security
- Magic byte validation using `finfo` (not just MIME from client)
- Random filenames (no user-controlled paths)
- PHP engine disabled in uploads directory via `.htaccess`
- File size limit enforced (2MB)
- Only JPEG, PNG, GIF, WEBP allowed

### Financial Security
- Database **transactions with SELECT FOR UPDATE** prevent race conditions / double-spend
- Balance checked atomically before deduction
- Negative balance prevention enforced at DB transaction level
- Self-transfer prevention

### HTTP Security Headers
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Activity Logging
Logs `<Webpage, Username, Timestamp, Client IP>` for every page access in the `activity_logs` table.

---

## Project Structure

```
transactiwar/
├── Dockerfile
├── docker-compose.yml
├── docker/
│   └── apache.conf
├── sql/
│   ├── schema.sql          # Database schema
│   └── seed.sql
├── src/                    # Web application root
│   ├── .htaccess
│   ├── config.php          # DB config, helpers, security utilities
│   ├── session_init.php    # Secure session setup
│   ├── header.php          # Shared navbar/header
│   ├── footer.php          # Shared footer
│   ├── index.php           # Landing page
│   ├── register.php        # User registration
│   ├── login.php           # Login
│   ├── logout.php          # Logout
│   ├── dashboard.php       # User dashboard
│   ├── profile.php         # Profile management
│   ├── view_profile.php    # View other user profiles
│   ├── search.php          # User search
│   ├── transfer.php        # Money transfer
│   ├── transactions.php    # Transaction history
│   ├── create_accounts.php # Auto account creation script
│   ├── css/
│   │   └── style.css
│   └── uploads/
│       └── profiles/       # Profile images (gitignored)
└── README.md
```

---

## Resources Referenced

- PHP Documentation: https://www.php.net/docs.php
- PDO Documentation: https://www.php.net/manual/en/book.pdo.php
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PHP password_hash(): https://www.php.net/manual/en/function.password-hash.php
- Docker Documentation: https://docs.docker.com/
- MySQL 8.0 Reference: https://dev.mysql.com/doc/refman/8.0/en/
- MDN HTTP Security Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
