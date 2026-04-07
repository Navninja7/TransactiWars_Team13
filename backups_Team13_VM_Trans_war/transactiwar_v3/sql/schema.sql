-- TransactiWar — Fortress Database Schema

CREATE DATABASE IF NOT EXISTS transactiwar;
USE transactiwar;

-- SECURITY: balance has DB-level CHECK constraint — cannot go negative
-- even if application logic is bypassed
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)   NOT NULL UNIQUE,
    email         VARCHAR(255)  NOT NULL UNIQUE,
    password_hash VARCHAR(255)  NOT NULL,
    balance       DECIMAL(15,2) NOT NULL DEFAULT 100.00 CHECK (balance >= 0),
    bio           TEXT          DEFAULT NULL,
    profile_image VARCHAR(255)  DEFAULT NULL,
    full_name     VARCHAR(100)  DEFAULT NULL,
    public_token  VARCHAR(64)   NOT NULL DEFAULT '' UNIQUE,
    is_locked     TINYINT(1)    NOT NULL DEFAULT 0,
    session_token VARCHAR(64)   DEFAULT NULL,
    created_at    DATETIME      DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_public_token (public_token)
);

-- SECURITY: amount CHECK ensures no zero or negative transfers at DB level
CREATE TABLE IF NOT EXISTS transactions (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    sender_id   INT           NOT NULL,
    receiver_id INT           NOT NULL,
    amount      DECIMAL(15,2) NOT NULL CHECK (amount > 0),
    comment     TEXT          DEFAULT NULL,
    created_at  DATETIME      DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id)   REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id),
    INDEX idx_sender   (sender_id),
    INDEX idx_receiver (receiver_id),
    INDEX idx_created  (created_at)
);

-- Activity log: Webpage, Username, Timestamp, IP — required by spec
CREATE TABLE IF NOT EXISTS activity_logs (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    webpage    VARCHAR(255) NOT NULL,
    username   VARCHAR(50)  DEFAULT 'guest',
    ip_address VARCHAR(45)  NOT NULL,
    logged_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username  (username),
    INDEX idx_logged_at (logged_at),
    INDEX idx_ip        (ip_address)
);

-- Rate limiting table (sliding window, no Redis needed)
CREATE TABLE IF NOT EXISTS rate_limits (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    bucket     VARCHAR(64)  NOT NULL,
    `key`      VARCHAR(255) NOT NULL,
    created_at INT          NOT NULL,
    INDEX idx_bucket_key (bucket, `key`, created_at)
);
