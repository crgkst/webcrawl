CREATE DATABASE IF NOT EXISTS crawler_db;
USE crawler_db;

CREATE TABLE IF NOT EXISTS websites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    parent_url TEXT,
    domain VARCHAR(255),
    link_count INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    content LONGTEXT,
    status VARCHAR(20) DEFAULT 'pending',
    website_id INT,
    FOREIGN KEY (website_id) REFERENCES websites(id)
);

CREATE TABLE IF NOT EXISTS emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    source_url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    reason VARCHAR(255),
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Safely add index on the domain column of the websites table
SET @exist := (SELECT COUNT(*)
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
    AND table_name = 'websites'
    AND index_name = 'idx_website_domain');

SET @sqlstmt := IF(@exist > 0, 'SELECT ''Index already exists.''',
    'CREATE INDEX idx_website_domain ON websites(domain)');

PREPARE stmt FROM @sqlstmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
