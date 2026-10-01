-- RDS MySQL에 접속한 뒤 직접 실행하세요. 서버가 자동 생성하지 않습니다.
CREATE DATABASE IF NOT EXISTS whs_cloud9 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE whs_cloud9;
CREATE TABLE IF NOT EXISTS users (
  id CHAR(36) PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  name VARCHAR(50) NOT NULL,
  password_hash VARCHAR(200) NOT NULL,
  avatar MEDIUMTEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- express-session 로그인 상태를 EC2 여러 대에서 공유합니다.
CREATE TABLE IF NOT EXISTS sessions (
  session_id VARCHAR(128) NOT NULL PRIMARY KEY,
  expires BIGINT UNSIGNED NOT NULL,
  data MEDIUMTEXT NOT NULL,
  INDEX sessions_expires_idx (expires)
);
