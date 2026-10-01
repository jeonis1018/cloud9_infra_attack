import { createHash } from 'node:crypto';

export const labPasswordHash = password => createHash('sha256').update(password).digest('hex');

export async function vulnerableLogin(db, email, password) {
  // 의도적인 SQLi: 사용자 입력을 RDS MySQL 쿼리에 직접 붙입니다.
  // SHA-256은 이 취약점 실습용 저장 방식입니다. 운영 인증 서비스에 사용하지 마세요.
  const [rows] = await db.query(`SELECT * FROM users WHERE email = '${email}' AND password_hash = '${labPasswordHash(password)}' LIMIT 1`);
  return rows[0];
}
