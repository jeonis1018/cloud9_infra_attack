import mysql from 'mysql2/promise';
import { readFile } from 'node:fs/promises';

export async function openDatabase() {
  for (const key of ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_SSL_CA']) {
    if (!process.env[key]) throw new Error(`${key} 설정이 필요합니다.`);
  }

  return mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: { ca: await readFile(process.env.DB_SSL_CA, 'utf8'), rejectUnauthorized: true },
    connectionLimit: 5,
    multipleStatements: false
  });
}
