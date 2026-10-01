import express from 'express';
import session from 'express-session';
import multer from 'multer';
import ejs from 'ejs';
import { S3Client } from '@aws-sdk/client-s3';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { runCommandLab } from './command-lab.js';
import { labPasswordHash, vulnerableLogin } from './login.js';
import { vulnerablePreview } from './ssrf.js';
import { openDatabase } from './database.js';
import { createFileStore } from './files.js';
import { runUploadedFile } from './file-runner.js';
import { loadSecrets } from './secrets.js';
const root = path.dirname(fileURLToPath(import.meta.url));
const limit = 5 * 1024 * 1024;
await loadSecrets();
if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET 또는 SECRETS_MANAGER_SECRET_ID 설정이 필요합니다.');
if (!process.env.S3_BUCKET) throw new Error('S3_BUCKET 설정이 필요합니다.');

const db = await openDatabase();
const s3 = new S3Client({ region: process.env.AWS_REGION || 'ap-northeast-2' });
const files = createFileStore({ s3, bucket: process.env.S3_BUCKET, prefix: process.env.S3_PREFIX || 'whs-uploads/' });
class MysqlSessionStore extends session.Store {
  constructor(pool) { super(); this.pool = pool; }
  get(id, callback) {
    this.pool.execute('SELECT data FROM sessions WHERE session_id = ? AND expires > ?', [id, Date.now()])
      .then(([rows]) => callback(null, rows[0] ? JSON.parse(rows[0].data) : null), callback);
  }
  set(id, value, callback = () => {}) {
    const expires = value.cookie?.expires ? new Date(value.cookie.expires).getTime() : Date.now() + (value.cookie?.originalMaxAge || 3600000);
    this.pool.execute('INSERT INTO sessions (session_id, expires, data) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE expires = VALUES(expires), data = VALUES(data)', [id, expires, JSON.stringify(value)])
      .then(() => callback(null), callback);
  }
  touch(id, value, callback = () => {}) {
    const expires = value.cookie?.expires ? new Date(value.cookie.expires).getTime() : Date.now() + (value.cookie?.originalMaxAge || 3600000);
    this.pool.execute('UPDATE sessions SET expires = ? WHERE session_id = ?', [expires, id]).then(() => callback(null), callback);
  }
  destroy(id, callback = () => {}) {
    this.pool.execute('DELETE FROM sessions WHERE session_id = ?', [id]).then(() => callback(null), callback);
  }
}
const sessionStore = new MysqlSessionStore(db);
async function findUser(column, value) {
  const [rows] = await db.execute(`SELECT * FROM users WHERE ${column === 'id' ? 'id' : 'email'} = ?`, [value]);
  return rows[0];
}
const publicUser = user => ({ id: user.id, name: user.name, email: user.email, avatar: user.avatar || null });
const fail = (status, message) => Object.assign(new Error(message), { status });
const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" });
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  // 브라우저의 다른 사이트가 폼을 몰래 제출하는 것을 막습니다. CORS를 열지 않습니다.
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('X-WHS-Request') !== '1') return res.status(403).json({ error: '허용되지 않은 요청입니다.' });
  next();
});
app.use(express.json({ limit: '8kb' }));
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, store: sessionStore,
  cookie: { maxAge: 3600000 } }));
app.get('/api/health', (req, res) => res.json({ ok: true, database: 'mysql', storage: 's3', vulnerableLab: true, commandLab: true }));
app.get('/api/me', async (req, res) => {
  const user = req.session.userId ? await findUser('id', req.session.userId) : null;
  res.json({ user: user ? publicUser(user) : null });
});
function credentials(body) {
  if (typeof body?.email !== 'string' || typeof body?.password !== 'string') throw fail(400, '이메일과 비밀번호를 입력하세요.');
  const email = body.email.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || body.password.length < 8 || body.password.length > 128) throw fail(400, '이메일 형식과 비밀번호 길이(8~128자)를 확인하세요.');
  return { email, password: body.password };
}
app.post('/api/register', async (req, res) => {
  const { email, password } = credentials(req.body);
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (!name || name.length > 50) throw fail(400, '이름은 1~50자로 입력하세요.');
  if (await findUser('email', email)) throw fail(409, '이미 가입된 이메일입니다.');
  const user = { id: randomUUID(), email, name, password_hash: labPasswordHash(password), avatar: null };
  await db.execute('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)', [user.id, email, name, user.password_hash]);
  res.status(201).json({ message: '가입했습니다. 로그인해 주세요.' });
});
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string' || !email || !password || email.length > 254 || password.length > 128) throw fail(400, '아이디와 비밀번호를 입력하세요.');
  const user = await vulnerableLogin(db, email, password);
  if (!user) throw fail(401, '이메일 또는 비밀번호가 다릅니다.');
  await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});
app.post('/api/logout', (req, res, next) => req.session.destroy(error => {
  if (error) return next(error);
  res.clearCookie('connect.sid').json({ message: '로그아웃했습니다.' });
}));
app.use('/api', async (req, res, next) => {
  const user = req.session.userId ? await findUser('id', req.session.userId) : null;
  if (!user) return res.status(401).json({ error: '먼저 로그인해 주세요.' });
  req.user = user;
  next();
});
// 위 로그인 검사 뒤에 등록해 로그인한 팀원만 가입 목록을 조회할 수 있게 합니다.
// 필요한 두 열만 SELECT하므로 이메일, UUID, 비밀번호 해시는 응답에 포함되지 않습니다.
app.get('/api/users', async (req, res) => {
  const [users] = await db.execute('SELECT name, created_at FROM users ORDER BY created_at DESC, id ASC');
  res.json({ users });
});
// 로그인한 사용자만 접근합니다. 명령은 웹앱을 실행한 EC2 사용자 권한으로 직접 실행됩니다.
app.post('/api/labs/os-command', async (req, res) => {
  res.json(await runCommandLab(req.body?.input));
});
app.post('/api/labs/ssti', (req, res) => {
  const template = req.body?.template;
  if (typeof template !== 'string' || !template || template.length > 2048) {
    throw fail(400, '템플릿을 1~2048자로 입력하세요.');
  }
  // 의도적인 SSTI: 사용자 입력을 서버에서 EJS 템플릿으로 실행합니다.
  res.json({ result: ejs.render(template, { name: req.user.name }) });
});
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: limit, files: 1, fields: 0 } });
app.post('/api/files', upload.single('file'), async (req, res) => {
  if (!req.file) throw fail(400, '파일을 선택하세요.');
  res.status(201).json(await files.save(req.user.id, req.file));
});
app.get('/api/files', async (req, res) => {
  res.json(await files.list(req.user.id, req.query.cursor));
});
// 사용자 UUID는 세션에서 확인한 req.user.id를 사용합니다.
// 클라이언트가 다른 사용자 key를 보내면 파일 저장소가 S3 요청 전에 거부합니다.
app.delete('/api/files', async (req, res) => {
  await files.remove(req.user.id, req.body?.key);
  res.json({ message: '파일을 삭제했습니다.' });
});
app.post('/api/files/execute', async (req, res) => {
  const file = await files.readExecutable(req.user.id, req.body?.key);
  res.json(await runUploadedFile(file));
});
app.post('/api/images/preview', async (req, res) => {
  delete req.session.preview;
  const result = await vulnerablePreview(req.body?.url);
  if (result.image) req.session.preview = result.image;
  res.json(result);
});
app.post('/api/profile/image', async (req, res) => {
  const avatar = req.session.preview;
  if (!avatar) throw fail(400, '먼저 이미지 URL을 미리보기 하세요.');
  await db.execute('UPDATE users SET avatar = ? WHERE id = ?', [avatar, req.user.id]);
  delete req.session.preview;
  res.json({ image: avatar });
});
app.use('/api', (req, res) => res.status(404).json({ error: '없는 API입니다.' }));
app.use(express.static(path.join(root, 'public')));
app.use((error, req, res, next) => {
  if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '이미 가입된 이메일입니다.' });
  const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : error instanceof multer.MulterError ? 400 : error.status || 500;
  if (status >= 500) console.error(JSON.stringify({ event: 'request_error', path: req.path, code: error.code || error.name }));
  res.status(status).json({ error: error.code === 'LIMIT_FILE_SIZE' ? '파일은 최대 5MB입니다.' : status >= 500 ? '처리하지 못했습니다. 서버 설정과 연결 상태를 확인하세요.' : error.message });
});
const server = app.listen(Number(process.env.PORT || 3000), process.env.HOST || '127.0.0.1', (error) => {
  if (error) { console.error('서버 실행 실패:', error.code); process.exit(1); }
  console.log(`WHS-Cloud9-Vuln-Web: http://${process.env.HOST || '127.0.0.1'}:${server.address().port} (RDS MySQL, S3)`);
});
