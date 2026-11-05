import express from 'express';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'change-this-secret-in-production';

const UPLOADS = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS);

// ---------- БД ----------
const db = new Database(path.join(__dirname, 'database.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, role TEXT DEFAULT 'USER', avatar TEXT, createdAt INTEGER
  );
  CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, filename TEXT NOT NULL,
    isShort INTEGER DEFAULT 0, views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0, 
    status TEXT DEFAULT 'OK', authorId TEXT NOT NULL, createdAt INTEGER,
    FOREIGN KEY(authorId) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY, videoId TEXT NOT NULL, userId TEXT NOT NULL, text TEXT NOT NULL,
    createdAt INTEGER, FOREIGN KEY(videoId) REFERENCES videos(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS subscriptions (
    subscriberId TEXT, channelId TEXT, PRIMARY KEY(subscriberId, channelId)
  );
`);

const adminExists = db.prepare("SELECT id FROM users WHERE role='ADMIN'").get();
if (!adminExists) {
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO users (id, username, email, password, role, createdAt)
              VALUES (?, 'admin', 'admin@test.com', ?, 'ADMIN', ?)`)
    .run(id, bcrypt.hashSync('admin123', 10), Date.now());
  console.log('✅ Админ создан: admin@test.com / admin123');
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + (path.extname(file.originalname) || '.mp4'))
});
const upload = multer({ storage, limits: { fileSize: 2 * 1024 * 1024 * 1024 } });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS));

function auth(roles = []) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Нет токена' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(payload.role)) return res.status(403).json({ error: 'Нет доступа' });
      req.user = payload; next();
    } catch { res.status(401).json({ error: 'Невалидный токен' }); }
  };
}

// --- API ---
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполните поля' });
  if (db.prepare('SELECT id FROM users WHERE email=? OR username=?').get(email, username)) 
    return res.status(409).json({ error: 'Занято' });

  const id = crypto.randomUUID();
  const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random&color=fff&size=128`;
  db.prepare(`INSERT INTO users (id, username, email, password, avatar, createdAt) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, username, email, bcrypt.hashSync(password, 10), avatar, Date.now());

  const token = jwt.sign({ id, username, role: 'USER', avatar }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, username, email, role: 'USER', avatar } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Неверные данные' });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, avatar: user.avatar }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, avatar: user.avatar } });
});

app.post('/api/change-password', auth(), (req, res) => {
  if (!req.body.newPassword || req.body.newPassword.length < 4) return res.status(400).json({ error: 'Короткий пароль' });
  db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(req.body.newPassword, 10), req.user.id);
  res.json({ ok: true });
});

app.get('/api/videos', (req, res) => {
  const { type, q } = req.query;
  let sql = `SELECT v.*, u.username AS authorName, u.avatar FROM videos v JOIN users u ON u.id = v.authorId WHERE v.status='OK'`;
  const params = [];
  if (q) { sql += ` AND LOWER(v.title) LIKE ?`; params.push('%' + q.toLowerCase() + '%'); }
  if (type === 'short') sql += ` AND v.isShort=1`;
  else if (type === 'video') sql += ` AND v.isShort=0`;
  
  res.json(db.prepare(sql + ` ORDER BY v.createdAt DESC`).all(...params));
});

app.get('/api/videos/:id', (req, res) => {
  const v = db.prepare(`SELECT v.*, u.username AS authorName, u.avatar FROM videos v JOIN users u ON u.id = v.authorId WHERE v.id=?`).get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Нет видео' });
  db.prepare('UPDATE videos SET views = views + 1 WHERE id=?').run(v.id);
  const comments = db.prepare(`SELECT c.*, u.username AS authorName, u.avatar FROM comments c JOIN users u ON u.id = c.userId WHERE c.videoId=? ORDER BY c.createdAt ASC`).all(v.id);
  res.json({ ...v, views: v.views + 1, comments });
});

app.post('/api/videos', auth(), upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Нет файла' });
  const { title, description, isShort } = req.body;
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO videos (id, title, description, filename, isShort, authorId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, title, description, req.file.filename, isShort === 'true' ? 1 : 0, req.user.id, Date.now());
  res.json({ id });
});

app.post('/api/videos/:id/like', auth(), (req, res) => {
  db.prepare('UPDATE videos SET likes = likes + 1 WHERE id=?').run(req.params.id); res.json({ ok: true });
});

app.post('/api/videos/:id/comment', auth(), (req, res) => {
  if (!req.body.text) return res.status(400).json({ error: 'Пусто' });
  db.prepare(`INSERT INTO comments (id, videoId, userId, text, createdAt) VALUES (?, ?, ?, ?, ?)`)
    .run(crypto.randomUUID(), req.params.id, req.user.id, req.body.text, Date.now());
  res.json({ ok: true });
});

// --- АДМИН ---
app.get('/api/admin/videos', auth(['ADMIN']), (req, res) => {
  res.json(db.prepare(`SELECT v.*, u.username AS authorName FROM videos v JOIN users u ON u.id = v.authorId ORDER BY v.createdAt DESC`).all());
});
app.get('/api/admin/users', auth(['ADMIN']), (req, res) => {
  res.json(db.prepare('SELECT id, username, email, role FROM users').all());
});
app.patch('/api/admin/videos/:id', auth(['ADMIN']), upload.single('video'), (req, res) => {
  const v = db.prepare('SELECT * FROM videos WHERE id=?').get(req.params.id);
  if (!v) return res.status(404).json({ error: '404' });
  let newFilename = v.filename;
  if (req.file) { fs.unlinkSync(path.join(UPLOADS, v.filename)); newFilename = req.file.filename; }
  db.prepare(`UPDATE videos SET title=?, description=?, status=?, filename=? WHERE id=?`)
    .run(req.body.title || v.title, req.body.description || v.description, req.body.status || v.status, newFilename, v.id);
  res.json({ ok: true });
});
app.delete('/api/admin/videos/:id', auth(['ADMIN']), (req, res) => {
  const v = db.prepare('SELECT filename FROM videos WHERE id=?').get(req.params.id);
  if (v) { fs.unlinkSync(path.join(UPLOADS, v.filename)); db.prepare('DELETE FROM videos WHERE id=?').run(req.params.id); }
  res.json({ ok: true });
});
app.delete('/api/admin/users/:id', auth(['ADMIN']), (req, res) => {
  if (req.params.id !== req.user.id) db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`✅ Сервер: http://localhost:${PORT}`));
