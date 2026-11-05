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
const PORT = 3000;
const JWT_SECRET = 'change-this-secret-in-production';

// ---------- Папки ----------
const UPLOADS = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS);

// ---------- БД ----------
const db = new Database(path.join(__dirname, 'database.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'USER',
    createdAt INTEGER
  );
  CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    filename TEXT NOT NULL,
    duration REAL DEFAULT 0,
    size INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    status TEXT DEFAULT 'OK',
    authorId TEXT NOT NULL,
    createdAt INTEGER,
    FOREIGN KEY(authorId) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    videoId TEXT NOT NULL,
    userId TEXT NOT NULL,
    text TEXT NOT NULL,
    createdAt INTEGER,
    FOREIGN KEY(videoId) REFERENCES videos(id) ON DELETE CASCADE,
    FOREIGN KEY(userId) REFERENCES users(id)
  );
`);

// ---------- Админ по умолчанию ----------
const adminExists = db.prepare("SELECT id FROM users WHERE role='ADMIN'").get();
if (!adminExists) {
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO users (id, username, email, password, role, createdAt)
              VALUES (?, ?, ?, ?, 'ADMIN', ?)`)
    .run(id, 'admin', 'admin@test.com',
         bcrypt.hashSync('admin123', 10), Date.now());
  console.log('✅ Админ создан: admin@test.com / admin123');
}

// ---------- Multer: файл сразу на диск ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.mp4';
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 } // 2 ГБ на файл
});

// ---------- Middleware ----------
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS));

function auth(roles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Нет токена' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(payload.role))
        return res.status(403).json({ error: 'Нет доступа' });
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: 'Невалидный токен' });
    }
  };
}

// ---------- РЕГИСТРАЦИЯ ----------
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Заполните все поля' });
  if (username.length < 2) return res.status(400).json({ error: 'Имя слишком короткое' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль мин. 4 символа' });
  if (!email.includes('@')) return res.status(400).json({ error: 'Некорректный email' });

  const exists = db.prepare('SELECT id FROM users WHERE email=? OR username=?')
    .get(email, username);
  if (exists) return res.status(409).json({ error: 'Email или имя заняты' });

  const id = crypto.randomUUID();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`INSERT INTO users (id, username, email, password, role, createdAt)
              VALUES (?, ?, ?, ?, 'USER', ?)`)
    .run(id, username, email, hash, Date.now());

  const token = jwt.sign({ id, username, role: 'USER' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, username, email, role: 'USER' } });
});

// ---------- ВХОД ----------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Неверный email или пароль' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({
    token,
    user: { id: user.id, username: user.username, email: user.email, role: user.role }
  });
});

// ---------- СПИСОК ВИДЕО ----------
app.get('/api/videos', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const videos = db.prepare(`
    SELECT v.*, u.username AS authorName
    FROM videos v JOIN users u ON u.id = v.authorId
    WHERE LOWER(v.title) LIKE ?
    ORDER BY v.createdAt DESC
  `).all('%' + q + '%');

  const header = req.headers.authorization || '';
  let me = null;
  if (header.startsWith('Bearer ')) {
    try { me = jwt.verify(header.slice(7), JWT_SECRET); } catch {}
  }
  const filtered = videos.filter(v =>
    v.status !== 'BLOCKED' ||
    (me && (me.role === 'ADMIN' || me.id === v.authorId))
  );
  res.json(filtered);
});

// ---------- ОДНО ВИДЕО ----------
app.get('/api/videos/:id', (req, res) => {
  const v = db.prepare(`
    SELECT v.*, u.username AS authorName
    FROM videos v JOIN users u ON u.id = v.authorId
    WHERE v.id = ?
  `).get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Не найдено' });

  db.prepare('UPDATE videos SET views = views + 1 WHERE id = ?').run(v.id);

  const comments = db.prepare(`
    SELECT c.*, u.username AS authorName
    FROM comments c JOIN users u ON u.id = c.userId
    WHERE c.videoId = ? ORDER BY c.createdAt ASC
  `).all(v.id);

  res.json({ ...v, views: v.views + 1, comments });
});

// ---------- ЗАГРУЗКА ВИДЕО ----------
app.post('/api/videos', auth(), upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });
  const { title, description } = req.body;
  if (!title) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Нужно название' });
  }

  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO videos
    (id, title, description, filename, size, authorId, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, title, description || '', req.file.filename,
         req.file.size, req.user.id, Date.now());

  res.json({ id, title });
});

// ---------- РЕДАКТИРОВАТЬ ВИДЕО ----------
app.patch('/api/videos/:id', auth(), upload.single('video'), (req, res) => {
  const v = db.prepare('SELECT * FROM videos WHERE id=?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Не найдено' });
  const canEdit = req.user.role === 'ADMIN' || req.user.id === v.authorId;
  if (!canEdit) return res.status(403).json({ error: 'Нет прав' });

  const { title, description, status } = req.body;
  const newTitle = title !== undefined ? title : v.title;
  const newDesc  = description !== undefined ? description : v.description;
  const newStatus = req.user.role === 'ADMIN' && status ? status : v.status;

  let newFilename = v.filename;
  if (req.file) {
    const oldPath = path.join(UPLOADS, v.filename);
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    newFilename = req.file.filename;
  }

  db.prepare(`UPDATE videos SET title=?, description=?, status=?, filename=?
              WHERE id=?`)
    .run(newTitle, newDesc, newStatus, newFilename, v.id);
  res.json({ ok: true });
});

// ---------- УДАЛИТЬ ВИДЕО ----------
app.delete('/api/videos/:id', auth(), (req, res) => {
  const v = db.prepare('SELECT * FROM videos WHERE id=?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Не найдено' });
  if (req.user.role !== 'ADMIN' && req.user.id !== v.authorId)
    return res.status(403).json({ error: 'Нет прав' });

  const fp = path.join(UPLOADS, v.filename);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  db.prepare('DELETE FROM comments WHERE videoId=?').run(v.id);
  db.prepare('DELETE FROM videos WHERE id=?').run(v.id);
  res.json({ ok: true });
});

// ---------- ЛАЙК ----------
app.post('/api/videos/:id/like', auth(), (req, res) => {
  db.prepare('UPDATE videos SET likes = likes + 1 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- КОММЕНТАРИЙ ----------
app.post('/api/videos/:id/comment', auth(), (req, res) => {
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Пусто' });
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO comments (id, videoId, userId, text, createdAt)
              VALUES (?, ?, ?, ?, ?)`)
    .run(id, req.params.id, req.user.id, text.trim(), Date.now());
  res.json({ ok: true });
});

// ---------- АДМИН: пользователи ----------
app.get('/api/admin/users', auth(['ADMIN']), (req, res) => {
  const users = db.prepare(
    'SELECT id, username, email, role, createdAt FROM users ORDER BY createdAt'
  ).all();
  res.json(users);
});

app.delete('/api/admin/users/:id', auth(['ADMIN']), (req, res) => {
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: 'Нельзя удалить себя' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- СТАРТ ----------
app.listen(PORT, () => {
  console.log(`\n✅ Сервер: http://localhost:${PORT}`);
  console.log(`📁 Видео хранятся в: ${UPLOADS}`);
  console.log(`💾 База данных: database.db\n`);
});