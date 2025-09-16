// server.js
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import slugify from 'slugify';
import expressLayouts from 'express-ejs-layouts';
import crypto from 'crypto';
import cron from 'node-cron';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();

/* --- DB-path + se till att katalogen finns --- */
const DB_PATH = process.env.DB_PATH || 'helpdesk.db';

// När DB_PATH är absolut (/app/data/helpdesk.db) -> skapa /app/data
// När det är relativt (helpdesk.db) blir dir '.' och då gör vi inget.
const dbDir = path.dirname(DB_PATH);
if (dbDir && dbDir !== '.' && !fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

/* --- Öppna databasen EFTER att katalogen finns --- */
const db = new Database(DB_PATH);

// --- Partner API endpoints + keys ---
const DEALER_APIS = [
  { source: 'nms',   url: 'https://portal.nmstuning.se/api/dealers',        apiKey: 'jNtCK7Z5qR8sqnxN5LpkdF5hJQqJ9m' },
  { source: 'dynex', url: 'https://portal.dynexperformance.se/api/dealers', apiKey: '04d87a25-3711-11f0-88c2-ac1f6bad7482' },
];

// MD5 helper
function md5(s) {
  return crypto.createHash('md5').update(String(s), 'utf8').digest('hex');
}

// Normalisera ett dealer-record från API:t
function normalizeDealer(rec) {
  return {
    dealer_id: rec.ID || '',
    email: (rec.email || '').trim().toLowerCase(),
    username: rec.username || '',
    company: rec.company || '',
    firstname: rec.firstname || '',
    lastname: rec.lastname || '',
    telephone: rec.telephone || null,
    added: rec.added || null,
  };
}

/* --- SQLite setup + bootstrap --- */
/* --- SQLite setup + bootstrap --- */
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initSchemaAndSeed() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      icon TEXT,
      sort_order INTEGER
    );

    -- Viktigt: EN version av topics_base, med kolumnen inkluderad
    CREATE TABLE IF NOT EXISTS topics_base (
      id TEXT PRIMARY KEY,
      created_by INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      answer_for_question_id INTEGER,
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS topics (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      excerpt TEXT,
      body TEXT,
      tags TEXT,
      is_resource INTEGER DEFAULT 0,
      download_url TEXT,
      FOREIGN KEY(id) REFERENCES topics_base(id) ON DELETE CASCADE
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS topics_fts USING fts5(
      id UNINDEXED, title, excerpt, body, content=''
    );

    CREATE TABLE IF NOT EXISTS topic_category (
      topic_id TEXT NOT NULL,
      category_id TEXT NOT NULL,
      PRIMARY KEY (topic_id, category_id),
      FOREIGN KEY(topic_id) REFERENCES topics_base(id) ON DELETE CASCADE,
      FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT NOT NULL,
      body TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS question_topic (
      question_id INTEGER NOT NULL,
      topic_id TEXT NOT NULL,
      PRIMARY KEY (question_id, topic_id),
      FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE,
      FOREIGN KEY(topic_id) REFERENCES topics_base(id) ON DELETE CASCADE
    );
  `);

  // ---- Liten migrations-hjälpare (för befintliga DB-filer) ----
  function hasColumn(table, col){
    const row = db.prepare(`PRAGMA table_info(${table})`).all()
      .find(r => r.name === col);
    return !!row;
  }
  function addColumnIfMissing(table, col, ddl){
    if (!hasColumn(table, col)) {
      db.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${ddl}`).run();
      console.log(`[DB:migration] ${table}.${col} added (${ddl})`);
    }
  }
  addColumnIfMissing('topics_base', 'answer_for_question_id', 'INTEGER');
  addColumnIfMissing('topics', 'is_resource', 'INTEGER DEFAULT 0');
  addColumnIfMissing('topics', 'download_url', 'TEXT');
  addColumnIfMissing('topics_base', 'answer_for_question_id', 'INTEGER');
  addColumnIfMissing('topics', 'is_resource', 'INTEGER DEFAULT 0');
  addColumnIfMissing('topics', 'download_url', 'TEXT');

  // notifierings-/svars-kolumner för frågor
  addColumnIfMissing('questions', 'answered_at', 'TEXT');
  addColumnIfMissing('questions', 'user_seen_answer_at', 'TEXT');
  // (frivillig) för admins: markera nya obesvarade frågor
  addColumnIfMissing('questions', 'admin_seen_new', 'INTEGER DEFAULT 0');
addColumnIfMissing('users', 'created_at', 'TEXT');
addColumnIfMissing('users', 'updated_at', 'TEXT');

// Backfill tidsstämplar för befintliga rader
db.prepare(`UPDATE users SET created_at = COALESCE(created_at, datetime('now'))`).run();
db.prepare(`UPDATE users SET updated_at = COALESCE(updated_at, datetime('now'))`).run();

  // Se till att FTS har innehåll
  const ftsCountRow = db.prepare(`SELECT count(*) AS n FROM topics_fts`).get();
  if (!ftsCountRow || !ftsCountRow.n) {
    const rows = db.prepare(`SELECT id, title, excerpt, body FROM topics`).all();
    const ins  = db.prepare(`INSERT INTO topics_fts (id,title,excerpt,body) VALUES (?,?,?,?)`);
    const tx   = db.transaction(arr => { arr.forEach(r => ins.run(r.id, r.title||'', r.excerpt||'', r.body||'')); });
    tx(rows);
    if (rows.length) console.log(`[DB] Rebuilt FTS for ${rows.length} topics`);
  }

  // Seed admin om saknas
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
  const adminExists = db.prepare(`SELECT 1 FROM users WHERE role='admin' LIMIT 1`).get();
  if (!adminExists) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.prepare(`INSERT INTO users (email, password_hash, name, role)
                VALUES (?,?,?, 'admin')`)
      .run(ADMIN_EMAIL, hash, 'Administrator');
    console.log('[DB] Seeded admin:', ADMIN_EMAIL);
  }
}
// Säkerställ att questions har svar-kolumnerna
function hasColumn(table, col) {
  const row = db.prepare(`PRAGMA table_info(${table})`).all()
    .find(r => r.name === col);
  return !!row;
}
function addColumn(table, col, ddl) {
  if (!hasColumn(table, col)) {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${ddl}`).run();
  }
}

// Obligatoriska svarfält
addColumn('questions', 'answer_title', 'TEXT');
addColumn('questions', 'answer_body', 'TEXT');
addColumn('questions', 'answer_tags', 'TEXT');
addColumn('questions', 'answered_by', 'TEXT');
addColumn('questions', 'answered_at', 'TEXT');      // kan vara TEXT (ISO) eller INTEGER (unix)
addColumn('questions', 'is_answered', 'INTEGER DEFAULT 0');

// Om du använder dessa någon annanstans i koden, se till att de finns också:
addColumn('questions', 'user_seen_answer_at', 'TEXT'); // markeras när frågeställaren sett svaret

initSchemaAndSeed();

// --- Dealers schema (NMS/Dynex) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS dealers (
    source        TEXT NOT NULL,                  -- 'nms' | 'dynex'
    dealer_id     TEXT NOT NULL,
    email         TEXT,
    username      TEXT,
    company       TEXT,
    firstname     TEXT,
    lastname      TEXT,
    telephone     TEXT,
    added         TEXT,
    md5_token     TEXT NOT NULL,                  -- md5(dealer_id + email)
    updated_at    TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (source, dealer_id)
  );

  CREATE INDEX IF NOT EXISTS idx_dealers_md5   ON dealers (md5_token);
  CREATE INDEX IF NOT EXISTS idx_dealers_email ON dealers (email);
`);

// Mjuk migrering: lägg till md5_token om den saknas, och backfilla
try {
  const cols = db.prepare("PRAGMA table_info(dealers)").all().map(c => c.name);
  if (!cols.includes('md5_token')) {
    db.exec(`ALTER TABLE dealers ADD COLUMN md5_token TEXT`);
    const rows = db.prepare(`SELECT source, dealer_id, IFNULL(lower(email),'') AS email FROM dealers`).all();
    const upd  = db.prepare(`UPDATE dealers SET md5_token=? WHERE source=? AND dealer_id=?`);
    for (const r of rows) {
      const token = crypto.createHash('md5').update(String(r.dealer_id) + String(r.email), 'utf8').digest('hex');
      upd.run(token, r.source, r.dealer_id);
    }
    db.exec(`CREATE INDEX IF NOT EXISTS idx_dealers_md5 ON dealers (md5_token)`);
  }
} catch {}

// ---------- EJS + Layouts ----------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');                 // => views/layout.ejs
app.set('layout extractScripts', true);      // valfritt: <%- script %> block
app.set('layout extractStyles', true);       // valfritt: <%- style %> block

// ---------- Middleware ----------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

// ---- Globala locals (EN källa för showHero + popularTags) ----
app.use((req, res, next) => {
  res.locals.title = 'Tuning Helpdesk';
  res.locals.user  = getUser(req) || null;

  // Döp vilka prefix som ska DÖLJA hero
  const noHeroPrefixes = ['/admin', '/login', '/register', '/ask', '/topic', '/profile', '/explore', '/questions'];
  res.locals.showHero = !noHeroPrefixes.some(p => req.path.startsWith(p));

  // Populära "chips" (taggar/kategorier) – globala
  try {
    const rows = db.prepare(`
      SELECT title
      FROM categories
      ORDER BY COALESCE(sort_order, 9999), title
      LIMIT 8
    `).all();
    res.locals.popularTags = rows.map(r => r.title);
  } catch {
    res.locals.popularTags = [];
  }

  next();
});

// Upsert-statement för dealers
const upsertDealerStmt = db.prepare(`
  INSERT INTO dealers (source, dealer_id, email, username, company, firstname, lastname, telephone, added, md5_token, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  ON CONFLICT(source, dealer_id) DO UPDATE SET
    email      = excluded.email,
    username   = excluded.username,
    company    = excluded.company,
    firstname  = excluded.firstname,
    lastname   = excluded.lastname,
    telephone  = excluded.telephone,
    added      = excluded.added,
    md5_token  = excluded.md5_token,
    updated_at = datetime('now')
`);

// Hämta dealers från partner-API
async function fetchDealersFrom(source, url, apiKey) {
  const res = await fetch(url, {
    headers: {
      'X-Tfs-siteapikey': apiKey,
      'Accept': 'application/json'
    }
  });
  if (!res.ok) throw new Error(`Dealer API (${source}) HTTP ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data)) throw new Error(`Dealer API (${source}) gav oväntat format`);
  return data;
}

// Skriv in/updatera dealers i batch
function upsertDealers(source, list) {
  const tx = db.transaction(() => {
    for (const rec of list) {
      const d = normalizeDealer(rec);
      const token = md5((d.dealer_id || '') + (d.email || ''));  // token skapas här
      upsertDealerStmt.run(
        source, d.dealer_id, d.email, d.username, d.company,
        d.firstname, d.lastname, d.telephone, d.added, token
      );
    }
  });
  tx();
}

// Kör sync för båda källorna
async function syncAllDealers() {
  for (const cfg of DEALER_APIS) {
    const rows = await fetchDealersFrom(cfg.source, cfg.url, cfg.apiKey);
    upsertDealers(cfg.source, rows);
  }
}

app.use((req, res, next) => {
  const u = getUser(req);
  res.locals.notifCount = 0;
  res.locals.adminOpenCount = 0;

  try {
    if (u && u.role === 'admin') {
      const row = db.prepare(`SELECT COUNT(*) AS n FROM questions WHERE status='open'`).get();
      res.locals.adminOpenCount = row?.n || 0;
    }
    if (u && u.role === 'user') {
      const row = db.prepare(`
        SELECT COUNT(*) AS n
        FROM questions
        WHERE user_id = ?
          AND status = 'answered'
          AND (user_seen_answer_at IS NULL OR user_seen_answer_at < answered_at)
      `).get(u.id);
      res.locals.notifCount = row?.n || 0;
    }
  } catch (e) {
    res.locals.notifCount = 0;
    res.locals.adminOpenCount = 0;
  }
  next();
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// ---------- auth helpers ----------
function signUser(u) {
  return jwt.sign(
    { id: u.id, email: u.email, role: u.role, name: u.name || '' },
    JWT_SECRET,
    { expiresIn: '14d' }
  );
}
function getUser(req) {
  const t = req.cookies?.auth;
  if (!t) return null;
  try { return jwt.verify(t, JWT_SECRET); } catch { return null; }
}
function requireAuth(req, res, next) {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  req.user = u; next();
}
function requireAdmin(req, res, next) {
  const u = getUser(req);
  if (!u || u.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  req.user = u; next();
}

// ---------- AUTH API ----------


// --- SSO md5-login ---
// Partnern länkar t.ex. till: https://din-helpdesk.se/sso/md5-login?token=<md5(id+email)>&redirect=/profile
app.get('/sso/md5-login', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim().toLowerCase();
    const redirectTo = (req.query.redirect && String(req.query.redirect)) || '/';
    if (!token) return res.status(400).send('Missing token');

    // Jämför mot pre-beräknad md5_token (SQLite har inte MD5-funktion som MySQL)
    const dealer = db.prepare(`SELECT * FROM dealers WHERE md5_token = ?`).get(token);
    if (!dealer) return res.status(403).send('Invalid token');

    const email = dealer.email || '';
    if (!email) return res.status(422).send('Dealer has no email');

    let user = db.prepare(`SELECT id, email, role, name FROM users WHERE lower(email)=lower(?)`).get(email);

    if (!user) {
      const displayName =
        [dealer.firstname, dealer.lastname].filter(Boolean).join(' ') ||
        dealer.username || dealer.company || email;

      db.prepare(`
        INSERT INTO users (email, name, role, password_hash, created_at, updated_at)
        VALUES (?, ?, 'user', NULL, datetime('now'), datetime('now'))
      `).run(email, displayName);

      user = db.prepare(`SELECT id, email, role, name FROM users WHERE lower(email)=lower(?)`).get(email);
    }

    // Sätt JWT-cookie (din befintliga helper)
    res.cookie('auth', signUser(user), {
      httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14 * 24 * 3600 * 1000
    });

    db.prepare(`UPDATE users SET updated_at = datetime('now') WHERE id=?`).run(user.id);
    return res.redirect(redirectTo);
  } catch (err) {
    console.error('SSO md5-login error:', err);
    return res.status(500).send('Login failed');
  }
});

app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email/password required' });
  const exists = db.prepare('SELECT 1 FROM users WHERE email=?').get(email);
  if (exists) return res.status(409).json({ error: 'email exists' });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (email,password_hash,name,role) VALUES (?,?,?,?)')
    .run(email, hash, name || '', 'user');
  const user = { id: info.lastInsertRowid, email, role: 'user', name: name || '' };
  res.cookie('auth', signUser(user), { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14*24*3600*1000 });
  res.json({ ok: true });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(password, u.password_hash)) return res.status(401).json({ error: 'invalid' });
  res.cookie('auth', signUser(u), { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14*24*3600*1000 });
  res.json({ ok: true });
});


app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth'); res.json({ ok: true });
});

// POST login
app.post('/login', (req, res) => {
  const { email, password, next: nextPath } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(password, u.password_hash)) {
    return res.status(401).render('login', { user: null, error: 'Fel e-post eller lösenord.', next: nextPath || '/' });
  }
  res.cookie('auth', signUser(u), { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14*24*3600*1000 });
  res.redirect(nextPath || '/');
});

// POST logout
app.post('/logout', (req, res) => { res.clearCookie('auth'); res.redirect('/'); });
app.get('/api/auth/me', (req, res) => {
  res.json(getUser(req) || null);
});

app.post('/register', (req, res) => {
  const { name, email, password, next: nextPath } = req.body;
  if (!email || !password) return res.status(400).render('register', { error: 'E-post och lösenord krävs', next: nextPath || '/' });

  const exists = db.prepare('SELECT 1 FROM users WHERE email=?').get(email);
  if (exists) return res.status(409).render('register', { error: 'E-posten finns redan', next: nextPath || '/' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (email,password_hash,name,role) VALUES (?,?,?,?)')
    .run(email, hash, name || '', 'user');
  const user = { id: info.lastInsertRowid, email, role: 'user', name: name || '' };
  res.cookie('auth', signUser(user), { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14*24*3600*1000 });
  res.redirect(nextPath || '/');
});


// Visa ämne – men om det är en resurs, skicka till /resources/:id
app.get('/topic/:id', (req, res) => {
  const topic = db.prepare(`
    SELECT b.id, b.created_at, b.updated_at, b.answer_for_question_id,
           t.title, t.excerpt, t.body, t.tags, t.is_resource, t.download_url,
           u.name AS author_name
    FROM topics_base b
    JOIN topics t ON t.id = b.id
    LEFT JOIN users u ON u.id = b.created_by
    WHERE b.id = ?
  `).get(req.params.id);

  if (!topic) {
    return res.status(404).render('404', { title: 'Hittades inte' });
  }

  // Resurs? Skicka till resurs-vyn.
  if (topic.is_resource) {
    return res.redirect(301, `/resources/${topic.id}`);
  }

  // Källfråga (om ämnet är ett svar)
  let sourceQuestion = null;
  if (topic.answer_for_question_id) {
    sourceQuestion = db.prepare(`
      SELECT q.id, q.user_id, q.title, q.body, q.created_at,
             u.name AS user_name
      FROM questions q
      LEFT JOIN users u ON u.id = q.user_id
      WHERE q.id = ?
    `).get(topic.answer_for_question_id);

    // Markera att frågeställaren har sett sitt svar
    const viewer = getUser(req);
    if (sourceQuestion && viewer && viewer.id === sourceQuestion.user_id) {
      db.prepare(`
        UPDATE questions
        SET user_seen_answer_at = datetime('now')
        WHERE id = ?
      `).run(sourceQuestion.id);
    }
  }

  // Relaterade frågor (uteslut källfrågan om sådan finns)
  let relatedQuestions = [];
  if (topic.answer_for_question_id) {
    relatedQuestions = db.prepare(`
      SELECT DISTINCT q.id, q.title
      FROM questions q
      JOIN question_topic qt ON qt.question_id = q.id
      WHERE qt.topic_id = ?
        AND q.id <> ?
      ORDER BY q.created_at DESC
      LIMIT 5
    `).all(topic.id, topic.answer_for_question_id);
  } else {
    relatedQuestions = db.prepare(`
      SELECT DISTINCT q.id, q.title
      FROM questions q
      JOIN question_topic qt ON qt.question_id = q.id
      WHERE qt.topic_id = ?
      ORDER BY q.created_at DESC
      LIMIT 5
    `).all(topic.id);
  }

  // Relaterade ämnen via första taggen
  const firstTag = (topic.tags || '').split(',')[0];
  const cat = firstTag ? firstTag.trim().toLowerCase() : '';
  let relatedTopics = [];
  if (cat) {
    relatedTopics = db.prepare(`
      SELECT b.id, t.title
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      WHERE b.id <> ?
        AND lower(t.tags) LIKE '%' || ? || '%'
      ORDER BY b.updated_at DESC
      LIMIT 5
    `).all(topic.id, cat);
  }

  res.locals.showHero = false;
  res.render('topic', {
    title: topic.title,
    topic,
    sourceQuestion,
    relatedQuestions,
    relatedTopics,
    user: getUser(req)
  });
});

// --- EDIT TOPIC (admin) ---
app.get('/admin/edit-topic/:id', requireAdmin, (req, res) => {
  const topic = db.prepare(`
    SELECT b.id, t.title, t.excerpt, t.body, t.tags,
           t.is_resource, t.download_url, b.updated_at
    FROM topics_base b
    JOIN topics t ON t.id = b.id
    WHERE b.id = ?
  `).get(req.params.id);

  if (!topic) return res.status(404).render('404', { title: 'Hittades inte' });

  const categories = db.prepare(`
    SELECT id, title
    FROM categories
    ORDER BY COALESCE(sort_order, 9999), title
  `).all();

  const currentCatRow = db.prepare(`
    SELECT category_id AS cid FROM topic_category WHERE topic_id = ?
  `).get(topic.id);

  res.render('edit-topic', {
    title: 'Redigera ämne',
    topic,
    categories,
    currentCat: currentCatRow ? currentCatRow.cid : ''
  });
});

app.post('/admin/edit-topic/:id', requireAdmin, (req, res) => {
  const id = req.params.id;

  const title        = (req.body.title || '').trim();
  const excerpt      = (req.body.excerpt || '').trim();
  const body         = (req.body.body || '').trim();
  const tags         = (req.body.tags || '').trim();
  const categoryId   = req.body.categoryId || null;

  // Nya fält
  const is_resource  = req.body.is_resource ? 1 : 0;               // checkbox -> 1/0
  const download_url = (req.body.download_url || '').trim();

  if (!title) return res.status(400).send('Titel krävs');

  db.prepare(`
    UPDATE topics
       SET title=?, excerpt=?, body=?, tags=?,
           is_resource=?, download_url=?
     WHERE id=?
  `).run(title, excerpt, body, tags, is_resource, download_url, id);

  db.prepare(`
    UPDATE topics_fts
       SET title=?, excerpt=?, body=?
     WHERE id=?
  `).run(title, excerpt, body, id);

  if (categoryId) {
    db.prepare(`
      INSERT OR REPLACE INTO topic_category (topic_id, category_id) VALUES (?,?)
    `).run(id, categoryId);
  }

  res.redirect('/admin');
});

// Visa en fråga i admin
app.get('/admin/questions/:id', requireAdmin, (req, res) => {
  const q = db.prepare(`
    SELECT q.*, u.name AS user_name, u.email AS user_email
    FROM questions q
    LEFT JOIN users u ON u.id = q.user_id
    WHERE q.id = ?
  `).get(req.params.id);

  if (!q) return res.status(404).render('404', { title: 'Hittades inte' });

  const linked = db.prepare(`
    SELECT t.id, t.title
    FROM question_topic qt
    JOIN topics t ON t.id = qt.topic_id
    WHERE qt.question_id = ?
    ORDER BY t.title
  `).all(q.id);

  const categories = db.prepare(`
    SELECT id, title
    FROM categories
    ORDER BY COALESCE(sort_order, 9999), title
  `).all();

  res.render('admin-question', {
    title: `Fråga #${q.id}`,
    q,
    linked,
    categories,     // <- WICHTIG: behövs för "Svara och publicera"-formuläret
    user: getUser(req)
  });
});

// Svara och publicera (skapar nytt ämne från en fråga)
// Admin: svara på en fråga och publicera som nytt ämne
/*app.post('/admin/questions/:id/answer', requireAdmin, (req, res) => {
  const qid = Number(req.params.id);
  const q = db.prepare('SELECT * FROM questions WHERE id=?').get(qid);
  if (!q) return res.status(404).render('404', { title: 'Frågan finns inte' });

  const answerHtml = (req.body.body || '').trim();   // endast SVARET
  const tags       = (req.body.tags || '').trim();
  const categoryId = (req.body.categoryId || '').trim();

  if (!answerHtml) {
    return res.status(400).render('admin-question', {
      title: `Fråga #${qid}`,
      q,
      linked: db.prepare(`
        SELECT t.id, t.title
        FROM question_topic qt
        JOIN topics t ON t.id = qt.topic_id
        WHERE qt.question_id = ?
        ORDER BY t.title
      `).all(qid),
      categories: db.prepare('SELECT id,title FROM categories ORDER BY COALESCE(sort_order,9999), title').all(),
      error: 'Innehåll krävs.'
    });
  }

  // Titel + unik slug
  const title    = `Svar: ${q.title}`;
  const baseSlug = slugify(title, { lower: true, strict: true }) || `fraga-${qid}`;
  let topicId = baseSlug, i = 2;
  while (db.prepare('SELECT 1 FROM topics_base WHERE id=?').get(topicId)) {
    topicId = `${baseSlug}-${i++}`;
  }

  // Excerpt från svaret (plain text)
  const excerpt = answerHtml.replace(/<[^>]+>/g, '').slice(0, 180);

  // Kör allt atomiskt
  const tx = db.transaction(() => {
    // Skapa ämnets basrad (sätter created_by)
    db.prepare('INSERT INTO topics_base (id, created_by) VALUES (?,?)')
      .run(topicId, req.user.id);

    // ⬅️ Viktigt: koppla ämnet till frågan så topic-sidan kan visa FRÅGA-kortet
    db.prepare(`
      UPDATE topics_base
      SET answer_for_question_id = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(qid, topicId);

    // Själva ämnesinnehållet (svaret)
    db.prepare('INSERT INTO topics (id, title, excerpt, body, tags) VALUES (?,?,?,?,?)')
      .run(topicId, title, excerpt, answerHtml, tags);

    db.prepare('INSERT INTO topics_fts (id, title, excerpt, body) VALUES (?,?,?,?)')
      .run(topicId, title, excerpt, answerHtml);

    // Valfri kategori
    if (categoryId) {
      db.prepare('INSERT OR REPLACE INTO topic_category (topic_id, category_id) VALUES (?,?)')
        .run(topicId, categoryId);
    }

    // Koppla fråga↔ämne och markera frågan som besvarad
    db.prepare('INSERT OR IGNORE INTO question_topic (question_id, topic_id) VALUES (?,?)')
      .run(qid, topicId);

db.prepare(`
  UPDATE questions
  SET status = 'answered',
      answered_at = datetime('now'),
      user_seen_answer_at = NULL
  WHERE id = ?
`).run(qid);
  });

  tx(); // kör transaktionen

  // Klart: gå till det nya ämnet
  res.redirect(`/topic/${topicId}`);
});
*/

// Admin: spara/redigera svar direkt på frågan
app.post('/admin/questions/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const q = db.prepare('SELECT * FROM questions WHERE id=?').get(id);
  if (!q) return res.status(404).render('404', { title: 'Fråga saknas' });

  const answer_title = (req.body.answer_title || '').trim() || `Svar: ${q.title}`;
  const answer_body  = (req.body.answer_body || '').trim();  
  const answer_tags  = (req.body.answer_tags || '').trim();
  const answered_by  = req.user?.name || req.user?.email || 'Admin';
  const answered_at  = new Date().toISOString();

  db.prepare(`
    UPDATE questions
       SET answer_title=?,
           answer_body=?,
           answer_tags=?,
           answered_by=?,
           answered_at=?,
           is_answered=1,
           status='answered',
           updated_at=datetime('now')
     WHERE id=?
  `).run(answer_title, answer_body, answer_tags, answered_by, answered_at, id);

  res.redirect('/questions/' + id);
});

// admin-only create/update/delete
app.post('/api/topics', requireAdmin, (req, res) => {
  const { id, title, excerpt, body, tags = [] } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });

  const topicId = id || slugify(title, { lower: true, strict: true });

  db.prepare('INSERT INTO topics_base (id, created_by) VALUES (?,?)')
    .run(topicId, req.user.id);

  db.prepare('INSERT INTO topics (id,title,excerpt,body,tags) VALUES (?,?,?,?,?)')
    .run(topicId, title, excerpt || '', body || '', Array.isArray(tags) ? tags.join(', ') : String(tags || ''));

  // 👉 Uppdatera FTS
  db.prepare(`INSERT INTO topics_fts (id, title, excerpt, body) VALUES (?,?,?,?)`)
    .run(topicId, title, excerpt || '', body || '');

  res.json({ ok: true, id: topicId });
});
app.put('/api/topics/:id', requireAdmin, (req, res) => {
  const { title, excerpt, body, tags = [] } = req.body;
  const base = db.prepare('SELECT 1 FROM topics_base WHERE id=?').get(req.params.id);
  if (!base) return res.status(404).json({ error: 'not found' });

  db.prepare('UPDATE topics_base SET updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.params.id);
  db.prepare('DELETE FROM topic_category WHERE topic_id=?').run(req.params.id);
const { categoryId } = req.body;
if (categoryId) {
  db.prepare('INSERT OR REPLACE INTO topic_category (topic_id, category_id) VALUES (?,?)')
    .run(req.params.id, categoryId);
}
  db.prepare('INSERT INTO topics (id,title,excerpt,body,tags) VALUES (?,?,?,?,?)')
    .run(req.params.id, title, excerpt || '', body || '', Array.isArray(tags) ? tags.join(', ') : String(tags || ''));

  // 👉 Synka FTS
  db.prepare(`DELETE FROM topics_fts WHERE id=?`).run(req.params.id);
  db.prepare(`INSERT INTO topics_fts (id, title, excerpt, body) VALUES (?,?,?,?)`)
    .run(req.params.id, title, excerpt || '', body || '');

  res.json({ ok: true });
});

// Lista + skapa kategorier
app.get('/admin/categories', requireAdmin, (req, res) => {
  // Kategorier + antal ämnen
  const cats = db.prepare(`
    SELECT c.id, c.title, c.icon, c.sort_order, COUNT(tc.topic_id) AS topic_count
    FROM categories c
    LEFT JOIN topic_category tc ON tc.category_id = c.id
    GROUP BY c.id
    ORDER BY COALESCE(c.sort_order, 9999), c.title
  `).all();

  // Alla ämnen per kategori (för expandern)
  const rows = db.prepare(`
    SELECT tc.category_id AS cid, b.id, t.title, b.updated_at
    FROM topic_category tc
    JOIN topics_base b ON b.id = tc.topic_id
    JOIN topics t      ON t.id  = tc.topic_id
    ORDER BY b.updated_at DESC
  `).all();

  const topicsByCat = {};
  for (const r of rows) {
    (topicsByCat[r.cid] ||= []).push(r);
  }

  // Alternativ för dropdowns (alla kategorier)
  const catOptions = db.prepare(`SELECT id, title FROM categories ORDER BY COALESCE(sort_order,9999), title`).all();

  res.render('categories', {
    title: 'Kategorier',
    cats,
    topicsByCat,
    catOptions
  });
});

app.post('/admin/categories', requireAdmin, (req, res) => {
  const { title, icon, sort_order } = req.body;
  if (!title) return res.status(400).send('Titel krävs');
  const id = slugify(title, { lower: true, strict: true });
  db.prepare('INSERT OR REPLACE INTO categories (id, title, icon, sort_order) VALUES (?,?,?,?)')
    .run(id, title, icon || null, isNaN(Number(sort_order)) ? null : Number(sort_order));
  res.redirect('/admin/categories');
});

app.post('/admin/categories/:id/update', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { title, icon, sort_order } = req.body;
  const exists = db.prepare('SELECT 1 FROM categories WHERE id=?').get(id);
  if (!exists) return res.status(404).send('Kategori finns inte');

  db.prepare(`
    UPDATE categories
    SET title = COALESCE(?, title),
        icon  = COALESCE(?, icon),
        sort_order = CASE WHEN ?='' OR ? IS NULL THEN NULL ELSE CAST(? AS INTEGER) END
    WHERE id = ?
  `).run(title ?? null, icon ?? null, sort_order, sort_order, sort_order, id);

  res.redirect('/admin/categories');
});

app.post('/admin/categories/move-topic', requireAdmin, (req, res) => {
  const { topicId, categoryId } = req.body;
  if (!topicId || !categoryId) return res.status(400).send('Saknar data');

  const topicOk = db.prepare('SELECT 1 FROM topics_base WHERE id=?').get(topicId);
  const catOk   = db.prepare('SELECT 1 FROM categories WHERE id=?').get(categoryId);
  if (!topicOk || !catOk) return res.status(400).send('Felaktigt topic/kategori');

  db.prepare('INSERT OR REPLACE INTO topic_category (topic_id, category_id) VALUES (?,?)')
    .run(topicId, categoryId);

  db.prepare('UPDATE topics_base SET updated_at=CURRENT_TIMESTAMP WHERE id=?').run(topicId);
  res.redirect('/admin/categories');
});

app.post('/admin/categories/:id/delete', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { moveTo } = req.body;

  const exists = db.prepare('SELECT 1 FROM categories WHERE id=?').get(id);
  if (!exists) return res.status(404).send('Kategori finns inte');

  if (moveTo) {
    const dest = db.prepare('SELECT 1 FROM categories WHERE id=?').get(moveTo);
    if (!dest) return res.status(400).send('Ogiltig mål-kategori');
    db.prepare('UPDATE topic_category SET category_id=? WHERE category_id=?').run(moveTo, id);
  } else {
    // släpp kopplingar
    db.prepare('DELETE FROM topic_category WHERE category_id=?').run(id);
  }

  db.prepare('DELETE FROM categories WHERE id=?').run(id);
  res.redirect('/admin/categories');
});

// Visa alla ämnen i en kategori
app.get('/admin/categories/:id/topics', requireAdmin, (req, res) => {
  const catId = req.params.id;

  const category = db.prepare(`SELECT id, title FROM categories WHERE id=?`).get(catId);
  if (!category) return res.status(404).send('Kategori saknas');

  const topics = db.prepare(`
    SELECT b.id, t.title,
           COALESCE(NULLIF(t.excerpt,''), substr(t.body,1,180)) AS excerpt,
           b.updated_at
    FROM topic_category tc
    JOIN topics t      ON t.id = tc.topic_id
    JOIN topics_base b ON b.id = tc.topic_id
    WHERE tc.category_id=?
    ORDER BY b.updated_at DESC
  `).all(catId);

  const otherCats = db.prepare(`
    SELECT id, title FROM categories
    WHERE id <> ?
    ORDER BY COALESCE(sort_order,9999), title
  `).all(catId);

  res.render('category-topics', {
    title: `Ämnen i ${category.title}`,
    category,
    topics,
    otherCats
  });
});

// Flytta ett ämne till annan kategori
app.post('/admin/categories/:id/topics/:topicId/move', requireAdmin, (req, res) => {
  const { id, topicId } = req.params;
  const { newCategoryId } = req.body;
  if (!newCategoryId) return res.status(400).send('Saknar ny kategori');

  const existsTopic = db.prepare(`SELECT 1 FROM topics_base WHERE id=?`).get(topicId);
  const existsCat   = db.prepare(`SELECT 1 FROM categories WHERE id=?`).get(newCategoryId);
  if (!existsTopic || !existsCat) return res.status(400).send('Felaktiga värden');

  // ersätt koppling (en primär kategori per topic)
  db.prepare(`DELETE FROM topic_category WHERE topic_id=?`).run(topicId);
  db.prepare(`INSERT OR REPLACE INTO topic_category (topic_id, category_id) VALUES (?,?)`)
    .run(topicId, newCategoryId);

  res.redirect(`/admin/categories/${id}/topics`);
});

// Ta bort koppling ämne<->kategori (inte radera ämnet)
app.post('/admin/categories/:id/topics/:topicId/remove', requireAdmin, (req, res) => {
  const { id, topicId } = req.params;
  db.prepare(`DELETE FROM topic_category WHERE topic_id=? AND category_id=?`).run(topicId, id);
  res.redirect(`/admin/categories/${id}/topics`);
});

// ---------- QUESTIONS ----------
app.post('/api/questions', requireAuth, (req, res) => {
  const { title, body } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  const info = db.prepare('INSERT INTO questions (user_id,title,body) VALUES (?,?,?)')
    .run(req.user.id, title, body || '');
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/questions', requireAuth, (req, res) => {
  const status = req.query.status || null;
  if (req.user.role === 'admin') {
    const rows = db.prepare(`
      SELECT q.*, u.email AS user_email
      FROM questions q LEFT JOIN users u ON u.id=q.user_id
      WHERE (? IS NULL OR q.status=?)
      ORDER BY q.created_at DESC`).all(status, status);
    return res.json(rows);
  }
  const rows = db.prepare(`
    SELECT q.* FROM questions q
    WHERE q.user_id=? OR q.status!='closed'
    ORDER BY q.created_at DESC`).all(req.user.id);
  res.json(rows);
});

app.get('/api/questions/:id', requireAuth, (req, res) => {
  const q = db.prepare('SELECT * FROM questions WHERE id=?').get(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  const links = db.prepare('SELECT topic_id FROM question_topic WHERE question_id=?').all(q.id);
  res.json({ ...q, topics: links.map(x => x.topic_id) });
});

app.put('/api/questions/:id/attach-topic', requireAdmin, (req, res) => {
  const { topicId } = req.body;
  const q = db.prepare('SELECT * FROM questions WHERE id=?').get(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  const t = db.prepare('SELECT 1 FROM topics_base WHERE id=?').get(topicId);
  if (!t) return res.status(400).json({ error: 'topic not found' });
  db.prepare('INSERT OR IGNORE INTO question_topic (question_id, topic_id) VALUES (?,?)')
    .run(q.id, topicId);
db.prepare("UPDATE questions SET status=?, updated_at=datetime('now') WHERE id=?")
  .run('answered', q.id);
  res.json({ ok: true });
});

app.put('/api/questions/:id/status', requireAdmin, (req, res) => {
  const { status } = req.body;
  if (!['open', 'answered', 'closed'].includes(status)) return res.status(400).json({ error: 'bad status' });
  db.prepare('UPDATE questions SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(status, req.params.id);
  res.json({ ok: true });
});

// --- helpers för kategorikorten ---
function getTopByTag(tag, limit = 4) {
  // Plockar senaste ämnen som innehåller taggen (komma-separerade tags i topics.tags)
  return db.prepare(`
    SELECT b.id, t.title
    FROM topics_base b
    JOIN topics t ON t.id = b.id
    WHERE ',' || lower(t.tags) || ',' LIKE '%,' || lower(?) || ',%'
    ORDER BY b.updated_at DESC
    LIMIT ?
  `).all(tag, limit);
}

// Bygger upp korten (ändra titlar/ikoner/taggar efter din domän)
function buildCategories() {
  // Hämta kategorier
const cats = db.prepare(`
  SELECT id, title, icon, sort_order
  FROM categories
  ORDER BY COALESCE(sort_order, 9999), title
`).all();

  // Hämta 3–4 senaste topics per kategori
  const stmt = db.prepare(`
    SELECT tc.category_id AS cid, t.id, t.title
    FROM topic_category tc
    JOIN topics t ON t.id = tc.topic_id
    JOIN topics_base b ON b.id = t.id
    ORDER BY b.updated_at DESC
  `).all();

  const byCat = new Map();
  for (const row of stmt) {
    if (!byCat.has(row.cid)) byCat.set(row.cid, []);
    const arr = byCat.get(row.cid);
    if (arr.length < 4) arr.push({ id: row.id, title: row.title });
  }

  return cats.map(c => ({
    id: c.id,
    title: c.title,
    icon: c.icon || 'ti-folder',
    items: byCat.get(c.id) || []
  }));
}
app.post('/admin/categories/bulk', requireAdmin, (req, res) => {
  const { title = {}, icon = {}, sort = {} } = req.body;
  const ids = new Set([...Object.keys(title), ...Object.keys(icon), ...Object.keys(sort)]);
  const update = db.prepare('UPDATE categories SET title=?, icon=?, sort_order=? WHERE id=?');
  for (const id of ids) {
    const t = (title[id] ?? '').trim();
    const i = (icon[id] ?? '').trim();
    const s = Number(sort[id] ?? null);
    // Hämta gamla och fyll i oförändrade värden
    const old = db.prepare('SELECT title, icon, sort_order FROM categories WHERE id=?').get(id);
    if (!old) continue;
    update.run(t || old.title, i || old.icon, Number.isFinite(s) ? s : old.sort_order, id);
  }
  res.redirect('/admin/categories');
});

// Publik fråga-sida (visa en fråga)
app.get('/question/:id', (req, res) => {
  const id = Number(req.params.id);

  // Hämta fråga + lite användardata (om du vill visa avsändare)
  const q = db.prepare(`
    SELECT q.id, q.user_id, q.title, q.body, q.status, q.created_at, q.updated_at,
           u.name  AS user_name, u.email AS user_email
    FROM questions q
    LEFT JOIN users u ON u.id = q.user_id
    WHERE q.id = ?
  `).get(id);

  if (!q) return res.status(404).render('404', { title: 'Hittades inte' });

  // Visa helst inte stängda frågor för andra än ägaren (valfritt)
  const me = getUser(req);
  const isOwner = me && me.id === q.user_id;
  if (q.status === 'closed' && !isOwner && (!me || me.role !== 'admin')) {
    return res.status(403).render('403', { title: 'Åtkomst nekad' });
  }

  // Hämta kopplade ämnen
  const linked = db.prepare(`
    SELECT t.id, t.title, t.excerpt
    FROM question_topic qt
    JOIN topics t ON t.id = qt.topic_id
    WHERE qt.question_id = ?
    ORDER BY t.title
  `).all(q.id);

  res.locals.showHero = false; // dölj hero på frågesidan
  res.render('question', {
    title: `Fråga #${q.id}`,
    q,
    linked,
    user: me,
    relatedQuestions: [],
    relatedTopics: [] 
  });
});

// ---------- VIEWS ----------
// Hem (öppen för alla)
app.get('/', (req, res) => {
  const user = getUser(req);

  // Senaste ämnen (som du hade innan)
  const topics = db.prepare(`
    SELECT b.id, t.title, t.excerpt, t.tags, b.updated_at
    FROM topics_base b
    JOIN topics t ON t.id = b.id
    ORDER BY b.updated_at DESC
    LIMIT 12
  `).all();

  // Senaste frågor
  const latestQuestions = db.prepare(`
    SELECT q.id, q.title, q.status, q.created_at
    FROM questions q
    ORDER BY q.created_at DESC
    LIMIT 6
  `).all();

  // Visa bara tre kategorikort
  const categoriesShow = buildCategories().slice(0, 3);

  res.render('home', {
    user,
    topics,
    latestQuestions,   // ⬅️ skickas till vyn
    categoriesShow,
    q: ''
  });
});

app.get('/resources', (req, res) => {
  const rows = db.prepare(`
    SELECT b.id, t.title, t.excerpt, t.download_url, b.updated_at
    FROM topics_base b
    JOIN topics t ON t.id=b.id
    WHERE t.is_resource=1
    ORDER BY b.updated_at DESC
  `).all();
  res.render('resources', { title: 'Resurser', resources: rows, user: getUser(req) });
});

// Ta bort ett ämne (admin) – och radera även källfrågan om detta är ett svar
app.post('/admin/topics/:id/delete', requireAdmin, (req, res) => {
  const id = req.params.id;

  const tx = db.transaction(() => {
    // 1) Kolla om ämnet är ett svar på en fråga
    const row = db.prepare(`
      SELECT answer_for_question_id AS qid
      FROM topics_base
      WHERE id = ?
    `).get(id);

    // 2) Ta bort FTS-raden (ingen FK)
    db.prepare('DELETE FROM topics_fts WHERE id=?').run(id);

    // 3) Ta bort ämnet; CASCADE tar bort topics + topic_category + question_topic (via topic_id)
    db.prepare('DELETE FROM topics_base WHERE id=?').run(id);

    // 4) Om ämnet var ett svar → ta bort själva frågan också
    if (row && row.qid) {
      // Raderar frågan; CASCADE tar samtidigt bort ev. question_topic-rader (via question_id)
      db.prepare('DELETE FROM questions WHERE id=?').run(row.qid);
    }
  });

  try {
    tx();
    res.redirect('/admin');
  } catch (e) {
    console.error('Delete topic failed:', e);
    res.status(500).send('Kunde inte ta bort ämnet.');
  }
});

// Publik vy för en fråga (med samma layout som topic-sidan)
app.get('/questions/:id', (req, res) => {
  const id = Number(req.params.id);
  const me = getUser(req);

  // Frågan
const q = db.prepare(`
  SELECT q.id, q.user_id, q.title, q.body, q.status, 
         q.created_at, q.updated_at,
         q.answer_title, q.answer_body, q.answer_tags,
         q.answered_by, q.answered_at, q.is_answered,
         u.name  AS user_name,
         u.email AS user_email
  FROM questions q
  LEFT JOIN users u ON u.id = q.user_id
  WHERE q.id = ?
`).get(id);
  if (!q) return res.status(404).render('404', { title: 'Hittades inte' });

  // Hämta kopplat svar-ämne (om något)
  const link = db.prepare(`
    SELECT qt.topic_id
    FROM question_topic qt
    WHERE qt.question_id = ?
    ORDER BY rowid DESC
    LIMIT 1
  `).get(id);

  let answerTopic = null;
  if (link && link.topic_id) {
    answerTopic = db.prepare(`
      SELECT b.id, b.created_at, b.updated_at,
             t.title, t.excerpt, t.body, t.tags,
             u.name AS author_name
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      LEFT JOIN users u ON u.id = b.created_by
      WHERE b.id = ?
    `).get(link.topic_id);

    // Om frågeställaren tittar på sin besvarade fråga → markera sedd
    if (me && me.id === q.user_id && q.status === 'answered') {
      db.prepare(`UPDATE questions SET user_seen_answer_at = datetime('now') WHERE id=?`).run(q.id);
    }
  }

  // Sidokolumn: relaterade frågor + fler ämnen i samma kategori (utifrån första taggen)
  let relatedQuestions = [];
  let relatedTopics    = [];
  if (answerTopic) {
    relatedQuestions = db.prepare(`
      SELECT DISTINCT q.id, q.title
      FROM questions q
      JOIN question_topic qt ON qt.question_id = q.id
      WHERE qt.topic_id = ?
        AND q.id <> ?
      ORDER BY q.created_at DESC
      LIMIT 5
    `).all(answerTopic.id, q.id);

    const firstTag = (answerTopic.tags || '').split(',')[0]?.trim().toLowerCase() || '';
    if (firstTag) {
      relatedTopics = db.prepare(`
        SELECT b.id, t.title
        FROM topics_base b
        JOIN topics t ON t.id = b.id
        WHERE b.id <> ?
          AND lower(IFNULL(t.tags,'')) LIKE '%' || ? || '%'
        ORDER BY b.updated_at DESC
        LIMIT 5
      `).all(answerTopic.id, firstTag);
    }
  }

  res.locals.showHero = false;
  res.render('question', {
    title: `Fråga: ${q.title}`,
    q,
    answerTopic,
    relatedQuestions,
    relatedTopics,
    user: me
  });
});

app.get('/explore', (req, res) => {
  const tab = (req.query.tab === 'questions') ? 'questions' : 'topics';
  const q    = (req.query.q || '').trim();
  const cat  = (req.query.cat || '').trim();  // category id
  const tag  = (req.query.tag || '').trim().toLowerCase();

  // Sidebar: kategorier
  const categories = db.prepare(`
    SELECT id, title
    FROM categories
    ORDER BY COALESCE(sort_order,9999), title
  `).all();

  // Sidebar: "populära taggar" – enkel utvinning från topics.tags
  const tagRows = db.prepare(`
    SELECT t.tags
    FROM topics t
    WHERE t.is_resource=0 AND IFNULL(t.tags,'') <> ''
  `).all();
  const tagCounter = {};
  for (const r of tagRows) {
    (r.tags || '').split(',').map(s=>s.trim()).filter(Boolean).forEach(t=>{
      const key = t.toLowerCase();
      tagCounter[key] = (tagCounter[key]||0) + 1;
    });
  }
  const allTags = Object.entries(tagCounter)
    .sort((a,b)=>b[1]-a[1])
    .slice(0,30)        // topp 30
    .map(([name,count])=>({ name, count }));

  // Data för listan
  let topics = [];
  let questions = [];

  if (tab === 'topics') {
    // Baslista: alla topics (ej resurser)
    let sql = `
      SELECT b.id, t.title, t.excerpt, t.tags, b.updated_at
      FROM topics_base b
      JOIN topics t ON t.id=b.id
      WHERE t.is_resource=0
    `;
    const params = [];

    if (q) {
      // enkel sök: använd FTS om du vill, men här gör vi LIKE för enkelhet
      sql += ` AND (lower(t.title) LIKE ? OR lower(t.excerpt) LIKE ? OR lower(t.body) LIKE ?) `;
      const like = `%${q.toLowerCase()}%`;
      params.push(like, like, like);
    }
    if (cat) {
      sql += ` AND EXISTS (SELECT 1 FROM topic_category tc WHERE tc.topic_id=b.id AND tc.category_id=?) `;
      params.push(cat);
    }
    if (tag) {
      sql += ` AND lower(IFNULL(t.tags,'')) LIKE ? `;
      params.push(`%${tag}%`);
    }

    sql += ` ORDER BY b.updated_at DESC LIMIT 30 `;
    topics = db.prepare(sql).all(...params);
  } else {
    // Senaste frågor
    let sql = `
      SELECT q.id, q.title, q.status, q.created_at
      FROM questions q
      WHERE 1=1
    `;
    const params = [];
    if (q) {
      sql += ` AND lower(q.title) LIKE ? OR lower(IFNULL(q.body,'')) LIKE ? `;
      const like = `%${q.toLowerCase()}%`;
      params.push(like, like);
    }
    sql += ` ORDER BY q.created_at DESC LIMIT 30 `;
    questions = db.prepare(sql).all(...params);
  }

  res.render('explore', {
    title: 'Utforska',
    tab,
    q, cat, tag,
    categories,
    tags: allTags,
    topics,
    questions,
    user: getUser(req)
  });
});

// Visa en specifik resurs (separat layout från vanliga topics)
app.get('/resources/:id', (req, res) => {
  const row = db.prepare(`
    SELECT b.id, t.title, t.excerpt, t.body, t.tags, b.updated_at,
           t.is_resource, t.download_url
    FROM topics_base b
    JOIN topics t ON t.id=b.id
    WHERE b.id = ?
  `).get(req.params.id);

  if (!row || !row.is_resource) {
    return res.status(404).render('404', { title: 'Resurs saknas' });
  }

  res.locals.showHero = false; // (om du vill dölja hero på detaljsidor)
  res.render('resource-show', {
    title: row.title,
    resource: row,
    user: getUser(req)
  });
});

// Sök (öppen för alla) – återanvänd "home" som vy
app.get('/api/search', (req, res) => {
  const raw = (req.query.q || '').trim();
  const q = raw.replace(/[^\p{L}\p{N}\s_-]/gu, '');

  if (!q) {
    const rows = db.prepare(`
      SELECT b.id, t.title, t.excerpt, b.updated_at
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      ORDER BY b.updated_at DESC
      LIMIT 12
    `).all();
    return res.json(rows);
  }

  const terms = q.split(/\s+/).filter(Boolean);
  const ftsQuery = terms.map(t => `${t}*`).join(' AND ');

  let rows = db.prepare(`
    SELECT t.id, t.title, t.excerpt, bm25(topics_fts) AS score
    FROM topics_fts f
    JOIN topics t ON t.id = f.id
    WHERE topics_fts MATCH ?
    ORDER BY score
    LIMIT 50
  `).all(ftsQuery);

  if (rows.length === 0) {
    const like = `%${q}%`;
    rows = db.prepare(`
      SELECT t.id, t.title, t.excerpt, 9999 AS score
      FROM topics t
      WHERE t.title LIKE ? OR t.excerpt LIKE ? OR t.body LIKE ?
      LIMIT 50
    `).all(like, like, like);
  }

  res.json(rows);
});

// --- PROFIL ---
// --- PROFIL ---
app.get('/profile', requireAuth, (req, res) => {
  const me = db.prepare('SELECT id,email,name,role FROM users WHERE id=?').get(req.user.id);
  const myQs = db.prepare(`
    SELECT id, title, status, created_at
    FROM questions
    WHERE user_id=?
    ORDER BY created_at DESC
  `).all(req.user.id);

  res.render('profile', {
    title: 'Min profil',
    me,
    myQs,
    ok: req.query.ok || null,
    err: req.query.err || null
  });
});

// Hjälpare för att rendera profilen med statusmeddelanden
function renderProfile(res, userId, { ok = null, err = null } = {}) {
  const me = db.prepare('SELECT id,email,name,role FROM users WHERE id=?').get(userId);
  const myQs = db.prepare(`
    SELECT id, title, status, created_at
    FROM questions
    WHERE user_id=?
    ORDER BY created_at DESC
  `).all(userId);

  return res.status(err ? 400 : 200).render('profile', {
    title: 'Min profil',
    me,
    myQs,
    ok,
    err
  });
}

// --- Uppdatera profil (namn/e-post) ---
// (Den här matchar ditt "Profilinställningar"-formulär om du vill peka det hit.
//  Men vi låter även /profile/update nedan hantera samma sak så din vy funkar nu.)
app.post('/profile', requireAuth, (req, res) => {
  const userId          = req.user.id;
  const name            = (req.body.name || '').trim();
  const email           = (req.body.email || '').trim();

  if (!email) {
    return renderProfile(res, userId, { err: 'E-post krävs.' });
  }

  // kolla om eposten används av annan
  const exists = db.prepare('SELECT id FROM users WHERE email=? AND id<>?').get(email, userId);
  if (exists) {
    return renderProfile(res, userId, { err: 'E-post används redan.' });
  }

db.prepare("UPDATE users SET name=?, email=?, updated_at=datetime('now') WHERE id=?")
  .run(name, email, userId);

  // uppdatera JWT så headern visar direkt
  const fresh = db.prepare('SELECT id,email,role,name FROM users WHERE id=?').get(userId);
  res.cookie('auth', signUser(fresh), {
    httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14*24*3600*1000
  });

  return res.redirect('/profile?ok=' + encodeURIComponent('Profil uppdaterad'));
});

// --- Uppdatera profil (kompatibel med din nuvarande vy) ---
app.post('/profile/update', requireAuth, (req, res) => {
  const userId          = req.user.id;
  const name            = (req.body.name || '').trim();
  const email           = (req.body.email || '').trim();
  const currentPassword = (req.body.current || req.body.current_password || '').trim();
  const newPassword1    = (req.body.password1 || req.body.new_password || '').trim();
  const newPassword2    = (req.body.password2 || '').trim();

  const msgs = [];

  // ---- 1) Uppdatera namn/e-post (var för sig) ----
// Uppdatera namn om angivet
if (name) {
  db.prepare('UPDATE users SET name=?, updated_at=datetime(\'now\') WHERE id=?')
    .run(name, userId);
  msgs.push('Namn uppdaterat');
}

if (email) {
  const exists = db.prepare('SELECT id FROM users WHERE email=? AND id<>?').get(email, userId);
  if (exists) {
    return renderProfile(res, userId, { err: 'E-post används redan.' });
  }
  db.prepare('UPDATE users SET email=?, updated_at=datetime(\'now\') WHERE id=?')
    .run(email, userId);
  msgs.push('E-post uppdaterad');
}

  // Om vi uppdaterade namn eller e-post: fräscha JWT så headern visar rätt
  if (name || email) {
    const fresh = db.prepare('SELECT id,email,role,name FROM users WHERE id=?').get(userId);
    res.cookie('auth', signUser(fresh), {
      httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14*24*3600*1000
    });
  }

  // ---- 2) Lösenordsbyte (om några pw-fält skickats) ----
  const wantsPwChange = !!(currentPassword || newPassword1 || newPassword2);
  if (wantsPwChange) {
    if (!currentPassword || !newPassword1 || !newPassword2) {
      return renderProfile(res, userId, { err: 'Fyll i nuvarande lösenord och båda fälten för nytt lösenord.' });
    }
    if (newPassword1 !== newPassword2) {
      return renderProfile(res, userId, { err: 'Nya lösenorden matchar inte.' });
    }
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(userId);
    if (!u || !bcrypt.compareSync(currentPassword, u.password_hash)) {
      return renderProfile(res, userId, { err: 'Nuvarande lösenord stämmer inte.' });
    }
    const hash = bcrypt.hashSync(newPassword1, 10);
db.prepare("UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=?")
  .run(hash, userId);
    msgs.push('Lösenord uppdaterat');
  }

  // ---- 3) Inget alls ifyllt? ----
  if (msgs.length === 0) {
    return renderProfile(res, userId, { err: 'Inget att uppdatera.' });
  }

  // ---- 4) Klart ----
  return res.redirect('/profile?ok=' + encodeURIComponent(msgs.join(' • ')));
});

// Sidorout för sökresultat (visar hero + lista under)
app.get('/search', (req, res) => {
  const qRaw = (req.query.q || '').trim();
  const q    = qRaw.replace(/[^\p{L}\p{N}\s_-]/gu, '');
  const popularTags = ['AutoTuner','Kom igång','Virtual Read','Credits & Köp'];

  let topics = [];
  if (q) {
    const terms    = q.split(/\s+/).filter(Boolean);
    const ftsQuery = terms.map(t => `${t}*`).join(' AND ');

    topics = db.prepare(`
      SELECT t.id, t.title, t.excerpt, bm25(topics_fts) AS score
      FROM topics_fts f
      JOIN topics t ON t.id = f.id
      WHERE topics_fts MATCH ?
      ORDER BY score
      LIMIT 50
    `).all(ftsQuery);

    if (topics.length === 0) {
      const like = `%${q}%`;
      topics = db.prepare(`
        SELECT t.id, t.title, t.excerpt, 9999 AS score
        FROM topics t
        WHERE t.title LIKE ? OR t.excerpt LIKE ? OR t.body LIKE ?
        LIMIT 50
      `).all(like, like, like);
    }
  }

  res.render('search', { title: 'Sök', q, topics });
});

// Visa formulär
app.get('/admin/new-topic', requireAdmin, (req, res) => {
  const categories = db.prepare(`
    SELECT id, title FROM categories
    ORDER BY COALESCE(sort_order, 9999), title
  `).all();
  res.render('new-topic', { title: 'Nytt ämne', categories, topic: {} });
});

// Hantera POST från formuläret
app.post('/admin/new-topic', requireAdmin, (req, res) => {
  const { title, excerpt, body, tags, categoryId } = req.body;
  if (!title) return res.status(400).send('Titel krävs');

  const is_resource  = req.body.is_resource ? 1 : 0;
  const download_url = (req.body.download_url || '').trim();

  const topicId = slugify(title, { lower: true, strict: true });

  // Bas
  db.prepare('INSERT INTO topics_base (id, created_by) VALUES (?,?)')
    .run(topicId, req.user.id);

  // Innehåll + resursfält
  db.prepare('INSERT INTO topics (id,title,excerpt,body,tags,is_resource,download_url) VALUES (?,?,?,?,?,?,?)')
    .run(topicId, title, excerpt || '', body || '', tags || '', is_resource, download_url);

  // FTS
  db.prepare('INSERT INTO topics_fts (id, title, excerpt, body) VALUES (?,?,?,?)')
    .run(topicId, title, excerpt || '', body || '');

  // Primär kategori
  if (categoryId) {
    db.prepare('INSERT OR REPLACE INTO topic_category (topic_id, category_id) VALUES (?,?)')
      .run(topicId, categoryId);
  }

  res.redirect('/admin');
});
// --- SUGGEST (topp-8 under sökfältet)
app.get('/api/suggest', (req, res) => {
  const raw = (req.query.q || '').trim();
  if (!raw) return res.json([]);

  // Rensa och gör enkla prefix-termer
  const q = raw.replace(/[^\p{L}\p{N}\s_-]/gu, '');
  const termsArr = q.split(/\s+/).filter(Boolean).map(t => `${t}*`);
  const ftsQuery = termsArr.length ? termsArr.join(' OR ') : '';

  let rows = [];
  // 1) FTS (snällare OR + prefix)
  if (ftsQuery) {
    try {
      rows = db.prepare(`
        SELECT 
          t.id,
          CASE 
            WHEN b.answer_for_question_id IS NOT NULL THEN
              'Fråga: ' || CASE 
                             WHEN instr(t.title, 'Svar: ') = 1 THEN substr(t.title, 7)
                             ELSE t.title
                           END
            ELSE t.title
          END AS title,
          substr(COALESCE(NULLIF(t.excerpt,''), t.body), 1, 120) AS snippet
        FROM topics_fts f
        JOIN topics      t ON t.id = f.id
        JOIN topics_base b ON b.id = f.id
        WHERE topics_fts MATCH ?
        ORDER BY bm25(topics_fts)
        LIMIT 8
      `).all(ftsQuery);
    } catch {
      rows = [];
    }
  }

  // 2) Fallback: LIKE om FTS gav noll
  if (!rows.length) {
    const esc  = (s) => s.replace(/[%_]/g, m => '\\' + m);
    const like = `%${esc(q)}%`;
    rows = db.prepare(`
      SELECT 
        b.id,
        CASE 
          WHEN b.answer_for_question_id IS NOT NULL THEN
            'Fråga: ' || CASE 
                           WHEN instr(t.title, 'Svar: ') = 1 THEN substr(t.title, 7)
                           ELSE t.title
                         END
          ELSE t.title
        END AS title,
        substr(COALESCE(NULLIF(t.excerpt,''), t.body), 1, 120) AS snippet
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      WHERE t.title   LIKE ? ESCAPE '\\'
         OR t.excerpt LIKE ? ESCAPE '\\'
         OR t.body    LIKE ? ESCAPE '\\'
      ORDER BY b.updated_at DESC
      LIMIT 8
    `).all(like, like, like);
  }

  res.json(rows);
});

// --- API: search (JSON som frontenden hämtar på /search)
app.get('/api/search', (req, res) => {
  const raw = (req.query.q || '').trim();
  const q   = raw.replace(/[^\p{L}\p{N}\s_-]/gu, '');

  const baseSelect = `
    SELECT
      t.id,
      CASE 
        WHEN b.answer_for_question_id IS NOT NULL THEN
          'Fråga: ' || CASE 
                         WHEN instr(t.title, 'Svar: ') = 1 THEN substr(t.title, 7)
                         ELSE t.title
                       END
        ELSE t.title
      END AS title,
      (b.answer_for_question_id IS NOT NULL) AS is_answer,
      COALESCE(NULLIF(t.excerpt,''), substr(t.body,1,200)) AS excerpt
    FROM topics_base b
    JOIN topics t ON t.id = b.id
  `;

  if (!q) {
    const rows = db.prepare(`${baseSelect} ORDER BY b.updated_at DESC LIMIT 50`).all();
    return res.json(rows);
  }

  const terms = q.split(/\s+/).filter(Boolean).map(t => `${t}*`).join(' AND ');
  let rows = [];

  try {
    rows = db.prepare(`
      SELECT
        t.id,
        CASE 
          WHEN b.answer_for_question_id IS NOT NULL THEN
            'Fråga: ' || CASE 
                           WHEN instr(t.title, 'Svar: ') = 1 THEN substr(t.title, 7)
                           ELSE t.title
                         END
          ELSE t.title
        END AS title,
        (b.answer_for_question_id IS NOT NULL) AS is_answer,
        COALESCE(NULLIF(t.excerpt,''), substr(t.body,1,200)) AS excerpt,
        bm25(topics_fts) AS score
      FROM topics_fts f
      JOIN topics      t ON t.id = f.id
      JOIN topics_base b ON b.id = f.id
      WHERE topics_fts MATCH ?
      ORDER BY score
      LIMIT 100
    `).all(terms);
  } catch { rows = []; }

  if (!rows.length) {
    const like = `%${q}%`;
    rows = db.prepare(`
      ${baseSelect}
      WHERE t.title   LIKE ?
         OR t.excerpt LIKE ?
         OR t.body    LIKE ?
      ORDER BY b.updated_at DESC
      LIMIT 100
    `).all(like, like, like);
  }

  res.json(rows);
});

// Kategorisida: visa alla topics som matchar en tagg/kategori
app.get('/category/:id', (req, res) => {
  const user = getUser(req);
  const catId = (req.params.id || '').toLowerCase().trim();

  // Hämta alla topics som har denna tagg (tags lagras som komma-separerad sträng)
  const topics = db.prepare(`
    SELECT b.id, t.title, t.excerpt, t.tags, b.updated_at
    FROM topics_base b
    JOIN topics t ON t.id = b.id
    WHERE ',' || lower(replace(t.tags,' ','')) || ',' LIKE '%,' || ? || ',%'
    ORDER BY b.updated_at DESC
  `).all(catId);

  res.render('category', {
    user,
    categoryId: catId,
    categoryTitle: catId.charAt(0).toUpperCase() + catId.slice(1),
    topics
  });
});

// Ta bort en fråga (admin)
app.post('/admin/questions/:id/delete', requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  // ta bort kopplingar först (om några)
  db.prepare('DELETE FROM question_topic WHERE question_id=?').run(id);

  // radera själva frågan
  db.prepare('DELETE FROM questions WHERE id=?').run(id);

  res.redirect('/admin');
});

app.get('/login', (req, res) =>
  res.render('login', { user: getUser(req), title: 'Logga in', next: req.query.next || '/' })
);
app.get('/register', (req, res) =>
  res.render('register', { user: getUser(req), title: 'Skapa konto', next: req.query.next || '/' })
);
// Visa "Ställ fråga" – men kräver inte inloggning för att nå sidan
app.get('/ask', (req, res) => {
  res.render('ask', { user: getUser(req), title: 'Ställ en fråga' });
});

app.get('/admin-accounts', requireAdmin, (req, res) => {
  const q       = (req.query.q || '').trim();
  const source  = (req.query.source || '').trim();     // '' | 'nms' | 'dynex'
  const perPage = Math.max(1, Number(req.query.perPage || 15));
  const page    = Math.max(1, Number(req.query.page || 1));

  // ... hämta users, dealers, totalFiltered, totalPages etc ...

  res.render('admin-accounts', {
    title: 'Konton & dealers',
    users,
    dealers,
    totalDealersAll,
    totalFiltered,
    totalPages,
    page,
    q,
    source,
    perPage
  });
});

app.get('/admin', requireAdmin, (req, res) => {
  const openQs = db.prepare(`
    SELECT id, title, created_at
    FROM questions
    WHERE status = 'open'
    ORDER BY created_at DESC
    LIMIT 50
  `).all();

  const latestTopics = db.prepare(`
    SELECT b.id, t.title, b.updated_at
    FROM topics_base b
    JOIN topics t ON t.id = b.id
    ORDER BY b.updated_at DESC
    LIMIT 10
  `).all();

  res.render('admin', {
    title: 'Adminpanel',
    openQs,
    latestTopics,
    user: getUser(req)
  });
});

// Kör en initial sync när servern startar
(async () => {
  try { await syncAllDealers(); }
  catch(e){ console.warn('Initial dealer sync failed:', e.message); }
})();

// Kör varje dygn kl 03:15 server-tid (cron-format "m h dom mon dow")
cron.schedule('15 3 * * *', async () => {
  try {
    console.log('[cron] Running daily dealer sync…');
    await syncAllDealers();
    console.log('[cron] Dealer sync done');
  } catch (e) {
    console.error('[cron] Dealer sync failed:', e);
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server kör på port " + PORT));