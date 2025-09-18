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
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

/* Hjälpare för migrationer – definiera EN gång */
function hasColumn(table, col) {
  const row = db.prepare(`PRAGMA table_info(${table})`).all().find(r => r.name === col);
  return !!row;
}
function addColumnIfMissing(table, col, ddl) {
  if (!hasColumn(table, col)) {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${ddl}`).run();
    db.prepare(`UPDATE topics SET downloads = COALESCE(downloads, 0)`).run();
  }
}

function initSchemaAndSeed() {
  // Bas-schema
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
      answered_at TEXT,
      user_seen_answer_at TEXT,
      admin_seen_new INTEGER DEFAULT 0,
      answer_title TEXT,
      answer_body  TEXT,
      answer_tags  TEXT,
      answered_by  TEXT,
      is_answered  INTEGER DEFAULT 0,
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

  // Extra kolumner
  addColumnIfMissing('topics_base', 'answer_for_question_id', 'INTEGER');
  addColumnIfMissing('topics', 'is_resource', 'INTEGER DEFAULT 0');
  addColumnIfMissing('topics', 'download_url', 'TEXT');
  addColumnIfMissing('topics', 'downloads', 'INTEGER DEFAULT 0');

  // Backfill users.password_hash (ska inte vara NULL)
  try {
    db.prepare(`UPDATE users SET password_hash='' WHERE password_hash IS NULL`).run();
  } catch (e) {
    console.warn('[DB:migration] kunde inte backfilla password_hash:', e.message);
  }

  // Säkerställ tidsstämplar finns (för gamla DB:er)
  addColumnIfMissing('users', 'created_at', 'TEXT');
  addColumnIfMissing('users', 'updated_at', 'TEXT');
  db.prepare(`UPDATE users SET created_at = COALESCE(created_at, datetime('now'))`).run();
  db.prepare(`UPDATE users SET updated_at = COALESCE(updated_at, datetime('now'))`).run();

  // Rebuild FTS om tom
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
    db.prepare(`
      INSERT INTO users (email, password_hash, name, role)
      VALUES (?,?,?, 'admin')
    `).run(ADMIN_EMAIL, hash, 'Administrator');
    console.log('[DB] Seeded admin:', ADMIN_EMAIL);
  }
}

// Kör init (EN gång)
initSchemaAndSeed();

/* Valfri: migrations för gamla DB:er som saknar svarskolumner i questions */
const qCols = {
  answer_title: 'TEXT',
  answer_body:  'TEXT',
  answer_tags:  'TEXT',
  answered_by:  'TEXT',
  answered_at:  'TEXT',
  is_answered:  'INTEGER DEFAULT 0',
  user_seen_answer_at: 'TEXT',
};
for (const [col, ddl] of Object.entries(qCols)) {
  addColumnIfMissing('questions', col, ddl);
}
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
    created_local TEXT,
    updated_at    TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (source, dealer_id)
  );

  CREATE INDEX IF NOT EXISTS idx_dealers_md5   ON dealers (md5_token);
  CREATE INDEX IF NOT EXISTS idx_dealers_email ON dealers (email);
  CREATE INDEX IF NOT EXISTS idx_dealers_updated ON dealers (updated_at);
`);

try {
  // Kolla befintliga kolumner en gång
  const cols = db.prepare(`PRAGMA table_info(dealers)`).all().map(c => c.name);

  // Lägg till md5_token om den saknas + backfill
  if (!cols.includes('md5_token')) {
    db.exec(`ALTER TABLE dealers ADD COLUMN md5_token TEXT`);
    const rows = db.prepare(`
      SELECT source, dealer_id, IFNULL(lower(email), '') AS email
      FROM dealers
    `).all();
    const upd = db.prepare(`UPDATE dealers SET md5_token = ? WHERE source = ? AND dealer_id = ?`);
    for (const r of rows) {
      const token = crypto.createHash('md5')
        .update(String(r.dealer_id) + String(r.email), 'utf8')
        .digest('hex');
      upd.run(token, r.source, r.dealer_id);
    }
  }

  // Lägg till created_local om den saknas + backfill (först-sedd-tid)
  if (!cols.includes('created_local')) {
    db.exec(`ALTER TABLE dealers ADD COLUMN created_local TEXT`);
    db.prepare(`
      UPDATE dealers
         SET created_local = COALESCE(created_local, updated_at, datetime('now'))
    `).run();
  }

  // (Index skapas idempotent i CREATE INDEX ovan)
} catch (e) {
}
// Frågekategorier (junction)
db.exec(`
  CREATE TABLE IF NOT EXISTS question_category (
    question_id INTEGER NOT NULL,
    category_id TEXT    NOT NULL,
    PRIMARY KEY (question_id, category_id)
  );

  CREATE INDEX IF NOT EXISTS idx_qc_cat ON question_category (category_id);
  CREATE INDEX IF NOT EXISTS idx_qc_q   ON question_category (question_id);
`);

// --- MIGRATION: skapa topic_categories om den saknas ---
db.exec(`
  CREATE TABLE IF NOT EXISTS topic_categories (
    topic_id    TEXT    NOT NULL,
    category_id INTEGER NOT NULL,
    PRIMARY KEY (topic_id, category_id)
  );

  CREATE INDEX IF NOT EXISTS idx_topic_categories_cat   ON topic_categories(category_id);
  CREATE INDEX IF NOT EXISTS idx_topic_categories_topic ON topic_categories(topic_id);
`);

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
app.use('/tinymce', express.static(path.join(__dirname, 'node_modules', 'tinymce')));

// ---- Globala locals (EN källa för showHero + popularTags) ----
app.use((req, res, next) => {
  res.locals.title = 'Tuning Helpdesk';
  res.locals.user  = getUser(req) || null;

  // Döp vilka prefix som ska DÖLJA hero
  const noHeroPrefixes = ['/admin', '/login', '/register', '/ask', '/topic', '/profile', '/explore', '/questions', '/resources'];
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
  INSERT INTO dealers (
    source, dealer_id, email, username, company, firstname, lastname, telephone, added, md5_token,
    created_local, updated_at
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  ON CONFLICT(source, dealer_id) DO UPDATE SET
    email         = excluded.email,
    username      = excluded.username,
    company       = excluded.company,
    firstname     = excluded.firstname,
    lastname      = excluded.lastname,
    telephone     = excluded.telephone,
    added         = excluded.added,
    md5_token     = excluded.md5_token,
    created_local = COALESCE(dealers.created_local, excluded.created_local),
    updated_at    = datetime('now')
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

function upsertDealers(source, list) {
  const tx = db.transaction(() => {
    for (const rec of list) {
      // behåll original-casing för token, men lagra email i lowercase
      const rawEmail = (rec.email || '').trim();
      const email    = rawEmail.toLowerCase();
      const dealerId = rec.ID || '';

      const d = {
        dealer_id: dealerId,
        email,
        username:  rec.username  || '',
        company:   rec.company   || '',
        firstname: rec.firstname || '',
        lastname:  rec.lastname  || '',
        telephone: rec.telephone || null,
        added:     rec.added     || null,
      };

      // TOKEN = md5(id + RAW email) — matchar partnerns MySQL-exempel
      const token = md5(dealerId + rawEmail);

      upsertDealerStmt.run(
        source, d.dealer_id, d.email, d.username, d.company,
        d.firstname, d.lastname, d.telephone, d.added, token
      );

      // Promo till dealer-roll om email finns, inte admin, och inte redan dealer
      if (d.email) {
        db.prepare(`
          UPDATE users
             SET role='dealer', updated_at=datetime('now')
           WHERE lower(email)=lower(?)
             AND role <> 'admin'
             AND role <> 'dealer'
        `).run(d.email);
      }
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
  res.locals.me = u || null;
  res.locals.notifCount = 0;
  res.locals.adminOpenCount = 0;
  res.locals.notifications = []; // <-- viktigt

  try {
    if (u && u.role === 'admin') {
      // Badge-count
      const row = db.prepare(`SELECT COUNT(*) AS n FROM questions WHERE status='open'`).get();
      res.locals.adminOpenCount = row?.n || 0;

      // Lista till popupen (senaste öppna)
      const rows = db.prepare(`
        SELECT id, title, created_at
        FROM questions
        WHERE status = 'open'
        ORDER BY created_at DESC
        LIMIT 10
      `).all();

      res.locals.notifications = rows.map(q => ({
        id: q.id,
        title: q.title || 'Ny fråga',
        message: 'Ny obesvarad fråga',
        href: `/questions/${q.id}`
      }));

    } else if (u && u.role === 'user') {
      // Badge-count
      const row = db.prepare(`
        SELECT COUNT(*) AS n
        FROM questions
        WHERE user_id = ?
          AND status = 'answered'
          AND (user_seen_answer_at IS NULL OR user_seen_answer_at < answered_at)
      `).get(u.id);
      res.locals.notifCount = row?.n || 0;

      // Lista till popupen (obesedda svar)
      const rows = db.prepare(`
        SELECT id, title, answered_at
        FROM questions
        WHERE user_id = ?
          AND status = 'answered'
          AND (user_seen_answer_at IS NULL OR user_seen_answer_at < answered_at)
        ORDER BY answered_at DESC
        LIMIT 10
      `).all(u.id);

      res.locals.notifications = rows.map(q => ({
        id: q.id,
        title: q.title || 'Ditt svar är klart',
        message: 'Nytt svar på din fråga',
        href: `/questions/${q.id}`
      }));
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
        VALUES (?, ?, 'user', '', datetime('now'), datetime('now'))
      `).run(email, displayName);

      user = db.prepare(`SELECT id, email, role, name FROM users WHERE lower(email)=lower(?)`).get(email);
    }

    // 🔹 Här stoppar du in dealer-roll-logiken
    const isDealerEmail = db.prepare(`
      SELECT 1 FROM dealers WHERE lower(email) = lower(?) LIMIT 1
    `).get(user.email);

    if (isDealerEmail && user.role !== 'admin' && user.role !== 'dealer') {
      db.prepare(`UPDATE users SET role='dealer', updated_at=datetime('now') WHERE id=?`).run(user.id);
      user.role = 'dealer'; // uppdatera lokalt objekt också
    }

    // Sätt JWT-cookie (din befintliga helper)
    res.cookie('auth', signUser(user), {
      httpOnly: true, sameSite: 'lax', secure: false, maxAge: 14 * 24 * 3600 * 1000
    });

    db.prepare(`UPDATE users SET updated_at = datetime('now') WHERE id=?`).run(user.id);
    return res.redirect(redirectTo);
  } catch (err) {
    return res.status(500).send('Login failed');
  }
});

app.get('/editor-test', (req, res) => {
  res.render('text-editor'); // matchar views/text-editor.ejs
});

// Kör: GET /admin/tools/backfill-dealer-roles
app.get('/admin/tools/backfill-dealer-roles', requireAdmin, (req, res) => {
  const sql = `
    UPDATE users
       SET role = 'dealer',
           updated_at = datetime('now')
     WHERE role <> 'admin'
       AND lower(email) IN (SELECT lower(email) FROM dealers WHERE email IS NOT NULL AND email <> '')
  `;
  const info = db.prepare(sql).run();
  res.send(`Dealer-roller uppdaterade: ${info.changes} användare`);
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
// --- RELATERADE ÄMNEN ---
// --- RELATERADE ÄMNEN (utan t.category_id: m2m + tagg-fallback) ---
let relatedTopics = [];

try {
  const catIds = db.prepare(`
    SELECT category_id FROM topic_categories WHERE topic_id = ?
  `).all(topic.id).map(r => r.category_id);

  if (catIds.length) {
    const placeholders = catIds.map(() => '?').join(',');
    relatedTopics = db.prepare(`
      SELECT DISTINCT b.id, t.title
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      JOIN topic_categories tc ON tc.topic_id = t.id
      WHERE tc.category_id IN (${placeholders})
        AND b.id <> ?
        AND IFNULL(t.is_resource, 0) = 0
      ORDER BY COALESCE(b.updated_at, b.created_at) DESC
      LIMIT 6
    `).all(...catIds, topic.id);
  }
} catch (e) {
  // Om topic_categories saknas, gå direkt till tagg-fallback
}

// Fallback via första taggen (om inga kategori-träffar)
if (!relatedTopics.length) {
  const firstTag = (topic.tags || '').split(',')[0]?.trim().toLowerCase() || '';
  if (firstTag) {
    relatedTopics = db.prepare(`
      SELECT b.id, t.title
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      WHERE b.id <> ?
        AND lower(IFNULL(t.tags,'')) LIKE '%' || ? || '%'
        AND IFNULL(t.is_resource, 0) = 0
      ORDER BY COALESCE(b.updated_at, b.created_at) DESC
      LIMIT 6
    `).all(topic.id, firstTag);
  }
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
  const id = Number(req.params.id);

  const q = db.prepare(`
    SELECT q.*, u.name AS user_name, u.email AS user_email
    FROM questions q
    LEFT JOIN users u ON u.id = q.user_id
    WHERE q.id=?
  `).get(id);

  if (!q) return res.status(404).send('Not found');

  // ev. redan kopplade ämnen (om du hade detta)
  const linked = db.prepare(`
    SELECT t.id, t.title
    FROM question_topic qt
    JOIN topics t ON t.id=qt.topic_id
    WHERE qt.question_id=?
    ORDER BY t.title
  `).all(id);

  // NYTT: alla kategorier + denna frågas kategorier
  const categories = db.prepare(`
    SELECT id, title
    FROM categories
    ORDER BY COALESCE(sort_order,9999), title
  `).all();

  const qCategoryIds = db.prepare(`
    SELECT category_id AS id
    FROM question_category
    WHERE question_id=?
  `).all(id).map(r => r.id);

  res.render('admin-question', {
    title: 'Fråga',
    q,
    linked,
    categories,
    qCategoryIds
  });
});

app.put('/api/questions/:id/category', express.json(), (req, res) => {
  const qid = Number(req.params.id);
  const { category_id } = req.body;
  if (!qid || !category_id) return res.status(400).json({ error: 'category_id krävs' });

  const tx = db.transaction(() => {
    db.prepare(`DELETE FROM question_category WHERE question_id = ?`).run(qid);
    db.prepare(`INSERT INTO question_category (question_id, category_id) VALUES (?, ?)`)
      .run(qid, String(category_id));
  });
  tx();

  res.json({ ok: true });
});

app.put('/api/questions/:id/categories', requireAdmin, express.json(), (req, res) => {
  const qid = Number(req.params.id);
  const ids = Array.isArray(req.body.category_ids) ? req.body.category_ids.filter(Boolean) : [];

  // validera att frågan finns
  const exists = db.prepare(`SELECT 1 FROM questions WHERE id=?`).get(qid);
  if (!exists) return res.status(404).json({ error: 'Fråga saknas' });

  const tx = db.transaction(() => {
    // 1) Spara frågans kategorier
    db.prepare(`DELETE FROM question_category WHERE question_id=?`).run(qid);
    if (ids.length) {
      const insQ = db.prepare(`INSERT OR IGNORE INTO question_category (question_id, category_id) VALUES (?, ?)`);
      for (const cid of ids) insQ.run(qid, String(cid));
    }
    db.prepare(`UPDATE questions SET updated_at=datetime('now') WHERE id=?`).run(qid);

    // 2) Synka till kopplat ÄMNE (om frågan har ett svar/ämne)
    const link = db.prepare(`
      SELECT topic_id FROM question_topic
      WHERE question_id=? ORDER BY rowid DESC LIMIT 1
    `).get(qid);

    if (link && ids.length) {
      // försök plural-tabellen först (vanligast i resten av koden)
      try {
        const insT = db.prepare(`INSERT OR IGNORE INTO topic_categories (topic_id, category_id) VALUES (?, ?)`);
        for (const cid of ids) insT.run(link.topic_id, String(cid));
      } catch (e) {
        // fallback om du råkar ha singular-tabellen
        try {
          const insT2 = db.prepare(`INSERT OR IGNORE INTO topic_category (topic_id, category_id) VALUES (?, ?)`);
          for (const cid of ids) insT2.run(link.topic_id, String(cid));
        } catch (_) { /* ignorera tyst */ }
      }
      // (valfritt) uppdatera topic timestamp
      try {
        db.prepare(`UPDATE topics_base SET updated_at=datetime('now') WHERE id=?`).run(link.topic_id);
      } catch (_) {}
    }
  });

  try {
    tx();
    res.json({ ok: true });
  } catch (e) {
    console.error('save categories failed', e);
    res.status(500).json({ error: 'Kunde inte spara kategorier' });
  }
});

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

// --- Autosuggest API ---
app.get('/api/suggest', (req, res) => {
  const raw = (req.query.q || '').trim();
  if (!raw) {
    return res.json([]);
  }

  const q = raw.replace(/[^\p{L}\p{N}\s_-]/gu, '');
  const termsArr = q.split(/\s+/).filter(Boolean).map(t => `${t}*`);
  const ftsQuery = termsArr.length ? termsArr.join(' OR ') : '';

  const results = [];
  const topicIds = new Set();
  const topicTitles = new Set();
  const norm = s => (s||'').toString().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'');

  // 1) Topics via FTS
  if (ftsQuery) {
    try {
      const topicRows = db.prepare(`
        SELECT t.id, t.title, t.is_resource AS is_resource,
               substr(COALESCE(NULLIF(t.excerpt,''), t.body), 1, 120) AS snippet
        FROM topics_fts f
        JOIN topics      t ON t.id = f.id
        JOIN topics_base b ON b.id = f.id
        WHERE topics_fts MATCH ?
        ORDER BY bm25(topics_fts)
        LIMIT 5
      `).all(ftsQuery);


      for (const r of topicRows) {
        const type = r.is_resource ? 'resource' : 'topic';
        results.push({ type, id: r.id, title: r.title, snippet: r.snippet || '' });
        topicIds.add(r.id);
        topicTitles.add(norm(r.title));
      }
    } catch (e) {
    }
  }

  // 2) Fallback topics (LIKE)
  if (results.length < 5) {
    const esc  = s => s.replace(/[%_]/g, m => '\\' + m);
    const like = `%${esc(q)}%`;
    const left = 5 - results.length;

    const topicLike = db.prepare(`
      SELECT b.id, t.title, t.is_resource AS is_resource,
             substr(COALESCE(NULLIF(t.excerpt,''), t.body), 1, 120) AS snippet
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      WHERE t.title   LIKE ? ESCAPE '\\'
         OR t.excerpt LIKE ? ESCAPE '\\'
         OR t.body    LIKE ? ESCAPE '\\'
      ORDER BY b.updated_at DESC
      LIMIT ?
    `).all(like, like, like, left);


    for (const r of topicLike) {
      if (topicIds.has(r.id)) continue;
      const type = r.is_resource ? 'resource' : 'topic';
      results.push({ type, id: r.id, title: r.title, snippet: r.snippet || '' });
      topicIds.add(r.id);
      topicTitles.add(norm(r.title));
    }
  }

  // 3) Questions (LIKE)
  if (results.length < 8) {
    const esc  = s => s.replace(/[%_]/g, m => '\\' + m);
    const like = `%${esc(q)}%`;
    const left = 8 - results.length;

    const qs = db.prepare(`
      SELECT id, title, substr(COALESCE(body,''), 1, 120) AS snippet
      FROM questions
      WHERE title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\'
      ORDER BY datetime(created_at) DESC
      LIMIT ?
    `).all(like, like, Math.min(left, 3));


    for (const r of qs) {
      if (topicTitles.has(norm(r.title))) {
        continue;
      }
      results.push({ type: 'question', id: String(r.id), title: r.title, snippet: r.snippet || '' });
    }
  }

  // Summering
  res.json(results);
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


/// Hjälpare
function shuffle(a){ for (let i=a.length-1;i>0;i--){ const j=Math.floor(Math.random()*(i+1)); [a[i],a[j]]=[a[j],a[i]] } return a; }
function hasTable(name){
  return !!db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).get(name);
}

// Bygg kategorikort (ämnen + resurser + frågor)
function buildCategoriesMixed(){
  const cats = db.prepare(`SELECT id, title, icon FROM categories ORDER BY COALESCE(sort_order,9999), title`).all();
  const catById = new Map(cats.map(c => [String(c.id), c]));

  // Ämnen + resurser
  const topicRows = db.prepare(`
    SELECT
      tc.category_id                         AS cid,
      t.id                                   AS id,
      t.title                                AS title,
      CASE WHEN t.is_resource=1 THEN 'resource' ELSE 'topic' END AS type,
      b.updated_at                           AS ts
    FROM topic_category tc
    JOIN topics      t ON t.id = tc.topic_id
    JOIN topics_base b ON b.id = t.id
  `).all();

  // Frågor (om tabellen finns)
  const questionRows = hasTable('question_category')
    ? db.prepare(`
        SELECT
          qc.category_id  AS cid,
          q.id            AS id,
          q.title         AS title,
          'question'      AS type,
          q.created_at    AS ts
        FROM question_category qc
        JOIN questions q ON q.id = qc.question_id
      `).all()
    : [];

  // Slå ihop & sortera nyast först
  const merged = [...topicRows, ...questionRows].sort((a,b) => (a.ts < b.ts ? 1 : -1));

  // Gruppera per kategori, max 4 poster per kort
  const byCat = new Map();
  for (const r of merged) {
    const key = String(r.cid);
    if (!byCat.has(key)) byCat.set(key, []);
    const bucket = byCat.get(key);
    if (bucket.length < 4) bucket.push({ id: r.id, title: r.title, type: r.type });
  }

  // Välj endast kategorier som har innehåll och slumpa 3
  const filled = Array.from(byCat.keys())
    .map(cid => {
      const c = catById.get(cid);
      return c ? {
        id: c.id,
        title: c.title,
        icon: c.icon || 'ti-folder',
        items: byCat.get(cid) || []
      } : null;
    })
    .filter(Boolean)
    .filter(card => card.items.length > 0);

  shuffle(filled);
  return filled.slice(0, 3);
}

// Bygger upp "kategorikort" till startsidan (ämnen + resurser + frågor)
function buildCategories() {
  // 1) Kategorier
  const cats = db.prepare(`
    SELECT id, title, icon, sort_order
    FROM categories
    ORDER BY COALESCE(sort_order, 9999), title
  `).all();

  // 2) Senaste poster per kategori (ämnen/resurser + frågor)
  const rows = db.prepare(`
    SELECT cid, id, title, type, ts
    FROM (
      -- Ämnen & resurser
      SELECT
        tc.category_id           AS cid,
        t.id                     AS id,
        t.title                  AS title,
        CASE WHEN t.is_resource = 1 THEN 'resource' ELSE 'topic' END AS type,
        b.updated_at             AS ts
      FROM topic_category tc
      JOIN topics       t ON t.id = tc.topic_id
      JOIN topics_base  b ON b.id = t.id

      UNION ALL

      -- Frågor
      SELECT
        qc.category_id           AS cid,
        q.id                     AS id,
        q.title                  AS title,
        'question'               AS type,
        q.created_at             AS ts
      FROM question_category qc
      JOIN questions        q ON q.id = qc.question_id
    )
    ORDER BY cid, ts DESC
  `).all();

  // 3) Grupp och ta topp 4 per kategori
  const byCat = new Map();
  for (const r of rows) {
    if (!byCat.has(r.cid)) byCat.set(r.cid, []);
    const arr = byCat.get(r.cid);
    if (arr.length < 4) {
      arr.push({
        id: r.id,
        title: r.title,
        type: r.type,
        href: r.type === 'resource'
          ? `/resources/${encodeURIComponent(r.id)}`
          : r.type === 'question'
            ? `/questions/${encodeURIComponent(r.id)}`
            : `/topic/${encodeURIComponent(r.id)}`
      });
    }
  }

  // 4) Returnera till vyn
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
 const categoriesShow = buildCategoriesMixed();
res.set('Cache-Control','no-store'); // så slumpen gäller varje laddning

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

app.get('/resources/:id/download', (req, res) => {
  const id = String(req.params.id || '').trim();

  const row = db.prepare(`
    SELECT download_url
    FROM topics
    WHERE id = ?
  `).get(id);

  if (!row)         return res.status(404).send('Resurs ej hittad');
  if (!row.download_url) return res.status(400).send('Ingen fil länkad');

  db.prepare(`UPDATE topics SET downloads = COALESCE(downloads,0) + 1 WHERE id = ?`).run(id);

  console.log('[download] incremented for', id);

  return res.redirect(row.download_url);
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

// Publik vy för en fråga (kategori-drivna relaterade listor + tagg-drivna relaterade frågor)
app.get('/questions/:id', (req, res) => {
  const id = Number(req.params.id);
  const me = getUser(req);

  // 1) Frågan
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

  // 2) Kopplat svar-ämne (om något)
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
             t.title, t.excerpt, t.body, t.tags, t.is_resource,
             u.name AS author_name
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      LEFT JOIN users u ON u.id = b.created_by
      WHERE b.id = ?
    `).get(link.topic_id);

    // Markera sedd för ägaren vid besvarad fråga
    if (me && me.id === q.user_id && q.status === 'answered') {
      db.prepare(`UPDATE questions SET user_seen_answer_at = datetime('now') WHERE id=?`).run(q.id);
    }
  }

  // 3) Kategorier att utgå ifrån (topic_categories -> fallback question_category)
  let catIds = [];
  try {
    if (answerTopic) {
      catIds = db.prepare(`
        SELECT category_id FROM topic_categories WHERE topic_id = ?
      `).all(answerTopic.id).map(r => r.category_id);
    }
  } catch (_) { /* ignore */ }
  if (!catIds.length) {
    try {
      catIds = db.prepare(`
        SELECT category_id FROM question_category WHERE question_id = ?
      `).all(q.id).map(r => r.category_id);
    } catch (_) { /* ignore */ }
  }

  // --- SIDOKOLUMN START ---
  let relatedQuestions = [];
  let relatedTopics    = [];

  if (catIds.length) {
    const ph = catIds.map(() => '?').join(',');

    // 1) Alla ÄMNEN + FRÅGOR i samma kategori
    // a) Topics (inkl resurser)
    const sameCatTopics = db.prepare(`
      SELECT DISTINCT 
        b.id   AS id,
        t.title,
        IFNULL(t.is_resource,0) AS is_resource,
        COALESCE(b.updated_at, b.created_at) AS ts,
        'topic' AS kind
      FROM topics_base b
      JOIN topics t            ON t.id = b.id
      JOIN topic_categories tc ON tc.topic_id = t.id
      WHERE tc.category_id IN (${ph})
        AND ( ? IS NULL OR b.id <> ? )
    `).all(...catIds, answerTopic ? answerTopic.id : null, answerTopic ? answerTopic.id : null);

    // b) Frågor i samma kategori
    const sameCatQuestions = db.prepare(`
      SELECT DISTINCT
        q2.id   AS id,
        q2.title,
        0       AS is_resource,
        COALESCE(q2.updated_at, q2.created_at) AS ts,
        'question' AS kind
      FROM questions q2
      JOIN question_category qc2 ON qc2.question_id = q2.id
      WHERE qc2.category_id IN (${ph})
        AND q2.id <> ?
    `).all(...catIds, q.id);

    relatedTopics = [...sameCatTopics, ...sameCatQuestions]
      .sort((a,b) => new Date(b.ts) - new Date(a.ts))
      .slice(0, 10);
  }

// 2) Relaterat på taggar (frågor + ämnen + resurser)
{
  const tagSet = new Set(
    ((answerTopic?.tags || '') + ',' + (q.answer_tags || ''))
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean)
  );
  const tags = Array.from(tagSet).slice(0, 8);

  relatedQuestions = []; // återanvänd variabeln, men nu fyller vi den med blandade typer

  if (tags.length) {
    const likeTopicTags = tags.map(() => `lower(IFNULL(t.tags,'')) LIKE ?`).join(' OR ');
    const likeQTags     = tags.map(() => `lower(IFNULL(q.answer_tags,'')) LIKE ?`).join(' OR ');
    const likeVals      = tags.map(t => `%${t}%`);

    // UNION: frågor (via topic.tags ELLER q.answer_tags) + topics (inkl. resurser) som matchar taggar
    relatedQuestions = db.prepare(`
      SELECT kind, id, title, is_resource FROM (
        -- Frågor: via kopplade ämnens taggar
        SELECT 'question' AS kind, q2.id AS id, q2.title AS title, 0 AS is_resource,
               datetime(q2.created_at) AS ts
        FROM questions q2
        JOIN question_topic qt2 ON qt2.question_id = q2.id
        JOIN topics t           ON t.id = qt2.topic_id
        WHERE q2.id <> ?
          AND ( ${likeTopicTags} )

        UNION

        -- Frågor: via egna answer_tags
        SELECT 'question' AS kind, q3.id AS id, q3.title AS title, 0 AS is_resource,
               datetime(q3.created_at) AS ts
        FROM questions q3
        WHERE q3.id <> ?
          AND ( ${likeQTags} )

        UNION

        -- Ämnen + Resurser: via topic.tags
        SELECT 'topic' AS kind, b.id AS id, t2.title AS title, IFNULL(t2.is_resource,0) AS is_resource,
               datetime(COALESCE(b.updated_at, b.created_at)) AS ts
        FROM topics_base b
        JOIN topics t2 ON t2.id = b.id
        WHERE ( ${likeTopicTags.replace(/t\./g, 't2.')} )
          AND b.id <> IFNULL(?, -1)  -- exkludera ev. aktuellt answerTopic
      )
      ORDER BY ts DESC
      LIMIT 10
    `).all(
      q.id,                // <> ? (för q2)
      ...likeVals,         // LIKE t.tags för frågor via topic
      q.id,                // <> ? (för q3)
      ...likeVals,         // LIKE q.answer_tags
      answerTopic ? answerTopic.id : null,  // exkludera aktuellt topic
      ...likeVals          // LIKE t2.tags för topics/resources
    );
  }

    // Fallback: om inga taggar eller 0 träffar — och vi HAR ett answerTopic — ta frågor via samma topic
    if ((!tags.length || !relatedQuestions.length) && answerTopic) {
      relatedQuestions = db.prepare(`
        SELECT DISTINCT q2.id, q2.title
        FROM questions q2
        JOIN question_topic qt2 ON qt2.question_id = q2.id
        WHERE qt2.topic_id = ?
          AND q2.id <> ?
        ORDER BY q2.created_at DESC
        LIMIT 5
      `).all(answerTopic.id, q.id);
    }
  }
  // --- SIDOKOLUMN SLUT ---

  res.locals.showHero = false;
  res.render('question', {
    title: `Fråga: ${q.title}`,
    q,
    answerTopic,
    relatedQuestions, // endast taggar (med fallback samma topic)
    relatedTopics,    // ALLT i samma kategori (ämnen + resurser + frågor)
    user: me
  });
});

app.get('/explore', (req, res) => {
  const tabParam = String(req.query.tab || '').toLowerCase();
  const tab = ['topics','questions','resources','all'].includes(tabParam) ? tabParam : 'all';

  const q   = (req.query.q   || '').trim().toLowerCase();
  const cat = (req.query.cat || '').trim();                   // category id
  const tag = (req.query.tag || '').trim().toLowerCase();

  // Sidebar: kategorier
  const categories = db.prepare(`
    SELECT id, title
    FROM categories
    ORDER BY COALESCE(sort_order, 9999), title
  `).all();

  // Sidebar: populära taggar (från icke-resursämnen)
  const tagRows = db.prepare(`
    SELECT t.tags
    FROM topics t
    WHERE t.is_resource = 0 AND IFNULL(t.tags,'') <> ''
  `).all();
  const tagCounter = {};
  for (const r of tagRows) {
    (r.tags || '').split(',').map(s=>s.trim()).filter(Boolean).forEach(tg=>{
      const key = tg.toLowerCase();
      tagCounter[key] = (tagCounter[key]||0) + 1;
    });
  }
  const tags = Object.entries(tagCounter)
    .sort((a,b)=>b[1]-a[1])
    .slice(0,30)
    .map(([name,count])=>({ name, count }));

  const like = q ? `%${q}%` : null;

  // ---- helpers (ämnen/resurser delar baskod)
  function fetchTopicsBase(isResource) {
    let sql = `
      SELECT b.id, t.title, t.excerpt, t.tags, t.is_resource, b.updated_at AS ts
      FROM topics_base b
      JOIN topics t ON t.id = b.id
      WHERE t.is_resource = ?
    `;
    const params = [isResource ? 1 : 0];

    if (q) {
      sql += ` AND (lower(t.title) LIKE ? OR lower(t.excerpt) LIKE ? OR lower(t.body) LIKE ?) `;
      params.push(like, like, like);
    }
    if (cat) {
      sql += ` AND EXISTS (SELECT 1 FROM topic_category tc WHERE tc.topic_id=b.id AND tc.category_id=?) `;
      params.push(cat);
    }
    if (!isResource && tag) {
      sql += ` AND lower(IFNULL(t.tags,'')) LIKE ? `;
      params.push(`%${tag}%`);
    }

    sql += ` ORDER BY datetime(ts) DESC LIMIT 100 `;
    return db.prepare(sql).all(...params);
  }

  function fetchTopics()    { return fetchTopicsBase(false); }
  function fetchResources() { return fetchTopicsBase(true);  }

  function fetchQuestions() {
    let sql = `
      SELECT q.id, q.title, q.status, q.created_at AS ts
      FROM questions q
      WHERE 1=1
    `;
    const params = [];
    if (q) {
      sql += ` AND (lower(q.title) LIKE ? OR lower(IFNULL(q.body,'')) LIKE ?) `;
      params.push(like, like);
    }
    if (cat) {
      sql += ` AND EXISTS (SELECT 1 FROM question_category qc WHERE qc.question_id=q.id AND qc.category_id=?) `;
      params.push(cat);
    }
    sql += ` ORDER BY datetime(ts) DESC LIMIT 100 `;
    return db.prepare(sql).all(...params);
  }

  // Hämta enligt tab
  let T=[], R=[], Q=[];
  if (tab === 'topics') {
    T = fetchTopics();
  } else if (tab === 'resources') {
    R = fetchResources();
  } else if (tab === 'questions') {
    Q = fetchQuestions();
  } else { // all
    T = fetchTopics();
    R = fetchResources();
    Q = fetchQuestions();
  }

  // Slå ihop till en enhetlig lista
  const items = [];
  for (const t of T) {
    items.push({
      type: 'topic',
      id:   t.id,
      title: t.title,
      excerpt: t.excerpt || '',
      ts:  t.ts,
      href: `/topic/${encodeURIComponent(t.id)}`
    });
  }
  for (const r of R) {
    items.push({
      type: 'resource',
      id:   r.id,
      title: r.title,
      excerpt: r.excerpt || '',
      ts:  r.ts,
      href: `/resources/${encodeURIComponent(r.id)}`
    });
  }
  for (const qrow of Q) {
    items.push({
      type: 'question',
      id:   String(qrow.id),
      title: qrow.title,
      excerpt: '', // kan fyllas med snippet om du vill
      ts:  qrow.ts,
      href: `/questions/${encodeURIComponent(qrow.id)}`
    });
  }

  items.sort((a,b)=> new Date(b.ts) - new Date(a.ts));

  res.render('explore', {
    title: 'Utforska',
    tab,
    q, cat, tag,
    categories,
    tags,
    items,
    user: getUser(req)
  });
});

// Visa en specifik resurs (separat layout från vanliga topics)
app.get('/resources/:id', (req, res) => {
  const row = db.prepare(`
    SELECT b.id, t.title, t.excerpt, t.body, t.tags, b.updated_at,
           t.is_resource, t.download_url, t.downloads
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

// 1) Manuell dealers-sync-knapp
app.post('/admin/sync-dealers', requireAdmin, async (req, res) => {
  try {
    await syncAllDealers();
    return res.redirect('/admin?ok=Dealer%20sync%20klar');
  } catch (e) {
    console.error('Admin sync error:', e);
    return res.redirect('/admin?err=Sync%20misslyckades');
  }
});

// 2) Bygg om sökindex (topics_fts)
app.post('/admin/reindex', requireAdmin, (req, res) => {
  try {
    // töm index
    db.prepare(`DELETE FROM topics_fts`).run();
    // återbygg från topics
    const rows = db.prepare(`SELECT id, COALESCE(title,'') AS title, COALESCE(excerpt,'') AS excerpt, COALESCE(body,'') AS body FROM topics`).all();
    const ins  = db.prepare(`INSERT INTO topics_fts (id,title,excerpt,body) VALUES (?,?,?,?)`);
    const tx   = db.transaction(list => { for (const r of list) ins.run(r.id, r.title, r.excerpt, r.body); });
    tx(rows);
    return res.redirect('/admin?ok=Sökindex%20återbyggt');
  } catch (e) {
    console.error('Reindex error:', e);
    return res.redirect('/admin?err=Kunde%20inte%20bygga%20om%20sökindex');
  }
});

// Lista alla frågor (admin)
app.get('/admin/questions', requireAdmin, (req, res) => {
  const status   = (req.query.status || '').trim();      // '', 'open', 'answered', 'closed'
  const q        = (req.query.q || '').trim();
  const page     = Math.max(1, Number(req.query.page || 1));
  const perPage  = Math.max(1, Math.min(50, Number(req.query.perPage || 15)));
  const offset   = (page - 1) * perPage;

  const where = [];
  const params = [];

  if (status) { where.push(`status = ?`); params.push(status); }
  if (q) {
    where.push(`(title LIKE ? OR body LIKE ?)`);
    params.push(`%${q}%`, `%${q}%`);
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ``;

  const totalRow = db.prepare(`SELECT COUNT(*) AS n FROM questions ${whereSql}`).get(...params);
  const total    = totalRow?.n || 0;
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  const rows = db.prepare(`
    SELECT q.id, q.title, q.status, q.created_at, q.updated_at,
           u.email AS user_email
    FROM questions q
    LEFT JOIN users u ON u.id = q.user_id
    ${whereSql}
    ORDER BY datetime(q.created_at) DESC
    LIMIT ? OFFSET ?
  `).all(...params, perPage, offset);

  res.render('admin-questions', {
    title: 'Frågor',
    questions: rows,
    q, status,
    page, perPage, total, totalPages
  });
});

// Sök i både topics och questions
app.get('/api/search', (req, res) => {
  const raw = (req.query.q || '').trim();
  // Tom fråga → visa senaste ämnen + frågor
  const hasQ = raw.length > 0;

  // Rensa + för LIKE
  const q = raw.replace(/[^\p{L}\p{N}\s_-]/gu, '');
  const esc = (s) => s.replace(/[%_]/g, m => '\\' + m);
  const like = `%${esc(q)}%`;

  // Hur många resultat totalt
  const LIMIT = 30;

  const sqlWithQ = `
    SELECT id, title, snippet, sort_ts, type FROM (
      SELECT 
        t.id AS id,
        t.title AS title,
        substr(COALESCE(NULLIF(t.excerpt,''), t.body), 1, 160) AS snippet,
        b.updated_at AS sort_ts,
        'topic' AS type
      FROM topics t
      JOIN topics_base b ON b.id = t.id
      WHERE t.title LIKE ? ESCAPE '\\'
         OR t.excerpt LIKE ? ESCAPE '\\'
         OR t.body LIKE ? ESCAPE '\\'

      UNION ALL

      SELECT
        q.id AS id,
        q.title AS title,
        substr(COALESCE(q.body, ''), 1, 160) AS snippet,
        q.updated_at AS sort_ts,
        'question' AS type
      FROM questions q
      WHERE q.title LIKE ? ESCAPE '\\'
         OR q.body LIKE ? ESCAPE '\\'
    )
    ORDER BY datetime(sort_ts) DESC
    LIMIT ${LIMIT}
  `;

  const sqlNoQ = `
    SELECT id, title, snippet, sort_ts, type FROM (
      SELECT 
        t.id AS id,
        t.title AS title,
        substr(COALESCE(NULLIF(t.excerpt,''), t.body), 1, 160) AS snippet,
        b.updated_at AS sort_ts,
        'topic' AS type
      FROM topics t
      JOIN topics_base b ON b.id = t.id

      UNION ALL

      SELECT
        q.id AS id,
        q.title AS title,
        substr(COALESCE(q.body, ''), 1, 160) AS snippet,
        q.updated_at AS sort_ts,
        'question' AS type
      FROM questions q
    )
    ORDER BY datetime(sort_ts) DESC
    LIMIT ${LIMIT}
  `;

  try {
    let rows = [];
    if (hasQ) {
      rows = db.prepare(sqlWithQ).all(like, like, like, like, like);
    } else {
      rows = db.prepare(sqlNoQ).all();
    }
    res.json(rows);
  } catch (e) {
    console.error('search error:', e);
    res.status(500).json([]);
  }
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
  const catId = req.params.id;

  const category = db.prepare(`
    SELECT id, title FROM categories WHERE id = ?
  `).get(catId);

  if (!category) {
    return res.status(404).render('404', { title: 'Kategori saknas' });
  }

  // Ämnen + resurser i kategorin
  const topicItems = db.prepare(`
    SELECT 
      b.id                AS id,
      t.title             AS title,
      COALESCE(NULLIF(t.excerpt,''), NULL) AS excerpt,
      b.updated_at        AS ts,
      CASE WHEN t.is_resource=1 THEN 'resource' ELSE 'topic' END AS type
    FROM topic_category tc
    JOIN topics_base b ON b.id = tc.topic_id
    JOIN topics      t ON t.id = b.id
    WHERE tc.category_id = ?
  `).all(catId);

  // Frågor i kategorin
  const questionItems = db.prepare(`
    SELECT 
      q.id              AS id,
      q.title           AS title,
      NULL              AS excerpt,
      q.created_at      AS ts,
      'question'        AS type
    FROM question_category qc
    JOIN questions q ON q.id = qc.question_id
    WHERE qc.category_id = ?
  `).all(catId);

  // Slå ihop och sortera
  const items = [...topicItems, ...questionItems]
    .sort((a, b) => new Date(b.ts) - new Date(a.ts))
    .map(it => ({
      ...it,
      href: it.type === 'question' 
              ? `/questions/${encodeURIComponent(it.id)}`
              : it.type === 'resource'
                ? `/resources/${encodeURIComponent(it.id)}`
                : `/topic/${encodeURIComponent(it.id)}`
    }));

  res.render('category', {
    title: category.title,
    category,
    items,
    user: getUser(req)
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

// /admin-accounts – lista users + dealers med sök, filter och paginering
app.get('/admin-accounts', requireAdmin, (req, res) => {
  // --- Query params (med defaults) ---
  const qRaw     = (req.query.q || '').trim();
  const q        = qRaw;                   // skickas till vyn
  const source   = (req.query.source || '').trim();      // '' | 'nms' | 'dynex'
  const perPage  = Math.max(1, Number(req.query.perPage || 15));
  const page     = Math.max(1, Number(req.query.page || 1));

  // --- Users: hämta en rimlig mängd (utan filter här) ---
  const users = db.prepare(`
    SELECT id, email, name, role, created_at, updated_at
    FROM users
    ORDER BY datetime(created_at) DESC
  `).all();

  // --- Dealers: bygg WHERE dynamiskt för filter/sök ---
  const where = [];
  const params = [];

  if (source === 'nms' || source === 'dynex') {
    where.push(`source = ?`);
    params.push(source);
  }

  if (qRaw) {
    // enkel fritext över flera fält (case-insensitive)
    const like = `%${qRaw.toLowerCase()}%`;
    where.push(`
      (
        lower(IFNULL(email,''))     LIKE ?
        OR lower(IFNULL(username,''))  LIKE ?
        OR lower(IFNULL(company,''))   LIKE ?
        OR lower(IFNULL(firstname,'')) LIKE ?
        OR lower(IFNULL(lastname,''))  LIKE ?
        OR lower(IFNULL(telephone,'')) LIKE ?
      )
    `);
    params.push(like, like, like, like, like, like);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  // --- Totals ---
  const totalDealersAll = db.prepare(`SELECT COUNT(*) AS n FROM dealers`).get().n;
  const totalFiltered   = db.prepare(`SELECT COUNT(*) AS n FROM dealers ${whereSql}`).get(...params).n;

  // --- Paginering ---
  const totalPages = Math.max(1, Math.ceil(totalFiltered / perPage));
  const safePage   = Math.min(page, totalPages);
  const offset     = (safePage - 1) * perPage;

// --- Hämta dealers för aktuell sida ---
const dealers = db.prepare(`
  SELECT
    source,
    dealer_id,
    email,
    username,
    company,
    firstname,
    lastname,
    telephone,
    added,
    updated_at,
    md5_token               -- <-- ta med token
  FROM dealers
  ${whereSql}
  ORDER BY datetime(updated_at) DESC
  LIMIT ? OFFSET ?
`).all(...params, perPage, offset);

// --- Render ---
res.render('admin-accounts', {
  title: 'Konton & dealers',
  users,
  dealers,
  totalDealersAll,
  totalFiltered,
  totalPages,
  page: safePage,
  q,
  source,
  perPage
});
});

app.get('/admin/dealers/token', requireAdmin, (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!email) return res.status(400).send('email is required');
  const row = db.prepare(`
    SELECT source, dealer_id, email, md5_token, updated_at
    FROM dealers
    WHERE lower(email) = ?
    ORDER BY updated_at DESC
    LIMIT 1
  `).get(email);
  if (!row) return res.status(404).send('not found');
  res.json(row);
});

// 3) (Valfritt) Senaste användare & dealers till dashboarden
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

  const latestUsers = db.prepare(`
    SELECT id, email, name, role, created_at
    FROM users
    ORDER BY datetime(created_at) DESC
    LIMIT 8
  `).all();

const latestDealers = db.prepare(`
  SELECT source, email, company, firstname, lastname, updated_at
  FROM dealers
  ORDER BY datetime(updated_at) DESC
  LIMIT 4
`).all();

  res.render('admin', {
    title: 'Adminpanel',
    openQs,
    latestTopics,
    latestUsers,
    latestDealers,
    ok: req.query.ok || '',
    err: req.query.err || ''
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