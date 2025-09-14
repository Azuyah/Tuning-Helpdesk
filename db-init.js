// db-init.js
import Database from 'better-sqlite3';

const db = new Database('helpdesk.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
BEGIN;

-- Rensa ev. gamla FTS-tabeller om de finns i fel skick
DROP TABLE IF EXISTS topics_fts;

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  name          TEXT,
  role          TEXT NOT NULL DEFAULT 'user',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- TOPICS (vanlig tabell)
CREATE TABLE IF NOT EXISTS topics (
  id          TEXT PRIMARY KEY,              -- slug
  title       TEXT NOT NULL,
  excerpt     TEXT,
  body        TEXT NOT NULL,
  author_id   INTEGER,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
);

-- CATEGORIES
CREATE TABLE IF NOT EXISTS categories (
  id    TEXT PRIMARY KEY,                    -- slug
  name  TEXT NOT NULL UNIQUE
);

-- TOPIC ↔ CATEGORY
CREATE TABLE IF NOT EXISTS topic_category (
  topic_id    TEXT NOT NULL,
  category_id TEXT NOT NULL,
  PRIMARY KEY (topic_id, category_id),
  FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE CASCADE,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
);

-- TAGS
CREATE TABLE IF NOT EXISTS tags (
  id    TEXT PRIMARY KEY,                    -- slug
  name  TEXT NOT NULL UNIQUE
);

-- TOPIC ↔ TAG
CREATE TABLE IF NOT EXISTS topic_tag (
  topic_id TEXT NOT NULL,
  tag_id   TEXT NOT NULL,
  PRIMARY KEY (topic_id, tag_id),
  FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id)   REFERENCES tags(id)   ON DELETE CASCADE
);

-- QUESTIONS
CREATE TABLE IF NOT EXISTS questions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  title      TEXT NOT NULL,
  body       TEXT,
  status     TEXT NOT NULL DEFAULT 'open',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- QUESTION ↔ TOPIC
CREATE TABLE IF NOT EXISTS question_topic (
  question_id INTEGER NOT NULL,
  topic_id    TEXT NOT NULL,
  PRIMARY KEY (question_id, topic_id),
  FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
  FOREIGN KEY (topic_id)    REFERENCES topics(id)    ON DELETE CASCADE
);

-- FTS5 utan triggers; vi uppdaterar i app-koden
CREATE VIRTUAL TABLE IF NOT EXISTS topics_fts USING fts5(
  id UNINDEXED,  -- vi lagrar slug men söker i title/excerpt/body
  title, excerpt, body,
  tokenize = 'porter'
);

COMMIT;
`);

console.log('✅ Databas initierad (utan triggers, appen uppdaterar FTS).');