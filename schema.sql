PRAGMA foreign_keys=ON;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL CHECK(role IN ('admin','user')) DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE VIRTUAL TABLE topics USING fts5(
  id UNINDEXED,
  title,
  excerpt,
  body,
  tags,
  content='',
  tokenize='porter'
);

CREATE TABLE topics_base (
  id TEXT PRIMARY KEY,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  title TEXT NOT NULL,
  body TEXT,
  status TEXT NOT NULL CHECK(status IN ('open','answered','closed')) DEFAULT 'open',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE question_topic (
  question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
  topic_id TEXT REFERENCES topics_base(id) ON DELETE CASCADE,
  PRIMARY KEY (question_id, topic_id)
);