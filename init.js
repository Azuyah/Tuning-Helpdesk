import Database from 'better-sqlite3';
import fs from 'fs';
import bcrypt from 'bcryptjs';

const DB_FILE = 'helpdesk.db';

// 1) Skapa/öppna DB och kör schema
const db = new Database(DB_FILE);
const schema = fs.readFileSync('./schema.sql', 'utf8');
db.exec(schema);

// 2) Skapa admin om saknas
const adminEmail = 'admin@example.com';
const admin = db.prepare('SELECT 1 FROM users WHERE email=?').get(adminEmail);

if (!admin) {
  const hash = bcrypt.hashSync('changeme', 10);
  db.prepare('INSERT INTO users (email, password_hash, name, role) VALUES (?,?,?,?)')
    .run(adminEmail, hash, 'Admin', 'admin');
  console.log(`✅ Admin skapad: ${adminEmail} / changeme`);
} else {
  console.log('ℹ️  Admin finns redan');
}

console.log('✅ Databas initierad:', DB_FILE);
db.close();