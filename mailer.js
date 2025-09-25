// mailer.js
import nodemailer from 'nodemailer';

export const mailTransport = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

const FROM = process.env.MAIL_FROM || process.env.SMTP_USER;
const BASE = process.env.PUBLIC_BASE_URL || 'http://localhost:3000';

// Hämta staff (admin + support)
export function getStaffEmails(db) {
  try {
    const rows = db.prepare(`
      SELECT email
      FROM users
      WHERE role IN ('admin','support')
        AND COALESCE(is_active,1)=1
        AND email IS NOT NULL
        AND TRIM(email) <> ''
    `).all();
    return rows.map(r => String(r.email).trim()).filter(e => e.includes('@'));
  } catch {
    return [];
  }
}

// Hämta endast admins
export function getAdminEmails(db) {
  try {
    const rows = db.prepare(`
      SELECT email
      FROM users
      WHERE role = 'admin'
        AND COALESCE(is_active,1)=1
        AND email IS NOT NULL
        AND TRIM(email) <> ''
    `).all();
    return rows.map(r => String(r.email).trim()).filter(e => e.includes('@'));
  } catch {
    return [];
  }
}

// Ny fråga → staff
export async function sendNewQuestionNotifications(db, { id, title, authorName }) {
  const toList = getStaffEmails(db);
  if (!toList.length) return;
  const url = `${BASE}/questions/${encodeURIComponent(id)}`;

  await mailTransport.sendMail({
    from: FROM,
    to: toList.join(','),
    subject: `Ny fråga: ${title}`,
    text:
`En ny fråga har skapats av ${authorName || 'okänd'}.

Titel: ${title}
Öppna: ${url}`,
    html:
`<p>En ny fråga har skapats av <strong>${authorName || 'okänd'}</strong>.</p>
<p><strong>Titel:</strong> ${escapeHtml(title)}</p>
<p><a href="${url}">Öppna frågan</a></p>`,
  });
}

// Fråga besvarad → frågeställaren
export async function sendQuestionAnswered(db, { id, title, userId }) {
  const row = db.prepare(`SELECT email, name FROM users WHERE id=?`).get(userId);
  if (!row || !row.email) return;
  const url = `${BASE}/questions/${encodeURIComponent(id)}`;

  await mailTransport.sendMail({
    from: FROM,
    to: row.email,
    subject: `Ditt svar är klart: ${title}`,
    text:
`Hej ${row.name || ''}!

Din fråga har besvarats.

Titel: ${title}
Läs svaret: ${url}`,
    html:
`<p>Hej ${row.name || ''}!</p>
<p>Din fråga har besvarats.</p>
<p><strong>Titel:</strong> ${escapeHtml(title)}</p>
<p><a href="${url}">Läs svaret</a></p>`,
  });
}

// Ny feedback → endast admins
export async function sendNewFeedbackNotifications(db, { id, category, message }) {
  const toList = getAdminEmails(db);
  if (!toList.length) return;
  const url = `${BASE}/admin/feedback`;

  await mailTransport.sendMail({
    from: FROM,
    to: toList.join(','),
    subject: `Ny feedback: ${category || 'okänd kategori'}`,
    text:
`Ny feedback har inkommit (${category || 'okänd kategori'}).

${message || ''}

Visa i admin: ${url}`,
    html:
`<p>Ny feedback har inkommit (<strong>${escapeHtml(category || 'okänd kategori')}</strong>).</p>
${message ? `<p>${escapeHtml(message)}</p>` : ''}
<p><a href="${url}">Visa i admin</a></p>`,
  });
}

// enkel HTML-escape
function escapeHtml(s='') {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}