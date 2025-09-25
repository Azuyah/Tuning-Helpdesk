// mailer.js
import nodemailer from 'nodemailer';

export const mailTransport = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT || 587),
  secure: String(process.env.MAIL_SECURE).toLowerCase() === 'false', // false för 587
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS },
  requireTLS: true,                 // tvinga STARTTLS
  tls: { minVersion: 'TLSv1.2' },   // modern TLS
  connectionTimeout: 15000,         // 15s
  socketTimeout: 20000,             // 20s
});

const FROM = process.env.MAIL_FROM || process.env.MAIL_USER;
const BASE = process.env.PUBLIC_BASE_URL || 'http://localhost:3000';

// ---- helpers ----
export function getStaffEmails(db) {
  const whereActive = activePredicate(db);
  try {
    const rows = db.prepare(`
      SELECT email
      FROM users
      WHERE role IN ('admin','support')
        AND ${whereActive}
        AND email IS NOT NULL
        AND TRIM(email) <> ''
    `).all();
    return rows.map(r => String(r.email).trim()).filter(e => e.includes('@'));
  } catch {
    return [];
  }
}

export function getAdminEmails(db) {
  const whereActive = activePredicate(db);
  try {
    const rows = db.prepare(`
      SELECT email
      FROM users
      WHERE role = 'admin'
        AND ${whereActive}
        AND email IS NOT NULL
        AND TRIM(email) <> ''
    `).all();
    return rows.map(r => String(r.email).trim()).filter(e => e.includes('@'));
  } catch {
    return [];
  }
}

// ---- mailers ----
export async function sendNewQuestionNotifications(db, { id, title, authorName }) {
  const toList = getStaffEmails(db);
  console.log('[mail] new-question: toList=', toList);

  if (!toList.length) {
    console.warn('[mail] new-question: NO RECIPIENTS (admin/support not found with valid emails)');
    return;
  }

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  const from = FROM;

  try {
    // validera transport (dyrt, men ok för debug)
    const verified = await mailTransport.verify().catch(e => ({ error: e.message }));
    console.log('[mail] transport.verify =', verified);

    const info = await mailTransport.sendMail({
      from,
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

    console.log('[mail] new-question sent. messageId=', info?.messageId);
  } catch (err) {
    console.error('[mail] new-question ERROR:', err);
  }
}

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

// ---- utils ----
function escapeHtml(s='') {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function activePredicate(db) {
  try {
    const cols = db.prepare(`PRAGMA table_info(users)`).all().map(c => c.name);
    if (cols.includes('is_active')) return 'COALESCE(is_active,1)=1';
    if (cols.includes('active'))    return 'COALESCE(active,1)=1';
  } catch {}
  return '1=1'; // om ingen kolumn finns: filtrera inte på aktiv
}