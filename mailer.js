// mailer.js — Resend-version (ingen SMTP behövs)
const FROM = process.env.MAIL_FROM || "Tuning Helpdesk <noreply@tuninghelpdesk.com>";
const BASE = process.env.PUBLIC_BASE_URL || "http://localhost:3000";

// -------------------- Resend core --------------------
async function sendViaResend({ from = FROM, to, subject, text, html, reply_to }) {
  if (!process.env.RESEND_API_KEY) {
    throw new Error("Missing RESEND_API_KEY");
  }
  const payload = {
    from,
    to: Array.isArray(to) ? to : [to],
    subject,
    text,
    html,
    reply_to, // valfritt
  };

  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const body = await resp.text(); // läs alltid kroppen för bra fel-logg
    if (!resp.ok) {
      console.error('[resend] HTTP', resp.status, body);
      throw new Error(`Resend error ${resp.status}: ${body}`);
    }

    console.log('[resend] OK:', body);
    return JSON.parse(body);
  } catch (e) {
    console.error('[resend] FAIL:', e);
    throw e;
  }
}

// Publik helper så servern kan skicka brev direkt om man vill
export async function sendMail({ from = FROM, to, subject, text, html }) {
  return sendViaResend({ from, to, subject, text, html });
}

// -------------------- DB helpers --------------------
// OBS: din users-tabell har kolumnen "active" (inte is_active).
// ---- helpers (ersätt båda funktionerna) ----
function tableHasColumn(db, table, col) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    return cols.some(c => c.name === col);
  } catch {
    return false;
  }
}

export function getStaffEmails(db) {
  const hasActive = tableHasColumn(db, 'users', 'active');
  const whereActive = hasActive ? `AND COALESCE(active,1)=1` : ``;

  const rows = db.prepare(`
    SELECT email, role${hasActive ? ', active' : ''}
    FROM users
    WHERE LOWER(role) IN ('admin','support')
      ${whereActive}
      AND email IS NOT NULL
      AND TRIM(email) <> ''
  `).all();

  const emails = rows
    .map(r => String(r.email || '').trim())
    .filter(e => e.includes('@'));

  console.log('[mail:getStaffEmails] found=', rows.length, 'emails=', emails);
  return emails;
}

export function getAdminEmails(db) {
  const hasActive = tableHasColumn(db, 'users', 'active');
  const whereActive = hasActive ? `AND COALESCE(active,1)=1` : ``;

  const rows = db.prepare(`
    SELECT email, role${hasActive ? ', active' : ''}
    FROM users
    WHERE LOWER(role) = 'admin'
      ${whereActive}
      AND email IS NOT NULL
      AND TRIM(email) <> ''
  `).all();

  const emails = rows
    .map(r => String(r.email || '').trim())
    .filter(e => e.includes('@'));

  console.log('[mail:getAdminEmails] found=', rows.length, 'emails=', emails);
  return emails;
}
// -------------------- Notifierare --------------------
export async function sendNewQuestionNotifications(db, { id, title, authorName, authorEmail }) {
  const toList = getStaffEmails(db);
  console.log('[mail:new-question] recipients =', toList);
  if (!toList.length) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  await sendViaResend({
    to: toList,
    subject: `Ny fråga: ${title}`,
    reply_to: authorEmail || undefined,
    text: `En ny fråga har skapats av ${authorName || "okänd"}.\n\nTitel: ${title}\nÖppna: ${url}`,
    html: `<p>En ny fråga har skapats av <strong>${escapeHtml(authorName || "okänd")}</strong>.</p>
           <p><strong>Titel:</strong> ${escapeHtml(title)}</p>
           <p><a href="${url}">Öppna frågan</a></p>`,
  });
}

export async function sendQuestionAnswered(db, { id, title, userId }) {
  const row = db.prepare(`SELECT email, name FROM users WHERE id=?`).get(userId);
  if (!row || !row.email) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  await sendViaResend({
    to: row.email,
    subject: `Ditt svar är klart: ${title}`,
    text: `Hej ${row.name || ""}!

Din fråga har besvarats.

Titel: ${title}
Läs svaret: ${url}`,
    html: `<p>Hej ${escapeHtml(row.name || "")}!</p>
<p>Din fråga har besvarats.</p>
<p><strong>Titel:</strong> ${escapeHtml(title)}</p>
<p><a href="${url}">Läs svaret</a></p>`,
  });
}

export async function sendNewFeedbackNotifications(db, { id, category, message }) {
  const toList = getAdminEmails(db); // endast admins
  if (!toList.length) return;

  const url = `${BASE}/admin/feedback`;
  await sendViaResend({
    to: toList,
    subject: `Ny feedback: ${category || "okänd kategori"}`,
    text: `Ny feedback har inkommit (${category || "okänd kategori"}).

${message || ""}

Visa i admin: ${url}`,
    html: `<p>Ny feedback har inkommit (<strong>${escapeHtml(category || "okänd kategori")}</strong>).</p>
${message ? `<p>${escapeHtml(message)}</p>` : ""}
<p><a href="${url}">Visa i admin</a></p>`,
  });
}

// -------------------- Utils --------------------
function escapeHtml(s = "") {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}