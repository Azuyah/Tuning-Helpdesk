// mailer.js — Resend + Mustache templates
import fs from "fs";
import path from "path";
import mustache from "mustache";

// Bas-uppgifter
const FROM = process.env.MAIL_FROM || "Tuning Helpdesk <noreply@tuninghelpdesk.com>";
const BASE = process.env.PUBLIC_BASE_URL || "http://localhost:3000";

// -------------------- Resend core --------------------
async function sendViaResend({ from = FROM, to, subject, text, html }) {
  if (!process.env.RESEND_API_KEY) {
    throw new Error("Missing RESEND_API_KEY");
  }
  const payload = {
    from,
    to: Array.isArray(to) ? to : [to],
    subject,
    text,
    html,
  };

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => "");
    throw new Error(`Resend error ${resp.status}: ${errText || resp.statusText}`);
  }
  return resp.json();
}

// Publik helper om du vill skicka fristående
export async function sendMail({ from = FROM, to, subject, text, html }) {
  return sendViaResend({ from, to, subject, text, html });
}

// -------------------- Template rendering --------------------
function renderTemplate(file, vars) {
  const emailsDir = path.join(process.cwd(), "emails");
  const layout = fs.readFileSync(path.join(emailsDir, "layout.html"), "utf8");
  const tpl    = fs.readFileSync(path.join(emailsDir, file), "utf8");
  const body   = mustache.render(tpl, vars);
  return mustache.render(layout, { ...vars, baseUrl: BASE, content: body });
}

// -------------------- DB helpers --------------------
// OBS: er users-tabell använder kolumnen "active" (inte is_active)
export function getStaffEmails(db) {
  try {
    const rows = db
      .prepare(`
        SELECT email
        FROM users
        WHERE role IN ('admin','support')
          AND COALESCE(active,1)=1
          AND email IS NOT NULL
          AND TRIM(email) <> ''
      `)
      .all();
    return rows.map(r => String(r.email).trim()).filter(e => e.includes("@"));
  } catch {
    return [];
  }
}

export function getAdminEmails(db) {
  try {
    const rows = db
      .prepare(`
        SELECT email
        FROM users
        WHERE role = 'admin'
          AND COALESCE(active,1)=1
          AND email IS NOT NULL
          AND TRIM(email) <> ''
      `)
      .all();
    return rows.map(r => String(r.email).trim()).filter(e => e.includes("@"));
  } catch {
    return [];
  }
}

// -------------------- Notifierare --------------------
export async function sendNewQuestionNotifications(db, { id, title, authorName }) {
  const toList = getStaffEmails(db);
  if (!toList.length) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;

  const html = renderTemplate("new-question.html", {
    author: authorName || "okänd",
    title,
    url
  });

  // ren text fallback
  const text = `En ny fråga har skapats av ${authorName || "okänd"}.

Titel: ${title}
Öppna: ${url}`;

  await sendViaResend({
    to: toList,
    subject: `Ny fråga: ${title}`,
    text,
    html,
  });
}

export async function sendQuestionAnswered(db, { id, title, userId }) {
  const row = db.prepare(`SELECT email, name FROM users WHERE id=?`).get(userId);
  if (!row || !row.email) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;

  const html = renderTemplate("question-answered.html", {
    name: row.name || "",
    title,
    url
  });

  const text = `Hej ${row.name || ""}!

Din fråga har besvarats.

Titel: ${title}
Läs svaret: ${url}`;

  await sendViaResend({
    to: row.email,
    subject: `Ditt svar är klart: ${title}`,
    text,
    html,
  });
}

export async function sendNewFeedbackNotifications(db, { id, category, message }) {
  const toList = getAdminEmails(db); // endast admins
  if (!toList.length) return;

  const url = `${BASE}/admin/feedback`;

  const html = renderTemplate("feedback.html", {
    category: category || "okänd kategori",
    message: message || "",
    url
  });

  const text = `Ny feedback har inkommit (${category || "okänd kategori"}).

${message || ""}

Visa i admin: ${url}`;

  await sendViaResend({
    to: toList,
    subject: `Ny feedback: ${category || "okänd kategori"}`,
    text,
    html,
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