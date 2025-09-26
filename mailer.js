// mailer.js — Resend + templates (robust, utan debug)
import fs from "fs";
import path from "path";
import mustache from "mustache";

// Miljö
const FROM = (process.env.MAIL_FROM || "noreply@tuninghelpdesk.com")
  .trim()
  .replace(/^["']|["']$/g, ""); // ta bort ev. kringliggande citationstecken
const BASE = process.env.PUBLIC_BASE_URL || "http://localhost:3000";
const RESEND_API_KEY = process.env.RESEND_API_KEY;

// -------------------- Resend core --------------------
async function sendViaResend({ from = FROM, to, subject, text, html }) {
  if (!RESEND_API_KEY) throw new Error("Missing RESEND_API_KEY");
  const payload = { from, to: Array.isArray(to) ? to : [to], subject, text, html };

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
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

export async function sendMail({ from = FROM, to, subject, text, html }) {
  return sendViaResend({ from, to, subject, text, html });
}

// -------------------- Template rendering --------------------
function safeRead(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function renderTemplate(fileName, vars) {
  const emailsDir = path.join(process.cwd(), "emails");
  const layout = safeRead(path.join(emailsDir, "layout.html"));
  const partial = safeRead(path.join(emailsDir, fileName));

  // Om mallar saknas -> enkel HTML så mailen ändå skickas
  if (!layout || !partial) {
    const simple = [
      `<h1 style="font-family:system-ui,Segoe UI,Roboto,Inter,sans-serif">${escapeHtml(vars.subject || "Meddelande")}</h1>`,
      vars.preheader ? `<p>${escapeHtml(vars.preheader)}</p>` : "",
      vars.intro ? `<p>${escapeHtml(vars.intro)}</p>` : "",
      vars.bodyHtml || "",
      vars.url ? `<p><a href="${vars.url}">${escapeHtml(vars.ctaLabel || "Öppna")}</a></p>` : "",
    ].join("\n");
    return simple;
  }

  const body = mustache.render(partial, vars);
  // injicera baseUrl + body i layout (layout använder {{{content}}} och {{baseUrl}})
  return mustache.render(layout, { ...vars, baseUrl: BASE, content: body });
}

// -------------------- DB helpers --------------------
function tableHasColumn(db, table, col) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    return cols.some((c) => c.name === col);
  } catch {
    return false;
  }
}

export function getStaffEmails(db) {
  const hasActive = tableHasColumn(db, "users", "active");
  const whereActive = hasActive ? `AND COALESCE(active,1)=1` : ``;
  const rows = db
    .prepare(
      `
    SELECT email
    FROM users
    WHERE LOWER(role) IN ('admin','support')
      ${whereActive}
      AND email IS NOT NULL
      AND TRIM(email) <> ''
  `
    )
    .all();
  return rows.map((r) => String(r.email).trim()).filter((e) => e.includes("@"));
}

export function getAdminEmails(db) {
  const hasActive = tableHasColumn(db, "users", "active");
  const whereActive = hasActive ? `AND COALESCE(active,1)=1` : ``;
  const rows = db
    .prepare(
      `
    SELECT email
    FROM users
    WHERE LOWER(role)='admin'
      ${whereActive}
      AND email IS NOT NULL
      AND TRIM(email) <> ''
  `
    )
    .all();
  return rows.map((r) => String(r.email).trim()).filter((e) => e.includes("@"));
}

// -------------------- Notifierare (matchar templates) --------------------
export async function sendNewQuestionNotifications(db, { id, title, authorName }) {
  const toList = getStaffEmails(db);
  if (!toList.length) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  const subject = `Ny fråga: ${title}`;

  // new-question.html väntar: {{author}}, {{title}}, {{url}}
  const html = renderTemplate("new-question.html", {
    author: authorName || "okänd",
    title,
    url,
    subject,
  });

  const text = `Ny fråga av ${authorName || "okänd"}\nTitel: ${title}\nÖppna: ${url}`;

  return sendViaResend({ to: toList, subject, text, html });
}

export async function sendQuestionAnswered(db, { id, title, userId }) {
  const row = db.prepare(`SELECT email, name FROM users WHERE id=?`).get(userId);
  if (!row || !row.email) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  const subject = `Ditt svar är klart: ${title}`;

  // question-answered.html väntar: {{name}}, {{title}}, {{url}}
  const html = renderTemplate("question-answered.html", {
    name: row.name || "",
    title,
    url,
    subject,
  });

  const text = `Hej ${row.name || ""}!\nDin fråga har besvarats.\nTitel: ${title}\nLäs svaret: ${url}`;

  return sendViaResend({ to: row.email, subject, text, html });
}

export async function sendNewFeedbackNotifications(db, { id, category, message }) {
  const toList = getAdminEmails(db);
  if (!toList.length) return;

  const url = `${BASE}/admin/feedback`;
  const subject = `Ny feedback: ${category || "okänd kategori"}`;

  // feedback.html väntar: {{category}}, {{message}}, {{url}}
  const html = renderTemplate("feedback.html", {
    category: category || "okänd kategori",
    message: message || "",
    url,
    subject,
  });

  const text = `Ny feedback (${category || "okänd kategori"})\n${message || ""}\nVisa i admin: ${url}`;

  return sendViaResend({ to: toList, subject, text, html });
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