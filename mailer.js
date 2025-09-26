// mailer.js — Resend + templates (robust, utan debug)
import fs from "fs";
import path from "path";
import mustache from "mustache";

// Miljö
const FROM = (process.env.MAIL_FROM || "noreply@tuninghelpdesk.com").trim().replace(/^["']|["']$/g, "");
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
  try { return fs.readFileSync(filePath, "utf8"); } catch { return null; }
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
      vars.ctaHref ? `<p><a href="${vars.ctaHref}">${escapeHtml(vars.ctaLabel || "Öppna")}</a></p>` : ""
    ].join("\n");
    return simple;
  }

  const body = mustache.render(partial, vars);
  // injicera baseUrl + body i layout
  return mustache.render(layout, { ...vars, baseUrl: BASE, content: body });
}

// -------------------- DB helpers --------------------
function tableHasColumn(db, table, col) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    return cols.some(c => c.name === col);
  } catch { return false; }
}

export function getStaffEmails(db) {
  const hasActive = tableHasColumn(db, "users", "active");
  const whereActive = hasActive ? `AND COALESCE(active,1)=1` : ``;
  const rows = db.prepare(`
    SELECT email
    FROM users
    WHERE LOWER(role) IN ('admin','support')
      ${whereActive}
      AND email IS NOT NULL
      AND TRIM(email) <> ''
  `).all();
  return rows.map(r => String(r.email).trim()).filter(e => e.includes("@"));
}

export function getAdminEmails(db) {
  const hasActive = tableHasColumn(db, "users", "active");
  const whereActive = hasActive ? `AND COALESCE(active,1)=1` : ``;
  const rows = db.prepare(`
    SELECT email
    FROM users
    WHERE LOWER(role)='admin'
      ${whereActive}
      AND email IS NOT NULL
      AND TRIM(email) <> ''
  `).all();
  return rows.map(r => String(r.email).trim()).filter(e => e.includes("@"));
}

// -------------------- Notifierare (med templates) --------------------
export async function sendNewQuestionNotifications(db, { id, title, authorName }) {
  const toList = getStaffEmails(db);
  if (!toList.length) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  const subject = `Ny fråga: ${title}`;
  const html = renderTemplate("new-question.html", {
    subject,
    preheader: `Ny fråga från ${authorName || "okänd"}.`,
    title: "Ny fråga",
    intro: `En ny fråga har skapats av ${escapeHtml(authorName || "okänd")}.`,
    meta: `Titel: ${escapeHtml(title)}`,
    ctaHref: url,
    ctaLabel: "Öppna frågan",
  });

  const text = [
    `Ny fråga: ${title}`,
    `Från: ${authorName || "okänd"}`,
    `Öppna: ${url}`
  ].join("\n");

  return sendViaResend({ to: toList, subject, text, html });
}

export async function sendQuestionAnswered(db, { id, title, userId }) {
  const row = db.prepare(`SELECT email, name FROM users WHERE id=?`).get(userId);
  if (!row || !row.email) return;

  const url = `${BASE}/questions/${encodeURIComponent(id)}`;
  const subject = `Ditt svar är klart: ${title}`;
  const html = renderTemplate("question-answered.html", {
    subject,
    preheader: "Ditt svar är klart.",
    title: "Ditt svar är klart",
    intro: `Hej ${escapeHtml(row.name || "")}!`,
    bodyHtml: `<p>Din fråga har besvarats.</p><p><strong>Titel:</strong> ${escapeHtml(title)}</p>`,
    ctaHref: url,
    ctaLabel: "Läs svaret",
  });

  const text = [
    `Hej ${row.name || ""}!`,
    `Din fråga har besvarats.`,
    `Titel: ${title}`,
    `Läs svaret: ${url}`
  ].join("\n");

  return sendViaResend({ to: row.email, subject, text, html });
}

export async function sendNewFeedbackNotifications(db, { id, category, message }) {
  const toList = getAdminEmails(db);
  if (!toList.length) return;

  const url = `${BASE}/admin/feedback`;
  const subject = `Ny feedback: ${category || "okänd kategori"}`;
  const html = renderTemplate("feedback.html", {
    subject,
    preheader: "Ny feedback har inkommit.",
    title: "Ny feedback",
    intro: `Kategori: ${escapeHtml(category || "okänd kategori")}`,
    bodyHtml: message ? `<pre style="white-space:pre-wrap">${escapeHtml(message)}</pre>` : "",
    ctaHref: url,
    ctaLabel: "Visa i admin",
  });

  const text = [
    `Ny feedback (${category || "okänd kategori"})`,
    message || "",
    `Visa i admin: ${url}`
  ].join("\n");

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