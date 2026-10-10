/**
 * Outgoing email (verification + password reset) over HTTPS APIs — no extra npm package.
 * (Render's free plan blocks SMTP ports, so an HTTP API is required.)
 *
 * Option A — Brevo (no domain needed, just a verified sender address):
 *   BREVO_API_KEY    from https://app.brevo.com (SMTP & API -> API Keys)
 *   MAIL_FROM        e.g. "Ovu <you@gmail.com>" — the address must be verified in Brevo (Senders)
 * Option B — Resend (needs a verified domain):
 *   RESEND_API_KEY   from https://resend.com
 *   MAIL_FROM        e.g. "Ovu <no-reply@yourdomain.com>"
 * If both keys are set, Brevo is used. Without any key nothing is sent: the message is printed in the server log.
 */
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export function createMailer({ env = process.env, fetchImpl = globalThis.fetch, log = console } = {}) {
  const brevoKey = env.BREVO_API_KEY?.trim();
  const resendKey = env.RESEND_API_KEY?.trim();
  const from = env.MAIL_FROM?.trim();
  const provider = brevoKey ? "brevo" : resendKey ? "resend" : null;
  const key = brevoKey || resendKey;
  const configured = !!(provider && from);
  // "Ovu <a@b.c>" -> { name: "Ovu", email: "a@b.c" }
  const parseFrom = (f) => {
    const m = /^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/.exec(f);
    return m ? { name: m[1].trim() || "Ovu", email: m[2].trim() } : { name: "Ovu", email: f.trim() };
  };

  async function send({ to, subject, text, html }) {
    if (!configured) {
      log.log(`[ovu][mail] (no mail provider configured; set BREVO_API_KEY (or RESEND_API_KEY) + MAIL_FROM) to=${to} subject="${subject}"\n${text}`);
      return { sent: false, reason: "not-configured" };
    }
    try {
      const r =
        provider === "brevo"
          ? await fetchImpl("https://api.brevo.com/v3/smtp/email", {
              method: "POST",
              headers: { "api-key": key, "Content-Type": "application/json", accept: "application/json" },
              body: JSON.stringify({ sender: parseFrom(from), to: [{ email: to }], subject, textContent: text, htmlContent: html }),
            })
          : await fetchImpl("https://api.resend.com/emails", {
              method: "POST",
              headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
              body: JSON.stringify({ from, to: [to], subject, text, html }),
            });
      if (!r.ok) {
        log.error(`[ovu][mail] ${provider === "brevo" ? "Brevo" : "Resend"} answered ${r.status}: ${(await r.text().catch(() => "")).slice(0, 300)}`);
        return { sent: false, reason: `provider-${r.status}` };
      }
      return { sent: true };
    } catch (e) {
      log.error("[ovu][mail] send failed:", e?.message || e);
      return { sent: false, reason: "network" };
    }
  }

  // Monochrome, table-based layout (Gmail / Outlook / Apple Mail). No remote images: the server
  // has no domain to host them on and most clients block them anyway, so the brand is a plain
  // black-and-white wordmark that matches the app.
  const INK = "#0a0a0b", MUTED = "rgba(10,10,11,0.64)", FAINT = "rgba(10,10,11,0.44)";
  const PAGE = "#f4f4f5", CARD = "#ffffff", LINE = "rgba(10,10,11,0.10)", SOFT = "#f4f4f5";
  const FONT = "-apple-system,'Segoe UI',Helvetica,Arial,sans-serif";
  const MONO = "'SF Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";
  const layout = ({ preheader, eyebrow, title, bodyHtml, buttonUrl, buttonLabel, meta, footer }) =>
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"></head>` +
    `<body style="margin:0;padding:0;background:${PAGE}">` +
    `<div style="display:none;max-height:0;overflow:hidden;opacity:0">${esc(preheader)}</div>` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${PAGE}"><tr><td align="center" style="padding:36px 16px">` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px">` +
    `<tr><td align="left" style="padding:0 4px 16px;font-family:${FONT}">` +
    `<span style="font-size:26px;font-weight:800;letter-spacing:-1.2px;color:${INK}">Ovu</span>` +
    `<span style="font-size:12px;font-weight:500;color:${FAINT}">&nbsp;&nbsp;3D drawing</span>` +
    `</td></tr>` +
    `<tr><td style="background:${CARD};border:1px solid ${LINE};border-radius:20px;padding:36px 34px;font-family:${FONT};color:${INK}">` +
    `<div style="margin:0 0 12px"><span style="display:inline-block;font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;color:${FAINT};border:1px solid ${LINE};border-radius:999px;padding:5px 12px">${esc(eyebrow)}</span></div>` +
    `<h1 style="margin:0 0 12px;font-size:23px;line-height:1.25;font-weight:700;letter-spacing:-0.4px;color:${INK}">${esc(title)}</h1>` +
    `<div style="font-size:15px;line-height:1.65;color:${MUTED}">${bodyHtml}</div>` +
    (buttonUrl
      ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:26px 0 4px"><tr><td align="center" bgcolor="${INK}" style="border-radius:12px">` +
        `<a href="${esc(buttonUrl)}" style="display:block;padding:15px 30px;font-family:${FONT};font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:12px">${esc(buttonLabel)}</a></td></tr></table>` +
        `<p style="margin:14px 0 0;font-size:12px;line-height:1.6;color:${FAINT}">Link not working? Paste this into your browser:<br><a href="${esc(buttonUrl)}" style="color:${INK};word-break:break-all">${esc(buttonUrl)}</a></p>`
      : "") +
    (meta ? `<p style="margin:18px 0 0;padding-top:16px;border-top:1px solid ${LINE};font-size:12.5px;line-height:1.6;color:${FAINT}">${meta}</p>` : "") +
    (footer ? `<div style="margin-top:14px;font-size:13px;line-height:1.6;color:${MUTED}">${footer}</div>` : "") +
    `</td></tr>` +
    `<tr><td align="center" style="padding:20px 12px 0;font-family:${FONT};font-size:12px;line-height:1.6;color:${FAINT}">If you didn't ask for this, just ignore this email.<br><span style="color:${INK};font-weight:700">Ovu</span></td></tr>` +
    `</table></td></tr></table></body></html>`;

  const firstName = (name) => String(name || "").trim().split(/\s+/)[0] || "there";

  return {
    configured,
    provider,
    send,
    verifyEmail: ({ to, name, url }) =>
      send({
        to,
        subject: "Confirm your Ovu account",
        text:
          `Hi ${firstName(name)},\n\nThanks for joining Ovu. Confirm this email address to activate your account:\n${url}\n\n` +
          `The link expires in 24 hours. If you didn't sign up, just ignore this email.\n\n— Ovu`,
        html: layout({
          preheader: "One quick tap to confirm your email.",
          eyebrow: "Email verification",
          title: "Confirm your email",
          bodyHtml:
            `<p style="margin:0">Hi ${esc(firstName(name))} — thanks for joining Ovu.</p>` +
            `<p style="margin:10px 0 0">Tap the button below to confirm this email address. Your account activates right away.</p>`,
          buttonUrl: url,
          buttonLabel: "Confirm my email",
          meta: "This link expires in 24 hours.",
        }),
      }),
    resetPassword: ({ to, name, url, code }) =>
      send({
        to,
        subject: "Reset your Ovu password",
        text:
          `Hi ${firstName(name)},\n\nWe got a request to reset your Ovu password. Choose a new one here:\n${url}\n\n` +
          `On the app? Open Forgot password, choose "I have a code" and enter:\n${code}\n\n` +
          `The link and code expire in 1 hour. If that wasn't you, just ignore this email.\n\n— Ovu`,
        html: layout({
          preheader: "Set a new password for your Ovu account.",
          eyebrow: "Password reset",
          title: "Reset your password",
          bodyHtml: `<p style="margin:0">Hi ${esc(firstName(name))} — we got a request to reset your Ovu password.</p><p style="margin:10px 0 0">Tap below to choose a new one.</p>`,
          buttonUrl: url,
          buttonLabel: "Choose a new password",
          meta: "Link and code expire in 1 hour.",
          footer: `On the app? Open Forgot password, choose “I have a code” and enter:<br><code style="display:block;margin-top:8px;padding:12px 14px;background:${SOFT};border:1px solid ${LINE};border-radius:10px;font-family:${MONO};font-size:15px;font-weight:700;letter-spacing:2px;text-align:center;word-break:break-all;color:${INK}">${esc(code)}</code>`,
        }),
      }),
  };
}
