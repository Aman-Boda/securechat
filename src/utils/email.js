// Sends email via Resend's HTTP API (https://api.resend.com/emails) using
// plain fetch — no SDK dependency needed, it's a single POST request.
//
// Email is treated as OPTIONAL infrastructure: if RESEND_API_KEY isn't set,
// the app still runs and registration/login still work — verification and
// reset emails just don't get sent, and the link is logged to the console
// instead so local development doesn't require a real Resend account.

const RESEND_API_URL = 'https://api.resend.com/emails';

function isConfigured() {
  return Boolean(process.env.RESEND_API_KEY);
}

async function sendEmail({ to, subject, html }) {
  if (!isConfigured()) {
    console.warn(`[email] RESEND_API_KEY not set — skipping real send. Would have sent to ${to}:`);
    console.warn(`[email] Subject: ${subject}`);
    console.warn(`[email] ${html}`);
    return { sent: false, reason: 'not_configured' };
  }

  const from = process.env.FROM_EMAIL || 'SecureChat <onboarding@resend.dev>';

  try {
    const res = await fetch(RESEND_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from, to: [to], subject, html }),
    });

    if (!res.ok) {
      const body = await res.text();
      console.error(`[email] Resend API error (${res.status}): ${body}`);
      return { sent: false, reason: 'api_error' };
    }

    return { sent: true };
  } catch (err) {
    console.error('[email] Failed to reach Resend API:', err);
    return { sent: false, reason: 'network_error' };
  }
}

function emailShell(bodyHtml) {
  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #14192B; color: #EDE9E2;">
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 24px;">
        <div style="width: 28px; height: 28px; border-radius: 6px; background: #6FA88A;"></div>
        <span style="font-weight: 700; font-size: 16px;">SecureChat</span>
      </div>
      ${bodyHtml}
    </div>
  `;
}

function buttonHtml(url, label) {
  return `<a href="${url}" style="display: inline-block; margin: 16px 0; padding: 10px 20px; background: #6FA88A; color: #0D1120; text-decoration: none; border-radius: 6px; font-weight: 600;">${label}</a>`;
}

async function sendVerificationEmail(to, verifyUrl) {
  const html = emailShell(`
    <p>Welcome to SecureChat! Confirm this is your email address to finish setting up your account.</p>
    ${buttonHtml(verifyUrl, 'Verify email')}
    <p style="font-size: 12px; color: #8B92B0;">This link expires in 24 hours. If you didn't create this account, you can ignore this email.</p>
  `);
  return sendEmail({ to, subject: 'Verify your SecureChat email', html });
}

async function sendPasswordResetEmail(to, resetUrl) {
  const html = emailShell(`
    <p>Someone requested a password reset for this SecureChat account. If that wasn't you, you can safely ignore this email — your password won't change.</p>
    ${buttonHtml(resetUrl, 'Reset password')}
    <p style="font-size: 12px; color: #8B92B0;">This link expires in 1 hour and can only be used once. Resetting your password will log out any other active sessions on this account.</p>
  `);
  return sendEmail({ to, subject: 'Reset your SecureChat password', html });
}

module.exports = { isConfigured, sendEmail, sendVerificationEmail, sendPasswordResetEmail };
