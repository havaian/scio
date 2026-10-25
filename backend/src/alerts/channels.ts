import { createTransport } from 'nodemailer';
import { Agent, EnvHttpProxyAgent, fetch } from 'undici';

/** One delivery channel. send() throws on failure; messages never contain secrets. */
export interface AlertChannel {
  name: string;
  send(subject: string, text: string): Promise<void>;
}

/** Removes configured secrets from an error message before it is logged or stored. */
export function scrub(msg: string, env: NodeJS.ProcessEnv = process.env): string {
  let out = msg;
  for (const k of ['TELEGRAM_BOT_TOKEN', 'SMTP_PASS']) {
    const v = env[k];
    if (v) out = out.split(v).join('***');
  }
  return out;
}

/** Telegram Bot API sendMessage, plain text (no parse_mode, so nothing needs escaping). */
export function telegramChannel(token: string, chatId: string): AlertChannel {
  // Same proxy behaviour as the rest of the backend: HTTPS_PROXY when set, direct otherwise.
  const dispatcher = process.env.HTTPS_PROXY || process.env.HTTP_PROXY ? new EnvHttpProxyAgent() : new Agent();
  return {
    name: 'telegram',
    async send(_subject, text) {
      const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
        dispatcher,
        signal: AbortSignal.timeout(15_000),
      });
      if (!r.ok) {
        const body = (await r.json().catch(() => ({}))) as any;
        throw new Error(`Telegram HTTP ${r.status}${body?.description ? `: ${body.description}` : ''}`);
      }
    },
  };
}

/** SMTP email via nodemailer. */
export function emailChannel(env: NodeJS.ProcessEnv): AlertChannel {
  const port = Number(env.SMTP_PORT || 587);
  const secure = env.SMTP_SECURE ? env.SMTP_SECURE === 'true' : port === 465;
  const transport = createTransport({
    host: env.SMTP_HOST,
    port,
    secure,
    auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS ?? '' } : undefined,
    connectionTimeout: 15_000,
  });
  const to = (env.ALERT_EMAIL_TO ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  return {
    name: 'email',
    async send(subject, text) {
      await transport.sendMail({ from: env.SMTP_FROM || env.SMTP_USER, to, subject, text });
    },
  };
}

/** Channels configured in the environment. Empty when none is. */
export function channelsFromEnv(env: NodeJS.ProcessEnv = process.env): AlertChannel[] {
  const out: AlertChannel[] = [];
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) out.push(telegramChannel(env.TELEGRAM_BOT_TOKEN, env.TELEGRAM_CHAT_ID));
  if (env.SMTP_HOST && env.ALERT_EMAIL_TO) out.push(emailChannel(env));
  return out;
}

/** Sends to every channel; one failing channel does not block the others. Returns per-channel results. */
export async function sendAll(channels: AlertChannel[], subject: string, text: string): Promise<{ name: string; ok: boolean; error?: string }[]> {
  return Promise.all(
    channels.map(async (c) => {
      try {
        await c.send(subject, text);
        return { name: c.name, ok: true };
      } catch (e: any) {
        return { name: c.name, ok: false, error: scrub(String(e?.message ?? e)) };
      }
    }),
  );
}
