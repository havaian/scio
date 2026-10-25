/**
 * Sends one test message to every configured alert channel and prints which succeeded.
 * Usage: npm run alerts:test (in Docker: docker compose exec backend npm run alerts:test). Exit code 1 if any channel failed.
 */
import { channelsFromEnv, sendAll } from './alerts/channels';
import { tbilisiTime } from './alerts/alerts.service';

async function main() {
  const channels = channelsFromEnv();
  if (!channels.length) {
    console.log('No alert channel configured. Set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID and/or SMTP_HOST + ALERT_EMAIL_TO.');
    process.exit(1);
  }
  const subject = 'Scio: test alert';
  const link = process.env.PUBLIC_URL ? `\n${process.env.PUBLIC_URL}` : '';
  const results = await sendAll(channels, subject, `${subject}\nAlerting works. Sent ${tbilisiTime(Date.now())}.${link}`);
  for (const r of results) console.log(`${r.name}: ${r.ok ? 'ok' : `failed - ${r.error}`}`);
  process.exit(results.every((r) => r.ok) ? 0 : 1);
}

main();
