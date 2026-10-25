import { DbService } from './storage/db.service';

/**
 * Deletes all audit runs (findings, AI results, stats, call logs). Uptime monitor history stays.
 * Usage: npm run runs:clear -- --yes
 */
function main() {
  if (!process.argv.includes('--yes')) {
    console.log('This deletes every audit run with its findings and call logs (uptime history stays).');
    console.log('Run again with --yes to confirm:  npm run runs:clear -- --yes');
    process.exit(1);
  }
  const db = new DbService();
  const n = db.clearRuns();
  db.onModuleDestroy();
  console.log(`Deleted ${n.runs} runs, ${n.findings} findings, ${n.exchanges} logged calls. Uptime history kept.`);
}

main();
