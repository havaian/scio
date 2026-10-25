import 'reflect-metadata';
// All times the server prints (logs) are Georgian time, like the dashboard and reports.
process.env.TZ = process.env.TZ || 'Asia/Tbilisi';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DbService } from './storage/db.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Runs left 'running' by the previous server process can never finish: mark them failed (server only, not the CLI).
  const interrupted = app.get(DbService).failInterruptedRuns();
  if (interrupted) console.log(`${interrupted} interrupted run(s) marked failed`);
  // The dashboard is served from the same origin (nginx), so CORS stays off unless CORS_ORIGIN names the allowed origin(s), comma-separated.
  const origins = process.env.CORS_ORIGIN?.split(',').map((o) => o.trim()).filter(Boolean);
  if (origins?.length) app.enableCors({ origin: origins });
  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
  console.log(`Scio API on http://localhost:${port}/api`);
}
bootstrap();
