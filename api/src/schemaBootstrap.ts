/**
 * Schema bootstrap + upgrade sync (runs in the API image on every boot).
 *
 * The core schema is defined in src/db/schema.ts and evolved with `drizzle-kit push`
 * — an idempotent diff that creates missing tables/columns. In dev, setup.sh runs it
 * on the HOST before starting containers; production images have no host-side tooling,
 * so this module does it IN THE IMAGE instead:
 *
 *   - FRESH database (no core tables): run `drizzle-kit push --force` with retries
 *     until Postgres accepts connections and the schema lands. Nothing exists yet,
 *     so there is no data to lose — --force only suppresses confirmation prompts.
 *   - EXISTING database: run a plain `drizzle-kit push` (NO --force) once per boot.
 *     Additive changes (new tables / columns — the normal upgrade case) apply
 *     automatically, exactly like dev's setup.sh does on every start. A data-loss
 *     change is REFUSED in non-interactive mode without --force, so it can never
 *     silently destroy production data; we log a loud warning and continue startup
 *     (the existing schema stays usable) until an operator reviews and runs the
 *     destructive push manually.
 *
 * drizzle-kit therefore ships in the runtime image (api/Dockerfile excludes it from
 * the dev prune). A Postgres advisory lock serializes concurrent boots (HA replicas)
 * so two instances never run DDL at the same time.
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import type { PoolClient } from 'pg';
import { pool } from './db';

/** Tables whose existence proves the schema was created (any one suffices). */
const CORE_TABLES = ['users', 'telemetry', 'devices'];
/** Serializes concurrent schema pushes across API instances. */
const ADVISORY_LOCK_KEY = 'unm_schema_bootstrap';

const ATTEMPTS = 30; // ~5 min of retries — covers Postgres still initializing on first boot
const RETRY_DELAY_MS = 10_000;
/** Hard cap per push attempt so a hung CLI can never wedge startup forever. */
const PUSH_TIMEOUT_MS = 120_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** True when at least one core table exists in the public schema. Throws if the DB is unreachable. */
async function hasCoreTables(): Promise<boolean> {
  const res = await pool.query(
    `SELECT EXISTS (
       SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = ANY($1) AND c.relkind IN ('r', 'p')
     ) AS found`,
    [CORE_TABLES]
  );
  return res.rows[0]?.found === true;
}

/** Waits until the DB answers, then reports whether core tables already exist (existing deployment). */
async function detectCoreTablesPresent(): Promise<boolean> {
  let lastErr: unknown = null;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    try {
      return await hasCoreTables();
    } catch (err) {
      lastErr = err; // connection not ready yet — retry until Postgres is up
      if (attempt < ATTEMPTS) await sleep(RETRY_DELAY_MS);
    }
  }
  throw new Error(`could not reach the database to check schema state: ${(lastErr as Error)?.message ?? 'unknown'}`);
}

/**
 * Marker drizzle-kit prints when it detects destructive statements. NOTE: in non-interactive
 * mode a refused data-loss push still EXITS 0 (it throws on the missing TTY but swallows it),
 * so the exit code alone cannot tell "applied" from "refused" — we must inspect the output.
 */
const DATA_LOSS_MARKER = /Found data-loss statements/;

/** Runs `drizzle-kit push` once, streaming its output to our stdout and returning it for analysis. */
function runPush(force: boolean): Promise<{ output: string }> {
  const bin = path.join(process.cwd(), 'node_modules', '.bin', 'drizzle-kit');
  return new Promise((resolve, reject) => {
    const args = [bin, 'push'];
    if (force) args.push('--force');
    const child = spawn(process.execPath, args, {
      cwd: process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    let output = '';
    const append = (chunk: Buffer) => {
      output += chunk.toString('utf8');
      process.stdout.write(chunk); // keep the CLI's progress visible in container logs
    };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`drizzle-kit push timed out after ${PUSH_TIMEOUT_MS / 1000}s`));
    }, PUSH_TIMEOUT_MS);
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) resolve({ output });
      else reject(new Error(`drizzle-kit push exited with code ${code}`));
    });
  });
}

/** Runs `fn` while holding a session-scoped Postgres advisory lock on a dedicated client. */
async function withAdvisoryLock<T>(fn: () => Promise<T>): Promise<T> {
  const client: PoolClient = await pool.connect();
  try {
    await client.query(`SELECT pg_advisory_lock(hashtext($1))`, [ADVISORY_LOCK_KEY]);
    return await fn();
  } finally {
    try {
      await client.query(`SELECT pg_advisory_unlock(hashtext($1))`, [ADVISORY_LOCK_KEY]);
    } catch { /* best-effort release */ }
    client.release();
  }
}

/**
 * Ensures the schema matches src/db/schema.ts before initDb() runs. No-op (fast) on a
 * steady-state deployment; bootstraps a fresh database; and applies additive upgrades
 * automatically. Throws only when a FRESH database cannot be brought up (at which point
 * startup would have crashed anyway). Never throws for an existing database — a refused
 * data-loss change is logged, not fatal.
 */
export async function ensureSchemaBootstrapped(): Promise<void> {
  const coreTablesPresent = await detectCoreTablesPresent();

  if (coreTablesPresent) {
    // Existing deployment: sync additive changes (new tables/columns). Non-fatal by design —
    // a pending data-loss change is refused without --force and must be applied manually.
    try {
      const { output } = await withAdvisoryLock(() => runPush(false));
      if (DATA_LOSS_MARKER.test(output)) {
        console.warn(
          `[api] schema sync REFUSED a data-loss change — review it and apply manually ` +
            `(docker exec <api> sh -c "cd /app/api && node_modules/.bin/drizzle-kit push --force"). Continuing with the existing schema.`
        );
      } else {
        console.log('[api] schema up to date.');
      }
    } catch (err) {
      console.warn(
        `[api] schema sync failed — if this is a data-loss change, review it and apply manually ` +
          `(docker exec <api> sh -c "cd /app/api && node_modules/.bin/drizzle-kit push --force"). Continuing with the existing schema. Cause: ${(err as Error).message}`
      );
    }
    return;
  }

  // Fresh database: bootstrap until the core tables exist.
  console.log(`[api] fresh database detected — running first-boot schema bootstrap (drizzle-kit push --force)…`);
  await withAdvisoryLock(async () => {
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      try {
        await runPush(true);
        if (await hasCoreTables()) {
          console.log(`[api] schema bootstrap complete (attempt ${attempt}) — core tables present.`);
          return;
        }
        console.warn(`[api] push succeeded but core tables still missing (attempt ${attempt}/${ATTEMPTS})`);
      } catch (err) {
        console.warn(`[api] schema bootstrap attempt ${attempt}/${ATTEMPTS} failed:`, (err as Error).message);
      }
      if (attempt < ATTEMPTS) await sleep(RETRY_DELAY_MS);
    }
    throw new Error(`schema bootstrap failed after ${ATTEMPTS} attempts — check DATABASE_URL and Postgres health`);
  });
}
