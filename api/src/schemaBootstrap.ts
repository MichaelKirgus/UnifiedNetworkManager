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
 *   - EXISTING database: run the ADDITIVE SCHEMA SYNC (src/schemaSync.ts) once per boot.
 *     It renders the current code's DDL via `drizzle-kit generate` and applies only what is
 *     missing — new tables, new columns on existing tables, indexes, foreign keys. This
 *     replaces the old plain `drizzle-kit push`, which could NOT run unattended here: this
 *     database holds objects deliberately absent from src/db/schema.ts (raw-SQL tables such as
 *     radacct / radius_monitor_state and the monthly flow-aggregation partition children), and
 *     whenever new items AND "missing" items coexist, drizzle-kit's rename-detection demands an
 *     interactive prompt — impossible without a TTY. It then ABORTS before applying anything
 *     while still exiting 0, so every image-tag upgrade silently skipped its migrations
 *     (notification_*, security_events, threat_iocs, …). The additive sync never sees those
 *     DB-only objects and can therefore never hit the prompt; it also never drops or alters
 *     existing structures, so data loss is impossible. Structural changes (dropping/renaming
 *     columns or tables) remain manual DDL, exactly as a refused drizzle push used to be.
 *
 * drizzle-kit therefore ships in the runtime image (api/Dockerfile excludes it from
 * the dev prune). A Postgres advisory lock serializes concurrent boots (HA replicas)
 * so two instances never run DDL at the same time.
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import type { PoolClient } from 'pg';
import { pool } from './db';
import { applyAdditiveSchema } from './schemaSync';

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

/** Runs `drizzle-kit push --force` once (fresh-database bootstrap only), streaming output to stdout. */
function runFreshPush(): Promise<{ output: string }> {
  const bin = path.join(process.cwd(), 'node_modules', '.bin', 'drizzle-kit');
  return new Promise((resolve, reject) => {
    const args = [bin, 'push', '--force'];
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
 * startup would have crashed anyway). Never throws for an existing database — sync
 * failures are logged, not fatal.
 */
export async function ensureSchemaBootstrapped(): Promise<void> {
  const coreTablesPresent = await detectCoreTablesPresent();

  if (coreTablesPresent) {
    // Existing deployment: apply additive changes automatically — new tables/columns/indexes
    // from this image's schema.ts land here on first boot after a tag change. Additive-only and
    // non-fatal by design; see src/schemaSync.ts for the mechanics and safety properties.
    try {
      const summary = await withAdvisoryLock(() => applyAdditiveSchema(pool));
      if (summary.createdTables.length === 0 && summary.addedColumns.length === 0) {
        console.log('[api] schema up to date.');
      } else {
        console.log(
          `[api] schema sync applied: ${summary.createdTables.length} table(s) [${summary.createdTables.join(', ')}], ` +
            `${summary.addedColumns.length} column(s), ${summary.ensuredIndexes} index(es) ensured, ` +
            `${summary.appliedForeignKeys} foreign key(s).`
        );
      }
      if (summary.errors.length > 0) {
        console.warn(`[api] schema sync completed with ${summary.errors.length} error(s): ${summary.errors.join(' | ')}`);
      }
    } catch (err) {
      console.warn(
        `[api] schema sync failed — new tables/columns from this release may be missing; check the logs and ` +
          `re-run after fixing the cause. Continuing with the existing schema. Cause: ${(err as Error).message}`
      );
    }
    return;
  }

  // Fresh database: bootstrap until the core tables exist.
  console.log(`[api] fresh database detected — running first-boot schema bootstrap (drizzle-kit push --force)…`);
  await withAdvisoryLock(async () => {
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      try {
        await runFreshPush();
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
