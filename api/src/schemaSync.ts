/**
 * Additive schema sync for EXISTING deployments (runs in the API image on every boot).
 *
 * WHY THIS EXISTS
 * ---------------
 * `drizzle-kit push` cannot run unattended against a database that holds objects which are
 * deliberately NOT declared in src/db/schema.ts — raw-SQL tables such as radacct /
 * radius_monitor_state and the monthly flow-aggregation partition children. Whenever the
 * schema gains new items at the same time those "missing" objects exist, drizzle-kit's
 * rename-detection demands an interactive prompt; without a TTY it ABORTS before applying
 * anything — yet still exits 0. The result was silent no-ops on every image-tag upgrade:
 * new tables (notification_*, security_events, threat_iocs, …) never appeared in production.
 *
 * HOW THIS WORKS
 * --------------
 * Instead of asking drizzle-kit to diff the live database, we ask it for the canonical DDL
 * of the CURRENT code (`drizzle-kit generate` into a throwaway dir — no DB connection needed),
 * then apply only the ADDITIVE parts against the live schema:
 *
 *   1. tables declared in src/db/schema.ts that do not exist yet → CREATE TABLE (verbatim)
 *   2. columns of existing tables that are missing            → ALTER TABLE … ADD COLUMN IF NOT EXISTS
 *   3. indexes                                                → CREATE [UNIQUE] INDEX IF NOT EXISTS
 *   4. foreign keys                                           → applied only when the constraint is absent and both tables exist
 *
 * Safety properties:
 *   - NEVER drops or alters existing tables/columns/indexes — data loss is impossible by construction.
 *   - Objects that live only in the database (radacct, flow partition children, …) are invisible
 *     to this logic, so the interactive-prompt trap cannot trigger.
 *   - Every statement is idempotent; a per-statement try/catch means one failure never blocks
 *     the rest. The caller serializes concurrent boots with an advisory lock.
 *
 * Structural changes (dropping/renaming columns or tables) are intentionally NOT applied —
 * those remain manual DDL, exactly as before.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Pool } from 'pg';

/** One parsed CREATE TABLE unit: the verbatim DDL plus its column definitions. */
export interface ParsedTable {
  name: string;
  ddl: string;
  /** Raw per-column definitions, e.g. `"ownerId" text` or `"audience" text DEFAULT '{"type":"all"}' not null`. */
  columns: string[];
}

/** One parsed index statement. */
export interface ParsedIndex {
  name: string;
  table: string;
  unique: boolean;
  ddl: string;
}

/** One parsed foreign-key constraint statement (drizzle emits these as ALTER TABLE … ADD CONSTRAINT). */
export interface ParsedForeignKey {
  constraintName: string;
  table: string;
  ddl: string;
}

export interface ParsedSchema {
  tables: ParsedTable[];
  indexes: ParsedIndex[];
  foreignKeys: ParsedForeignKey[];
}

/** Result of one additive sync pass — logged by the caller. */
export interface SyncSummary {
  createdTables: string[];
  addedColumns: Array<{ table: string; column: string }>;
  ensuredIndexes: number;
  appliedForeignKeys: number;
  errors: string[];
}

const GENERATE_TIMEOUT_MS = 60_000;

/**
 * Runs `drizzle-kit generate` against src/db/schema.ts into a fresh temp dir and returns the
 * generated SQL. No database connection is required — this is pure schema → DDL rendering, so
 * it always reflects the code currently running in this image.
 */
export async function generateSchemaDdl(bin: string): Promise<string> {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-schema-sync-'));
  try {
    await new Promise<void>((resolve, reject) => {
      const args = [bin, 'generate', '--name', 'sync-probe', '--dialect', 'postgresql', '--schema', './src/db/schema.ts', '--out', outDir];
      const child = spawn(process.execPath, args, { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      const append = (chunk: Buffer) => { output += chunk.toString('utf8'); };
      child.stdout.on('data', append);
      child.stderr.on('data', append);
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`drizzle-kit generate timed out after ${GENERATE_TIMEOUT_MS / 1000}s`));
      }, GENERATE_TIMEOUT_MS);
      child.on('error', (err) => { clearTimeout(timer); reject(err); });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(`drizzle-kit generate exited with code ${code}: ${output.slice(-500)}`));
      });
    });
    const files = fs.readdirSync(outDir).filter((f) => f.endsWith('.sql'));
    if (files.length === 0) throw new Error('drizzle-kit generate produced no SQL file');
    return fs.readFileSync(path.join(outDir, files[0]), 'utf8');
  } finally {
    try { fs.rmSync(outDir, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
  }
}

/**
 * Splits drizzle-kit's generated migration SQL into table / index / foreign-key units.
 * Statement separator is the literal `--> statement-breakpoint` marker drizzle emits.
 */
export function parseMigrationSql(sql: string): ParsedSchema {
  const result: ParsedSchema = { tables: [], indexes: [], foreignKeys: [] };

  for (const raw of sql.split('--> statement-breakpoint')) {
    const stmt = raw.trim();
    if (!stmt) continue;

    const tableMatch = /^CREATE TABLE "([^"]+)" \(/.exec(stmt);
    if (tableMatch) {
      result.tables.push({ name: tableMatch[1], ddl: stmt, columns: extractColumnDefs(stmt) });
      continue;
    }

    const indexMatch = /^CREATE (UNIQUE )?INDEX "([^"]+)" ON "([^"]+)"/.exec(stmt);
    if (indexMatch) {
      result.indexes.push({ name: indexMatch[2], table: indexMatch[3], unique: Boolean(indexMatch[1]), ddl: stmt });
      continue;
    }

    const fkMatch = /^ALTER TABLE "([^"]+)" ADD CONSTRAINT "([^"]+)"/.exec(stmt);
    if (fkMatch && /FOREIGN KEY/i.test(stmt)) {
      result.foreignKeys.push({ table: fkMatch[1], constraintName: fkMatch[2], ddl: stmt });
      continue;
    }

    // Anything else (e.g. a future statement type) is intentionally ignored — additive-only.
  }

  return result;
}

/**
 * Extracts the per-column definition lines from a CREATE TABLE body. Table-level constraint
 * lines (`CONSTRAINT … UNIQUE(…)`, `PRIMARY KEY(…)`) are skipped; continuation lines (if drizzle
 * ever wraps a column) are appended to the previous column instead of starting a new one.
 */
export function extractColumnDefs(createTableSql: string): string[] {
  const open = createTableSql.indexOf('(');
  const close = createTableSql.lastIndexOf(')');
  if (open === -1 || close <= open) return [];
  const body = createTableSql.slice(open + 1, close);

  const columns: string[] = [];
  for (const rawLine of body.split('\n')) {
    const line = rawLine.trim().replace(/,$/, '');
    if (!line) continue;
    if (/^CONSTRAINT\b/i.test(line)) continue; // table-level constraint, not a column
    if (/^PRIMARY KEY\s*\(/i.test(line)) continue; // composite PK declared as table constraint
    if (columns.length > 0 && !/^"/.test(line)) {
      columns[columns.length - 1] += ` ${line}`; // continuation of the previous column def
      continue;
    }
    columns.push(line);
  }
  return columns;
}

/** Builds an idempotent ADD COLUMN statement from a raw column definition. */
export function buildAddColumn(table: string, columnDef: string): { sql: string; primaryKeyStripped: boolean } {
  let def = columnDef.trim();
  // A missing column on an EXISTING table can never be its primary key (the PK already exists);
  // strip the marker so the ADD COLUMN cannot fail on a non-empty table.
  const primaryKeyStripped = /PRIMARY KEY/i.test(def);
  if (primaryKeyStripped) def = def.replace(/\s*PRIMARY KEY\b/i, '').trim();
  return { sql: `ALTER TABLE "${table}" ADD COLUMN IF NOT EXISTS ${def}`, primaryKeyStripped };
}

/** Rewrites a CREATE [UNIQUE] INDEX statement into its idempotent form. */
export function buildIdempotentIndex(index: ParsedIndex): string {
  if (index.unique) return index.ddl.replace(/^CREATE UNIQUE INDEX/, 'CREATE UNIQUE INDEX IF NOT EXISTS');
  return index.ddl.replace(/^CREATE INDEX/, 'CREATE INDEX IF NOT EXISTS');
}

/** Lists all base + partitioned table names in the public schema. */
async function listLiveTables(pool: Pool): Promise<Set<string>> {
  const res = await pool.query(
    `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`
  );
  return new Set(res.rows.map((r: { relname: string }) => r.relname));
}

/** Lists column names of one table (empty set when the table does not exist). */
async function listLiveColumns(pool: Pool, table: string): Promise<Set<string>> {
  const res = await pool.query(
    `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1`,
    [table]
  );
  return new Set(res.rows.map((r: { column_name: string }) => r.column_name));
}

/** True when a constraint with this name already exists. */
async function constraintExists(pool: Pool, name: string): Promise<boolean> {
  const res = await pool.query(`SELECT 1 FROM pg_constraint WHERE conname = $1`, [name]);
  return res.rows.length > 0;
}

/**
 * Applies all additive schema changes (missing tables/columns/indexes/FKs) to the live database.
 * Never throws for individual statement failures — they are collected in summary.errors so a
 * single broken object can never wedge API startup. Throws only when the DDL cannot be generated
 * at all or the database is unreachable (the caller treats both as non-fatal warnings).
 */
export async function applyAdditiveSchema(pool: Pool): Promise<SyncSummary> {
  const summary: SyncSummary = { createdTables: [], addedColumns: [], ensuredIndexes: 0, appliedForeignKeys: 0, errors: [] };

  const ddl = await generateSchemaDdl(path.join(process.cwd(), 'node_modules', '.bin', 'drizzle-kit'));
  const schema = parseMigrationSql(ddl);
  if (schema.tables.length === 0) throw new Error('generated DDL contains no tables — refusing to sync');

  const liveTables = await listLiveTables(pool);

  // 1. Missing tables → create verbatim, in generated order.
  for (const table of schema.tables) {
    if (liveTables.has(table.name)) continue;
    try {
      await pool.query(table.ddl);
      liveTables.add(table.name);
      summary.createdTables.push(table.name);
      console.log(`[api] schema sync: created missing table "${table.name}"`);
    } catch (err) {
      const msg = `CREATE TABLE ${table.name} failed: ${(err as Error).message}`;
      summary.errors.push(msg);
      console.warn(`[api] schema sync: ${msg}`);
    }
  }

  // 2. Existing tables → add missing columns (idempotent, additive only).
  for (const table of schema.tables) {
    if (!liveTables.has(table.name)) continue;
    let liveColumns: Set<string>;
    try {
      liveColumns = await listLiveColumns(pool, table.name);
    } catch (err) {
      summary.errors.push(`column introspection for ${table.name} failed: ${(err as Error).message}`);
      continue;
    }
    for (const columnDef of table.columns) {
      const colName = /^"([^"]+)"/.exec(columnDef)?.[1];
      if (!colName || liveColumns.has(colName)) continue;
      const { sql, primaryKeyStripped } = buildAddColumn(table.name, columnDef);
      try {
        await pool.query(sql);
        summary.addedColumns.push({ table: table.name, column: colName });
        console.log(`[api] schema sync: added missing column "${table.name}.${colName}"${primaryKeyStripped ? ' (stripped PRIMARY KEY marker — existing table)' : ''}`);
      } catch (err) {
        const msg = `ADD COLUMN ${table.name}.${colName} failed: ${(err as Error).message}`;
        summary.errors.push(msg);
        console.warn(`[api] schema sync: ${msg}`);
      }
    }
  }

  // 3. Indexes → idempotent CREATE for every table that now exists.
  for (const index of schema.indexes) {
    if (!liveTables.has(index.table)) continue;
    try {
      await pool.query(buildIdempotentIndex(index));
      summary.ensuredIndexes += 1;
    } catch (err) {
      const msg = `CREATE INDEX ${index.name} failed: ${(err as Error).message}`;
      summary.errors.push(msg);
      console.warn(`[api] schema sync: ${msg}`);
    }
  }

  // 4. Foreign keys → apply when absent and both tables exist (referenced table may have just been created).
  for (const fk of schema.foreignKeys) {
    if (!liveTables.has(fk.table)) continue;
    try {
      if (await constraintExists(pool, fk.constraintName)) continue;
      await pool.query(fk.ddl);
      summary.appliedForeignKeys += 1;
      console.log(`[api] schema sync: applied missing foreign key "${fk.constraintName}"`);
    } catch (err) {
      const msg = `ADD CONSTRAINT ${fk.constraintName} failed: ${(err as Error).message}`;
      summary.errors.push(msg);
      console.warn(`[api] schema sync: ${msg}`);
    }
  }

  return summary;
}
