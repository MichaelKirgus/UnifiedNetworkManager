import pg from 'pg';
import type { Dispatcher } from 'undici';
import { z, ZodTypeAny } from 'zod';
import { apiDispatcher, isTransportError, mtlsLive } from './mcpMtls.js';

/**
 * Extended debug tools — served ONLY on the /debug/mcp endpoint (keyed by
 * MCP_DEBUG_KEY). They exist to diagnose UNM itself: read-only SQL against the
 * platform database and live probes of every registered plugin endpoint.
 *
 * Safety model:
 *   - query_database accepts a single SELECT/WITH statement only (comments are
 *     stripped before the check, multiple statements rejected), caps results at
 *     MAX_ROWS rows, and runs with a 10s statement_timeout on the pool.
 *   - plugin_probe is pure outbound GET traffic to /healthz + /discover.
 */

/** Matches the SDK's CallToolResult shape (index signature required for assignability). */
export interface DebugToolResult {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export interface DebugTool {
  name: string;
  description: string;
  /** Zod raw shape for the MCP input schema (same convention as specTools). */
  inputSchema: Record<string, ZodTypeAny>;
  handler: (args: Record<string, unknown>) => Promise<DebugToolResult>;
}

const MAX_ROWS = 200;
const PROBE_TIMEOUT_MS = 5_000;

let pool: pg.Pool | null = null;

/** Lazily-created read-only-ish pool (enforcement is in assertReadOnly). */
function getPool(): pg.Pool {
  if (!pool) {
    const url = process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm';
    // statement_timeout keeps a runaway query from wedging the pool.
    pool = new pg.Pool({ connectionString: url, max: 4, options: '-c statement_timeout=10s' });
  }
  return pool;
}

/** Rejects anything that is not a single read-only SELECT/WITH statement. */
function assertReadOnly(sql: string): void {
  const stripped = sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ').trim();
  if (!/^(select|with)\b/i.test(stripped)) {
    throw new Error('Only read-only queries (SELECT / WITH) are allowed on the debug endpoint');
  }
  const withoutTrailingSemicolon = stripped.replace(/;\s*$/, '');
  if (/;/.test(withoutTrailingSemicolon)) {
    throw new Error('Multiple statements are not allowed — send one query per call');
  }
}

function textResult(text: string, isError = false): DebugToolResult {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) };
}

/**
 * GETs one path on a plugin endpoint. mTLS Stage 2: when the MCP's own leaf is
 * live, try https + client cert FIRST (mTLS-live plugins answer there); a
 * transport-level failure falls back to plain http — so probes work against
 * mixed fleets exactly like the API's dual-transport discovery probe.
 */
async function probePath(endpoint: string, pathName: string): Promise<{ status?: number; body?: unknown; error?: string }> {
  // Scheme-less entries (e.g. "host:4080") are normalized to plain http first —
  // fetch() rejects them outright and the https flip below needs a scheme too.
  const base = /^https?:\/\//i.test(endpoint) ? endpoint.replace(/\/$/, '') : `http://${endpoint.replace(/\/$/, '')}`;
  if (mtlsLive()) {
    try {
      return await doProbe(`${base.replace(/^http/i, 'https')}${pathName}`, apiDispatcher());
    } catch (err) {
      // Only transport-level failures ("wrong transport") fall through to the
      // plain-http attempt; anything else is a real probe result.
      if (!isTransportError(err)) return { error: (err as Error).message };
    }
  }
  try {
    return await doProbe(`${base}${pathName}`);
  } catch (err) {
    return { error: (err as Error).message };
  }

  /** Performs the GET; THROWS on transport failure so callers can fall back. */
  async function doProbe(url: string, dispatcher?: Dispatcher): Promise<{ status?: number; body?: unknown }> {
    const res = await fetch(url, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS), ...(dispatcher ? { dispatcher } : {}) });
    const text = await res.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      /* not JSON — keep raw */
    }
    return { status: res.status, body };
  }
}

export function buildDebugTools(): DebugTool[] {
  const tools: DebugTool[] = [
    {
      name: 'query_database',
      description:
        'Run a READ-ONLY SQL query against the UNM Postgres database (single SELECT/WITH statement, max 200 rows). ' +
        'Useful for inspecting the plugins, devices, device_plugins, telemetry, config_jobs, plans and users tables while diagnosing issues.',
      inputSchema: { sql: z.string().describe('A single SELECT or WITH statement') },
      handler: async (args) => {
        const sql = typeof args.sql === 'string' ? args.sql : '';
        if (!sql.trim()) return textResult('Missing required argument "sql"', true);
        try {
          assertReadOnly(sql);
          const result = await getPool().query(sql);
          const rowCount = result.rowCount ?? result.rows.length;
          const rows = result.rows.slice(0, MAX_ROWS);
          const note = rowCount > MAX_ROWS ? `\n(truncated to ${MAX_ROWS} of ${rowCount} rows)` : '';
          return textResult(`rows: ${rowCount}\n${JSON.stringify(rows, null, 2)}${note}`);
        } catch (err) {
          return textResult(`Query failed: ${(err as Error).message}`, true);
        }
      },
    },
    {
      name: 'plugin_probe',
      description:
        'Probe every registered plugin endpoint (read from the plugins table — plugins self-register, so there is no static list): fetches /healthz and /discover, returning per-plugin ' +
        'reachability plus identity (uuid/name/version) and capabilities. Use to diagnose why a plugin is missing or stale.',
      inputSchema: {},
      handler: async () => {
        // Endpoints come from the plugins table (push-based self-registration),
        // not from any static env list — UNM keeps no catalog of plugins.
        let endpoints: string[] = [];
        try {
          const result = await getPool().query('SELECT DISTINCT endpoint FROM plugins WHERE endpoint IS NOT NULL AND endpoint <> \'\'');
          endpoints = (result.rows as Array<{ endpoint: string }>).map((r) => r.endpoint);
        } catch (err) {
          return textResult(`Could not read registered plugin endpoints from the database: ${(err as Error).message}`, true);
        }
        if (endpoints.length === 0) return textResult('No plugins are registered in the plugins table yet', true);

        const results: unknown[] = [];
        await Promise.all(
          endpoints.map(async (endpoint) => {
            const [healthz, discover] = await Promise.all([probePath(endpoint, '/healthz'), probePath(endpoint, '/discover')]);
            results.push({ endpoint, healthz, discover });
          })
        );
        return textResult(JSON.stringify(results, null, 2));
      },
    },
  ];

  return tools;
}
