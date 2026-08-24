import pg from 'pg';
import { z, ZodTypeAny } from 'zod';

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

async function probePath(endpoint: string, pathName: string): Promise<{ status?: number; body?: unknown; error?: string }> {
  try {
    const res = await fetch(`${endpoint}${pathName}`, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    const text = await res.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      /* not JSON — keep raw */
    }
    return { status: res.status, body };
  } catch (err) {
    return { error: (err as Error).message };
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
        'Probe every plugin endpoint listed in PLUGIN_POLL_ENDPOINTS: fetches /healthz and /discover, returning per-plugin ' +
        'reachability plus identity (uuid/name/version) and capabilities. Use to diagnose why a plugin is missing or stale.',
      inputSchema: {},
      handler: async () => {
        const endpoints = (process.env.PLUGIN_POLL_ENDPOINTS ?? '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        if (endpoints.length === 0) return textResult('PLUGIN_POLL_ENDPOINTS is not set', true);

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
