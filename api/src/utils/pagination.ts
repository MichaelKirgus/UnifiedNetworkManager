/**
 * Shared query-string pagination parsing for list endpoints.
 *
 * Endpoints that adopt this support three params: `page` (1-based), `pageSize`
 * (clamped to a max) and `all=true` (one unpaginated response with every
 * matching row — the "All" entry in the webapp's rows-per-page select). When
 * NONE of them is present, callers keep their legacy behavior (see
 * hasPaginationParams) so existing consumers are never broken by an upgrade.
 *
 * NOTE on types: express-openapi-validator v5 forces coerceTypes — declared
 * integer/boolean query params arrive at the handler as REAL numbers/booleans,
 * not strings. Every check below accepts both forms (see backups.ts cursorId).
 */

export interface ParsedPagination {
  page: number;
  pageSize: number;
  /** all=true → return every matching row in one response (no LIMIT/OFFSET). */
  all: boolean;
}

export type PaginationResult = ParsedPagination | { error: string };

/** True when the caller asked for paged mode — any of page/pageSize/all present.
 * `includeAll=false` for endpoints whose `all` param has a DIFFERENT meaning
 * (e.g. /notifications uses all=true to ignore personal visibility prefs). */
export function hasPaginationParams(query: Record<string, unknown>, opts?: { includeAll?: boolean }): boolean {
  if (query.page !== undefined || query.pageSize !== undefined) return true;
  return (opts?.includeAll ?? true) && query.all !== undefined;
}

function toInt(v: unknown): number | null {
  if (typeof v === 'number' && Number.isInteger(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && Number.isInteger(Number(v))) return Number(v);
  return null;
}

/** Parse + validate page/pageSize/all. Non-numeric → error object; pageSize is
 * CLAMPED to the max (unbounded-by-accident is exactly what the cap prevents). */
export function parsePagination(
  query: Record<string, unknown>,
  opts?: { defaultPageSize?: number; maxPageSize?: number }
): PaginationResult {
  const def = opts?.defaultPageSize ?? 50;
  const max = opts?.maxPageSize ?? 200;

  let page = 1;
  if (query.page !== undefined) {
    const n = toInt(query.page);
    if (n === null || n < 1) return { error: `"page" must be a positive integer` };
    page = n;
  }

  let pageSize = def;
  if (query.pageSize !== undefined) {
    const n = toInt(query.pageSize);
    if (n === null || n < 1) return { error: `"pageSize" must be a positive integer` };
    pageSize = Math.min(n, max);
  }

  // Coerced booleans arrive as real booleans — accept both forms.
  const allRaw = query.all;
  if (allRaw !== undefined && typeof allRaw !== 'boolean') {
    if (typeof allRaw !== 'string' || !['true', 'false'].includes(allRaw)) {
      return { error: `"all" must be "true" or "false"` };
    }
  }

  return { page, pageSize, all: allRaw === true || allRaw === 'true' };
}

/** LIMIT/OFFSET for a parsed pagination — null = unbounded (all=true). */
export function limitOffset(pg: ParsedPagination): { limit: number; offset: number } | null {
  if (pg.all) return null;
  return { limit: pg.pageSize, offset: (pg.page - 1) * pg.pageSize };
}

/** Envelope page/pageSize for the response — all=true reports one page holding everything. */
export function envelopePage(pg: ParsedPagination, total: number): { page: number; pageSize: number } {
  return pg.all ? { page: 1, pageSize: total } : { page: pg.page, pageSize: pg.pageSize };
}

/** Parse + validate a comma-separated page-size list ("25,50,100") — the format of the global
 * `tablePageSizeOptions` setting. Throws on malformed input; order is preserved (first = default). */
export function parseTablePageSizeOptions(raw: string): number[] {
  const parts = raw.split(',').map((p) => p.trim()).filter((p) => p !== '');
  if (parts.length === 0) throw new Error('at least one page size is required');
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) throw new Error(`"${part}" is not a positive integer`);
    const n = Number(part);
    if (n < 1 || n > 1000) throw new Error('page sizes must be between 1 and 1000');
    out.push(n);
  }
  return out;
}
