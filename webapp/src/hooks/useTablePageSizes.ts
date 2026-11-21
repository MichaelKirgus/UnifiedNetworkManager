import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

/** Fallback rows-per-page choices — mirrors the API registry default for `tablePageSizeOptions`. */
export const DEFAULT_TABLE_PAGE_SIZES: number[] = [25, 50, 100];

/** Tolerant parser for the `tablePageSizeOptions` value ("25,50,100").
 * Order is preserved (first entry = initial page size); duplicates and invalid
 * entries are dropped; an unusable value falls back to the defaults. */
export function parseTablePageSizeOptions(raw: unknown): number[] {
  if (typeof raw !== 'string') return DEFAULT_TABLE_PAGE_SIZES;
  const out: number[] = [];
  for (const part of raw.split(',')) {
    const t = part.trim();
    if (!/^\d+$/.test(t)) continue;
    const n = Number(t);
    if (n >= 1 && n <= 1000 && !out.includes(n)) out.push(n);
  }
  return out.length > 0 ? out : DEFAULT_TABLE_PAGE_SIZES;
}

/** Rows-per-page choices for server-paginated tables — the global
 * `tablePageSizeOptions` setting, served via GET /auth/me (no system:read needed).
 * Reads the shared ['me'] query so it costs no extra request. */
export function useTablePageSizeOptions(): number[] {
  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me });
  return useMemo(() => parseTablePageSizeOptions(meQuery.data?.tablePageSizeOptions), [meQuery.data]);
}
