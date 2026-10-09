/**
 * Shared helpers for the JSON-string-array columns that several route files
 * store on their tables (devices.tags/deviceTypes, documented hosts' tags +
 * macs/dnsNames, documented networks' subnets/gateways/…). Previously each of
 * those routes re-implemented these two functions verbatim — one owner now.
 */

/** Parses a stored JSON string array defensively (bad data → []). Trims + dedupes. */
export function readStringArray(raw: unknown): string[] {
  let arr: unknown = raw;
  if (typeof raw === 'string') {
    try { arr = JSON.parse(raw); } catch { return []; }
  }
  if (!Array.isArray(arr)) return [];
  const out: string[] = [];
  for (const v of arr) {
    if (typeof v !== 'string') continue;
    const t = v.trim();
    if (t !== '' && !out.includes(t)) out.push(t);
  }
  return out;
}

/** Validates a request-body field as an array of non-empty strings; returns the deduped list or an error. */
export function parseStringArrayField(raw: unknown, field: string): { value?: string[]; error?: string } {
  if (!Array.isArray(raw)) return { error: `"${field}" must be an array of strings` };
  for (const v of raw as unknown[]) {
    if (typeof v !== 'string' || v.trim() === '') return { error: `"${field}" entries must be non-empty strings` };
  }
  const out: string[] = [];
  for (const v of raw as string[]) {
    const t = v.trim();
    if (!out.includes(t)) out.push(t);
  }
  return { value: out };
}
