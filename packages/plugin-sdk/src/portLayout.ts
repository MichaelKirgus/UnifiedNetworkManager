/**
 * Generic switch-face layout suggestion for plugins that do not (or cannot)
 * propagate a model-specific panel layout. Produces balanced, unlabeled rows:
 * ports are ordered by their numeric port number when it can be parsed from
 * the item key ('P12' → 12, '12' → 12), otherwise by array order; the count is
 * split into `rows` bands of (nearly) equal size — e.g. a 48-port switch with
 * rows=3 becomes three bands of 16 ports each, like a real front panel.
 */

import type { StateItem, SwitchLayout } from './types';

/** Extracts the numeric port number from an item key ('P12' → 12, '5' → 5).
 *  Name-based keys like 'em0' or 'bridge0' are NOT numeric — they keep their
 *  original (array) order in the generic layout. */
export function portNumberFromKey(key: string): number | null {
  const m = /^p?(\d+)$/i.exec(key.trim());
  return m ? Number(m[1]) : null;
}

/**
 * Builds a generic SwitchLayout for the given items.
 * @param items   The section's StateItems (only `key` is used).
 * @param rows    Target number of bands (default 3 — typical switch face). Clamped to [1, items.length].
 */
export function suggestPortLayout(items: Pick<StateItem, 'key'>[], rows = 3): SwitchLayout {
  const ordered = [...items];
  // Numeric keys sort by port number; non-numeric keep their relative order at the end.
  ordered.sort((a, b) => {
    const na = portNumberFromKey(a.key);
    const nb = portNumberFromKey(b.key);
    if (na !== null && nb !== null) return na - nb;
    if (na !== null) return -1;
    if (nb !== null) return 1;
    return 0;
  });

  const n = ordered.length;
  if (n === 0) return { groups: [] };
  const r = Math.max(1, Math.min(rows, n));
  const base = Math.floor(n / r);
  const extra = n % r; // first `extra` bands get one more port

  const groups: SwitchLayout['groups'] = [];
  let cursor = 0;
  for (let i = 0; i < r; i++) {
    const size = base + (i < extra ? 1 : 0);
    if (size === 0) continue;
    groups.push({ id: `row-${i + 1}`, portKeys: ordered.slice(cursor, cursor + size).map((it) => it.key) });
    cursor += size;
  }
  return { groups };
}
