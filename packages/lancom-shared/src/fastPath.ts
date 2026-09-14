/**
 * LANCOM fast-path counter helpers.
 *
 * The per-plugin `walk*Counters()` loops stay in each plugin — their index
 * decoding (text vs integer), column→direction maps, sample-key formats and
 * extra metrics (CRC deltas, trap-name joins) are vendor content. What IS
 * shared is the tiny "accumulate one tracker rate into a per-key rx/tx record"
 * block that appeared at ~5 sites across lancom-lcos / lancom-lx / lancom-sx;
 * it lives here once as accumulateRate().
 */

/** One rate sample per interface: bits/s (or raw deltas) in each direction. */
export type RatePair = { rx: number | null; tx: number | null };

/**
 * Folds one counter-tracker rate into a per-key rx/tx record, creating the key
 * on first use. `rate === null` (first sample / reset / wrap) leaves the slot
 * untouched so the next cycle re-baselines. Pass `round: false` to keep the
 * tracker's raw float value (e.g. per-second event deltas).
 */
export function accumulateRate(
  rates: Record<string, RatePair>,
  key: string,
  dir: 'rx' | 'tx',
  rate: number | null,
  round = true
): void {
  if (rate === null) return;
  const cur = rates[key] ?? (rates[key] = { rx: null, tx: null });
  const v = round ? Math.round(rate) : rate;
  if (dir === 'rx') cur.rx = v;
  else cur.tx = v;
}
