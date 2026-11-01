/**
 * CVE vulnerability tracking — CVSS v3.x base-score computation (pure).
 *
 * OSV.dev carries severity as CVSS *vector* strings, not scores. Computing the
 * base score locally keeps every provider dependency-free and gives us a real
 * 0–10 number for ranking/badges instead of a coarse word. Implements the
 * official v3.x formula (spec §5.4–§5.7) including the "Roundup" rule.
 */

const V3_METRIC_VALUES: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};
// PR depends on Scope — resolved at parse time (spec §5.4).
const V3_PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const V3_PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** CVSS v3.x "Roundup" — round UP to the first decimal (7.34 → 7.4). */
export function cvssRoundup(x: number): number {
  return Math.ceil(x * 10 - 1e-9) / 10;
}

/** Parses a CVSS v3.x vector string into its base score, or null when not v3/incomplete. */
export function parseCvssVector(vector: string): number | null {
  const m = (vector ?? '').trim().match(/^CVSS:3\.[01]\/(.+)$/i);
  if (!m) return null; // v2/v4/unknown — leave scoring to the fallback path

  const metrics: Record<string, string> = {};
  for (const token of m[1].split('/')) {
    const idx = token.indexOf(':');
    if (idx <= 0) continue;
    metrics[token.slice(0, idx).toUpperCase()] = token.slice(idx + 1).toUpperCase();
  }

  for (const key of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const) {
    if (!metrics[key]) return null; // incomplete vector — don't guess
  }
  const scopeChanged = metrics.S === 'C';
  const av = V3_METRIC_VALUES.AV[metrics.AV];
  const ac = V3_METRIC_VALUES.AC[metrics.AC];
  const pr = (scopeChanged ? V3_PR_CHANGED : V3_PR_UNCHANGED)[metrics.PR];
  const ui = V3_METRIC_VALUES.UI[metrics.UI];
  const c = V3_METRIC_VALUES.C[metrics.C];
  const i = V3_METRIC_VALUES.I[metrics.I];
  const a = V3_METRIC_VALUES.A[metrics.A];
  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) return null;

  // ISS (spec §5.6): 1 − [(1−C)(1−I)(1−A)]
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  // Impact sub-score (§5.5): scope-changed uses the 7.52/3.25 formula with the
  // (ISS×0.973+0.014)^15 term; unchanged is the simple 6.42×ISS.
  const impactSubScore = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss * 0.973 + 0.014, 15)
    : 6.42 * iss;
  if (impactSubScore <= 0) return 0; // no impact → base score 0
  const exploitability = 8.22 * av * ac * pr * ui; // §5.7
  const raw = scopeChanged ? Math.min(1.08 * (impactSubScore + exploitability), 10) : Math.min(impactSubScore + exploitability, 10);
  return cvssRoundup(raw);
}
