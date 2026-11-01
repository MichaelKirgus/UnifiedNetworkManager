/**
 * CVE vulnerability tracking — pure version matching.
 *
 * Given an advisory's affected-range bounds (OSV "events" normalized to
 * AffectedRange[]) and a device's installed version string, decide whether the
 * installed version is affected. No I/O, no DB — fully unit-testable.
 *
 * Version strings are ecosystem-specific, so each family gets its own
 * comparator:
 *   - Debian/Ubuntu  → dpkg algorithm (epoch:upstream-revision)
 *   - Alpine         → apk-style (X.Y.Z-rN; the rN revision is stripped and the
 *                      rest compared with the same segment walk as dpkg)
 *   - npm            → semver-ish (leading v, prerelease sorts before release)
 *   - anything else  → generic segmented comparison (numeric segments numeric,
 *                      the rest lexicographic) — a deliberate approximation for
 *                      ecosystems we don't model precisely yet.
 */

import type { AffectedRange } from './types';

/** Splits "1:2.3-4" into epoch "1" and remainder "2.3-4". */
function splitEpoch(v: string): [number, string] {
  const i = v.indexOf(':');
  if (i < 0) return [0, v];
  const e = Number.parseInt(v.slice(0, i), 10);
  return [Number.isFinite(e) ? e : 0, v.slice(i + 1)];
}

/**
 * dpkg version comparison of the NON-EPOCH part (upstream[-revision]).
 * Implements the classic algorithm: alternate runs of non-digits and digits;
 * non-digit runs compare lexicographically with the modified ordering where
 * '~' sorts before everything (including empty), digits sort before letters,
 * and uppercase sorts 32 below lowercase; digit runs compare numerically.
 */
function compareDpkgPart(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    // Non-digit run first.
    const aStart = i;
    while (i < a.length && !/\d/.test(a[i])) i++;
    const bStart = j;
    while (j < b.length && !/\d/.test(b[j])) j++;
    if (aStart !== i || bStart !== j) {
      // dpkg's modified ordering for the non-digit run: '~' sorts before EVERYTHING
      // including end-of-run, then end-of-run, then all other characters in ASCII
      // order with uppercase folded down to lowercase. (No digits appear here —
      // digit runs are handled separately.)
      const rank = (c: string | null): number => {
        if (c === '~') return -1;
        if (c === null) return 0; // end-of-run sorts after '~' but before real chars
        const code = c.charCodeAt(0);
        return code >= 65 && code <= 90 ? code + 32 : code; // fold A–Z down to a–z
      };
      for (let k = 0; ; k++) {
        const ac = aStart + k < i ? a[aStart + k] : null;
        const bc = bStart + k < j ? b[bStart + k] : null;
        if (ac === null && bc === null) break;
        const ar = rank(ac);
        const br = rank(bc);
        if (ar !== br) return ar < br ? -1 : 1;
      }
    }
    // Digit run.
    const aNumStart = i;
    while (i < a.length && /\d/.test(a[i])) i++;
    const bNumStart = j;
    while (j < b.length && /\d/.test(b[j])) j++;
    if (aNumStart !== i || bNumStart !== j) {
      // Compare numerically, but guard against absurd lengths (string compare of
      // the trimmed digits is exact for values that fit in a double; beyond
      // that fall back to length-then-lexicographic which matches big-number order).
      const an = a.slice(aNumStart, i).replace(/^0+(?=\d)/, '');
      const bn = b.slice(bNumStart, j).replace(/^0+(?=\d)/, '');
      if (an.length !== bn.length) return an.length < bn.length ? -1 : 1;
      if (an !== bn) return an < bn ? -1 : 1;
    }
  }
  return 0;
}

/** Full dpkg comparison: epoch, then upstream part, then debian revision. */
export function compareDpkg(a: string, b: string): number {
  const [aEpoch, aRest] = splitEpoch(a);
  const [bEpoch, bRest] = splitEpoch(b);
  if (aEpoch !== bEpoch) return aEpoch < bEpoch ? -1 : 1;

  // Split the debian/ubuntu revision off at the LAST dash.
  const aUp = aRest.lastIndexOf('-') >= 0 ? aRest.slice(0, aRest.lastIndexOf('-')) : aRest;
  const aRev = aRest.lastIndexOf('-') >= 0 ? aRest.slice(aRest.lastIndexOf('-') + 1) : '';
  const bUp = bRest.lastIndexOf('-') >= 0 ? bRest.slice(0, bRest.lastIndexOf('-')) : bRest;
  const bRev = bRest.lastIndexOf('-') >= 0 ? bRest.slice(bRest.lastIndexOf('-') + 1) : '';

  const up = compareDpkgPart(aUp, bUp);
  if (up !== 0) return up;
  return compareDpkgPart(aRev, bRev);
}

/** Strips an apk revision suffix ("-r3") from an Alpine version. */
function stripApkRevision(v: string): string {
  const m = v.match(/^(.*)-r(\d+)$/i);
  return m ? m[1] : v;
}

/** Alpine comparison — the rN revision is a build counter, not a release order. */
export function compareAlpine(a: string, b: string): number {
  const up = compareDpkgPart(stripApkRevision(a), stripApkRevision(b));
  if (up !== 0) return up;
  // Tie-break on the revision counter itself (2.4.5-r1 < 2.4.5-r2).
  const ra = Number((a.match(/-r(\d+)$/i)?.[1] ?? '0'));
  const rb = Number((b.match(/-r(\d+)$/i)?.[1] ?? '0'));
  return ra === rb ? 0 : ra < rb ? -1 : 1;
}

/** Splits "1.2.3-beta.4+build" into [core, prerelease]. */
function splitSemver(v: string): [string[], string | null] {
  let s = v.trim().replace(/^[v=]+/, '');
  const buildIdx = s.indexOf('+');
  if (buildIdx >= 0) s = s.slice(0, buildIdx); // build metadata never affects precedence
  let pre: string | null = null;
  const dashIdx = s.indexOf('-');
  if (dashIdx >= 0) {
    pre = s.slice(dashIdx + 1);
    s = s.slice(0, dashIdx);
  }
  return [s.split('.'), pre];
}

/** semver-ish comparison — good enough for npm/pypi-style versions. */
export function compareSemverish(a: string, b: string): number {
  const [aParts, aPre] = splitSemver(a);
  const [bParts, bPre] = splitSemver(b);
  const len = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < len; i++) {
    const an = Number.parseInt(aParts[i] ?? '0', 10);
    const bn = Number.parseInt(bParts[i] ?? '0', 10);
    const av = Number.isFinite(an) ? an : 0;
    const bv = Number.isFinite(bn) ? bn : 0;
    if (av !== bv) return av < bv ? -1 : 1;
  }
  // Prerelease sorts BEFORE the corresponding release: 1.2.3-beta < 1.2.3.
  if (aPre === null && bPre === null) return 0;
  if (aPre === null) return 1;
  if (bPre === null) return -1;
  // Both prerelease: compare identifier by identifier (numeric vs alpha rules).
  const aIds = aPre.split('.');
  const bIds = bPre.split('.');
  for (let i = 0; i < Math.max(aIds.length, bIds.length); i++) {
    const ai = aIds[i];
    const bi = bIds[i];
    if (ai === undefined) return -1;
    if (bi === undefined) return 1;
    const an = Number.parseInt(ai, 10);
    const bn = Number.parseInt(bi, 10);
    if (Number.isFinite(an) && Number.isFinite(bn)) {
      if (an !== bn) return an < bn ? -1 : 1;
    } else if (ai !== bi) {
      // Numeric identifiers sort before alphanumeric ones.
      const aNum = Number.isFinite(an);
      const bNum = Number.isFinite(bn);
      if (aNum !== bNum) return aNum ? -1 : 1;
      return ai < bi ? -1 : 1;
    }
  }
  return 0;
}

/** Generic fallback: split on dots/dashes/underscores, compare segment-wise. */
export function compareGeneric(a: string, b: string): number {
  const as = a.split(/[.\-_+]/).filter(Boolean);
  const bs = b.split(/[.\-_+]/).filter(Boolean);
  for (let i = 0; i < Math.max(as.length, bs.length); i++) {
    const x = as[i] ?? '';
    const y = bs[i] ?? '';
    if (x === y) continue;
    const xn = Number(x);
    const yn = Number(y);
    if (Number.isFinite(xn) && Number.isFinite(yn)) return xn < yn ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/** Picks the comparator for an ecosystem tag (case-insensitive substring match). */
export function versionComparatorFor(ecosystem: string | null | undefined): (a: string, b: string) => number {
  const e = (ecosystem ?? '').toLowerCase();
  if (e.includes('debian') || e.includes('ubuntu')) return compareDpkg;
  if (e.includes('alpine')) return compareAlpine;
  if (e === 'npm' || e.includes('node')) return compareSemverish;
  return compareGeneric;
}

/**
 * Builds the affected intervals from an ordered list of range bounds (OSV
 * "events"): a '>' / '>=' opens an interval, a '<' / '<=' closes it. A trailing
 * open bound means "up to infinity". Returns [start, end) pairs where either
 * side may be null (unbounded).
 */
export function buildIntervals(ranges: AffectedRange[]): Array<{ start: AffectedRange | null; end: AffectedRange | null }> {
  const intervals: Array<{ start: AffectedRange | null; end: AffectedRange | null }> = [];
  let open: AffectedRange | null = null;
  for (const r of ranges) {
    if (!r || typeof r.version !== 'string' || !r.version.trim()) continue;
    if (r.type === '>' || r.type === '>=') {
      // A new introduction supersedes any still-open one (OSV events are ordered).
      open = r;
    } else {
      intervals.push({ start: open, end: r });
      open = null;
    }
  }
  if (open) intervals.push({ start: open, end: null });
  return intervals;
}

/**
 * Does `installed` fall inside any of the advisory's affected ranges?
 *   - installed null/empty → TRUE (conservative: an unversioned package with a
 *     known advisory is flagged — better a false positive than a blind spot).
 *   - no usable ranges → FALSE (nothing to match against).
 */
export function matchesVersion(
  ranges: AffectedRange[],
  installed: string | null | undefined,
  ecosystem?: string | null
): boolean {
  const v = typeof installed === 'string' ? installed.trim() : '';
  if (!v) return true; // unversioned → assume affected (see above)

  const intervals = buildIntervals(ranges);
  if (intervals.length === 0) return false;

  const cmp = versionComparatorFor(ecosystem);
  for (const { start, end } of intervals) {
    let ok = true;
    if (start) {
      const c = cmp(v, start.version);
      ok = start.type === '>=' ? c >= 0 : c > 0;
    }
    if (ok && end) {
      const c = cmp(v, end.version);
      ok = end.type === '<=' ? c <= 0 : c < 0;
    }
    if (ok) return true;
  }
  return false;
}
