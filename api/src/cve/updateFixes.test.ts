/**
 * Unit tests for the "which CVEs does this update fix" computation.
 */

import { advisoriesFixedBy, summarizeFixes } from './updateFixes';
import type { CveAdvisoryLite } from './updateFixes';
import type { AffectedRange } from './types';

const range = (type: AffectedRange['type'], version: string): AffectedRange => ({ type, version });

function advisory(
  id: string,
  severityRank: CveAdvisoryLite['severityRank'],
  affectedRanges: AffectedRange[]
): CveAdvisoryLite {
  return { id, severityRank, affectedRanges };
}

// Advisory affecting [1.0, 2.5) — installed 2.4 is vulnerable, 3.0 is not.
const AFFECTED_1_0_TO_2_5: AffectedRange[] = [range('>=', '1.0'), range('<', '2.5')];

describe('advisoriesFixedBy', () => {
  it('includes an advisory when the current version is affected and the latest is not', () => {
    const fixed = advisoriesFixedBy(
      [advisory('CVE-1', 'high', AFFECTED_1_0_TO_2_5)],
      '2.4',
      '3.0'
    );
    expect(fixed.map((a) => a.id)).toEqual(['CVE-1']);
  });

  it('excludes an advisory when the latest version is still affected (update does not fix it)', () => {
    const fixed = advisoriesFixedBy(
      [advisory('CVE-1', 'high', AFFECTED_1_0_TO_2_5)],
      '2.4',
      '2.4.1' // still inside [1.0, 2.5) → the update does not fix it
    );
    expect(fixed).toEqual([]);

    const stillAffected = advisoriesFixedBy(
      [advisory('CVE-1', 'high', AFFECTED_1_0_TO_2_5)],
      '2.4',
      '2.4' // latest == current, both inside the range
    );
    expect(stillAffected).toEqual([]);
  });

  it('excludes an advisory when the current version is not affected at all', () => {
    const fixed = advisoriesFixedBy(
      [advisory('CVE-1', 'high', AFFECTED_1_0_TO_2_5)],
      '3.0',
      '4.0'
    );
    expect(fixed).toEqual([]);
  });

  it('returns [] when the latest version is unknown — a fix cannot be verified', () => {
    const adv = advisory('CVE-1', 'critical', AFFECTED_1_0_TO_2_5);
    for (const latest of [null, '', undefined]) {
      expect(advisoriesFixedBy([adv], '2.4', latest)).toEqual([]);
    }
  });

  it('treats a null/empty current version as affected (conservative) when the latest is out of range', () => {
    const fixed = advisoriesFixedBy(
      [advisory('CVE-1', 'medium', AFFECTED_1_0_TO_2_5)],
      null,
      '3.0'
    );
    expect(fixed.map((a) => a.id)).toEqual(['CVE-1']);

    // But an unknown latest still blocks the claim.
    expect(advisoriesFixedBy([advisory('CVE-1', 'medium', AFFECTED_1_0_TO_2_5)], null, null)).toEqual([]);
  });

  it('never matches advisories without usable ranges (matchesVersion returns false)', () => {
    const fixed = advisoriesFixedBy(
      [advisory('CVE-1', 'high', [])],
      '2.4',
      '3.0'
    );
    expect(fixed).toEqual([]);
  });

  it('keeps only the fixing subset when several advisories are mixed', () => {
    const fixed = advisoriesFixedBy(
      [
        advisory('CVE-A', 'critical', AFFECTED_1_0_TO_2_5), // fixed by 3.0
        advisory('CVE-B', 'low', [range('>=', '9.0')]), // current not affected → excluded
        advisory('CVE-C', 'high', [range('>=', '1.0'), range('<', '4.0')]), // latest 3.0 still in range → excluded
      ],
      '2.4',
      '3.0'
    );
    expect(fixed.map((a) => a.id)).toEqual(['CVE-A']);
  });

  it('returns [] for an empty advisory list', () => {
    expect(advisoriesFixedBy([], '2.4', '3.0')).toEqual([]);
  });
});

describe('summarizeFixes', () => {
  it('returns null when no advisories are fixed', () => {
    expect(summarizeFixes([])).toBeNull();
  });

  it('counts by severity rank and orders topIds critical-first, then by id', () => {
    const summary = summarizeFixes([
      advisory('CVE-10', 'medium', []),
      advisory('CVE-2', 'critical', []),
      advisory('CVE-3', 'high', []),
      advisory('CVE-4', 'low', []),
      advisory('CVE-5', 'unknown', []),
      advisory('CVE-1', 'critical', []),
    ]);
    expect(summary).toEqual({
      total: 6,
      critical: 2,
      high: 1,
      medium: 1,
      low: 1,
      unknown: 1,
      topIds: ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-10', 'CVE-4', 'CVE-5'],
    });
  });

  it('caps topIds at the requested limit (default 8)', () => {
    const many = Array.from({ length: 12 }, (_, i) => advisory(`CVE-${String(i).padStart(3, '0')}`, 'low', []));
    expect(summarizeFixes(many)?.topIds).toHaveLength(8);

    const limited = summarizeFixes(many, 3);
    expect(limited?.topIds).toEqual(['CVE-000', 'CVE-001', 'CVE-002']);
  });

  it('dedupes advisories sharing a CVE id (OSV emits one row per range-set variant)', () => {
    const summary = summarizeFixes([
      advisory('CVE-2026-5773', 'high', []), // same id, second variant — must not double-count
      advisory('CVE-2026-5773', 'high', []),
      advisory('CVE-2026-1111', 'critical', []),
    ]);
    expect(summary).toEqual({
      total: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      unknown: 0,
      topIds: ['CVE-2026-1111', 'CVE-2026-5773'],
    });
  });
});
