/**
 * Unit tests for the CVE worker's pure helpers — CVSS v3 vector scoring
 * (cvss.ts), ecosystem mapping (ecosystems.ts) and advisory PK dedupe
 * (types.ts). The network path itself is covered by live E2E.
 */

import { parseCvssVector } from './cvss';
import { mapToOsvEcosystem } from './ecosystems';
import { dedupeAdvisoriesByPk } from './types';
import type { AdvisoryRow } from './types';

function advisory(overrides: Partial<AdvisoryRow> & Pick<AdvisoryRow, 'ecosystem' | 'packageName' | 'id'>): AdvisoryRow {
  return { severityScore: null, severityRank: 'unknown', affectedRanges: [], ...overrides };
}

describe('parseCvssVector', () => {
  it('scores a known critical vector (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8)', () => {
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('scores a known high vector (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5)', () => {
    // Hand-computed per the v3.1 spec: ISS=0.56 → impact 3.5952;
    // exploitability 8.22×0.85×0.77×0.62×0.85 = 2.8353; base 6.4305 → roundup 6.5.
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')).toBe(6.5);
  });

  it('scores a known medium vector (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N = 4.3)', () => {
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N')).toBe(4.3);
  });

  it('scores a known low vector (AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N = 2.5)', () => {
    // Hand-computed per the v3.1 spec: ISS=0.22 → impact 1.4124;
    // exploitability 8.22×0.55×0.44×0.62×0.85 = 1.0483; base 2.4607 → roundup 2.5.
    expect(parseCvssVector('CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N')).toBe(2.5);
  });

  it('handles scope-changed vectors (S:C uses the changed-impact formula)', () => {
    // AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 (the classic "scope changed critical").
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
  });

  it('applies the CVSS roundup rule (round UP to one decimal)', () => {
    // AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L → base 7.0688… → rounds up to 7.1.
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L')).toBe(7.1);
  });

  it('returns null for non-v3 or incomplete vectors', () => {
    expect(parseCvssVector('CVSS:2/AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull();
    expect(parseCvssVector('not-a-vector')).toBeNull();
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:L')).toBeNull(); // missing metrics
  });

  it('is case-insensitive on the vector prefix', () => {
    expect(parseCvssVector('cvss:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });
});

describe('mapToOsvEcosystem', () => {
  it('maps plugin ecosystem tags onto OSV.dev ecosystem names', () => {
    expect(mapToOsvEcosystem('debian')).toBe('Debian');
    expect(mapToOsvEcosystem('ubuntu')).toBe('Debian'); // Ubuntu advisories live in the Debian source
    expect(mapToOsvEcosystem('alpine')).toBe('Alpine'); // no release → bare name (versionless lookups only)
    expect(mapToOsvEcosystem('alpine:v3.19')).toBe('Alpine:v3.19'); // OSV keys Alpine per release
    expect(mapToOsvEcosystem('alpine:3.18')).toBe('Alpine:v3.18');
    expect(mapToOsvEcosystem('npm')).toBe('npm');
    expect(mapToOsvEcosystem('pypi')).toBe('PyPI');
  });

  it('returns null for unknown/empty tags (worker skips those packages)', () => {
    expect(mapToOsvEcosystem('unknown')).toBeNull();
    expect(mapToOsvEcosystem('')).toBeNull();
    expect(mapToOsvEcosystem(null)).toBeNull();
    expect(mapToOsvEcosystem('routeros')).toBeNull(); // no OSV source yet
  });
});

describe('dedupeAdvisoriesByPk', () => {
  it('drops duplicate (ecosystem, packageName, id) rows — one per queried version of a package', () => {
    const base = advisory({ ecosystem: 'Debian', packageName: 'openssl', id: 'DEBIAN-CVE-2024-0727' });
    // Same advisory returned by the openssl@3.0.x AND openssl@3.2.x queries —
    // a single ON CONFLICT statement containing both is rejected by Postgres.
    const rows = [base, { ...base }, base];
    expect(dedupeAdvisoriesByPk(rows)).toHaveLength(1);
  });

  it('keeps the FIRST occurrence and preserves order of distinct keys', () => {
    const a1 = advisory({ ecosystem: 'Debian', packageName: 'openssl', id: 'CVE-2024-0727', severityScore: 9.8, severityRank: 'critical' });
    const a2 = advisory({ ecosystem: 'Debian', packageName: 'curl', id: 'CVE-2023-38545', severityScore: 6.1, severityRank: 'medium' });
    const a1dup = { ...a1, summary: 'should be ignored — keep-first' };
    expect(dedupeAdvisoriesByPk([a1, a2, a1dup])).toEqual([a1, a2]);
  });

  it('treats different ecosystems or ids as distinct rows', () => {
    const d = advisory({ ecosystem: 'Debian', packageName: 'openssl', id: 'CVE-2024-0727' });
    const n = advisory({ ecosystem: 'npm', packageName: 'openssl', id: 'CVE-2024-0727' });
    const d2 = advisory({ ecosystem: 'Debian', packageName: 'openssl', id: 'CVE-2023-5678' });
    expect(dedupeAdvisoriesByPk([d, n, d2])).toHaveLength(3);
  });

  it('handles an empty input', () => {
    expect(dedupeAdvisoriesByPk([])).toEqual([]);
  });
});
