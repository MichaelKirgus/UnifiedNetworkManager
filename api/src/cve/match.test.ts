/**
 * Unit tests for cve/match.ts — the pure version-matching core. Covers each
 * comparator family (dpkg, alpine, semver-ish, generic) and the range-interval
 * logic that decides whether an installed version is affected by an advisory.
 */

import {
  compareAlpine,
  compareDpkg,
  compareGeneric,
  compareSemverish,
  matchesVersion,
  versionComparatorFor,
} from './match';
import type { AffectedRange } from './types';

const lt = (version: string): AffectedRange => ({ type: '<', version });
const gt = (version: string): AffectedRange => ({ type: '>', version });
const gte = (version: string): AffectedRange => ({ type: '>=', version });

describe('compareDpkg', () => {
  it('orders plain numeric segments numerically, not lexicographically', () => {
    expect(compareDpkg('1.2.3', '1.2.10')).toBeLessThan(0); // "3" < "10" as numbers
    expect(compareDpkg('1.10', '1.9')).toBeGreaterThan(0);
  });

  it('handles epochs (epoch wins over everything else)', () => {
    expect(compareDpkg('2:1.0', '1:9.9')).toBeGreaterThan(0);
    expect(compareDpkg('1.0', '1:1.0')).toBeLessThan(0); // no epoch = epoch 0
  });

  it('splits the debian revision at the LAST dash and compares it last', () => {
    expect(compareDpkg('1.2-3', '1.2-4')).toBeLessThan(0);
    expect(compareDpkg('1.2+dfsg-3', '1.2+dfsg-10')).toBeLessThan(0); // numeric revs
  });

  it('applies the ~ rule (tilde sorts before everything, incl. empty)', () => {
    expect(compareDpkg('1.0~beta', '1.0')).toBeLessThan(0);
    expect(compareDpkg('1.0~a', '1.0~b')).toBeLessThan(0);
  });

  it('matches real-world Debian/Ubuntu ordering examples', () => {
    // openssl versions as seen on Ubuntu hosts (from dpkg --compare-versions).
    expect(compareDpkg('3.0.2-0ubuntu1.8', '3.0.2-0ubuntu1.9')).toBeLessThan(0);
    expect(compareDpkg('1.1.1n-0ubuntu3.9', '1.1.1n-0ubuntu3.10')).toBeLessThan(0);
  });
});

describe('compareAlpine', () => {
  it('compares the release part with dpkg semantics', () => {
    expect(compareAlpine('2.4.5-r0', '2.4.6-r0')).toBeLessThan(0);
    expect(compareAlpine('1.2.3-r1', '1.2.10-r0')).toBeLessThan(0); // 3 < 10 numerically
  });

  it('tie-breaks on the rN revision counter', () => {
    expect(compareAlpine('2.4.5-r1', '2.4.5-r2')).toBeLessThan(0);
    expect(compareAlpine('2.4.5-r10', '2.4.5-r9')).toBeGreaterThan(0); // numeric, not lex
  });

  it('treats a missing revision as r0', () => {
    expect(compareAlpine('2.4.5', '2.4.5-r1')).toBeLessThan(0);
  });
});

describe('compareSemverish', () => {
  it('compares numeric segments numerically and pads missing ones as zero', () => {
    expect(compareSemverish('1.2.3', '1.2.10')).toBeLessThan(0);
    expect(compareSemverish('1.2', '1.2.0')).toBe(0);
  });

  it('strips a leading v and ignores build metadata', () => {
    expect(compareSemverish('v1.2.3+build.5', '1.2.3')).toBe(0);
  });

  it('sorts prerelease before the corresponding release', () => {
    expect(compareSemverish('1.2.3-beta', '1.2.3')).toBeLessThan(0);
    expect(compareSemverish('1.2.3-alpha', '1.2.3-beta')).toBeLessThan(0);
  });

  it('compares numeric prerelease identifiers numerically', () => {
    expect(compareSemverish('1.0.0-rc.9', '1.0.0-rc.10')).toBeLessThan(0);
  });
});

describe('compareGeneric', () => {
  it('splits on dots/dashes/underscores and compares segment-wise', () => {
    expect(compareGeneric('2.4.5_1', '2.4.6')).toBeLessThan(0);
    expect(compareGeneric('1-2-3', '1-2-10')).toBeLessThan(0); // numeric segments
  });

  it('falls back to lexicographic for non-numeric segments', () => {
    expect(compareGeneric('abc', 'abd')).toBeLessThan(0);
  });
});

describe('versionComparatorFor', () => {
  it('routes ecosystem tags to the right comparator (case-insensitive)', () => {
    expect(versionComparatorFor('DEBIAN')).toBe(compareDpkg);
    expect(versionComparatorFor('ubuntu')).toBe(compareDpkg);
    expect(versionComparatorFor('ALPINE_LINUX')).toBe(compareAlpine);
    expect(versionComparatorFor('npm')).toBe(compareSemverish);
    expect(versionComparatorFor('pypi')).toBe(compareGeneric); // unmodeled → generic
    expect(versionComparatorFor(undefined)).toBe(compareGeneric);
  });
});

describe('matchesVersion', () => {
  it('flags versions below the fix bound (single < range)', () => {
    const ranges = [lt('1.2.3')];
    expect(matchesVersion(ranges, '1.2.2')).toBe(true);
    expect(matchesVersion(ranges, '1.2.3')).toBe(false); // fixed AT 1.2.3
    expect(matchesVersion(ranges, '1.3.0')).toBe(false);
  });

  it('flags versions inside an introduced..fixed window', () => {
    const ranges = [gt('1.0'), lt('2.5')];
    expect(matchesVersion(ranges, '1.0')).toBe(false); // '>' is exclusive
    expect(matchesVersion(ranges, '1.0.1')).toBe(true);
    expect(matchesVersion(ranges, '2.4.9')).toBe(true);
    expect(matchesVersion(ranges, '2.5')).toBe(false);
  });

  it('treats a trailing open bound as "up to infinity"', () => {
    const ranges = [gte('3.0')];
    expect(matchesVersion(ranges, '2.9.9')).toBe(false);
    expect(matchesVersion(ranges, '3.0')).toBe(true); // '>=' is inclusive
    expect(matchesVersion(ranges, '99.0')).toBe(true);
  });

  it('handles multiple disjoint windows (re-introduced vulnerabilities)', () => {
    const ranges = [gt('1.0'), lt('2.0'), gt('4.0'), lt('5.0')];
    expect(matchesVersion(ranges, '1.5')).toBe(true);
    expect(matchesVersion(ranges, '3.0')).toBe(false); // gap between windows
    expect(matchesVersion(ranges, '4.5')).toBe(true);
  });

  it('uses the ecosystem comparator for the comparison', () => {
    const ranges = [lt('1:2.0')]; // epoch in the bound
    expect(matchesVersion(ranges, '1.9', 'debian')).toBe(true); // epoch 0 < epoch 1
    expect(matchesVersion(ranges, '2:1.0', 'debian')).toBe(false); // epoch 2 > epoch 1
  });

  it('treats unversioned packages as affected (conservative)', () => {
    const ranges = [lt('1.0')];
    expect(matchesVersion(ranges, null)).toBe(true);
    expect(matchesVersion(ranges, '')).toBe(true);
    expect(matchesVersion(ranges, '   ')).toBe(true);
  });

  it('returns false when there are no usable ranges', () => {
    expect(matchesVersion([], '1.0')).toBe(false);
    expect(matchesVersion([{ type: '<', version: '' }], '1.0')).toBe(false);
  });

  it('matches real-world Debian advisory shapes end-to-end', () => {
    // e.g. CVE in openssl fixed at 3.0.2-0ubuntu1.9 on an Ubuntu host.
    const ranges = [lt('3.0.2-0ubuntu1.9')];
    expect(matchesVersion(ranges, '3.0.2-0ubuntu1.8', 'debian')).toBe(true);
    expect(matchesVersion(ranges, '3.0.2-0ubuntu1.9', 'debian')).toBe(false);
  });

  it('matches Alpine advisory shapes end-to-end', () => {
    const ranges = [lt('2.4.6-r0')];
    expect(matchesVersion(ranges, '2.4.5-r3', 'alpine')).toBe(true);
    expect(matchesVersion(ranges, '2.4.6-r1', 'alpine')).toBe(false);
  });
});
