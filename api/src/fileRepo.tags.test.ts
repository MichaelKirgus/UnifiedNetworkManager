/**
 * Unit tests for the flat repo-file tag helpers (fileRepo.ts). Tags are pure
 * metadata — never part of storage paths or blob keys — so they stay portable
 * across filesystem/S3/cloud file-repo backends. The DB-backed paths (list
 * filter, dedupe-union) are covered by scripts/e2e-log-rule-feeds.ts (live).
 */

// uuid v14 ships an ESM node entry that jest cannot require — fileRepo.ts only
// needs it for row ids, which these tests never assert on.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import { sanitizeTags } from './fileRepo';

describe('sanitizeTags', () => {
  it('slugifies to lowercase (same rules as categories)', () => {
    expect(sanitizeTags(['Log Rules', 'Threat Intel'])).toEqual(['log-rules', 'threat-intel']);
  });

  it('dedupes case-insensitively and preserves order (underscores are kept, like categories)', () => {
    expect(sanitizeTags(['log-rules', 'Log-Rules', 'LOG RULES', 'map'])).toEqual(['log-rules', 'map']);
    expect(sanitizeTags(['log_rules', 'log-rules'])).toEqual(['log_rules', 'log-rules']);
  });

  it('drops empty/whitespace-only entries', () => {
    expect(sanitizeTags(['', '   ', '!!!', 'geoip'])).toEqual(['geoip']);
  });

  it('caps at 10 tags and 64 chars each', () => {
    const many = Array.from({ length: 15 }, (_, i) => `tag-${i}`);
    expect(sanitizeTags(many)).toHaveLength(10);
    expect(sanitizeTags(['a'.repeat(200)])[0]).toHaveLength(64);
  });

  it('returns [] for null/undefined input', () => {
    expect(sanitizeTags(null)).toEqual([]);
    expect(sanitizeTags(undefined)).toEqual([]);
  });
});
