/**
 * Unit tests for the pure helpers of the Sigma rule feed engine (Phase 2):
 * GitHub repo-reference normalization and file-repo snapshot naming. The sync
 * orchestration itself is covered by scripts/e2e-log-rule-feeds.ts (live).
 */

// uuid v14 ships an ESM node entry that jest cannot require — feeds.ts only
// needs it for row ids, which these tests never assert on.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import { logRuleFeedFileName, normalizeGithubRepo } from './feeds';

describe('normalizeGithubRepo', () => {
  it('accepts a plain github.com repo URL', () => {
    expect(normalizeGithubRepo('https://github.com/SigmaHQ/sigma')).toEqual({ owner: 'SigmaHQ', repo: 'sigma' });
  });

  it('accepts www. and .git variants', () => {
    expect(normalizeGithubRepo('https://www.github.com/SigmaHQ/sigma.git')).toEqual({ owner: 'SigmaHQ', repo: 'sigma' });
  });

  it('accepts a bare owner/repo without scheme', () => {
    expect(normalizeGithubRepo('SigmaHQ/sigma')).toEqual({ owner: 'SigmaHQ', repo: 'sigma' });
  });

  it('extracts pathPrefix from a /tree/<branch>/<dir> folder URL', () => {
    expect(normalizeGithubRepo('https://github.com/SigmaHQ/sigma/tree/main/rules/linux')).toEqual({
      owner: 'SigmaHQ',
      repo: 'sigma',
      pathPrefix: 'rules/linux',
    });
  });

  it('extracts the parent directory from a /blob/<branch>/<path>/file.yml URL', () => {
    expect(normalizeGithubRepo('https://github.com/SigmaHQ/sigma/blob/main/rules/linux/ssh.yml')).toEqual({
      owner: 'SigmaHQ',
      repo: 'sigma',
      pathPrefix: 'rules/linux',
    });
  });

  it('a blob URL at the repo root yields no pathPrefix', () => {
    expect(normalizeGithubRepo('https://github.com/SigmaHQ/sigma/blob/main/rules.yml')).toEqual({
      owner: 'SigmaHQ',
      repo: 'sigma',
    });
  });

  it('accepts raw.githubusercontent.com URLs (owner/repo are the first path segments)', () => {
    expect(normalizeGithubRepo('https://raw.githubusercontent.com/SigmaHQ/sigma/main/rules/linux/ssh.yml')).toEqual({
      owner: 'SigmaHQ',
      repo: 'sigma',
      pathPrefix: 'rules/linux',
    });
  });

  it('rejects non-GitHub hosts even when the shape looks like owner/repo', () => {
    expect(normalizeGithubRepo('https://example.com/foo/bar')).toBeNull();
    expect(normalizeGithubRepo('https://gitlab.com/foo/bar')).toBeNull();
  });

  it('rejects org-level and malformed inputs', () => {
    expect(normalizeGithubRepo('https://github.com/SigmaHQ')).toBeNull();
    expect(normalizeGithubRepo('SigmaHQ')).toBeNull();
    expect(normalizeGithubRepo('')).toBeNull();
    expect(normalizeGithubRepo('not a url at all with spaces')).toBeNull();
  });

  it('strips query/fragment noise', () => {
    expect(normalizeGithubRepo('https://github.com/SigmaHQ/sigma?tab=readme#readme')).toEqual({ owner: 'SigmaHQ', repo: 'sigma' });
  });
});

describe('logRuleFeedFileName', () => {
  it('sanitizes the feed name and date-suffixes a .yml file', () => {
    const name = logRuleFeedFileName('My Feed!');
    expect(name).toMatch(/^log-rule-feed-My-Feed-\d{4}-\d{2}-\d{2}\.yml$/);
  });

  it('falls back to "feed" for names that sanitize to empty', () => {
    const name = logRuleFeedFileName('!!!');
    expect(name).toMatch(/^log-rule-feed-feed-\d{4}-\d{2}-\d{2}\.yml$/);
  });

  it('caps the base at 80 chars', () => {
    const name = logRuleFeedFileName('x'.repeat(500));
    expect(name).toMatch(/^log-rule-feed-x{80}-\d{4}-\d{2}-\d{2}\.yml$/);
  });
});
