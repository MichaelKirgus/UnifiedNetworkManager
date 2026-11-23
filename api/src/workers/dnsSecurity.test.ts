/**
 * Unit tests for workers/dnsSecurity.ts — the pure DNS heuristic helpers:
 * Shannon entropy, DGA label feature extraction + the three-gate decision,
 * the DGA base-domain whitelist + per-client volume gate, and
 * base-domain / subdomain-label decomposition and the tunnel verdict.
 */

// uuid v14 ships an ESM node entry that jest cannot require — the import chain
// (flowSecurity/threatIntel) only needs it for row ids, which these tests never touch.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import {
  baseDomainOf,
  dgaCandidateLabel,
  dgaVolumeDecision,
  isDgaBaseDomainWhitelisted,
  isDgaLike,
  parseBaseDomainWhitelist,
  shannonEntropy,
  tunnelLabelLen,
  tunnelVerdict,
} from './dnsSecurity';

/** Default detector thresholds (mirror the systemSettings defaults). */
const DGA_DEFAULTS = { minLabelLen: 12, minEntropy: 3.6, maxVowelRatio: 0.25 };

describe('shannonEntropy', () => {
  it('returns 0 for empty or single-character strings', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaa')).toBe(0);
  });

  it('computes the textbook values for uniform distributions', () => {
    expect(shannonEntropy('ab')).toBeCloseTo(1, 10); // log2(2)
    expect(shannonEntropy('abcd')).toBeCloseTo(2, 10); // log2(4)
  });

  it('sits between the uniform bounds for mixed strings', () => {
    const h = shannonEntropy('stackoverflow');
    expect(h).toBeGreaterThan(3.5);
    expect(h).toBeLessThan(Math.log2(13)); // < all-distinct upper bound
  });
});

describe('dgaCandidateLabel', () => {
  it('returns null for single-label names (no non-TLD label to evaluate)', () => {
    expect(dgaCandidateLabel('com')).toBeNull();
  });

  it('evaluates the SLD of a two-label domain', () => {
    const f = dgaCandidateLabel('example.com');
    expect(f).toMatchObject({ label: 'example', len: 7 });
    expect(f!.vowelRatio).toBeCloseTo(3 / 7, 10); // e,a,e
  });

  it('picks the LONGEST non-TLD label (subdomains are eligible too)', () => {
    const f = dgaCandidateLabel('acknowledgement.example.com');
    expect(f!.label).toBe('acknowledgement');
    expect(f!.len).toBe(15);
  });
});

describe('isDgaLike', () => {
  it('flags a random consonant-heavy label (all three gates pass)', () => {
    // 13 distinct consonants: entropy = log2(13) ≈ 3.70 ≥ 3.6, zero vowels
    const f = dgaCandidateLabel('xkqzvbnmrtwpl.net')!;
    expect(isDgaLike(f, DGA_DEFAULTS)).toBe(true);
  });

  it('does NOT flag a long human word (entropy + vowel gates)', () => {
    // 'stackoverflow': len 13 ≥ 12 — but entropy ≈ 3.55 < 3.6 AND vowel ratio
    // 4/13 ≈ 0.31 > 0.25 keep it out.
    const f = dgaCandidateLabel('stackoverflow.example.com')!;
    expect(isDgaLike(f, DGA_DEFAULTS)).toBe(false);
  });

  it('does NOT flag a verbose human subdomain (entropy + vowel gates)', () => {
    // 'acknowledgement': len 15 — entropy ≈ 3.46 < 3.6 and vowel ratio 5/15 ≈ 0.33 > 0.25
    const f = dgaCandidateLabel('acknowledgement.example.com')!;
    expect(isDgaLike(f, DGA_DEFAULTS)).toBe(false);
  });

  it('does NOT flag a short random label (length gate)', () => {
    // same character profile as the positive case but only 11 chars < 12
    const f = dgaCandidateLabel('xkqzvbnmrtw.net')!;
    expect(isDgaLike(f, DGA_DEFAULTS)).toBe(false);
  });

  it('honours relaxed thresholds (opt-in sensitivity)', () => {
    const f = dgaCandidateLabel('stackoverflow.example.com')!;
    // lowering the entropy gate to 3.5 AND raising the vowel gate to 35% lets
    // this human word through — that is what the settings are for, and users
    // accept the extra false positives knowingly.
    expect(isDgaLike(f, { ...DGA_DEFAULTS, minEntropy: 3.5, maxVowelRatio: 0.35 })).toBe(true);
  });
});

describe('baseDomainOf / tunnelLabelLen', () => {
  it('takes the last two labels as the (naive) registered domain', () => {
    expect(baseDomainOf('a.b.example.com')).toBe('example.com');
    expect(baseDomainOf('example.com')).toBe('example.com');
    expect(baseDomainOf('com')).toBeNull();
  });

  it('measures only labels LEFT of the base domain (the encodable part)', () => {
    expect(tunnelLabelLen('abc.tunnel.test')).toBe(3);
    expect(tunnelLabelLen('xy.zw.tunnel.test')).toBe(2); // max, not sum
    expect(tunnelLabelLen('tunnel.test')).toBeNull(); // no subdomain → nothing to encode in
  });
});

describe('tunnelVerdict', () => {
  const ts = Array.from({ length: 30 }, (_, i) => i * 60_000);

  it('fires when both the query count and average label length clear their gates', () => {
    // 30 queries, avg subdomain label 30 chars ≥ 24
    expect(tunnelVerdict({ ts, labelLenSum: 900 }, 30, 24)).toEqual({ queries: 30, avgLabelLen: 30 });
  });

  it('returns null below the minimum query count', () => {
    const short = ts.slice(0, 29);
    expect(tunnelVerdict({ ts: short, labelLenSum: 870 }, 30, 24)).toBeNull();
  });

  it('returns null when labels are too short (high volume ≠ tunneling)', () => {
    // 30 queries but avg label length 10 < 24 — e.g. normal CDN subdomains
    expect(tunnelVerdict({ ts, labelLenSum: 300 }, 30, 24)).toBeNull();
  });

  it('rounds the average label length to one decimal', () => {
    // 10 queries, sum 245 → avg 24.5 ≥ 24 (fires at threshold)
    const ts10 = Array.from({ length: 10 }, (_, i) => i * 60_000);
    expect(tunnelVerdict({ ts: ts10, labelLenSum: 245 }, 10, 24)).toEqual({ queries: 10, avgLabelLen: 24.5 });
  });
});

describe('parseBaseDomainWhitelist', () => {
  it('parses a comma-separated list and normalises case + whitespace', () => {
    const set = parseBaseDomainWhitelist('CloudApp.Azure.com, cloudfront.net');
    expect(set).toEqual(new Set(['cloudapp.azure.com', 'cloudfront.net']));
  });

  it('accepts mixed separators (commas, spaces, newlines) and drops empty entries', () => {
    const set = parseBaseDomainWhitelist('a.com\n b.org ,\t c.io ,,');
    expect(set).toEqual(new Set(['a.com', 'b.org', 'c.io']));
  });

  it('returns an empty set for empty / separator-only input', () => {
    expect(parseBaseDomainWhitelist('').size).toBe(0);
    expect(parseBaseDomainWhitelist(' , \n ').size).toBe(0);
  });
});

describe('isDgaBaseDomainWhitelisted', () => {
  const wl = parseBaseDomainWhitelist('cloudapp.azure.com, cloudfront.net');

  it('matches domains sitting UNDER an entry (suffix semantics)', () => {
    // OneDrive for Business: last-two-labels base is azure.com — the suffix match still covers it.
    expect(isDgaBaseDomainWhitelisted('onedsc12345.westus.cloudapp.azure.com', wl)).toBe(true);
    expect(isDgaBaseDomainWhitelisted('d2ly6zhewrzsqf.cloudfront.net', wl)).toBe(true);
  });

  it('matches the entry itself (case-insensitively)', () => {
    expect(isDgaBaseDomainWhitelisted('CLOUDFRONT.NET', wl)).toBe(true);
  });

  it('does NOT match sibling or lookalike zones', () => {
    expect(isDgaBaseDomainWhitelisted('evil.cloudapp.azure.com.evil.example.net', wl)).toBe(false); // suffix must be a full label boundary
    expect(isDgaBaseDomainWhitelisted('xcloudfront.net', wl)).toBe(false);
    expect(isDgaBaseDomainWhitelisted('onedsc12345.westus.onedrive.com', wl)).toBe(false);
  });

  it('never matches with an empty whitelist', () => {
    expect(isDgaBaseDomainWhitelisted('anything.example.com', new Set())).toBe(false);
  });
});

describe('dgaVolumeDecision', () => {
  it('reports nothing while the client is below the distinct-domain threshold', () => {
    // 3 distinct DGA-like domains < 10 — e.g. OneDrive endpoints from one host
    expect(dgaVolumeDecision(3, false, 10)).toEqual({ confirmClient: false, reportNewDomain: false });
  });

  it('confirms the client exactly at the threshold and reports everything tracked', () => {
    // 10th distinct domain crosses min=10 → confirm + report all (incl. this one)
    expect(dgaVolumeDecision(10, false, 10)).toEqual({ confirmClient: true, reportNewDomain: true });
  });

  it('reports new domains immediately once the client is confirmed', () => {
    // already confirmed → every further DGA-like domain fires without re-accumulating
    expect(dgaVolumeDecision(1, true, 10)).toEqual({ confirmClient: false, reportNewDomain: true });
  });

  it('min=1 restores the legacy behaviour (report on first sight)', () => {
    expect(dgaVolumeDecision(1, false, 1)).toEqual({ confirmClient: true, reportNewDomain: true });
  });
});
