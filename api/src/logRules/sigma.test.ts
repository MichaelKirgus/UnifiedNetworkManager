/**
 * Unit tests for logRules/sigma.ts — the Sigma single-line subset parser.
 * Pins: matcher semantics (eq/contains/startswith/endswith/re, case-insensitive,
 * list = OR), selection AND / condition boolean grammar (and/or/not + parens),
 * field allow-list rejections with named errors, level mapping, logsource
 * scoping, the unm.threshold extension validation, multi-document handling and
 * the import batch semantics.
 */

import { BUILTIN_LOG_RULES } from './builtin';
import {
  CompiledLogRule,
  LogRuleParseError,
  compileSigmaObject,
  importAllSigmaRules,
  parseSigmaRule,
} from './sigma';

const ROW = (over: Partial<Record<string, string | null>> = {}) => ({
  message: '',
  appname: null as string | null,
  facility: null as string | null,
  hostname: 'host1',
  srcIp: null as string | null,
  dstIp: null as string | null,
  ...over,
});

/** Parses a YAML rule or fails the test. */
function rule(yamlText: string): CompiledLogRule {
  return parseSigmaRule(yamlText);
}

describe('sigma parser — matchers', () => {
  it('plain value = case-insensitive equality (whole-value, not substring)', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    message: 'Failed Password'\ncondition: s`);
    expect(r.evaluate(ROW({ message: 'failed password' }))).toBe(true); // case-insensitive eq
    expect(r.evaluate(ROW({ message: 'sshd[1]: Failed password for root' }))).toBe(false); // not equal → no match
  });

  it('a list of plain values is OR', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    appname: ['sshd', 'sudo']\ncondition: s`);
    expect(r.evaluate(ROW({ appname: 'SSHD' }))).toBe(true);
    expect(r.evaluate(ROW({ appname: 'sudo' }))).toBe(true);
    expect(r.evaluate(ROW({ appname: 'cron' }))).toBe(false);
  });

  it('contains is a case-insensitive substring', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    message:\n      contains: 'NOT in sudoers'\ncondition: s`);
    expect(r.evaluate(ROW({ message: 'sudo: bob : user bob NOT in sudoers ; TTY=pts/0' }))).toBe(true);
    expect(r.evaluate(ROW({ message: 'sudo: bob : COMMAND=/bin/ls' }))).toBe(false);
  });

  it('startswith / endswith', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    message:\n      startswith: 'useradd'\ncondition: s`);
    expect(r.evaluate(ROW({ message: 'useradd[42]: new user foo' }))).toBe(true);
    expect(r.evaluate(ROW({ message: 'pam_unix(useradd:session)' }))).toBe(false);

    const r2 = rule(`title: t\ndetection:\n  s:\n    message:\n      endswith: '.log'\ncondition: s`);
    expect(r2.evaluate(ROW({ message: '/var/log/auth.log' }))).toBe(true);
    expect(r2.evaluate(ROW({ message: 'auth.log.bak' }))).toBe(false);
  });

  it('re is an unanchored regex; invalid patterns are rejected with the pattern named', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    message:\n      re: '(?i)union\\s+select'\ncondition: s`);
    expect(r.evaluate(ROW({ message: 'GET /x?q=1 UNION SELECT * FROM users' }))).toBe(true);
    expect(r.evaluate(ROW({ message: 'plain request' }))).toBe(false);

    expect(() => rule(`title: t\ndetection:\n  s:\n    message:\n      re: '(unclosed'\ncondition: s`)).toThrow(LogRuleParseError);
  });

  it('multiple keys in one selection are AND', () => {
    const r = rule(
      `title: t\nlogsource:\n  service: sshd\ndetection:\n  s:\n    appname: 'sshd'\n    message:\n      contains: 'Failed password'\ncondition: s`
    );
    expect(r.evaluate(ROW({ appname: 'sshd', message: 'Failed password for root' }))).toBe(true);
    // Right message, wrong appname → the AND fails.
    expect(r.evaluate(ROW({ appname: 'cron', message: 'Failed password for root' }))).toBe(false);
  });

  it('absent (NULL) fields never match a matcher on them', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    srcIp: '10.0.0.5'\ncondition: s`);
    expect(r.evaluate(ROW({ message: 'x' }))).toBe(false); // srcIp null
    expect(r.evaluate(ROW({ srcIp: '10.0.0.5', message: 'x' }))).toBe(true);
  });

  it('numeric values are stringified for comparison', () => {
    const r = rule(`title: t\ndetection:\n  s:\n    message: 401\ncondition: s`);
    expect(r.evaluate(ROW({ message: 'GET /admin HTTP/1.1" 401 512' }))).toBe(false); // eq is whole-value
    const r2 = rule(`title: t\ndetection:\n  s:\n    message:\n      contains: 401\ncondition: s`);
    expect(r2.evaluate(ROW({ message: 'GET /admin HTTP/1.1" 401 512' }))).toBe(true);
  });
});

describe('sigma parser — condition grammar', () => {
  it('and / or with correct precedence (and binds tighter)', () => {
    const r = rule(
      `title: t\ndetection:\n  a:\n    message: 'alpha'\n  b:\n    appname: 'x'\n  c:\n    facility: 'auth'\ncondition: a or b and c`
    );
    // (a) OR (b AND c) — not (a OR b) AND c.
    expect(r.evaluate(ROW({ message: 'alpha' }))).toBe(true); // a alone suffices
    expect(r.evaluate(ROW({ appname: 'x', facility: 'auth' }))).toBe(true); // b and c
    expect(r.evaluate(ROW({ appname: 'x' }))).toBe(false); // b without c, no a
  });

  it('not negates; parentheses group explicitly', () => {
    const r = rule(
      `title: t\ndetection:\n  fail:\n    message:\n      contains: 'Failed password'\n  root:\n    message:\n      contains: 'for root from'\ncondition: fail and not (root)`
    );
    expect(r.evaluate(ROW({ message: 'Failed password for alice from 10.0.0.9' }))).toBe(true);
    expect(r.evaluate(ROW({ message: 'Failed password for root from 10.0.0.9' }))).toBe(false);
  });

  it('rejects unknown selections naming the known ones', () => {
    try {
      rule(`title: t\ndetection:\n  a:\n    message: 'x'\ncondition: a and b`);
      fail('expected LogRuleParseError');
    } catch (err) {
      expect(err).toBeInstanceOf(LogRuleParseError);
      expect((err as LogRuleParseError).issues.join()).toContain('"b" is not defined in detection');
    }
  });

  it('rejects unbalanced parentheses and dangling operators', () => {
    expect(() => rule(`title: t\ndetection:\n  a:\n    message: 'x'\ncondition: (a`)).toThrow(LogRuleParseError);
    expect(() => rule(`title: t\ndetection:\n  a:\n    message: 'x'\ncondition: a and`)).toThrow(LogRuleParseError);
  });
});

describe('sigma parser — field allow-list & rejections', () => {
  it('rejects fields UNM does not ingest, naming the supported set', () => {
    try {
      rule(`title: t\ndetection:\n  s:\n    winlog.eventid: 4625\ncondition: s`);
      fail('expected LogRuleParseError');
    } catch (err) {
      expect(err).toBeInstanceOf(LogRuleParseError);
      const issues = (err as LogRuleParseError).issues.join();
      expect(issues).toContain('field "winlog.eventid"');
      expect(issues).toContain('message, appname, facility, hostname, srcIp, dstIp');
    }
  });

  it('rejects unsupported modifiers', () => {
    expect(() => rule(`title: t\ndetection:\n  s:\n    message:\n      re_all: 'x'\ncondition: s`)).toThrow(/unsupported modifier "re_all"/);
  });

  it('rejects aggregation-style detection blocks', () => {
    // count() by … arrives as a non-mapping value → rejected.
    expect(() => rule(`title: t\ndetection:\n  s:\n    message: 'x'\ncondition: count(s) > 5`)).toThrow(LogRuleParseError);
  });

  it('requires title, detection and condition', () => {
    expect(() => parseSigmaRule(`detection:\n  s:\n    message: 'x'\ncondition: s`)).toThrow(/"title"/);
    expect(() => parseSigmaRule(`title: t\ncondition: s`)).toThrow(/"detection"/);
    expect(() => parseSigmaRule(`title: t\ndetection:\n  s:\n    message: 'x'`)).toThrow(/"condition"/);
  });

  it('rejects empty selections and unknown level values', () => {
    expect(() => rule(`title: t\ndetection:\n  s: {}\ncondition: s`)).toThrow(/selection "s" is empty/);
    expect(() => rule(`title: t\nlevel: urgent\ndetection:\n  s:\n    message: 'x'\ncondition: s`)).toThrow(/"level"/);
  });

  it('rejects multi-document input on the single-rule entry point', () => {
    expect(() => parseSigmaRule(`title: a\ndetection:\n  s:\n    message: '1'\ncondition: s\n---\ntitle: b\ndetection:\n  s:\n    message: '2'\ncondition: s`)).toThrow(/multi-document/);
  });

  it('rejects invalid YAML with the parser message', () => {
    expect(() => parseSigmaRule(`title: [unclosed`)).toThrow(LogRuleParseError);
  });
});

describe('sigma parser — metadata, scoping & threshold', () => {
  it('maps levels low/medium/high/critical → info/warning/critical; default warning', () => {
    expect(rule(`title: t\nlevel: low\ndetection:\n  s:\n    message: 'x'\ncondition: s`).level).toBe('info');
    expect(rule(`title: t\nlevel: medium\ndetection:\n  s:\n    message: 'x'\ncondition: s`).level).toBe('warning');
    expect(rule(`title: t\nlevel: high\ndetection:\n  s:\n    message: 'x'\ncondition: s`).level).toBe('critical');
    expect(rule(`title: t\nlevel: critical\ndetection:\n  s:\n    message: 'x'\ncondition: s`).level).toBe('critical');
    expect(rule(`title: t\ndetection:\n  s:\n    message: 'x'\ncondition: s`).level).toBe('warning');
  });

  it('carries tags, references, id and description through', () => {
    const r = rule(
      `title: t\nid: abc-123\ndescription: a test rule\nreferences: ['https://example.com']\ntags: ['att&ck.t1110']\nlevel: high\ndetection:\n  s:\n    message: 'x'\ncondition: s`
    );
    expect(r.sigmaId).toBe('abc-123');
    expect(r.description).toBe('a test rule');
    expect(r.references).toEqual(['https://example.com']);
    expect(r.tags).toEqual(['att&ck.t1110']);
  });

  it('logsource.service scopes by appname (case-insensitive); product is the fallback', () => {
    const r = rule(
      `title: t\nlogsource:\n  service: sshd\ndetection:\n  s:\n    message: 'Failed password'\ncondition: s`
    );
    expect(r.scopeAppname).toBe('sshd');
    expect(r.evaluate(ROW({ appname: 'SSHD', message: 'Failed password' }))).toBe(true);
    expect(r.evaluate(ROW({ appname: 'cron', message: 'Failed password' }))).toBe(false);
    expect(r.evaluate(ROW({ message: 'Failed password' }))).toBe(false); // NULL appname

    const r2 = rule(`title: t\nlogsource:\n  product: linux\ndetection:\n  s:\n    message: 'x'\ncondition: s`);
    expect(r2.scopeAppname).toBe('linux');
  });

  it('parses the unm.threshold extension and validates its fields', () => {
    const r = rule(
      `title: t\ndetection:\n  s:\n    message: 'Failed password'\ncondition: s\nunm.threshold:\n  count: 5\n  withinMinutes: 5\n  groupBy: srcIp`
    );
    expect(r.threshold).toEqual({ count: 5, withinMs: 300_000, groupBy: 'srcIp' });

    expect(() => rule(`title: t\ndetection:\n  s:\n    message: 'x'\ncondition: s\nunm.threshold:\n  count: 1\n  withinMinutes: 5\n  groupBy: srcIp`)).toThrow(/count/);
    expect(() => rule(`title: t\ndetection:\n  s:\n    message: 'x'\ncondition: s\nunm.threshold:\n  count: 5\n  withinMinutes: 0\n  groupBy: srcIp`)).toThrow(/withinMinutes/);
    expect(() => rule(`title: t\ndetection:\n  s:\n    message: 'x'\ncondition: s\nunm.threshold:\n  count: 5\n  withinMinutes: 5\n  groupBy: ip`)).toThrow(/groupBy/);
    expect(() => rule(`title: t\ndetection:\n  s:\n    message: 'x'\ncondition: s\nunm:\n  other: 1`)).toThrow(/top-level "unm\.threshold"/);
  });

  it('the name option overrides the title', () => {
    const r = compileSigmaObject({ title: 'Original Title', detection: { s: { message: 'x' } }, condition: 's' }, { name: 'My Name' });
    expect(r.name).toBe('My Name');
  });
});

describe('sigma parser — import batch', () => {
  it('parses all documents; per-doc errors never abort the batch', () => {
    const text = [
      `title: good one\ndetection:\n  s:\n    message: 'ok'\ncondition: s`,
      `title: bad field\ndetection:\n  s:\n    winlog.x: 1\ncondition: s`, // unsupported field
      `title: second good\ntags: ['att&ck.t1078']\ndetection:\n  s:\n    message: 'fine'\ncondition: s`,
    ].join('\n---\n');
    const out = importAllSigmaRules(text);
    expect(out).toHaveLength(3);
    expect(!!out[0].rule).toBe(true);
    expect(out[0].name).toBe('good one');
    expect(out[0].yaml).toContain('good one'); // raw document carried for storage
    expect(out[1].rule).toBeUndefined();
    expect(out[1].error).toMatch(/field "winlog\.x"/);
    expect(out[2].name).toBe('second good');
  });

  it('returns nothing for empty input', () => {
    expect(importAllSigmaRules('   \n  ')).toHaveLength(0);
  });
});

describe('built-in rule pack (builtin.ts)', () => {
  const byName = (name: string): CompiledLogRule => {
    const b = BUILTIN_LOG_RULES.find((x) => x.name === name);
    expect(b).toBeDefined();
    // Same call the worker makes — stored DB name wins over the YAML title.
    return parseSigmaRule(String(b!.yaml), { name });
  };

  it('every builtin parses and compiles (guards String.raw escaping + (?i) stripping)', () => {
    expect(BUILTIN_LOG_RULES.length).toBeGreaterThanOrEqual(15);
    for (const b of BUILTIN_LOG_RULES) {
      const r = parseSigmaRule(b.yaml, { name: b.name }); // throws LogRuleParseError on failure
      expect(r.name).toBe(b.name);
    }
  });

  it('thresholded builtins carry their thresholds', () => {
    expect(byName('ssh-brute-force').threshold).toEqual({ count: 5, withinMs: 300_000, groupBy: 'srcIp' });
    expect(byName('web-auth-failure-burst').threshold).toEqual({ count: 20, withinMs: 600_000, groupBy: 'srcIp' });
    expect(byName('ssh-root-login-success').threshold).toBeNull(); // per-line rule
  });

  it('builtins match realistic log lines', () => {
    expect(byName('ssh-brute-force').evaluate(ROW({ message: 'sshd[123]: Failed password for root from 10.0.0.9 port 51234 ssh2', srcIp: '10.0.0.9' }))).toBe(true);
    expect(byName('ssh-invalid-user-burst').evaluate(ROW({ message: 'sshd[124]: Invalid user admin from 10.0.0.9 port 51235', srcIp: '10.0.0.9' }))).toBe(true);
    expect(byName('sudo-command-executed').evaluate(ROW({ message: 'sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls' }))).toBe(true);
    expect(byName('sudoers-violation').evaluate(ROW({ message: 'sudo: eve : user eve NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/id' }))).toBe(true);
    expect(byName('new-user-account').evaluate(ROW({ message: 'useradd[42]: new user name=foo UID=1001 GID=1001 home=/home/foo shell=/bin/bash' }))).toBe(true);
    expect(byName('ssh-root-login-success').evaluate(ROW({ message: 'sshd[99]: Accepted publickey for root from 10.0.0.7 port 51236 ssh2', srcIp: '10.0.0.7' }))).toBe(true);
    expect(byName('sql-injection-attempt').evaluate(ROW({ message: 'GET /products?id=1 UNION SELECT * FROM users HTTP/1.1' }))).toBe(true);
    expect(byName('xss-attempt').evaluate(ROW({ message: 'POST /comment body=<script>alert(1)</script>' }))).toBe(true);
    // Negative control — an ordinary auth line matches none of the above.
    const benign = ROW({ message: 'CRON[7]: pam_unix(cron:session): session opened for user root', srcIp: null });
    expect(byName('ssh-brute-force').evaluate(benign)).toBe(false);
    expect(byName('sudo-command-executed').evaluate(benign)).toBe(false);
  });
});
