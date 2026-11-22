/**
 * Unit tests for fileTail's PURE logic — no SSH, no network. The host script
 * itself is covered by the E2E (scripts/e2e-file-tail.ts) against a real shell.
 */

import {
  parseLogSources,
  decideFileTailActions,
  decodeBase64Block,
  buildFileTailReadScript,
  parseFileTailOutput,
  parseHostZuluOffset,
  parseLogLineTimestampMs,
  detectLogLevel,
  fileTailVendorEventId,
  buildFileTailRows,
  logSourcePatternToRegex,
  matchLogSource,
  FILE_TAIL_MARKER_OFFSET,
  type FileTailCursor,
} from './fileTail';

// ---------------------------------------------------------------------------
// parseLogSources — line grammar `<pattern> [label] [level]`
// ---------------------------------------------------------------------------

describe('parseLogSources', () => {
  it('parses pattern-only lines', () => {
    const out = parseLogSources('/var/log/nginx/*.log');
    expect(out).toEqual([{ pattern: '/var/log/nginx/*.log' }]);
  });

  it('parses pattern + label + level', () => {
    const out = parseLogSources('/opt/app/logs/archive/*.out app-x\n/var/log/auth.log auth error');
    expect(out).toEqual([
      { pattern: '/opt/app/logs/archive/*.out', label: 'app-x' },
      { pattern: '/var/log/auth.log', label: 'auth', level: 'error' },
    ]);
  });

  it('skips comments, blank lines and malformed entries', () => {
    const out = parseLogSources('# comment\n\n/var/log/x.log\nrelative/path.log\n/a b bogus-level\n');
    expect(out).toEqual([{ pattern: '/var/log/x.log' }]);
  });

  it('keeps the first of duplicate patterns', () => {
    const out = parseLogSources('/a/b.log one\n/a/b.log two');
    expect(out).toHaveLength(1);
    expect(out[0].label).toBe('one');
  });

  it('returns [] for empty/absent input', () => {
    expect(parseLogSources('')).toEqual([]);
    expect(parseLogSources(null)).toEqual([]);
    expect(parseLogSources(undefined)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// decideFileTailActions — the rotation decision table
// ---------------------------------------------------------------------------

describe('decideFileTailActions', () => {
  const cur = (inode: string | null, offset: number): FileTailCursor => ({ inode, offset });

  it('baselines unseen paths', () => {
    const d = decideFileTailActions(new Map(), [{ path: '/a', size: 100, inode: '1' }], 200);
    expect(d.plans).toEqual([{ kind: 'baseline', path: '/a', lines: 200 }]);
    expect(d.droppedPaths).toEqual([]);
  });

  it('reads [offset,size) when the same inode grew', () => {
    const d = decideFileTailActions(new Map([['/a', cur('1', 50)]]), [{ path: '/a', size: 80, inode: '1' }], 200);
    expect(d.plans).toEqual([{ kind: 'read', path: '/a', from: 50, to: 80 }]);
  });

  it('skips quiet files (size == offset)', () => {
    const d = decideFileTailActions(new Map([['/a', cur('1', 80)]]), [{ path: '/a', size: 80, inode: '1' }], 200);
    expect(d.plans).toEqual([{ kind: 'skip', path: '/a' }]);
  });

  it('resets to [0,size) on truncate (same inode shrank)', () => {
    const d = decideFileTailActions(new Map([['/a', cur('1', 50)]]), [{ path: '/a', size: 30, inode: '1' }], 200);
    expect(d.plans).toEqual([{ kind: 'read', path: '/a', from: 0, to: 30 }]);
  });

  it('baselines on rotation (different inode)', () => {
    const d = decideFileTailActions(new Map([['/a', cur('1', 50)]]), [{ path: '/a', size: 12, inode: '2' }], 42);
    expect(d.plans).toEqual([{ kind: 'baseline', path: '/a', lines: 42 }]);
  });

  it('uses size-only identity when inodes are unknown (grow reads, shrink re-baselines)', () => {
    const grow = decideFileTailActions(new Map([['/a', cur(null, 10)]]), [{ path: '/a', size: 20, inode: null }], 5);
    expect(grow.plans).toEqual([{ kind: 'read', path: '/a', from: 10, to: 20 }]);

    const shrink = decideFileTailActions(new Map([['/a', cur(null, 10)]]), [{ path: '/a', size: 4, inode: null }], 5);
    expect(shrink.plans).toEqual([{ kind: 'baseline', path: '/a', lines: 5 }]);
  });

  it('drops cursors for paths that vanished', () => {
    const d = decideFileTailActions(
      new Map([['/gone', cur('1', 0)], ['/here', cur('2', 0)]]),
      [{ path: '/here', size: 5, inode: '2' }],
      10,
    );
    expect(d.droppedPaths).toEqual(['/gone']);
  });

  it('ignores malformed stats (negative/NaN sizes)', () => {
    const d = decideFileTailActions(new Map(), [{ path: '/a', size: -5, inode: '1' }, { path: '', size: 3, inode: null }], 10);
    expect(d.plans).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Section codec — base64 blocks + sectioned output parser
// ---------------------------------------------------------------------------

describe('decodeBase64Block', () => {
  it('decodes wrapped lines back to the original bytes', () => {
    const b64 = Buffer.from('hello world\nsecond line').toString('base64');
    const wrapped = `${b64.slice(0, 13)}\n${b64.slice(13)}`;
    expect(decodeBase64Block(wrapped).toString()).toBe('hello world\nsecond line');
  });

  it('tolerates arbitrary whitespace', () => {
    expect(decodeBase64Block('aGVs bG8=\n').toString()).toBe('hello');
  });
});

describe('parseFileTailOutput', () => {
  const data = Buffer.from('payload-bytes');
  const b64 = data.toString('base64'); // 'cGF5bG9hZC1ieXRlcw==' (short — one line)

  it('parses offset, stats (paths with spaces) and base64 sections', () => {
    const stdout = [
      `${FILE_TAIL_MARKER_OFFSET} +0130`,
      '__STAT__ /var/log/app/my app.log 1234 5678',
      '__STAT__ /var/log/quiet.log 0 -',
      '__FILE__ /var/log/app/my app.log 100',
      '__DATA_BEGIN__',
      b64,
      '__DATA_END__',
      'some shell noise line',
    ].join('\n');

    const p = parseFileTailOutput(stdout);
    expect(p.offsetMinutes).toBe(90); // +0130 → 1h30 east of UTC
    expect(p.stats.get('/var/log/app/my app.log')).toEqual({ path: '/var/log/app/my app.log', size: 1234, inode: '5678' });
    expect(p.stats.get('/var/log/quiet.log')?.inode).toBeNull(); // '-' → null

    const sec = p.sections.get('/var/log/app/my app.log');
    expect(sec?.startOffset).toBe(100);
    expect(sec?.data.toString()).toBe('payload-bytes');
  });

  it('decodes multi-line (wrapped) base64 blocks', () => {
    const big = Buffer.alloc(250, 0x41); // 'AAA…' — wraps over several lines at 100 cols
    const wrapped = big.toString('base64').match(/.{1,76}/g)?.join('\n') ?? '';
    const stdout = [
      `${FILE_TAIL_MARKER_OFFSET} +0000`,
      '__STAT__ /big 250 9',
      '__FILE__ /big 0',
      '__DATA_BEGIN__',
      wrapped,
      '__DATA_END__',
    ].join('\n');
    const p = parseFileTailOutput(stdout);
    expect(p.sections.get('/big')?.data).toEqual(big);
  });

  it('returns empty structures for empty output', () => {
    const p = parseFileTailOutput('');
    expect(p.offsetMinutes).toBe(0);
    expect(p.stats.size).toBe(0);
    expect(p.sections.size).toBe(0);
  });
});

describe('parseHostZuluOffset', () => {
  it('parses ±hhmm (and ±hh:mm) into minutes east of UTC', () => {
    expect(parseHostZuluOffset('+0100')).toBe(60);
    expect(parseHostZuluOffset('-0530')).toBe(-330);
    expect(parseHostZuluOffset('+02:00')).toBe(120);
    expect(parseHostZuluOffset('garbage')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// buildFileTailReadScript — smoke checks on the generated POSIX sh
// ---------------------------------------------------------------------------

describe('buildFileTailReadScript', () => {
  it('embeds shell-quoted patterns and cursor lines, and uses only POSIX constructs', () => {
    const script = buildFileTailReadScript(
      [{ pattern: "/var/log/it's.log", label: 'x' }, { pattern: '/opt/app/**/*.out' }],
      new Map([['/var/log/it\'s.log', { inode: '77', offset: 1234 }]]),
    );

    expect(script).toContain("'/var/log/it'\\''s.log'"); // shQuote escaping (' → '\'' )
    expect(script).toContain('/opt/app/**/*.out');
    expect(script).toContain("/var/log/it's.log\t77\t1234"); // cursor heredoc line
    expect(script).toContain('UNM_CURSORS_EOF');
    expect(script).toContain('__OFFSET__');
    expect(script).not.toContain('[[ '); // no bashisms — runs via the remote login shell (sh)
  });

  it('emits an empty cursor heredoc when there are no cursors', () => {
    const script = buildFileTailReadScript([{ pattern: '/a.log' }], new Map());
    expect(script).toMatch(/<<'UNM_CURSORS_EOF'\nUNM_CURSORS_EOF/);
  });

  it('skips compressed archives and binary files on the host (rotated .gz / wtmp under broad patterns)', () => {
    const script = buildFileTailReadScript([{ pattern: '/var/log/*' }], new Map());
    expect(script).toContain('*.gz|*.gzip|*.xz|*.bz2|*.zst|*.zip|*.lz4) continue'); // rotated archives never tailed
    expect(script).toContain("tr -d '\\000'"); // NUL-byte binary guard (wtmp/btmp/lastlog)
  });
});

// ---------------------------------------------------------------------------
// Line heuristics — timestamps + levels
// ---------------------------------------------------------------------------

describe('parseLogLineTimestampMs', () => {
  const FB = Date.UTC(2027, 0, 5, 12, 0, 0); // read time: Jan 5 2027 (for rollover tests)

  it('parses ISO 8601 with explicit Z', () => {
    expect(parseLogLineTimestampMs('2026-11-22T17:10:04Z msg', 0, FB)).toBe(Date.parse('2026-11-22T17:10:04Z'));
  });

  it('parses ISO 8601 with explicit ±hh:mm zone', () => {
    expect(parseLogLineTimestampMs('2026-11-22T17:10:04+02:00 msg', 99, FB))
      .toBe(Date.parse('2026-11-22T17:10:04+02:00'));
  });

  it('treats zone-less ISO as host-local (offset applied)', () => {
    const expected = Date.UTC(2026, 10, 22, 17, 10, 4) - 60 * 60_000; // +0100 host
    expect(parseLogLineTimestampMs('2026-11-22 17:10:04 msg', 60, FB)).toBe(expected);
  });

  it('parses nginx timestamps with zone', () => {
    const expected = Date.parse('2026-11-22T17:10:04+01:00');
    expect(parseLogLineTimestampMs('[22/Nov/2026:17:10:04 +0100] GET / HTTP/1.1', 0, FB)).toBe(expected);
  });

  it('parses BSD syslog with the read-time year and Dec→Jan rollover guard', () => {
    // Nov line read in Jan → must land in the PREVIOUS year.
    const expected = Date.UTC(2026, 10, 22, 17, 10, 4) - 30 * 60_000; // +0030 host
    expect(parseLogLineTimestampMs('Nov 22 17:10:04 host sshd[1]: msg', 30, FB)).toBe(expected);

    // A Jan line read in Jan → current year.
    const expectedJan = Date.UTC(2027, 0, 2, 8, 0, 0);
    expect(parseLogLineTimestampMs('Jan  2 08:00:00 host cron[1]: msg', 0, FB)).toBe(expectedJan);
  });

  it('falls back to the read time when no timestamp is recognizable', () => {
    expect(parseLogLineTimestampMs('just some text without a date', 60, FB)).toBe(FB);
  });
});

describe('detectLogLevel', () => {
  it('maps error-ish words to error (highest precedence)', () => {
    expect(detectLogLevel('[error] boom')).toBe('error');
    expect(detectLogLevel('Nov 22 CRIT kernel: oops')).toBe('error');
    expect(detectLogLevel('FATAL: out of memory')).toBe('error');
  });

  it('maps warn-ish words to warn, debug/trace to debug', () => {
    expect(detectLogLevel('warning: disk almost full')).toBe('warn');
    expect(detectLogLevel('[warn] retrying')).toBe('warn');
    expect(detectLogLevel('debug: entering loop')).toBe('debug');
  });

  it('defaults to info and lets the source override win', () => {
    expect(detectLogLevel('all good here')).toBe('info');
    expect(detectLogLevel('[error] boom', 'warn')).toBe('warn');
  });
});

// ---------------------------------------------------------------------------
// Dedupe identity
// ---------------------------------------------------------------------------

describe('fileTailVendorEventId', () => {
  it('is a stable 40-char hex sha1 that changes with every input part', () => {
    const id = fileTailVendorEventId('h', '/p', '7', 123, 'some line');
    expect(id).toMatch(/^[0-9a-f]{40}$/);
    expect(fileTailVendorEventId('h', '/p', '7', 123, 'some line')).toBe(id); // stable (re-push dedupe)
    expect(fileTailVendorEventId('h2', '/p', '7', 123, 'some line')).not.toBe(id);
    expect(fileTailVendorEventId('h', '/q', '7', 123, 'some line')).not.toBe(id);
    expect(fileTailVendorEventId('h', '/p', '8', 123, 'some line')).not.toBe(id); // rotation → new identity
    expect(fileTailVendorEventId('h', '/p', '7', 124, 'some line')).not.toBe(id);
  });

  it('does NOT collide when a truncate reuses an offset under the same inode (live regression)', () => {
    // Pre-truncate: "rot-a\n" at offset 0 of inode 7. Post-truncate: "t1\n" at
    // offset 0 of the SAME inode — different content must yield a different id,
    // otherwise the API dedupe silently drops the new line.
    const before = fileTailVendorEventId('h', '/p.log', '7', 0, 'rot-a');
    const after = fileTailVendorEventId('h', '/p.log', '7', 0, 't1');
    expect(after).not.toBe(before);
  });
});

// ---------------------------------------------------------------------------
// buildFileTailRows — section → rows with exact byte offsets
// ---------------------------------------------------------------------------

describe('buildFileTailRows', () => {
  const base = {
    host: 'h',
    path: '/p.log',
    identity: '7',
    appname: 'app',
    offsetMinutes: 0,
    readTimeMs: Date.UTC(2026, 10, 22, 12, 0, 0), // fixed → zone-less lines are deterministic
  };

  it('splits complete lines with exact absolute offsets', () => {
    const r = buildFileTailRows({ ...base, startOffset: 100, data: Buffer.from('a\nb\nc\n') });
    expect(r.consumedBytes).toBe(6);
    expect(r.rows.map((x) => x.message)).toEqual(['a', 'b', 'c']);
    r.rows.forEach((row, i) => {
      expect(row.vendorEventId).toBe(fileTailVendorEventId('h', '/p.log', '7', 100 + (i * 2), row.message));
      expect(row.hostname).toBe('h');
      expect(row.appname).toBe('app');
    });
  });

  it('holds back an incomplete trailing line (cursor stops before it)', () => {
    const r = buildFileTailRows({ ...base, startOffset: 0, data: Buffer.from('a\nb') });
    expect(r.rows.map((x) => x.message)).toEqual(['a']); // 'b' is still being written
    expect(r.consumedBytes).toBe(2); // next beat re-reads from byte 2
  });

  it('treats a >64KB "line" as complete (buffered writers)', () => {
    const blob = Buffer.alloc(70_000, 0x61); // no newlines at all
    const r = buildFileTailRows({ ...base, startOffset: 0, data: blob });
    expect(r.rows).toHaveLength(1);
    expect(r.consumedBytes).toBe(70_000);
  });

  it('keeps only the last N lines for baseline reads (offsets stay exact)', () => {
    const r = buildFileTailRows({ ...base, startOffset: 50, data: Buffer.from('a\nb\nc\n'), maxLines: 2 });
    expect(r.rows.map((x) => x.message)).toEqual(['b', 'c']);
    expect(r.rows[0].vendorEventId).toBe(fileTailVendorEventId('h', '/p.log', '7', 52, 'b'));
    expect(r.consumedBytes).toBe(6); // ALL complete lines are consumed, not just the kept ones
  });

  it('returns nothing for empty data', () => {
    expect(buildFileTailRows({ ...base, startOffset: 0, data: Buffer.alloc(0) })).toEqual({ rows: [], consumedBytes: 0 });
  });
});

// ---------------------------------------------------------------------------
// Pattern → file attribution (glob matching)
// ---------------------------------------------------------------------------

describe('logSourcePatternToRegex / matchLogSource', () => {
  it('matches exact paths and single-segment * globs (no slash crossing)', () => {
    expect(logSourcePatternToRegex('/var/log/x.log').test('/var/log/x.log')).toBe(true);
    const star = logSourcePatternToRegex('/var/log/*.log');
    expect(star.test('/var/log/a.log')).toBe(true);
    expect(star.test('/var/log/sub/a.log')).toBe(false); // * must not cross /
  });

  it('matches ** recursively, including zero directory segments', () => {
    const rec = logSourcePatternToRegex('/opt/app/**/*.out');
    expect(rec.test('/opt/app/x.out')).toBe(true); // zero segments
    expect(rec.test('/opt/app/deep/nest/y.out')).toBe(true);
    expect(rec.test('/other/app/x.out')).toBe(false);
  });

  it('escapes regex metacharacters in literal parts', () => {
    const re = logSourcePatternToRegex('/var/log/app (1).log');
    expect(re.test('/var/log/app (1).log')).toBe(true);
    expect(re.test('/var/log/appX1.log')).toBe(false); // parens/dot are literal, not regex
  });

  it('matchLogSource returns the FIRST matching source', () => {
    const sources = [
      { pattern: '/var/log/*.log' },
      { pattern: '/var/log/auth.log', label: 'auth' },
    ];
    expect(matchLogSource('/var/log/auth.log', sources)?.label).toBeUndefined(); // first wins
    expect(matchLogSource('/var/log/other.log', sources)?.pattern).toBe('/var/log/*.log');
    expect(matchLogSource('/etc/passwd', sources)).toBeNull();
  });
});
