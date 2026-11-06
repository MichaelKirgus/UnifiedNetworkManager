/**
 * SECURITY tests for the rendered post-auth audit logger (radius-auth-log.sh).
 *
 * This is the most security-critical piece of the RADIUS feature: a malicious
 * or buggy NAS/supplicant can set User-Name / Called-Station-Id /
 * Calling-Station-Id to arbitrary bytes, and those values are interpolated into
 * a SQL string that psql executes as the unm_radius role. The ONLY thing
 * standing between an attacker and `radpostauth` (and, via crafted input, other
 * tables) is the sanitizer in renderAuthLogScript().
 *
 * Strategy: render the REAL script with fixed DB creds, drop a STUB `psql` on
 * PATH that records its SQL argument to a file, run the script under bash with
 * hostile argv (exactly what rlm_exec would pass), and assert:
 *   1. No injection payload survives into the SQL string (quotes/semicolons/
 *      backticks/newlines are stripped by the [A-Za-z0-9._:@/-] allow-list).
 *   2. Legitimate values pass through intact (no false-positive over-sanitizing
 *      that would corrupt the audit trail).
 *   3. Length caps hold.
 *   4. The verdict is restricted to Access-Accept/Access-Reject else "unknown".
 *   5. Fail-open: a failing psql (or missing psql) NEVER makes the script exit
 *      non-zero — logging must not affect authentication.
 *
 * These run in plain jest (CI runs `cd api && npm test` with no DB/Docker), so
 * they gate every PR without needing a live FreeRADIUS or Postgres.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
// Import from the PURE module (no db/pg/uuid chain) so this suite runs in plain
// jest with no database — exactly how CI invokes it.
import { renderAuthLogScript, type ParsedDbUrl } from './radiusRender';

const DB: ParsedDbUrl = { host: 'postgres', port: 5432, user: 'unm_radius', password: 'pw-with-quotes\'and-dashes', database: 'unm' };
const CREDS = { user: 'unm_radius', password: 's3cr3t-pw' };

interface Harness {
  dir: string;
  scriptPath: string;
  captureFile: string;
  cleanup: () => void;
}

/** Renders the real script into a temp dir and installs a stub `psql` that
 * records its SQL argument (argv[2]) to captureFile, then exits with exitCode. */
function setup(psqlExitCode = 0): Harness {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-authlog-test-'));
  const binDir = path.join(dir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });

  const scriptPath = path.join(dir, 'radius-auth-log.sh');
  fs.writeFileSync(scriptPath, renderAuthLogScript(DB, CREDS), { mode: 0o750 });

  const captureFile = path.join(dir, 'psql-sql.txt');
  // The rendered script invokes `timeout 5 psql -qc "SQL"` → psql sees $1=-qc, $2=SQL.
  const psqlStub = [
    '#!/bin/bash',
    `printf '%s\\n' "$2" > "${captureFile}"`,
    `exit ${psqlExitCode}`,
    '',
  ].join('\n');
  fs.writeFileSync(path.join(binDir, 'psql'), psqlStub, { mode: 0o755 });

  return {
    dir,
    scriptPath,
    captureFile,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/** Runs the rendered script under bash with the given argv (post-rlm_exec). */
function run(h: Harness, args: string[], envOverride: NodeJS.ProcessEnv = {}): { status: number; stdout: string; stderr: string } {
  const r = spawnSync('bash', [h.scriptPath, ...args], {
    encoding: 'utf8',
    // Prepend the stub bin dir so `psql` resolves to our recorder.
    env: { ...process.env, PATH: `${path.join(h.dir, 'bin')}:${process.env.PATH}`, ...envOverride },
  });
  return { status: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** Reads the SQL string the stub psql captured (empty if psql never ran). */
function capturedSql(h: Harness): string {
  try {
    return fs.readFileSync(h.captureFile, 'utf8').trim();
  } catch {
    return '';
  }
}

describe('renderAuthLogScript — SQL-injection resistance', () => {
  it('passes legitimate values through intact (no over-sanitizing)', () => {
    const h = setup();
    try {
      const r = run(h, ['Access-Reject', 'alice@corp.example', 'ap-01:aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66']);
      expect(r.status).toBe(0);
      const sql = capturedSql(h);
      // The username, verdict and both station ids must appear verbatim.
      expect(sql).toContain("'alice@corp.example'");
      expect(sql).toContain("'Access-Reject'");
      expect(sql).toContain("NULLIF('ap-01:aa:bb:cc:dd:ee:ff', '')");
      expect(sql).toContain("NULLIF('11:22:33:44:55:66', '')");
      // And it must be a single INSERT, not something else.
      expect(sql.startsWith('INSERT INTO radpostauth')).toBe(true);
    } finally {
      h.cleanup();
    }
  });

  it('neutralizes a classic quote-breakout in User-Name', () => {
    const h = setup();
    try {
      // `x' OR '1'='1` and the DROP variant both contain quotes/semicolons/spaces.
      for (const evil of [
        "x'; DROP TABLE radpostauth;--",
        "a' OR '1'='1",
        "user', 'x', 'y'); DELETE FROM radpostauth; --",
      ]) {
        const r = run(h, ['Access-Reject', evil, 'ap-01', 'aa:bb']);
        expect(r.status).toBe(0);
        const sql = capturedSql(h);
        // The payload must NOT survive — the allow-list strips quotes/;/space.
        expect(sql).not.toContain('DROP TABLE');
        expect(sql).not.toContain("OR '1'='1");
        expect(sql).not.toContain(evil);
        // The username collapses to the safe default.
        expect(sql).toContain("'unknown'");
      }
    } finally {
      h.cleanup();
    }
  });

  it('neutralizes injection in Called-Station-Id and Calling-Station-Id', () => {
    const h = setup();
    try {
      run(h, ['Access-Reject', 'alice', "a'); DELETE FROM radpostauth;--", '`id`; DROP TABLE x']);
      const sql = capturedSql(h);
      expect(sql).not.toContain('DELETE FROM');
      expect(sql).not.toContain('DROP TABLE');
      // Both station ids collapse to empty (NULLIF('', '') → NULL column).
      expect(sql).toContain("NULLIF('', '')");
    } finally {
      h.cleanup();
    }
  });

  it('strips shell metacharacters (backticks, $(), double quotes)', () => {
    const h = setup();
    try {
      for (const evil of ['`id`', '$(rm -rf /)', '"$(whoami)"', 'a; b | c']) {
        run(h, ['Access-Reject', evil, '', '']);
        const sql = capturedSql(h);
        expect(sql).not.toContain('`');
        expect(sql).not.toContain('$(');
        expect(sql).not.toContain(evil);
      }
    } finally {
      h.cleanup();
    }
  });

  it('defeats newline / multi-line injection', () => {
    const h = setup();
    try {
      run(h, ['Access-Reject', 'evil\n; DROP TABLE radpostauth;', '', '']);
      const sql = capturedSql(h);
      // Newline is not in the allow-list → username becomes "unknown".
      expect(sql).toContain("'unknown'");
      expect(sql).not.toContain('DROP TABLE');
    } finally {
      h.cleanup();
    }
  });

  it('caps User-Name length at 128', () => {
    const h = setup();
    try {
      const longUser = 'a'.repeat(300); // all valid chars, so only the cap applies
      run(h, ['Access-Reject', longUser, '', '']);
      const sql = capturedSql(h);
      expect(sql).toContain(`'${'a'.repeat(128)}'`);
      expect(sql).not.toContain(`'${'a'.repeat(129)}`);
    } finally {
      h.cleanup();
    }
  });

  it('caps station-id lengths at 75', () => {
    const h = setup();
    try {
      run(h, ['Access-Reject', 'alice', 'b'.repeat(200), 'c'.repeat(200)]);
      const sql = capturedSql(h);
      expect(sql).toContain(`NULLIF('${'b'.repeat(75)}', '')`);
      expect(sql).toContain(`NULLIF('${'c'.repeat(75)}', '')`);
      expect(sql).not.toContain('b'.repeat(76));
    } finally {
      h.cleanup();
    }
  });

  it('restricts the verdict to Access-Accept/Access-Reject else "unknown"', () => {
    const h = setup();
    try {
      // A crafted Packet-Type that is not a real RADIUS code must be neutralized.
      run(h, ['Access-Reject; DROP TABLE radpostauth', 'alice', '', '']);
      let sql = capturedSql(h);
      expect(sql).not.toContain('DROP TABLE');
      expect(sql).toContain("'unknown'");

      // Legit verdicts pass through.
      run(h, ['Access-Accept', 'bob', '', '']);
      sql = capturedSql(h);
      expect(sql).toContain("'Access-Accept'");
    } finally {
      h.cleanup();
    }
  });

  it('treats a missing User-Name as "unknown" (shifted/absent argv is safe)', () => {
    const h = setup();
    try {
      // Only the verdict supplied — $2/$3/$4 absent. set -u must not crash.
      const r = run(h, ['Access-Reject']);
      expect(r.status).toBe(0);
      const sql = capturedSql(h);
      expect(sql).toContain("'unknown'");
    } finally {
      h.cleanup();
    }
  });

  it('sanitizes even a SHIFTED injection value (missing attr shifts args left)', () => {
    const h = setup();
    try {
      // Simulate rlm_exec dropping the User-Name token: $2 is actually a hostile
      // station id. It must still be sanitized, never injected.
      run(h, ['Access-Reject', "x'; DROP TABLE radpostauth;--", 'aa:bb']);
      const sql = capturedSql(h);
      expect(sql).not.toContain('DROP TABLE');
    } finally {
      h.cleanup();
    }
  });

  it('escapes a single quote in the DB password (PG* env stays valid bash)', () => {
    // The rendered script bsh-escapes creds; a `'` in the password must not break
    // out of its single-quoted assignment and corrupt the SQL string. Render with
    // such a password, run, and assert psql still received a clean INSERT.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-authlog-pw-'));
    try {
      const binDir = path.join(dir, 'bin');
      fs.mkdirSync(binDir, { recursive: true });
      const scriptPath = path.join(dir, 'radius-auth-log.sh');
      // Password with a single quote — the bsh() escaper must handle it.
      fs.writeFileSync(scriptPath, renderAuthLogScript(DB, { user: 'unm_radius', password: "it's-a-secret" }), { mode: 0o750 });
      const captureFile = path.join(dir, 'psql-sql.txt');
      fs.writeFileSync(path.join(binDir, 'psql'), `#!/bin/bash\nprintf '%s\\n' "$2" > "${captureFile}"\nexit 0\n`, { mode: 0o755 });

      const r = spawnSync('bash', [scriptPath, 'Access-Reject', 'alice', '', ''], {
        encoding: 'utf8',
        env: { ...process.env, PATH: `${binDir}:${process.env.PATH}` },
      });
      expect(r.status).toBe(0); // a broken quote would make the assignment fail
      const sql = fs.readFileSync(captureFile, 'utf8').trim();
      expect(sql.startsWith('INSERT INTO radpostauth')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('renderAuthLogScript — fail-open (logging never affects auth)', () => {
  it('exits 0 when psql fails', () => {
    const h = setup(/* psqlExitCode */ 1);
    try {
      const r = run(h, ['Access-Reject', 'alice', 'ap-01', 'aa:bb']);
      expect(r.status).toBe(0); // MUST be 0 — a logging failure can't reject auth
      expect(r.stderr).toContain('auth-log insert failed');
    } finally {
      h.cleanup();
    }
  });

  it('exits 0 when psql is missing entirely (not on PATH)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-authlog-nopg-'));
    try {
      // Render the real script, but put an EMPTY bin dir FIRST on PATH so
      // `timeout` resolves to nothing (command-not-found) and psql is absent too.
      // bash itself is invoked by absolute path via spawnSync's resolved binary,
      // so it still runs. Both failure modes must be swallowed → exit 0.
      const scriptPath = path.join(dir, 'radius-auth-log.sh');
      fs.writeFileSync(scriptPath, renderAuthLogScript(DB, CREDS), { mode: 0o750 });
      const emptyDir = path.join(dir, 'emptybin');
      fs.mkdirSync(emptyDir, { recursive: true });
      // Use the real bash binary directly so an emptied PATH can't hide it.
      const r = spawnSync('/bin/bash', [scriptPath, 'Access-Reject', 'alice', '', ''], {
        encoding: 'utf8',
        env: { ...process.env, PATH: emptyDir },
      });
      expect(r.status).toBe(0); // fail-open even with no psql/timeout at all
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exits 0 and writes nothing when the DB is unreachable (psql times out)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-authlog-to-'));
    try {
      const scriptPath = path.join(dir, 'radius-auth-log.sh');
      fs.writeFileSync(scriptPath, renderAuthLogScript(DB, CREDS), { mode: 0o750 });
      // A `timeout` that always times out (simulates psql hanging on a dead DB).
      const binDir = path.join(dir, 'bin');
      fs.mkdirSync(binDir, { recursive: true });
      fs.writeFileSync(path.join(binDir, 'timeout'), '#!/bin/bash\nexit 124\n', { mode: 0o755 });
      const r = spawnSync('bash', [scriptPath, 'Access-Reject', 'alice', '', ''], {
        encoding: 'utf8',
        env: { ...process.env, PATH: `${binDir}:${process.env.PATH}` },
      });
      expect(r.status).toBe(0); // 124 (timeout) is swallowed by the fail-open || branch
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
