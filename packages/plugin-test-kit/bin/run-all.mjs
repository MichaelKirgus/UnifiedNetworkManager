/**
 * @unm/plugin-test-kit — run every plugin's suite (CI entry point).
 *
 * Usage (from repo root):
 *   node packages/plugin-test-kit/bin/run-all.mjs            # all plugins, sequential
 *   node packages/plugin-test-kit/bin/run-all.mjs --only generic-ntp,docker
 *   node packages/plugin-test-kit/bin/run-all.mjs --skip basic-auth,secrets-provider
 *
 * Iterates every plugins/<name>/package.json folder (excluding _template), runs
 * the single-plugin runner for each in its own child process (so one plugin's crash
 * or leaked handle can't take down the rest), and prints a summary table.
 * Exit code: 0 only when every suite passed; 1 otherwise. Plugins that are not
 * built yet are reported as SKIPPED-UNBUILT and do NOT fail the run — CI builds
 * everything first via `make build`, so this only matters for partial local runs.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

// bin/ → plugin-test-kit/ → packages/ → repo root (three levels up)
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..');
const pluginsDir = path.join(root, 'plugins');
const runner = new URL('./run.mjs', import.meta.url);

function parseArgs() {
  const only = new Set();
  const skip = new Set();
  for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (a === '--only') (process.argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean).forEach((s) => only.add(s));
    else if (a === '--skip') (process.argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean).forEach((s) => skip.add(s));
  }
  return { only, skip };
}

// Generous on purpose: a loaded dev machine stretches every internal timeout
// (spawn 20s + T4/T5/T8 3×30s ≈ 120 s worst case) several-fold. This is a
// safety net, not an expectation — healthy plugins finish in seconds.
const PER_PLUGIN_BUDGET_MS = Number(process.env.PLUGIN_TEST_PLUGIN_TIMEOUT_MS ?? 480_000);

/**
 * Runs one plugin's suite in its own process group (detached). On budget
 * expiry the WHOLE group is SIGKILLed — runner AND its plugin child — so a
 * timeout can never leave an orphaned plugin behind. (spawnSync's timeout did
 * exactly that: it killed only the direct child, whose stdout pipe then kept
 * this process blocked forever.)
 */
function runOne(name) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [runner.pathname, name], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true, // own process group (POSIX) → kill(-pid) reaches the plugin child too
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
    }, PER_PLUGIN_BUDGET_MS);
    child.on('error', (err) => { clearTimeout(timer); resolve({ error: err, out }); });
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      // Give the pipes a beat to flush their final bytes.
      setTimeout(() => resolve({ status: code, signal, out }), 50);
    });
  });
}

const { only, skip } = parseArgs();

const plugins = fs
  .readdirSync(pluginsDir, { withFileTypes: true })
  .filter((e) => e.isDirectory() && e.name !== '_template' && fs.existsSync(path.join(pluginsDir, e.name, 'package.json')))
  .map((e) => e.name)
  .sort();

const rows = []; // {name, status: PASS|FAIL|UNBUILT|ERROR, detail}
for (const name of plugins) {
  if (only.size > 0 && !only.has(name)) continue;
  if (skip.has(name)) {
    rows.push({ name, status: 'SKIPPED', detail: '--skip' });
    console.log(`\n── ${name} ── skipped (--skip)`);
    continue;
  }

  const built = fs.existsSync(path.join(pluginsDir, name, 'dist', 'src', 'index.js'));
  if (!built) {
    rows.push({ name, status: 'UNBUILT', detail: 'missing dist/src/index.js' });
    console.log(`\n── ${name} ── SKIPPED (not built — run \`make build\`)`);
    continue;
  }

  const startedAt = Date.now();
  const r = await runOne(name);
  const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
  const out = r.out ?? '';
  if (out.trim()) process.stdout.write(out.endsWith('\n') ? out : `${out}\n`);

  let status, detail;
  if (r.error) {
    status = 'ERROR';
    detail = r.error.message;
  } else if (r.signal === 'SIGKILL' && Date.now() - startedAt >= PER_PLUGIN_BUDGET_MS - 5_000) {
    // Distinguish "we killed it on budget" from an external SIGKILL.
    status = 'ERROR';
    detail = `hard timeout after ${Math.round(PER_PLUGIN_BUDGET_MS / 1000)} s (whole process group killed) (${elapsed}s)`;
  } else if (r.status === 0) {
    const m = out.match(/→ (\d+) passed, (\d+) failed(?:, (\d+) skipped)?/);
    status = 'PASS';
    detail = m ? `${m[1]}✓ ${m[2]}✗${m[3] ? ` ${m[3]}skip` : ''} (${elapsed}s)` : `(${elapsed}s)`;
  } else {
    status = 'FAIL';
    const failedLine = out.split('\n').filter((l) => l.includes('✗')).slice(-5).join(' | ');
    detail = `${failedLine || `exit ${r.status}`} (${elapsed}s)`;
  }
  rows.push({ name, status, detail });
}

// ── Summary table ─────────────────────────────────────────────────────────────
console.log('\n════ Plugin test suite summary ════');
const width = Math.max(...rows.map((r) => r.name.length), 4);
for (const row of rows) {
  const mark = row.status === 'PASS' ? '✓' : row.status === 'FAIL' || row.status === 'ERROR' ? '✗' : '·';
  console.log(`  ${mark} ${row.name.padEnd(width)}  ${row.status.padEnd(8)} ${row.detail}`);
}
const failed = rows.filter((r) => r.status === 'FAIL' || r.status === 'ERROR');
const unbuilt = rows.filter((r) => r.status === 'UNBUILT').length;
console.log(`\n  ${rows.length - failed.length - unbuilt}/${rows.length} passed${unbuilt ? `, ${unbuilt} not built` : ''}${failed.length ? ` — FAILURES: ${failed.map((f) => f.name).join(', ')}` : ''}`);
process.exit(failed.length > 0 ? 1 : 0);
