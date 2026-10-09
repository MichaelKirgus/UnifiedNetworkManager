/**
 * @unm/plugin-test-kit — single-plugin test runner.
 *
 * Usage (from repo root or a plugin dir):
 *   node packages/plugin-test-kit/bin/run.mjs <plugin-dir>
 *   node packages/plugin-test-kit/bin/run.mjs generic-ntp        # resolves plugins/<name>
 *
 * Loads the optional per-plugin config at <plugin-dir>/test/config.mjs:
 *   export default {
 *     env?: Record<string,string>,          // extra child-process env (e.g. SFLOW_PORT)
 *     monitoringAddress?: string,           // T4 target — may reference ${mockPort}
 *     settings?: object,                    // x-unm-settings for T4
 *     expectHealth?: 'ok'|'warning'|'critical',
 *     deadAddress?: string,                 // T5 target (default: closed 127.0.0.1 port)
 *     settingsForDead?: object,
 *     expectDeadHealth?: 'critical'|'warning'|'unknown',
 *     extraChecks?: async ({url, discover, caps, optionKeys, rec}) => void,
 *     // OR: start mock appliances yourself and return the suite config. Use this
 *     // when a mock's port must land in `settings` (not just the address):
 *     setup?: async () => ({ monitoringAddress, settings, ... }),
 *   }
 * Exits 0 when every check passes (skips allowed), 1 otherwise.
 */

import { pathToFileURL } from 'node:url';
import path from 'node:path';
import process from 'node:process';
import { spawnPlugin } from '../src/harness.js';
import { runContractSuite } from '../src/suite.js';

function resolveRepoRoot() {
  // bin/ → plugin-test-kit/ → packages/ → repo root (three levels up)
  return path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..');
}

async function loadConfig(pluginDir) {
  const cfgPath = path.join(pluginDir, 'test', 'config.mjs');
  try {
    await import('node:fs').then((fs) => fs.accessSync(cfgPath));
    const mod = await import(pathToFileURL(cfgPath).href);
    return mod.default ?? {};
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error(`failed to load ${cfgPath}: ${err.message}`);
  }
}

async function main() {
  const arg = process.argv[2];
  if (!arg) {
    console.error('usage: run.mjs <plugin-dir | plugin-name>');
    process.exit(2);
  }
  const root = resolveRepoRoot();
  let pluginDir = path.resolve(arg);
  if (!path.basename(pluginDir).startsWith('_') && !pluginDir.includes(`${path.sep}plugins${path.sep}`)) {
    // Bare name → plugins/<name>
    const candidate = path.join(root, 'plugins', arg);
    try {
      await import('node:fs').then((fs) => fs.accessSync(candidate));
      pluginDir = candidate;
    } catch { /* keep resolved arg */ }
  }

  let entryOk = false;
  try {
    await import('node:fs').then((fs) => fs.accessSync(path.join(pluginDir, 'dist', 'src', 'index.js')));
    entryOk = true;
  } catch { /* fall through */ }
  if (!entryOk) {
    console.error(`✗ ${path.basename(pluginDir)}: not built (missing dist/src/index.js) — run \`make build\` first.`);
    process.exit(1);
  }

  const config = (await loadConfig(pluginDir)) ?? {};
  const name = path.basename(pluginDir);

  // Mocks + final suite config. Either the declarative `mocks` block (first mock's
  // port is substituted into ${mockPort} in monitoringAddress) or an async
  // setup() hook that starts its own mocks and returns the full suite config.
  const mocksApi = await import('../src/mocks/index.js');
  const { getDeadTcpPort, getDeadUdpPort } = await import('../src/harness.js');
  const mocks = [];
  let suiteConfig;
  if (typeof config.setup === 'function') {
    const started = await config.setup({ ...mocksApi, getDeadTcpPort, getDeadUdpPort });
    mocks.push(...(started.mocks ?? []));
    suiteConfig = { ...config, ...(started.config ?? {}) };
    delete suiteConfig.setup;
  } else {
    if (config.mocks?.http) mocks.push(await startHttpMock(config.mocks.http));
    if (config.mocks?.ntp) mocks.push(await startNtpMock(config.mocks.ntp));
    if (config.mocks?.dockerDaemon) mocks.push(await startDockerDaemonMock());
    suiteConfig = { ...config };
    delete suiteConfig.mocks;
    const mockPort = mocks[0]?.port;
    if (typeof suiteConfig.monitoringAddress === 'string') {
      suiteConfig.monitoringAddress = suiteConfig.monitoringAddress.replace('${mockPort}', String(mockPort ?? ''));
    }
  }

  // Hard watchdog: a single plugin must never hang the whole run (e.g. a child
  // that ignores SIGTERM). 300 s covers spawn(20s) + T4/T5/T8 timeouts (3×30s)
  // with headroom for loaded dev machines; CI runners finish in seconds.
  const watchdog = setTimeout(() => {
    console.error(`✗ ${name}: hard timeout after 300 s — killing child and aborting this plugin.`);
    // Kill the child BEFORE exiting so we don't leave an orphan behind.
    const cleanup = (plugin ? plugin.kill().catch(() => {}) : Promise.resolve());
    cleanup.then(() => process.exit(1));
    setTimeout(() => process.exit(1), 2_000).unref(); // failsafe if kill hangs
  }, 120_000);

  let plugin;
  try {
    plugin = await spawnPlugin({ pluginDir, env: suiteConfig.env ?? config.env });
    const rec = await runContractSuite({ url: plugin.url, config: suiteConfig });

    console.log(`\n── ${name} ──`);
    for (const r of rec.results) {
      if (r.skipped) continue;
      const mark = r.ok ? '✓' : '✗';
      console.log(`  ${mark} [${r.id}] ${r.label}${!r.ok && r.detail ? ` — ${r.detail}` : ''}`);
    }
    const skipped = rec.results.filter((r) => r.skipped).length;
    console.log(`  → ${rec.passed} passed, ${rec.failed} failed${skipped ? `, ${skipped} skipped` : ''}`);

    if (rec.failed > 0) {
      // Surface the plugin's own output for diagnosis.
      const tail = plugin.tail();
      if (tail.trim()) console.log(`\n--- plugin output ---\n${tail}\n---------------------`);
      process.exitCode = 1;
    }
  } finally {
    clearTimeout(watchdog);
    await plugin?.kill().catch(() => {});
    for (const m of mocks) await m.stop().catch(() => {});
  }
}

main().catch((err) => {
  console.error(`✗ runner error: ${err.stack ?? err.message}`);
  process.exit(1);
});
