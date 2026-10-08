/**
 * @unm/plugin-test-kit — plugin process harness.
 *
 * Spawns a BUILT plugin (dist/src/index.js) as a standalone child process on an
 * ephemeral port and waits for /healthz. "Standalone" means UNM_API_URL +
 * PLUGIN_API_KEY are UNSET, so the SDK's self-registration loop stays off and
 * the requirePluginKey middleware is skipped — exactly how a plugin behaves
 * before it joins a deployment. mDNS advertising failures are non-fatal in the
 * SDK (caught), so this works in CI containers without multicast too.
 */

import { spawn } from 'node:child_process';
import dgram from 'node:dgram';
import net from 'node:net';

/** Allocates an OS-free TCP port (bind :0, close, return). */
export function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

/** A TCP port that is (almost certainly) closed — for dead-target tests. */
export function getDeadTcpPort() {
  return getFreePort();
}

/** A UDP port nothing listens on — for dead-target tests of UDP plugins. */
export function getDeadUdpPort() {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.on('error', reject);
    sock.bind(0, '127.0.0.1', () => {
      const port = sock.address().port;
      sock.close(() => resolve(port));
    });
  });
}

const LOG_TAIL = 40; // lines kept from the child's output for failure diagnostics

/**
 * Spawns a built plugin and resolves once /healthz answers 200.
 *
 * @param {object} opts
 * @param {string} opts.pluginDir   Absolute path to plugins/<name> (used as cwd).
 * @param {string} [opts.entry]     Entry file, default <pluginDir>/dist/src/index.js.
 * @param {Record<string,string>} [opts.env]  Extra env for the child (e.g. SFLOW_PORT).
 * @param {number} [opts.healthTimeoutMs=20000]  Max wait for /healthz.
 * @returns {Promise<{port:number, url:string, kill:()=>Promise<void>, tail:()=>string}>}
 */
export async function spawnPlugin({ pluginDir, entry, env = {}, healthTimeoutMs = 20_000 }) {
  const port = await getFreePort();
  const entryPath = entry ?? `${pluginDir}/dist/src/index.js`;

  // Isolate from any host deployment: the SDK keys registration on
  // `process.env.PLUGIN_API_KEY !== undefined`, so these must be DELETED, not blanked.
  const childEnv = { ...process.env };
  for (const k of ['UNM_API_URL', 'PLUGIN_API_KEY', 'UNM_TLS']) delete childEnv[k];
  // MDNS_ADVERTISE=0 (deliberately NOT overridable by config.env): test children
  // are reached directly on their known port, so they must stay silent on the
  // LAN — a live dev stack runs plugins with the SAME mDNS names + UUIDs, and
  // sharing that namespace is the one real interference channel.
  Object.assign(childEnv, env, {
    PORT: String(port),
    ADVERTISED_ENDPOINT: `http://127.0.0.1:${port}`,
    MDNS_ADVERTISE: '0',
  });

  const child = spawn(process.execPath, [entryPath], {
    cwd: pluginDir,
    env: childEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let outTail = [];
  const push = (line) => {
    outTail.push(line);
    if (outTail.length > LOG_TAIL * 2) outTail.splice(0, outTail.length - LOG_TAIL * 2);
  };
  child.stdout.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach(push));
  child.stderr.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach(push));

  let exitInfo = null;
  const exited = new Promise((resolve) => {
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });

  // Kill state MUST be declared before the healthz loop: on a healthy spawn we
  // `return wrap()` early, so anything declared after that return is in its
  // temporal dead zone when kill() later runs (ReferenceError → swallowed by
  // run.mjs's .catch → child never killed → runner hangs forever).
  let termSent = false;
  /** Bounded wait for the child to actually die. Polls exitCode/signalCode
   * (set synchronously by libuv) instead of trusting ONLY the 'exit' event —
   * that event fires only after all stdio pipes have closed, so a child that
   * dies with data still in flight would otherwise stall us indefinitely. */
  async function waitDead(ms) {
    const t0 = Date.now();
    while (child.exitCode === null && child.signalCode === null && Date.now() - t0 < ms) {
      await new Promise((res) => setTimeout(res, 100));
    }
  }
  async function kill() {
    if (child.exitCode !== null || child.signalCode !== null) return;
    if (!termSent) {
      // NOTE: do NOT gate on `child.killed` — Node sets that flag the moment WE
      // call kill(), so it would suppress the SIGKILL escalation forever.
      termSent = true;
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
    }
    await waitDead(3_000);
    if (child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      await waitDead(5_000); // bounded: a kernel-stuck (D-state) child must not hang the suite
    }
  }

  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + healthTimeoutMs;
  for (;;) {
    if (exitInfo !== null || child.exitCode !== null) break;
    try {
      // Per-attempt timeout: a child that accepts TCP but stalls its event
      // loop must not hold the poll open past the overall deadline.
      const r = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(2_000) });
      if (r.status === 200) return wrap();
    } catch {
      /* not up yet */
    }
    if (Date.now() >= deadline) break;
    // Race the sleep against process exit so a crashed plugin fails fast.
    await Promise.race([new Promise((res) => setTimeout(res, 250)), exited.then(() => 'exited')]);
    if (child.exitCode !== null || child.signalCode !== null) break;
  }

  const info = exitInfo ?? { code: child.exitCode, signal: child.signalCode };
  await kill();
  throw new Error(
    `plugin did not become healthy within ${healthTimeoutMs} ms (exit=${info.code ?? 'n/a'}${info.signal ? `, signal=${info.signal}` : ''})\n--- last output ---\n${outTail.slice(-LOG_TAIL).join('\n')}`
  );

  function wrap() {
    return {
      port,
      url,
      tail: () => outTail.slice(-LOG_TAIL).join('\n'),
      kill: async () => {
        await kill();
        // Give the event loop a beat so buffered output lands in the tail.
        await new Promise((res) => setTimeout(res, 50));
      },
    };
  }
}

/** One bounded HTTP request against the plugin under test. */
export async function callPlugin(url, method, pathName, { body, headers = {}, timeoutMs = 15_000 } = {}) {
  const startedAt = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${url}${pathName}`, {
      method,
      headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      /* non-JSON body */
    }
    return { status: res.status, json, text, ms: Date.now() - startedAt };
  } finally {
    clearTimeout(timer);
  }
}
