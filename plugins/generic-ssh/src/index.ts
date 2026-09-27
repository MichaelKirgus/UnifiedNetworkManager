/**
 * Generic SSH Plugin (Linux) — main entry point.
 *
 * A vendor-agnostic management plugin for ANY device that allows access over
 * SSH. Everything rides one transport — a pooled ssh2 session per host (SDK):
 *
 *   POST /monitoring  two-tier cadence collection: live CPU/memory/swap/bandwidth
 *                     every poll, inventory (interfaces+MACs, ARP/NDP, routes,
 *                     filesystems, disks) at the SDK's 15-min interval. ALWAYS 200.
 *   POST /probe       short-cycle live telemetry for on-demand webapp polling.
 *   WS   /console     interactive SSH shell (capability 'sshConsole') — the
 *                     DeviceDetail "Shell" button opens a full xterm.js PTY.
 *   POST /filesystem  generic, root-scoped SFTP file manager (capability
 *                     'filesystem') — Storage page browses mounted filesystems,
 *                     DeviceDetail offers a "Files" button for the whole tree.
 *
 * Data sources are plain POSIX reads (/proc, /sys, iproute2, df, lsblk) so it
 * works on any Linux box from busybox routers to full servers; every source is
 * best-effort — a missing tool degrades that section only.
 */

import path from 'path';
import {
  PluginOptionDescriptor,
  isTransientTransportError,
  createPluginLogger,
  createPluginServer,
  createTerminalPool,
  makeConsoleUpgrade,
  readSettings,
  resolvePluginIdentity,
  probeHandler,
  filesystemHandler,
  stateHandler,
  validateInput,
  hostFromAddress,
  resolveSshPort,
  dynamicSshHostVerifier,
  resolveSshCredentials,
  buildDeviceTimeInfo,
  createSftpPool,
  warnOnce,
  type QuickAction,
} from '@unm/plugin-sdk';
import type { ProbeRequestBody, StateRequestBody } from '@unm/plugin-sdk';

import { SshBackend, closeSshPools, resolveGenericSshCredentials } from './client/sshClient';
import { createElevatedBackend } from './client/privilege';
import { collectLive, collectMonitoring, getInventory } from './monitoring';
import { collectProbeStates, collectProbeStats, type ProbeContainerStat, type ProbeContainerState } from './containers';
import { stateStore } from './stateStore';
import { collectSecurityChecks, DEFAULT_WATCHED_FILES, type SecuritySettings } from './security';
import { buildPlan, listCatalogWithIntents, PlanningError } from './plan';
import type { PlanRequest } from './plan';
import { getAction } from './actions/registry';
import type { ActionContext } from './actions/types';
import { buildGenericSshState } from './state';

// Base UUID + shared state store live in ./stateStore so the monitoring path and
// the security actions both bind to the SAME instance-scoped effective uuid.
import { PLUGIN_UUID } from './stateStore';
export { PLUGIN_UUID };
export const PLUGIN_NAME = 'Generic SSH Plugin (Linux)';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.2.0 — Docker / Docker Compose support (Containers page): emits the generic
  // containers[] + images[] metrics at the inventory cadence (one row per "App"
  // = compose project, same grouping as the Docker plugin), serves probe keys
  // containerStates/containerStats over SSH, and adds the action catalog:
  // containers.start/stop/restart/delete, containers.deploy-compose (with a
  // USER-CHOSEN working dir for the saved docker-compose.yml — default
  // /opt/compose/<name>), containers.update + compose.config.read (edit YAML),
  // containers.logs.read and images.delete. All over the host's `docker` CLI;
  // hosts without docker simply yield no container data (keys omitted).
  version: '0.2.0',
  vendors: ['linux'],
  // monitoring + inventory: two-tier cadence collection over SSH (live metrics
  // every poll; interfaces/ARP/routes/filesystems/disks at the 15-min interval).
  // ssh: SSH is THE data path — exec for metrics/inventory + all config actions.
  // filesystem: POST /filesystem — SFTP file manager (Storage page + DeviceDetail).
  // probe: short-cycle live telemetry for on-demand webapp polling.
  // sshConsole: interactive shell over WebSocket (/console) — the "Shell" button.
  // configuration: POST /config — one action step (registry dispatch); Config page
  //                actions + config jobs. planning: POST /plan — multi-device intents
  //                (WireGuard tunnel) fanned into ordered steps with auto-snapshots.
  // updates: emits metrics['updates'] (upgradable OS packages via the host's
  //          package manager) for the cross-device Updates page; applying is a plan.
  // securityChecks: per-appliance security checks (file integrity, failed logins,
  //                 active rate limiting, account hygiene) → Security page.
  capabilities: ['monitoring', 'inventory', 'ssh', 'filesystem', 'probe', 'sshConsole', 'configuration', 'planning', 'updates', 'securityChecks'],
});

// Persistent file-integrity baselines live in UNM's database (plugin state store),
// NOT on local disk — a container rebuild must not re-baseline every watched host.
// The shared, instance-scoped store is imported from ./stateStore above so the
// security actions bind to the exact same effective uuid as this monitoring path.

/**
 * The options this plugin exposes for configuration. Declared in /discover so
 * the API can persist + validate user-set values and the webapp can render a
 * generic form — this plugin never stores settings itself; it receives them on
 * every call via the `x-unm-settings` header (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the device's SSH daemon. Used for metrics collection, filesystem browsing and the interactive web console when the management address carries no explicit port.",
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
  {
    key: 'sudoUser',
    label: 'Sudo target user',
    type: 'string' as const,
    default: '',
    maxLength: 64,
    description:
      "Optional username to elevate to via sudo (empty = the default, usually root). Only used when the logged-in user is not already root and has passwordless sudo — or when a dedicated root credential slot is bound.",
  },
  {
    key: 'securityChecksEnabled',
    label: 'Enable security checks',
    type: 'boolean' as const,
    default: true,
    description:
      'Run per-appliance security checks during inventory polls (file integrity of important config files, unsuccessful logins, active rate limiting / brute-force protection, account hygiene). Findings appear on the cross-device Security page.',
  },
  {
    key: 'securityWatchedFiles',
    label: 'Security — watched files',
    type: 'string' as const,
    default: DEFAULT_WATCHED_FILES.join(', '),
    maxLength: 1024,
    description:
      'Comma-separated absolute paths whose sha256 is baselined (first sight) and checked for changes on every inventory poll. A changed file raises a critical finding; re-baseline it via the security.rebaseline action once verified.',
  },
  {
    key: 'securityAuthFailureWindowHours',
    label: 'Security — failed-login window (hours)',
    type: 'integer' as const,
    default: 24,
    min: 1,
    max: 720,
    description: 'Look-back window for counting unsuccessful login attempts.',
  },
  {
    key: 'securityAuthFailureWarnThreshold',
    label: 'Security — failed-login warning threshold',
    type: 'integer' as const,
    default: 10,
    min: 1,
    max: 1_000_000,
    description: 'Unsuccessful logins in the window at or above this count raise a WARNING finding (below it is INFO — normal scanner noise).',
  },
  {
    key: 'securityAuthFailureCriticalThreshold',
    label: 'Security — failed-login critical threshold',
    type: 'integer' as const,
    default: 50,
    min: 1,
    max: 1_000_000,
    description: 'Unsuccessful logins in the window at or above this count raise a CRITICAL finding (likely an active brute-force attempt).',
  },
];

// Structured logs shipped to the API — emission is gated per call by the
// `logToApi` option via setEnabled().
const logger = createPluginLogger(identity);

/** Reads the configured SSH port from effective settings (default 22). */
function sshPortOf(settings: Record<string, unknown>): number {
  return resolveSshPort(settings.sshPort);
}

// --- Interactive SSH console (capability 'sshConsole') -------------------------
// The webapp's DeviceDetail page renders a generic "Shell" button for any plugin
// advertising 'sshConsole'; the API proxies the browser's xterm.js to our
// /console WebSocket, which opens a PTY on the bound `ssh` slot (falling back
// to the primary username/password — one login feeds everything here).
const termPool = createTerminalPool();

const consoleUpgrade = makeConsoleUpgrade({
  expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
  path: '/console',
  onOpen: async (hello) => {
    const host = hostFromAddress(hello.managementAddress);
    if (!host) throw new Error('Missing management address');
    // The primary credential IS an SSH login by definition of this plugin
    // (username/password or key pair) — one login feeds everything here.
    const creds = resolveSshCredentials(hello.credentials as Record<string, unknown> | undefined);
    if (!creds) {
      throw new Error('No SSH credential available — bind a usernamePassword or sshKeyPair secret to the assignment.');
    }
    // Configured SSH port (plugin option `sshPort`, default 22) — delivered by
    // the API in the console hello frame so a per-device override is honored.
    const sshPort = resolveSshPort(hello.settings?.['sshPort']);
    const conn = await termPool.get(host, sshPort, creds, {
      // UNM certificate pinning — resolves the freshest trusted fingerprint at
      // handshake time (pooled sessions outlive single requests). A mismatch
      // rejects the handshake BEFORE any auth message is sent.
      hostKeyVerifier: dynamicSshHostVerifier(host, sshPort),
      onHostKey: (fp) => console.warn(`[generic-ssh-plugin] observed host key for ${host}:${sshPort} → ${fp} (pin it in the device's SSH settings to enforce strict verification)`),
    });
    return conn.openShell(creds); // a plain login shell, like PuTTY
  },
});

/** Quick actions propagated to the Devices page "Device Actions" column. This
 * plugin is SSH-only (no web UI), so it offers shell + files shortcuts that reuse
 * the existing console + filesystem dialogs — no /quick-action route needed.
 */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'shell',
    label: 'Shell',
    description: 'Interactive SSH shell on the host (uses the bound or primary credential)',
    iconPath: '/icons/generic-ssh.svg',
    kind: 'shell',
  },
  {
    id: 'files',
    label: 'Files',
    description: "Browse the device's filesystem over SFTP (uses the bound or primary credential)",
    iconPath: '/icons/generic-ssh.svg',
    kind: 'files',
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'generic-ssh-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Primary credential = a username/password login OR an SSH key pair — this
    // plugin has no other transport at all. `requiredSecretTypes` drives the
    // webapp's multi-type picker; `requiredSecretType` stays for older consumers.
    requiredSecretType: 'usernamePassword',
    requiredSecretTypes: ['usernamePassword', 'sshKeyPair'],
    // Optional dedicated ROOT slot — a second SSH login that has root access on
    // the host. Used ONLY when the primary user cannot elevate via passwordless
    // sudo (or is not root itself): privileged commands then run on a direct
    // session as this user, no sudo involved.
    credentialSlots: [
      {
        name: 'root',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          "Optional second SSH login with ROOT access on the host. Used only when the primary user is not root and has no passwordless sudo — privileged commands (package updates, routes, snapshots) then run directly as this user.",
      },
    ],
    // Metric descriptors are generated DYNAMICALLY from each /monitoring poll —
    // the UI always matches the data this specific box returned (a busybox router
    // has no lsblk; a full server does).
    metrics: [],
    // Action catalog: single-device actions + multi-device intents. The API
    // persists it and validates plan steps against it.
    actions: listCatalogWithIntents(),
    options: PLUGIN_OPTIONS,
    // Quick actions for the Devices page "Device Actions" column — shell/files
    // reuse the existing console + filesystem dialogs (capability-gated).
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/generic-ssh.svg',
  },
});
const app = server.app;

// --- Shared request plumbing ----------------------------------------------------

/** Extracts the management host + SSH port from one request body. */
function targetOf(managementAddress: string, settings: Record<string, unknown>): { host: string | null; port: number } {
  return { host: hostFromAddress(managementAddress), port: sshPortOf(settings) };
}

/** Reads the optional sudo target user from effective settings ('' = default). */
function sudoUserOf(settings?: Record<string, unknown>): string | undefined {
  const v = typeof settings?.sudoUser === 'string' ? (settings.sudoUser as string).trim() : '';
  return v !== '' ? v : undefined;
}

/** Resolves the SSH backend for one request (undefined = no usable credential).
 *  Privilege-aware: a bound `root` slot, an already-root login or passwordless
 *  sudo is detected once per host and cached — see client/privilege.ts. */
async function backendFor(host: string, port: number, credentials: Record<string, unknown>, settings?: Record<string, unknown>) {
  const creds = resolveGenericSshCredentials(credentials);
  if (!creds) return undefined;
  try {
    return await createElevatedBackend(host, port, credentials, sudoUserOf(settings));
  } catch (err) {
    // No usable credential shape — degrade to the plain user-level backend so
    // at least the reads that work without root keep working.
    warnOnce('generic-ssh', `privilege:${host}`, `Privilege probe failed for ${host}: ${(err as Error).message} — falling back to user-level exec`);
    return new SshBackend(host, port, creds);
  }
}

// ---------------------------------------------------------------------------
// POST /monitoring — two-tier cadence collection. ALWAYS responds 200 (the API's
// telemetry worker treats non-200 as transport failure); health carries the verdict.
// ---------------------------------------------------------------------------
app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Model/firmware selected in the webapp device form — echoed back as system.*
  // metrics (informational).
  const selectedModel = typeof body.model === 'string' && body.model ? body.model : null;
  const selectedFirmware = typeof body.firmwareVersion === 'string' && body.firmwareVersion ? body.firmwareVersion : null;

  // Effective settings injected by the API (defaults ⊕ user overrides).
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  // Decrypted assignment fields: primary at top level + bound slots under
  // `slots` (the optional `root` slot when the user bound a second login).
  const credentials = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  // Window-based scheduling: the API sends collectInventory=false on metrics-only
  // polls (absent = full collection, old-API compatible).
  const collectInventoryFlag = body.collectInventory !== false;

  try {
    if (!managementAddress) throw new Error('Missing managementAddress');
    const { host, port } = targetOf(managementAddress, settings);
    if (!host) throw new Error(`Unparseable management address "${managementAddress}"`);

    const backend = await backendFor(host, port, credentials, settings);
    if (!backend) {
      // No SSH credential bound — nothing to collect. The device stays visible
      // with a critical health so the user notices the missing assignment.
      res.status(200).json({
        deviceId,
        collectedAt: new Date().toISOString(),
        health: 'critical',
        metrics: {},
        error: 'No SSH credential bound — assign a usernamePassword or sshKeyPair secret to this device.',
      });
      return;
    }

    const result = await collectMonitoring(host, backend, { collectInventory: collectInventoryFlag });

    // Security checks ride the INVENTORY window (like updates): file-integrity
    // baselines + failed-login/rate-limit/account scans are comparatively heavy,
    // so they run at most once per inventory cycle. Failure → omit the key
    // entirely (absent = no wipe, per the ingestion contract).
    if (collectInventoryFlag) {
      try {
        const secSettings: SecuritySettings = {
          enabled: settings.securityChecksEnabled !== false,
          watchedFiles: String(settings.securityWatchedFiles ?? DEFAULT_WATCHED_FILES.join(', '))
            .split(',')
            .map((s) => s.trim())
            .filter((s) => s.startsWith('/')),
          authFailureWindowHours: Number(settings.securityAuthFailureWindowHours ?? 24),
          authFailureWarnThreshold: Number(settings.securityAuthFailureWarnThreshold ?? 10),
          authFailureCriticalThreshold: Number(settings.securityAuthFailureCriticalThreshold ?? 50),
        };
        result.metrics['securityChecks'] = await collectSecurityChecks(host, deviceId, backend, stateStore, secSettings);
      } catch {
        /* best-effort — a failed check must never sink the poll */
      }
    }

    if (selectedModel) result.metrics['system.model'] = selectedModel;
    if (selectedFirmware) result.metrics['system.firmwareVersion'] = selectedFirmware;

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: result.health,
      metrics: result.metrics,
      metricDescriptors: result.metricDescriptors,
      // Echo back the effective settings we received — proof that the
      // API→plugin settings injection loop works end to end.
      activeSettings: {
        sshPort: port,
        logToApi: settings.logToApi === true,
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: {},
      error: (err as Error).message,
    });
  }
});

// ---------------------------------------------------------------------------
// POST /probe — SHORT-CYCLE live telemetry (capability 'probe'). The webapp polls
// this every few seconds through the API broker. Keep it CHEAP: one pooled SSH
// exec batch over the shared pool (connection reused).
// Probe keys:
//   - 'systemStats' (default): CPU %, load averages, memory + swap — /proc reads.
//   - 'traffic': per-interface byte counters (/sys/class/net statistics).
//   - 'deviceTime': device clock for the Time page's on-demand refresh.
//   - 'containerStates': live docker state of every container (one cheap
//     `docker ps -a` pass with stable template accessors) — feeds the
//     Containers page's State badges + settle watch; honors an optional
//     `names` selection.
//   - 'containerStats': per-container CPU/RAM/I-O from ONE bounded
//     `docker stats --no-stream` pass (the same source the TrueNAS plugin uses).
// Unknown keys are ignored; an empty/absent list means "the default set".
// ---------------------------------------------------------------------------
const PROBE_KEYS = new Set(['systemStats', 'traffic', 'deviceTime', 'containerStates', 'containerStats']);

app.post('/probe', probeHandler(async (body: ProbeRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  if (!body.managementAddress) throw new Error('Missing managementAddress');
  const { host, port } = targetOf(body.managementAddress, settings);
  if (!host) throw new Error(`Unparseable management address "${body.managementAddress}"`);

  const backend = await backendFor(host, port, body.credentials as Record<string, unknown>, settings);
  if (!backend) throw new Error('No SSH credential bound — probe unavailable');

  const keys = Array.isArray(body.keys) && body.keys.length > 0 ? body.keys : ['systemStats'];
  const want = (k: string): boolean => keys.includes(k);

  const metrics: Record<string, unknown> = {};
  if (want('containerStates') || want('containerStats')) {
    // Container live data — one cheap `docker ps -a` (+ one bounded docker stats
    // pass). null = transport failure → throw (webapp keeps last good data); an
    // EMPTY map is a valid answer (no containers at all) and must reach the caller.
    const nameSel = Array.isArray(body.names) && body.names.length > 0 ? body.names : undefined;
    const [states, stats] = await Promise.all([
      want('containerStates') ? collectProbeStates(backend, nameSel) : Promise.resolve(null),
      want('containerStats') ? collectProbeStats(backend) : Promise.resolve(null),
    ]);
    if (want('containerStates')) {
      if (!states) throw new Error('Docker states probe returned no data');
      const flat: Record<string, ProbeContainerState> = {};
      for (const [name, s] of states) flat[name] = s;
      metrics['containerStates'] = flat;
    }
    if (want('containerStats')) {
      if (!stats) throw new Error('Docker stats probe returned no data');
      const flat: Record<string, ProbeContainerStat> = {};
      for (const [name, s] of stats) flat[name] = s;
      metrics['containerStats'] = flat;
    }
  } else if (want('deviceTime')) {
    // Cheap single read — the clock is the only thing a Time-page refresh needs.
    const sections = await backend.runSections([
      { name: 'date', cmd: "date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z" },
      { name: 'tz', cmd: "echo \"TZFILE=$(cat /etc/timezone 2>/dev/null)\"; echo \"SYMLINK=$(readlink -f /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')\"" },
    ]).catch(() => new Map<string, string>());
    const localIso = (sections.get('date') ?? '').trim().split('\n')[0]?.trim() ?? '';
    if (!localIso) throw new Error('SSH date probe returned no data');
    metrics['system.deviceTime'] = buildDeviceTimeInfo(localIso, null) ?? { localIso };
  } else {
    // systemStats + traffic in ONE combined round-trip.
    const live = await collectLive(backend);
    Object.assign(metrics, live.metrics);
  }

  return { collectedAt: new Date().toISOString(), metrics };
}, 'generic-ssh-plugin'));

// ---------------------------------------------------------------------------
// POST /filesystem — generic, root-scoped SFTP file manager (capability
// 'filesystem'). The webapp's Storage page browses a mounted filesystem and the
// DeviceDetail page offers a "Files" button for the whole tree; both drive this
// ONE endpoint through the API broker. The caller passes `context` describing
// WHAT to browse:
//   { kind: 'root' }                    → root = '/' (the full device tree)
//   { kind: 'mount', mountpoint }       → root = that df-reported mountpoint
// Every subsequent `path` is resolved RELATIVE to that root and confined to it —
// a webapp-supplied relative path can never walk out of the scoped tree (the SDK
// rejects `..` traversal + root escape). Requires an SSH credential.
// Ops: list | read | stat | write | mkdir | rmdir | unlink | rename.
// ---------------------------------------------------------------------------

/** Process-wide SFTP session pool — one connection per host+root, reused across requests. */
const fsSftpPool = createSftpPool();
process.on('SIGTERM', () => {
  fsSftpPool.closeAll();
  closeSshPools();
  termPool.closeAll();
});
process.on('SIGINT', () => {
  fsSftpPool.closeAll();
  closeSshPools();
  termPool.closeAll();
});

app.post(
  '/filesystem',
  filesystemHandler(async (body, req) => {
    const settings = readSettings(req, PLUGIN_OPTIONS);
    logger.setEnabled(settings.logToApi === true);

    const host = hostFromAddress(body.managementAddress);
    if (!host) throw new Error('Missing managementAddress');

    // The primary credential IS an SSH login by definition of this plugin —
    // SFTP browses the tree as that user (no elevation: file access stays
    // scoped to what the login user can see).
    const sshCreds = resolveSshCredentials(body.credentials as Record<string, unknown> | undefined);
    if (!sshCreds) throw new Error('No SSH credential bound — filesystem browsing unavailable');

    // Resolve the SFTP root from the caller's context (what to browse).
    const ctx = body.context ?? {};
    let root: string;
    const kind = typeof ctx['kind'] === 'string' ? (ctx['kind'] as string) : '';
    if (kind === 'root') {
      root = '/';
    } else if (kind === 'mount') {
      const mp = typeof ctx['mountpoint'] === 'string' ? (ctx['mountpoint'] as string).trim() : '';
      if (!mp || !mp.startsWith('/')) throw new Error('mount context requires an absolute "mountpoint"');
      root = mp;
    } else {
      throw new Error(`Unsupported filesystem context kind "${kind || '(none)'}" — expected "root" or "mount"`);
    }

    // One pooled SFTP session per host+root; every path is confined to `root`.
    const fsPort = sshPortOf(settings);
    const session = await fsSftpPool.get(host, fsPort, sshCreds, { root, timeoutMs: 30_000, hostKeyVerifier: dynamicSshHostVerifier(host, fsPort) });
    const op = body.op;
    const relPath = typeof body.path === 'string' ? body.path : '';

    switch (op) {
      case 'list': {
        const abs = session.resolve(relPath);
        const r = await session.list(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: r.path, entries: r.entries.map((e) => ({ name: e.name, isDirectory: e.isDirectory, sizeBytes: e.sizeBytes, mtimeMs: e.mtimeMs })) };
      }
      case 'stat': {
        const abs = session.resolve(relPath);
        const s = await session.stat(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs, isDirectory: s.isDirectory, sizeBytes: s.sizeBytes, mtimeMs: s.mtimeMs };
      }
      case 'read': {
        const abs = session.resolve(relPath);
        const buf = await session.readFile(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs, contentBase64: buf.toString('base64'), sizeBytes: buf.length };
      }
      case 'write': {
        if (typeof body.contentBase64 !== 'string') throw new Error('write requires contentBase64');
        const abs = session.resolve(relPath);
        await session.writeFile(abs, Buffer.from(body.contentBase64, 'base64'), sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'mkdir': {
        if (!relPath) throw new Error('mkdir requires a path');
        const abs = session.resolve(relPath);
        await session.mkdir(abs, sshCreds, body.parents === true);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'rmdir': {
        if (!relPath) throw new Error('rmdir requires a path');
        const abs = session.resolve(relPath);
        await session.rmdir(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'unlink': {
        if (!relPath) throw new Error('unlink requires a path');
        const abs = session.resolve(relPath);
        await session.unlink(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'rename': {
        if (!relPath || typeof body.targetPath !== 'string' || !body.targetPath) throw new Error('rename requires path + targetPath');
        const from = session.resolve(relPath);
        const to = session.resolve(body.targetPath);
        await session.rename(from, to, sshCreds);
        return { collectedAt: new Date().toISOString(), path: to };
      }
      default:
        throw new Error(`Unsupported filesystem op "${op}"`);
    }
  }, 'generic-ssh-plugin')
);

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one device. This is the unit
// of work the API's config-job worker + plan executor dispatch (registry shape:
// {actionId, input, credentials}). The plugin owns ALL logic: it validates the
// input against the action's schema and runs the executor; the API only propagates.
// ---------------------------------------------------------------------------
app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Registry shape preferred; legacy `{action, payload}` maps onto it.
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : (typeof body.action === 'string' ? body.action : undefined);
  const input: Record<string, unknown> =
    body.input && typeof body.input === 'object'
      ? (body.input as Record<string, unknown>)
      : body.payload && typeof body.payload === 'object'
        ? (body.payload as Record<string, unknown>)
        : {};

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId (or legacy "action")' } });
    return;
  }
  if (!managementAddress) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted fields are the base (the primary
  // username/password); bound slots arrive under credentials.slots.<name>;
  // provisioned plan material arrives namespaced by secretRef and is merged as-is.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  try {
    const host = hostFromAddress(managementAddress);
    if (!host) throw new Error(`Unparseable management address "${managementAddress}"`);
    const backend = await backendFor(host, sshPortOf(settings), creds, settings);
    if (!backend) {
      res.status(200).json({ success: false, result: { error: 'No SSH credential bound — configuration actions unavailable.' } });
      return;
    }

    // Validate input against the action's declared schema — the plugin is the
    // authority on what it accepts.
    const issues = validateInput(action.inputSchema, input);
    if (issues.length > 0) {
      res.status(200).json({ success: false, result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` } });
      return;
    }

    const ctx: ActionContext = { backend, host, deviceId, credentials: creds };
    const result = await action.execute(ctx, input);
    if (!result.success) {
      logger.warn(`Config action ${actionId} reported failure for ${managementAddress}: ${typeof result.error === 'string' ? result.error : JSON.stringify(result.details ?? {})}`, { deviceId, context: { host: managementAddress, actionId } });
    }
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { host: managementAddress, actionId } });
    // Transport-level failures (SSH channel down / device not ready yet) are
    // transient — the plan executor re-dispatches them per the plan's retry
    // policy. Command-level failures already come back as ok:false results.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
  }
});

// ---------------------------------------------------------------------------
// POST /plan — plans a multi-device intent (or fans out a single action across a
// batch). The plugin does ALL the planning — cross-device references, dependency
// ordering, credential provisioning requests. It never generates key material:
// provisionRequests are non-secret descriptors the API persists with the plan;
// the secrets provider owns crypto.
// ---------------------------------------------------------------------------
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};

  const planReq: PlanRequest = {
    intent: {
      actionId: typeof body.intent?.actionId === 'string' ? body.intent.actionId : '',
      inputs: (body.intent?.inputs && typeof body.intent.inputs === 'object' ? body.intent.inputs : {}) as Record<string, unknown>,
    },
    devices: Array.isArray(body.devices)
      ? (body.devices as PlanRequest['devices']).map((d) => ({
          deviceId: String(d.deviceId),
          managementAddress: String(d.managementAddress ?? ''),
          credentials: (d.credentials && typeof d.credentials === 'object' ? d.credentials : {}) as Record<string, unknown>,
        }))
      : [],
  };

  try {
    const plan = buildPlan(planReq);
    res.status(200).json({ plan });
  } catch (err) {
    if (err instanceof PlanningError) {
      logger.error(`Planning ${planReq.intent.actionId} failed: ${err.message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
      res.status(400).json({ error: err.message });
      return;
    }
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${(err as Error).message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: (err as Error).message });
  }
});

// ---------------------------------------------------------------------------
// POST /state — dynamic device-state document for the UNM Config page. The API
// broker calls this with fresh credentials + injected settings and returns the
// response verbatim to the webapp. Built from FRESH reads so it always reflects
// current configuration; read-only (writes flow through actions).
// ---------------------------------------------------------------------------
app.post('/state', stateHandler(async (body: StateRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  if (!body.managementAddress) throw new Error('Missing managementAddress');

  // Credentials: the assignment's decrypted fields are at top level of
  // `credentials` (primary username/password) — same model as /config.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  const host = hostFromAddress(body.managementAddress);
  if (!host) throw new Error(`Unparseable management address "${body.managementAddress}"`);
  const backend = await backendFor(host, sshPortOf(settings), creds, settings);
  if (!backend) throw new Error('No SSH credential bound — device state unavailable.');

  return buildGenericSshState(backend);
}, 'generic-ssh-plugin'));

// --- Startup --------------------------------------------------------------------

server.listen();
