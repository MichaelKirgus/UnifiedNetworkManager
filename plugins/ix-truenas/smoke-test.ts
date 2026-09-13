/**
 * End-to-end smoke test for the TrueNAS plugin (first config-capable release).
 *
 * Boots a MOCK TrueNAS appliance — a WebSocket JSON-RPC server at /api/current
 * answering the documented methods the plugin calls — then boots the REAL plugin
 * (importing src/index.ts, which listens on PORT) and exercises:
 *   - GET  /discover    → capabilities include configuration+planning+deviceState; catalog present
 *   - POST /monitoring  → system/pools/networks/ports metrics collected from the mock
 *   - POST /state       → Pools + Interfaces + System sections with power actions
 *   - POST /config      → read action executes; system.reboot returns a job id; unknown → success:false
 *   - POST /plan        → single-device fan-out yields one step per device
 */
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';

const MOCK_PORT = 48761;
const PLUGIN_PORT = 48762;
const BASE = `http://localhost:${PLUGIN_PORT}`;

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra) : '');
  }
}

// --- Mock TrueNAS appliance (WebSocket JSON-RPC at /api/current) ----------------------

const httpServer = http.createServer((_req, res) => {
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', (req, socket, head) => {
  if ((req.url ?? '').split('?')[0] !== '/api/current') {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws));
});

wss.on('connection', (ws: WebSocket) => {
  let authenticated = false;
  ws.on('message', (raw) => {
    const msg = JSON.parse(String(raw)) as { id?: number; method?: string; params?: unknown[] };
    const reply = (result: unknown, error?: { code: number; message: string }) => {
      if (!ws.readyState || ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify(error ? { jsonrpc: '2.0', id: msg.id, error } : { jsonrpc: '2.0', id: msg.id, result }));
    };

    switch (msg.method) {
      case 'auth.login_ex':
        authenticated = true;
        return reply({ response_type: 'SUCCESS' });
      case 'system.info':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply({
          hostname: 'mock-truenas',
          version: 'SCALE 25.04.2',
          model: 'Intel Core i7-8700',
          cores: 6,
          loadavg: [1.2, 0.9, 0.7],
          physmem: 32_212_254_720,
          uptime_seconds: 123_456,
        });
      case 'pool.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Topology is a DICT of vdev categories (real TrueNAS shape); leaf disks
        // carry `disk` (bare name) + `path` (/dev/...). da0 → tank mirror,
        // da1 → cache stripe.
        return reply([
          {
            name: 'tank', status: 'ONLINE', size: 8_796_093_022_208, allocated: 4_398_046_511_104, free: 4_398_046_511_104,
            scan: { function: 'SCRUB', state: 'SCANNING', percentage: 42 },
            topology: { data: [{ type: 'MIRROR', children: [
              { type: 'DISK', path: '/dev/da0', disk: 'da0' },
              { type: 'DISK', path: '/dev/da3', disk: 'da3' },
            ] }], log: [], cache: [], spares: [] },
          },
          {
            name: 'cache', status: 'DEGRADED', size: 1_099_511_627_776, allocated: 549_755_813_888, free: 549_755_813_888,
            topology: { data: [{ type: 'DISK', path: '/dev/da1', disk: 'da1' }], log: [], cache: [], spares: [] },
          },
        ]);
      case 'interface.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply([
          { name: 'vnet0', description: 'NET_MANAGEMENT', state: { link_state: 'LINK_STATE_UP', link_address: 'aa:bb:cc:dd:ee:01' }, aliases: [JSON.stringify({ type: 'INET', address: '10.25.0.10', netmask: 16 })] },
          { name: 'vnet1', description: 'LAN', state: { link_state: 'LINK_STATE_DOWN', link_address: 'aa:bb:cc:dd:ee:02' }, aliases: [JSON.stringify({ type: 'INET', address: '192.168.50.1', netmask: 24 })], vlan_tag: 50 },
        ]);
      case 'alert.list':
        // Active SMART alerts (25.10+ has no public SMART API — health comes
        // from these): da1 failed a selftest, da3 uncorrected errors (both
        // WARNING ⇒ device health stays 'warning'). A dismissed CRITICAL alert
        // must NOT affect anything.
        return reply([
          { id: 'a1', klass: 'SMARTFailedSelfTestAlert', severity: 'WARNING', dismissed: false, args: { name: 'da1', serial: 'SAMSUNG-XYZ' }, text: 'da1 (SAMSUNG-XYZ) failed a SMART selftest.' },
          { id: 'a2', klass: 'SMARTUncorrectedErrorsAlert', severity: 'WARNING', dismissed: false, args: { name: '/dev/da3', serial: 'WD-ABC456' }, text: '12 uncorrectable errors reported for /dev/da3 (WD-ABC456).' },
          { id: 'a3', klass: 'SMARTSpareBlockCountAlert', severity: 'CRITICAL', dismissed: true, args: { name: 'da0', serial: 'WD-ABC123' }, text: 'dismissed — must not affect health' },
        ]);
      case 'staticroute.query':
        return reply([{ id: 1, destination: '0.0.0.0/0', gateway: '10.25.0.1', description: 'default' }]);
      case 'pool.dataset.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // MODERN shape (25.10+/26): properties FLATTENED to top-level keys; size
        // props carry bytes in `parsed` + human text as the field value. One LEGACY
        // nested entry is included too — both shapes must parse identically.
        return reply([
          {
            name: 'tank/vm', type: 'filesystem', state: 'ONLINE',
            referenced: { parsed: 1_073_741_824, value: '1 GB' },
            used: { parsed: 1_509_949_440, value: '1.4 GB' },
            quota: { parsed: 5_368_709_120, value: '5 GB' },
            mountpoint: '/mnt/tank/vm',
            compression: 'lz4', compressratio: '1.21x', readonly: false,
          },
          {
            // Nested dataset — parent must be its IMMEDIATE parent (tank/vm), not the pool.
            name: 'tank/vm/nested', type: 'filesystem', state: 'ONLINE',
            referenced: { parsed: 104_857_600, value: '100 MB' },
            mountpoint: '/mnt/tank/vm/nested',
          },
          {
            // ZVOL — block device (VM disk / iSCSI LUN), must be propagated as zfs-zvol.
            name: 'tank/zvols/disk0', type: 'volume', state: 'ONLINE',
            volsize: { parsed: 8_589_934_592, value: '8 GB' },
            used: { parsed: 2_147_483_648, value: '2 GB' },
          },
          {
            // LEGACY nested shape (pre-25.10) — must still parse.
            name: 'tank/legacy', type: 'filesystem', state: 'ONLINE',
            properties: {
              referenced: { value: 209_715_200 },
              quota: { value: 1_073_741_824, parsed: '1 GB' },
              mountpoint: '/mnt/tank/legacy',
            },
          },
          { name: 'tank@snap-1', type: 'snapshot', state: 'ONLINE', properties: {} }, // must be excluded
        ]);
      case 'disk.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply([
          // Modern shape (24.10+): `type` + integer `rotationrate`.
          { name: 'da0', model: 'WDC WD40EFRX-68N', serial: 'WD-ABC123', size: 4_000_787_035_008, type: 'HDD', rotationrate: 7200 },
          // Legacy shape (older releases): boolean `rotation_rate`, no `type`.
          { name: 'da1', model: 'Samsung SSD 970 EVO', serial: 'SAMSUNG-XYZ', size: 512_110_190_624, rotation_rate: false },
          // Second tank mirror member (CRITICAL smart alert target).
          { name: 'da3', model: 'WDC WD40EFRX-68N', serial: 'WD-ABC456', size: 4_000_787_035_008, type: 'HDD', rotationrate: 7200 },
        ]);
      case 'boot.get_disks':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Boot media is a separate device (USB stick) not in disk.query.
        return reply(['da2']);
      case 'system.datastore':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Boot media is a separate device (USB stick) not in hardware.disk.query.
        return reply({ disk: 'da2', hostname: 'mock-truenas' });
      case 'system.dmidecode_info':
        return reply({ 'baseboard-product-name': 'To Be Filled By O.E.M.', 'system-serial-number': 'TN-SERIAL-001' });
      case 'system.reboot':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(42); // job id — the appliance will go down shortly
      case 'system.shutdown':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(43);
      // --- Shares-page methods (SMB/NFS exports + live client sessions) -------
      case 'sharing.smb.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // MODERN shape (25.10+/26): rows carry their own path + enabled.
        return reply([
          { id: 1, name: 'tank/vm', path: '/mnt/tank/vm', dataset: 'tank/vm', enabled: true, comment: 'VM exports' },
          { id: 2, name: 'public', path: '/mnt/public', dataset: null, enabled: false, comment: '' },
        ]);
      case 'sharing.nfs.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // NFS shares are keyed by their exported path.
        return reply([
          { id: 38, path: '/mnt/tank/vm', ro: false, hosts: ['*'], enabled: true },
          { id: 42, path: '/mnt/tank/legacy', ro: true, hosts: [], enabled: true },
        ]);
      case 'smb.status':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // NO info-level filter → includes per-share share_connections. Two sessions:
        // one with two open shares (tank/vm + public), one IPC$-only (no rows).
        return reply([
          {
            session_id: '100', username: 'alice', remote_machine: '192.168.50.20',
            creation_time: new Date(Date.now() - 3_600_000).toISOString(), session_dialect: 'SMB3_11',
            share_connections: [
              { service: 'tank/vm', machine: '192.168.50.20' },
              { service: 'public', machine: '192.168.50.20' },
            ],
          },
          {
            session_id: '200', username: 'bob', remote_machine: '192.168.50.30',
            creation_time: new Date(Date.now() - 60_000).toISOString(), session_dialect: 'SMB2_10',
            share_connections: [{ service: 'IPC$', machine: '192.168.50.30' }],
          },
        ]);
      case 'nfs.get_nfs3_clients':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // export = "<client>:/mnt/path" — the path IS the NFS share's identity.
        return reply([
          { ip: '192.168.50.40', export: '192.168.50.40:/mnt/tank/vm' },
          { ip: '192.168.50.41', export: '192.168.50.41:/mnt/tank/legacy' },
        ]);
      case 'nfs.get_nfs4_clients':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Wrappers of {info:{address, clientid, status}} — no per-export identity.
        return reply([
          { info: { address: '192.168.50.42', clientid: '0xabc', status: 'ACTIVE' } },
        ]);
      default:
        return reply(null, { code: -32601, message: `Method ${msg.method} does not exist` });
    }
  });
});

// --- Test driver -----------------------------------------------------------------------

async function main(): Promise<void> {
  await new Promise<void>((r) => httpServer.listen(MOCK_PORT, () => r()));
  console.log(`[smoke] mock TrueNAS (ws JSON-RPC) on :${MOCK_PORT}`);

  process.env.PORT = String(PLUGIN_PORT);
  await import('./src/index');
  await new Promise((r) => setTimeout(r, 300));
  console.log(`[smoke] plugin on :${PLUGIN_PORT}`);

  const creds = { username: 'root', password: 'truenas' };
  // The mock is plain HTTP — the client picks ws/wss from the `transport` setting
  // (auto → wss), so inject transport=http on every call via x-unm-settings.
  const ADDR = `localhost:${MOCK_PORT}`;
  const SETTINGS = JSON.stringify({ transport: 'http' });
  const post = (path: string, body: unknown) =>
    fetch(`${BASE}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-unm-settings': SETTINGS }, body: JSON.stringify(body) });

  // --- /discover -----------------------------------------------------------------------
  const disc = (await (await fetch(`${BASE}/discover`)).json()) as Record<string, unknown>;
  console.log('\n== /discover ==');
  check('uuid is the TrueNAS plugin uuid', disc.uuid === '00000000-0000-4000-8000-000000000009', disc.uuid);
  const caps = (disc.capabilities ?? []) as string[];
  check('capabilities include configuration+planning+deviceState', ['configuration', 'planning', 'deviceState'].every((c) => caps.includes(c)), caps);
  const actions = (disc.actions ?? []) as { id: string; riskLevel: string }[];
  check('action catalog has all expected actions', ['containers.stop','containers.start','containers.restart','containers.upgrade','containers.delete','images.delete','compose.config.read','containers.update','alerts.dismiss','alerts.undismiss','shares.smb.create','shares.smb.update','shares.smb.delete','shares.nfs.create','shares.nfs.update','shares.nfs.delete','shares.iscsi.create','shares.iscsi.delete','shares.nvmeof.create','shares.nvmeof.delete'].every((id) => actions.some((a) => a.id === id)), `count=${actions.length}`);
  check('dangerous destructive/power actions marked', actions.filter((a) => a.riskLevel === 'dangerous').map((a) => a.id).sort().join(',') === ['containers.delete','images.delete','system.reboot','system.shutdown','vms.delete','storage.delete','shares.smb.delete','shares.nfs.delete','shares.iscsi.delete','shares.nvmeof.delete'].sort().join(','));

  // --- /monitoring ---------------------------------------------------------------------
  const mon = (await post('/monitoring', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds })) as Response;
  const monJson = (await mon.json()) as { health?: string; metrics?: Record<string, unknown> };
  console.log('\n== /monitoring ==');
  // The mock includes a DEGRADED pool ('cache') → health must be warning, not ok.
  check('health warning (degraded pool present)', monJson.health === 'warning', { health: monJson.health, err: monJson.metrics?.['system.error'] });
  const m = monJson.metrics ?? {};
  check('hostname + version collected', m['system.hostname'] === 'mock-truenas' && m['system.version'] === 'SCALE 25.04.2');
  check('CPU load computed from loadavg/cores', typeof m['system.cpuLoad'] === 'number', m['system.cpuLoad']);
  const pools = (m['pools'] ?? []) as Record<string, unknown>[];
  check('pools table has 2 rows', pools.length === 2, `count=${pools.length}`);
  check('pool usage gauge computed', typeof m['storage.poolUsedPct'] === 'number' && (m['storage.poolUsedPct'] as number) > 0, m['storage.poolUsedPct']);
  const networks = (m['networks'] ?? []) as Record<string, unknown>[];
  check('networks inventory emitted (one row per IP alias)', networks.length === 2 && networks.some((r) => r.name === 'NET_MANAGEMENT' && r.ip === '10.25.0.10'), networks);
  const ports = (m['ports'] ?? []) as Record<string, unknown>[];
  check('ports[] inventory emitted with live state + MAC', ports.length === 2 && ports.some((p) => p.name === 'NET_MANAGEMENT' && p.status === 'up' && (p.extra as Record<string, unknown>)?.mac === 'aa:bb:cc:dd:ee:01'), ports);
  check('ports[] carries vlanId for VLAN interfaces', ports.some((p) => p.name === 'LAN' && p.vlanId === 50), ports);

  // --- Storage inventory (Storage page): filesystems[] + disks[] --------------
  const fsRows = (m['filesystems'] ?? []) as Record<string, unknown>[];
  check('filesystems[] emitted: 2 pools + 4 datasets/zvols (snapshot excluded)', fsRows.length === 6 && fsRows.some((r) => r.name === 'tank' && r.type === 'zfs-pool') && fsRows.some((r) => r.name === 'tank/vm' && r.type === 'zfs-dataset'), fsRows);
  const dsRow = fsRows.find((r) => r.name === 'tank/vm');
  check('dataset extra carries ZFS props for config/state use', !!dsRow && (dsRow.extra as Record<string, unknown>)?.quota === 5_368_709_120 && (dsRow.extra as Record<string, unknown>)?.compression === 'lz4' && (dsRow.extra as Record<string, unknown>)?.referenced === 1_073_741_824, dsRow?.extra);
  check('dataset parent is the POOL for top-level datasets', dsRow?.parent === 'tank', dsRow?.parent);
  // Per-dataset size/used/free (the user's ask): filesystems use referenced as
  // used + quota as capacity; free = cap - used.
  check('dataset carries its own size/used/free (quota-based)', !!dsRow && dsRow.sizeBytes === 5_368_709_120 && dsRow.usedBytes === 1_073_741_824 && dsRow.freeBytes === 4_294_967_296, { size: dsRow?.sizeBytes, used: dsRow?.usedBytes, free: dsRow?.freeBytes });
  check('dataset mountpoint parsed from flattened string', dsRow?.mountpoint === '/mnt/tank/vm', dsRow?.mountpoint);
  const nestedRow = fsRows.find((r) => r.name === 'tank/vm/nested');
  check('nested dataset parent is its IMMEDIATE parent (hierarchy)', nestedRow?.type === 'zfs-dataset' && nestedRow?.parent === 'tank/vm', nestedRow);
  check('dataset without quota: used set, size null (unlimited)', !!nestedRow && nestedRow.usedBytes === 104_857_600 && nestedRow.sizeBytes === null && nestedRow.freeBytes === null, { size: nestedRow?.sizeBytes, used: nestedRow?.usedBytes });
  const zvolRow = fsRows.find((r) => r.name === 'tank/zvols/disk0');
  check('zvols propagated as zfs-zvol with volsize-based capacity', !!zvolRow && zvolRow.type === 'zfs-zvol' && zvolRow.parent === 'tank/zvols' && zvolRow.sizeBytes === 8_589_934_592 && zvolRow.usedBytes === 2_147_483_648 && zvolRow.freeBytes === 6_442_450_944, { size: zvolRow?.sizeBytes, used: zvolRow?.usedBytes, free: zvolRow?.freeBytes });
  const legacyRow = fsRows.find((r) => r.name === 'tank/legacy');
  check('LEGACY nested property shape still parses', !!legacyRow && legacyRow.sizeBytes === 1_073_741_824 && legacyRow.usedBytes === 209_715_200 && legacyRow.mountpoint === '/mnt/tank/legacy', { size: legacyRow?.sizeBytes, used: legacyRow?.usedBytes });
  const diskRows = (m['disks'] ?? []) as Record<string, unknown>[];
  check('disks[] emitted: 3 disks + boot media', diskRows.length === 4 && diskRows.some((d) => d.name === 'da0' && d.rotationRate === 'hdd') && diskRows.some((d) => d.name === 'da1' && d.rotationRate === 'ssd'), diskRows);
  check('boot media tagged with boot-pool', diskRows.some((d) => d.name === 'da2' && d.poolName === 'boot-pool'), diskRows);
  // Pool membership from the pool.query topology dict (leaf `disk`/`path`).
  check('disks tagged with their pool via topology walk', diskRows.some((d) => d.name === 'da0' && d.poolName === 'tank') && diskRows.some((d) => d.name === 'da1' && d.poolName === 'cache'), diskRows);
  // SMART health from active alert.list entries (no public SMART API on 25.10+).
  check('disk without ACTIVE smart alert → healthy (dismissed CRITICAL ignored)', diskRows.some((d) => d.name === 'da0' && d.health === 'healthy'), diskRows);
  check('WARNING smart alert → degraded + text in extra', diskRows.some((d) => d.name === 'da1' && d.health === 'degraded' && typeof (d.extra as Record<string, unknown>)?.['smart'] === 'string'), diskRows);
  check('WARNING smart alert with /dev/ prefix stripped → degraded', diskRows.some((d) => d.name === 'da3' && d.health === 'degraded'), diskRows);

  // --- Shares inventory + live sessions (Shares page) -------------------------
  const shareRows = (m['shares'] ?? []) as Record<string, unknown>[];
  check('shares[] emitted: 2 SMB + 2 NFS', shareRows.length === 4 && shareRows.filter((r) => r.type === 'smb').length === 2 && shareRows.filter((r) => r.type === 'nfs').length === 2, shareRows);
  const smbVmShare = shareRows.find((r) => r.type === 'smb' && r.name === 'tank/vm');
  check('SMB share carries its own path (modern sharing.smb.query shape)', smbVmShare?.path === '/mnt/tank/vm', smbVmShare);
  check('disabled SMB share reported as disabled', shareRows.find((r) => r.type === 'smb' && r.name === 'public')?.status === 'disabled', shareRows);
  // Live session counts stamped onto SMB/NFS shares (IPC$-only sessions excluded).
  check('SMB share sessionCount stamped from live data', smbVmShare?.sessionCount === 1 && shareRows.find((r) => r.type === 'smb' && r.name === 'public')?.sessionCount === 1, shareRows);
  check('NFS share sessionCount stamped by exported path', shareRows.find((r) => r.type === 'nfs' && r.name === '/mnt/tank/vm')?.sessionCount === 1 && shareRows.find((r) => r.type === 'nfs' && r.name === '/mnt/tank/legacy')?.sessionCount === 1, shareRows);
  const sessionRows = (m['shareSessions'] ?? []) as Record<string, unknown>[];
  // 2 SMB share-connections + 2 NFSv3 clients + 1 NFSv4 client = 5 rows.
  check('shareSessions[] emitted: 2 smb + 3 nfs', sessionRows.length === 5 && sessionRows.filter((r) => r.type === 'smb').length === 2 && sessionRows.filter((r) => r.type === 'nfs').length === 3, sessionRows);
  const aliceVm = sessionRows.find((r) => r.type === 'smb' && r.shareName === 'tank/vm');
  check('SMB session carries user + client address', aliceVm?.user === 'alice' && aliceVm?.clientAddress === '192.168.50.20', aliceVm);
  check('SMB session uptime computed from creation_time', typeof aliceVm?.uptimeSeconds === 'number' && (aliceVm!.uptimeSeconds as number) >= 3_500, aliceVm);
  const nfs3Row = sessionRows.find((r) => r.type === 'nfs' && r.clientAddress === '192.168.50.40');
  check('NFSv3 export prefix stripped → share path', nfs3Row?.shareName === '/mnt/tank/vm', nfs3Row);
  const nfs4Row = sessionRows.find((r) => r.type === 'nfs' && r.clientAddress === '192.168.50.42');
  check('NFSv4 client row (no per-export identity)', !!nfs4Row && nfs4Row.shareName === '', nfs4Row);

  // --- /state --------------------------------------------------------------------------
  const stateRes = await post('/state', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds });
  const stateJson = (await stateRes.json()) as { collectedAt?: string; sections?: { id: string; label: string; kind?: string; layout?: { groups: { id: string; portKeys: string[] }[] }; items?: { key: string; title: string; status?: string; fields?: Record<string, unknown>; actions?: { actionId: string }[] }[] }[] };
  console.log('\n== /state ==');
  check('HTTP 200', stateRes.status === 200);
  const sectionIds = (stateJson.sections ?? []).map((s) => s.id);
  check('has pools + interfaces + system sections', ['pools', 'interfaces', 'system'].every((id) => sectionIds.includes(id)), sectionIds);
  const poolSection = (stateJson.sections ?? []).find((s) => s.id === 'pools');
  check('2 pool items with size/used fields', poolSection?.items?.length === 2 && /TB/.test(String(poolSection.items![0].fields?.Size)), poolSection?.items);
  const degradedPool = poolSection?.items?.find((i) => i.key === 'cache');
  check('DEGRADED pool flagged critical-ish status', !!degradedPool, degradedPool);
  const ifSection = (stateJson.sections ?? []).find((s) => s.id === 'interfaces');
  const mgmtIface = ifSection?.items?.find((i) => i.key === 'NET_MANAGEMENT');
  check('management interface up with MAC + IP', mgmtIface?.status === 'up' && mgmtIface.fields?.MAC === 'aa:bb:cc:dd:ee:01' && Array.isArray(mgmtIface.fields?.IPs), mgmtIface);
  // Virtual switch face: kind + layout must cover every interface exactly once.
  const ifLayoutKeys = (ifSection?.layout?.groups ?? []).flatMap((g) => g.portKeys);
  check('interfaces section is a virtual switch', ifSection?.kind === 'switch', ifSection?.kind);
  check(
    'interface layout covers all items exactly once',
    ifLayoutKeys.length === (ifSection?.items?.length ?? 0) && new Set(ifLayoutKeys).size === ifLayoutKeys.length,
    ifLayoutKeys
  );
  const sysSection = (stateJson.sections ?? []).find((s) => s.id === 'system');
  check('system item advertises reboot + shutdown', !!sysSection?.items?.[0]?.actions && ['system.reboot', 'system.shutdown'].every((id) => sysSection.items![0].actions!.some((a) => a.actionId === id)), sysSection?.items?.[0]?.actions);

  // --- /config (read action) -----------------------------------------------------------
  const cfgRead = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'pools.read', input: {} });
  const cfgReadJson = (await cfgRead.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config pools.read ==');
  check('success true with poolCount', cfgRead.status === 200 && cfgReadJson.success === true && (cfgReadJson.result?.details as Record<string, unknown>)?.poolCount === 2, cfgReadJson);

  // --- /config (system.reboot → job id) -------------------------------------------------
  const cfgReboot = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.reboot', input: { reason: 'smoke test reboot' } });
  const cfgRebootJson = (await cfgReboot.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config system.reboot ==');
  check('success true with job id', cfgReboot.status === 200 && cfgRebootJson.success === true && ((cfgRebootJson.result?.details as Record<string, unknown>)?.jobId === 42), cfgRebootJson);

  // --- /config (validation + unknown action) -------------------------------------------
  const badInput = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.reboot', input: {} });
  const badInputJson = (await badInput.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config validation ==');
  check('missing required reason rejected', badInput.status === 200 && badInputJson.success === false && /reason/.test(String(badInputJson.result?.error)), badInputJson);

  const unknown = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'nope.nope', input: {} });
  const unknownJson = (await unknown.json()) as { success?: boolean };
  check('unknown action → 400 + success:false', unknown.status === 400 && unknownJson.success === false);

  // --- /plan (single-device fan-out) ----------------------------------------------------
  const planRes = await post('/plan', {
    intent: { actionId: 'system.reboot', inputs: { reason: 'smoke test reboot' } },
    devices: [
      { deviceId: 'devA', managementAddress: ADDR, credentials: creds },
      { deviceId: 'devB', managementAddress: ADDR, credentials: creds },
    ],
  });
  const planJson = (await planRes.json()) as { plan?: { provisionRequests: unknown[]; steps: { stepIndex: number; deviceId: string; actionId: string; input: Record<string, unknown> }[] } };
  console.log('\n== /plan system.reboot ==');
  check('HTTP 200', planRes.status === 200);
  const plan = planJson.plan!;
  check('no provision requests (TrueNAS needs no secrets)', Array.isArray(plan.provisionRequests) && plan.provisionRequests.length === 0);
  check('fan-out yields one step per device', plan.steps.length === 2 && plan.steps.every((s) => s.actionId === 'system.reboot' && s.input.reason === 'smoke test reboot'), plan.steps);

  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[smoke] fatal:', err);
  process.exit(1);
});
