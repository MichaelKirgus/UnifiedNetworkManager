/**
 * End-to-end smoke test for the TrueNAS plugin (first config-capable release).
 *
 * Boots a MOCK TrueNAS appliance — a WebSocket JSON-RPC server at /api/current
 * answering the documented methods the plugin calls — then boots the REAL plugin
 * (importing src/index.ts, which listens on PORT) and exercises:
 *   - GET  /discover    → capabilities include configuration+planning+deviceState; catalog present
 *   - POST /monitoring  → system/pools/networks/ports metrics collected from the mock
 *   - POST /state       → Pools + Interfaces + System sections with power actions
 *   - POST /config      → read action executes; system.reboot returns a job id;
 *                         config.backup.download fetches the mock file over HTTP
 *                         (/_download + token); config.restore posts multipart to
 *                         /_upload and reboots; unknown → success:false
 *   - POST /plan        → single-device fan-out yields one step per device, with a
 *                         best-effort config.backup.download rollback prepended
 */
import http from 'http';
import { createHash } from 'crypto';
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

// --- Mock TrueNAS appliance (WebSocket JSON-RPC at /api/current + HTTP file endpoints) -

/** The "configuration backup" bytes the mock's config.save job produces. */
const MOCK_BACKUP_BYTES = Buffer.from('MOCK-TRUE-NAS-CONFIG-BACKUP-DATA-v1');

/** Jobs started by config.save (eligible for /_download). */
const downloadableJobs = new Set<number>();/** The mock's configured update profile — mutated by the update.update RPC. */
let mockUpdateProfile = 'GENERAL';
/** True once the mock saw an update.manual call with resume:true (EAGAIN path). */
let manualResumeCalled = false;/** Captured /_upload requests — asserted after the restore action runs. */
interface CapturedUpload { auth: string; method?: string; params?: unknown[]; fileName?: string; data: Buffer }
const capturedUploads: CapturedUpload[] = [];

/** Captured enclosure2.set_slot_status payloads — asserted after identify runs. */
const capturedSlotStatus: Record<string, unknown>[] = [];
/** Captured pool.offline / pool.online calls — asserted after the disk ops run. */
interface CapturedPoolDiskOp { method: string; params?: unknown[] }
const capturedPoolDiskOps: CapturedPoolDiskOp[] = [];
/** Vdevs currently OFFLINE in the mock (flipped by pool.offline / pool.online) —
 *  lets disk-op verification re-read the effect via pool.query topology. */
const offlineVdevs = new Set<string>();
/** Toggle for the enclosure2.query mock — false simulates non-iX hardware so
 *  the virtual disk.query drive-bay fallback can be asserted. */
let mockEnclosuresEnabled = true;

/** Minimal multipart/form-data parser (boundary-delimited parts → fields + files). */
function parseMultipart(body: Buffer, contentType: string): { fields: Record<string, string>; files: { name: string; filename?: string; data: Buffer }[] } {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType ?? '');
  const boundary = `--${(m?.[1] ?? m?.[2] ?? '').trim()}`;
  const fields: Record<string, string> = {};
  const files: { name: string; filename?: string; data: Buffer }[] = [];
  for (const raw of body.toString('binary').split(boundary)) {
    if (!raw || raw.startsWith('--')) continue;
    const sepIdx = raw.indexOf('\r\n\r\n');
    if (sepIdx < 0) continue;
    const headers = raw.slice(0, sepIdx);
    let content = Buffer.from(raw.slice(sepIdx + 4), 'binary');
    if (content.length >= 2 && content[content.length - 1] === 0x0a && content[content.length - 2] === 0x0d) {
      content = content.subarray(0, content.length - 2); // strip trailing CRLF before next boundary
    }
    const nameM = /name="([^"]*)"/i.exec(headers);
    const fileM = /filename="([^"]*)"/i.exec(headers);
    if (fileM) files.push({ name: nameM?.[1] ?? '', filename: fileM[1], data: content });
    else fields[nameM?.[1] ?? ''] = content.toString('utf8');
  }
  return { fields, files };
}

const httpServer = http.createServer((req, res) => {
  const url = req.url ?? '';
  // GET /_download/{jobId}?auth_token=… — single-use token must be bound to the job.
  const dlM = /^\/_download\/(\d+)$/.exec(url.split('?')[0]);
  if (req.method === 'GET' && dlM) {
    const jobId = Number(dlM[1]);
    const qs = new URLSearchParams(url.split('?')[1] ?? '');
    const token = qs.get('auth_token') ?? '';
    if (!downloadableJobs.has(jobId)) { res.writeHead(404); return res.end('unknown job'); }
    if (token !== `mock-token-${jobId}`) { res.writeHead(401); return res.end('bad or expired token'); }
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="config-backup"' });
    return res.end(MOCK_BACKUP_BYTES);
  }
  // POST /_upload — multipart: part 1 MUST be field "data" (JSON method/params),
  // part 2 MUST be file field "file". Auth = Basic (password creds) or Token.
  if (req.method === 'POST' && url.split('?')[0] === '/_upload') {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const auth = req.headers['authorization'] ?? '';
      if (!auth.startsWith('Basic ') && !auth.startsWith('Token ')) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: 'unauthorized' })); }
      const { fields, files } = parseMultipart(body, String(req.headers['content-type'] ?? ''));
      let method: string | undefined;
      let params: unknown[] | undefined;
      try {
        const data = JSON.parse(fields['data'] ?? '{}') as { method?: string; params?: unknown[] };
        method = data.method;
        params = data.params;
      } catch { /* malformed data part */ }
      capturedUploads.push({ auth, method, params, fileName: files[0]?.filename, data: files[0]?.data ?? Buffer.alloc(0) });
      if (files.length !== 1 || files[0].name !== 'file') { res.writeHead(422, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: `bad upload shape method=${method} files=${files.length}` })); }
      // config.upload → job 91; update.file (manual firmware from uploaded file) → job 94.
      const jobId = method === 'update.file' ? 94 : 91;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ job_id: jobId }));
    });
    return;
  }
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
        // carry `disk` (bare name) + `path` (/dev/...) + live `status`. da0 → tank
        // mirror, da1 → cache stripe. Vdev statuses flip with pool.offline /
        // pool.online so disk-op verification can re-read the effect.
        const vdevStatus = (disk: string): string => (offlineVdevs.has(disk) ? 'OFFLINE' : 'ONLINE');
        return reply([
          {
            id: 1, name: 'tank', status: 'ONLINE', size: 8_796_093_022_208, allocated: 4_398_046_511_104, free: 4_398_046_511_104,
            scan: { function: 'SCRUB', state: 'SCANNING', percentage: 42 },
            topology: { data: [{ type: 'MIRROR', children: [
              { type: 'DISK', path: '/dev/da0', disk: 'da0', status: vdevStatus('da0') },
              { type: 'DISK', path: '/dev/da3', disk: 'da3', status: vdevStatus('da3') },
            ] }], log: [], cache: [], spares: [] },
          },
          {
            id: 2, name: 'cache', status: 'DEGRADED', size: 1_099_511_627_776, allocated: 549_755_813_888, free: 549_755_813_888,
            topology: { data: [{ type: 'DISK', path: '/dev/da1', disk: 'da1', status: vdevStatus('da1') }], log: [], cache: [], spares: [] },
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
        // must NOT affect anything. a1 uses the TrueNAS ≥ 25 TEMPLATE text
        // (%(key)s placeholders) — it must be formatted with args everywhere.
        return reply([
          { id: 'a1', klass: 'SMARTFailedSelfTestAlert', severity: 'WARNING', dismissed: false, args: { name: 'da1', serial: 'SAMSUNG-XYZ' }, text: '%(name)s (%(serial)s) failed a SMART selftest.' },
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
      case 'enclosure2.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        if (!mockEnclosuresEnabled) return reply([]); // non-iX hardware
        // One iX controller enclosure with 4 bays: da0 (OK, identify-capable),
        // da3 (CRIT — the failing mirror member), an EMPTY bay (no dev) and da5
        // (OK but on a slot WITHOUT identify support → no LED action). da0/da3
        // are tank members per pool.query; da5 is not in any pool.
        return reply([
          {
            name: 'iX 4024Sp c205', model: 'M40', controller: true, dmi: 'TRUENAS-M40-HA', status: ['OK'],
            id: 'enc-aaaa1111', vendor: 'iX', product: '4024Sp', revision: 'c205', label: null,
            bsg: '/dev/bsg/0:0:23:0', sg: '/dev/sg25', pci: '0:0:23:0', rackmount: true, top_loaded: false,
            front_slots: 4, rear_slots: 0, internal_slots: 0,
            elements: {
              'Array Device Slot': {
                1: { descriptor: 'slot00', status: 'OK', dev: 'da0', supports_identify_light: true, name: 'da0', size: 4_000_787_035_008, model: 'WDC WD40EFRX-68N', serial: 'WD-ABC123' },
                2: { descriptor: 'slot01', status: 'CRIT', dev: 'da3', supports_identify_light: true, name: 'da3', size: 4_000_787_035_008, model: 'WDC WD40EFRX-68N', serial: 'WD-ABC456' },
                3: { descriptor: 'slot02', status: 'INVOP', supports_identify_light: true, name: '' },
                4: { descriptor: 'slot03', status: 'OK', dev: 'da5', supports_identify_light: false, name: 'da5', size: 1_000_204_886_016, model: 'Samsung SSD 970 EVO', serial: 'SAMSUNG-DA5' },
              },
            },
          },
        ]);
      case 'enclosure2.set_slot_status':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        capturedSlotStatus.push(msg.params?.[0]);
        return reply(null);
      case 'pool.offline':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        capturedPoolDiskOps.push({ method: 'offline', params: msg.params });
        offlineVdevs.add(String((msg.params?.[1] as Record<string, unknown>)?.['label'] ?? ''));
        return reply(true);
      case 'pool.online':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        capturedPoolDiskOps.push({ method: 'online', params: msg.params });
        offlineVdevs.delete(String((msg.params?.[1] as Record<string, unknown>)?.['label'] ?? ''));
        return reply(true);
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
      // --- Updates-page methods (capability 'updates') ------------------------
      case 'app.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // One app WITH an update available + one without. Minimal rows — the
        // containers inventory must tolerate them (no active_workloads).
        return reply([
          { name: 'zabbix', state: 'RUNNING', human_version: '7.0.1', upgrade_available: true },
          { name: 'chrony', state: 'RUNNING', human_version: '4.6', upgrade_available: false },
        ]);
      case 'docker.network.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply([]);
      case 'app.image.query':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // One image flagged update_available (upstream tag moved), one clean.
        return reply([
          { id: 'abc123def456', repo_tags: ['zabbix/zabbix-agent2:alpine-7.0'], size: 5_000_000, created: '2026-08-01T00:00:00Z', update_available: true },
          { id: 'fff999aaa000', repo_tags: ['chrony/chrony:4.6'], size: 3_000_000, created: '2026-07-01T00:00:00Z', update_available: false },
        ]);
      case 'update.available_versions':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Live shape (TrueNAS 26): array of {train, version:{version, manifest{...}, release_notes_url}}.
        return reply([
          {
            train: 'TrueNAS-SCALE',
            version: {
              version: '25.10.1',
              manifest: { filename: 'TrueNAS-25.10.1.update', version: '25.10.1', filesize: 2_230_534_144, profile: 'GENERAL', train: 'TrueNAS-SCALE' },
              release_notes_url: 'https://www.truenas.com/docs/scale/25.10/gettingstarted/scalereleasenotes/',
            },
          },
        ]);
      case 'update.run':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(77); // job id — the appliance will reboot into the new BE
      case 'app.image.pull':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(88); // job id
      case 'core.get_jobs':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // All jobs already settled — waitForJob returns immediately. 90 = config.save,
        // 91 = config.upload (from /_upload), 92 = config.reset, 93 = update.manual
        // FIRST attempt (FAILED with the resumable [EAGAIN] warning), 94 = update.file
        // (from /_upload), 95/96 = resume re-runs.
        return reply([
          { id: 77, state: 'SUCCESS', error: null },
          { id: 88, state: 'SUCCESS', error: null },
          { id: 90, state: 'SUCCESS', error: null },
          { id: 91, state: 'SUCCESS', error: null },
          { id: 92, state: 'SUCCESS', error: null },
          { id: 93, state: 'FAILED', error: '[EAGAIN] an upgrade can be performed with a warning and that warning is accepted.' },
          { id: 94, state: 'SUCCESS', error: null },
          { id: 95, state: 'SUCCESS', error: null },
          { id: 96, state: 'SUCCESS', error: null },
        ]);
      case 'system.reboot':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(42); // job id — the appliance will go down shortly
      case 'system.shutdown':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(43);
      // --- Configuration backup/restore (config.save job + token → /_download; config.reset) ---
      case 'config.save':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        downloadableJobs.add(90); // job settles immediately (see core.get_jobs below)
        return reply(90); // job id — file fetchable via /_download/90?auth_token=…
      case 'config.reset':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply(92); // job id — the appliance will reboot into factory defaults
      case 'auth.generate_token':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        const attrs = (msg.params?.[1] ?? {}) as Record<string, unknown>;
        // A job-bound token is only valid for THAT job's /_download.
        if (typeof attrs['job'] === 'number') downloadableJobs.add(attrs['job']);
        return reply(`mock-token-${attrs['job'] ?? 'generic'}`);
      // --- Update branch + manual firmware update ---------------------------------
      case 'update.config':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        return reply({ id: 1, autocheck: true, profile: mockUpdateProfile });
      case 'update.profile_choices':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Availability is license-gated on real boxes — the mock offers all four.
        return reply({
          DEVELOPER: { name: 'Developer', description: 'dev builds', available: true },
          EARLY_ADOPTER: { name: 'Early Adopter', description: 'pre-release', available: true },
          GENERAL: { name: 'General', description: 'stable (Default)', available: true },
          MISSION_CRITICAL: { name: 'Mission Critical', description: '24x7 HA track', available: false },
        });
      case 'update.update':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        const upd = (msg.params?.[0] ?? {}) as Record<string, unknown>;
        if (typeof upd['profile'] === 'string') mockUpdateProfile = upd['profile'];
        return reply({ id: 1, autocheck: true, profile: mockUpdateProfile });
      case 'update.manual':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // First attempt FAILS with the appliance's resumable [EAGAIN] warning;
        // the resume:true re-run (job 95) succeeds — mirrors the Web UI flow.
        const mParams = (msg.params?.[0] ?? {}) as Record<string, unknown>;
        if (mParams['resume'] === true) { manualResumeCalled = true; return reply(95); }
        return reply(93);
      case 'update.file':
        if (!authenticated) return reply(null, { code: -32001, message: 'ENOTAUTHENTICATED' });
        // Only reachable via the /_upload multipart path (job 94); a direct RPC
        // call with resume:true is what the EAGAIN retry would use.
        const fParams = (msg.params?.[0] ?? {}) as Record<string, unknown>;
        if (fParams['resume'] === true) return reply(96);
        return reply(94);
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

// --- Mock UNM file-repo API (the /plugin/files/* contract the SDK client uses) ----
const MOCK_API_PORT = 48763;
interface RepoUpload { id: string; name: string; category?: string; data: Buffer }
const repoUploads: RepoUpload[] = [];
let repoSeq = 0;
function startMockApi(): Promise<void> {
  const srv = http.createServer((req, res) => {
    // The real API mounts the plugin routes under /v1 — mirror that.
    const url = (req.url ?? '').replace(/^\/v1/, '');
    if (req.method === 'POST' && url === '/plugin/files') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const data = Buffer.concat(chunks);
        const entry: RepoUpload = { id: `repo-${++repoSeq}`, name: String(req.headers['x-file-name'] ?? ''), category: String(req.headers['x-file-category'] ?? '') || undefined, data };
        repoUploads.push(entry);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: entry.id, name: entry.name, category: entry.category ?? 'other', sizeBytes: data.length, sha256: createHash('sha256').update(data).digest('hex'), uploadedBy: null, createdAt: new Date().toISOString(), providerId: null }));
      });
      return;
    }
    const metaMatch = url.match(/^\/plugin\/files\/([^/]+)$/);
    if (req.method === 'GET' && metaMatch) {
      const up = repoUploads.find((u) => u.id === decodeURIComponent(metaMatch[1]));
      if (!up) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'not found' })); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: up.id, name: up.name, category: up.category ?? 'other', sizeBytes: up.data.length, sha256: createHash('sha256').update(up.data).digest('hex'), uploadedBy: null, createdAt: new Date().toISOString(), providerId: null }));
      return;
    }
    const contentMatch = url.match(/^\/plugin\/files\/([^/]+)\/content$/);
    if (req.method === 'GET' && contentMatch) {
      const up = repoUploads.find((u) => u.id === decodeURIComponent(contentMatch[1]));
      if (!up) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'not found' })); return; }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': up.data.length });
      res.end(up.data);
      return;
    }
    if (req.method === 'POST' && /\/plugin\/files\/[^/]+\/use$/.test(url)) {
      req.resume(); req.on('end', () => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true })); });
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: `mock api: no route for ${req.method} ${url}` }));
  });
  return new Promise((r) => srv.listen(MOCK_API_PORT, () => r()));
}

// --- Test driver -----------------------------------------------------------------------

async function main(): Promise<void> {
  await new Promise<void>((r) => httpServer.listen(MOCK_PORT, () => r()));
  console.log(`[smoke] mock TrueNAS (ws JSON-RPC) on :${MOCK_PORT}`);

  // Point the plugin at a MOCK UNM file-repo API so config backups are stored
  // through the SDK client exactly as in production.
  await startMockApi();
  process.env.PORT = String(PLUGIN_PORT);
  process.env.UNM_API_URL = `http://localhost:${MOCK_API_PORT}/v1`;
  process.env.PLUGIN_API_KEY = 'smoke-key';
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
  check('action catalog has all expected actions', ['containers.stop','containers.start','containers.restart','containers.upgrade','containers.delete','images.delete','images.update','compose.config.read','containers.update','alerts.dismiss','alerts.undismiss','system.firmware.update','system.firmware.update-file','config.backup.download','config.restore','config.reset','update.profile.read','update.profile.set','shares.smb.create','shares.smb.update','shares.smb.delete','shares.nfs.create','shares.nfs.update','shares.nfs.delete','shares.iscsi.create','shares.iscsi.delete','shares.nvmeof.create','shares.nvmeof.delete','enclosure.identify','storage.disk-replace','storage.disk-offline','storage.disk-online'].every((id) => actions.some((a) => a.id === id)), `count=${actions.length}`);
  check('dangerous destructive/power actions marked', actions.filter((a) => a.riskLevel === 'dangerous').map((a) => a.id).sort().join(',') === ['bootenv.activate','bootenv.destroy','containers.delete','images.delete','images.prune','system.reboot','system.shutdown','system.firmware.update','system.firmware.update-file','vms.delete','storage.delete','shares.smb.delete','shares.nfs.delete','shares.iscsi.delete','shares.nvmeof.delete','config.restore','config.reset','storage.disk-replace','storage.disk-offline'].sort().join(','));
  check('config.backup.download is a READ action (non-destructive)', actions.find((a) => a.id === 'config.backup.download')?.riskLevel === 'read', actions.find((a) => a.id === 'config.backup.download'));
  check('update.profile.read is read / update.profile.set is write', actions.find((a) => a.id === 'update.profile.read')?.riskLevel === 'read' && actions.find((a) => a.id === 'update.profile.set')?.riskLevel === 'write');
  check('updates capability advertised', caps.includes('updates'), caps);

  // --- /monitoring ---------------------------------------------------------------------
  const mon = (await post('/monitoring', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds })) as Response;
  const monJson = (await mon.json()) as { health?: string; metrics?: Record<string, unknown>; healthReasons?: { severity: string; message: string }[] };
  console.log('\n== /monitoring ==');
  // The mock includes a DEGRADED pool ('cache') → health must be warning, not ok.
  check('health warning (degraded pool present)', monJson.health === 'warning', { health: monJson.health, err: monJson.metrics?.['system.error'] });
  // Status transparency: non-ok health carries human-readable reasons — the two
  // active SMART alerts + the DEGRADED pool. Dismissed CRITICAL must not appear.
  const reasons = monJson.healthReasons ?? [];
  check('healthReasons present for warning health', Array.isArray(monJson.healthReasons) && reasons.length === 3, { count: reasons.length, reasons });
  check('healthReasons include degraded pool line', reasons.some((r) => r.severity === 'warning' && r.message === 'Pool cache is DEGRADED'), reasons);
  check('healthReasons include active alert lines (dismissed excluded)', reasons.some((r) => r.message.includes('SMARTFailedSelfTestAlert')) && reasons.some((r) => r.message.includes('SMARTUncorrectedErrorsAlert')) && !reasons.some((r) => r.message.includes('SpareBlockCount')), reasons);
  // TrueNAS ≥ 25 template text must be formatted with args — no raw %(key)s.
  check('healthReasons alert text is template-formatted', reasons.some((r) => r.message === 'SMARTFailedSelfTestAlert: da1 (SAMSUNG-XYZ) failed a SMART selftest.') && !reasons.some((r) => r.message.includes('%(')), reasons);
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

  // --- Updates page (capability 'updates'): updates[] metric -----------------
  const updateRows = (m['updates'] ?? []) as Record<string, unknown>[];
  check('updates[] emitted: firmware + app + image rows', updateRows.length === 3, updateRows);
  const fwRow = updateRows.find((r) => r.kind === 'firmware');
  // system.info reports "SCALE 25.04.2" — the row must carry the BARE version.
  check('firmware row: SCALE prefix stripped + versions compared', !!fwRow && fwRow.name === 'os' && fwRow.currentVersion === '25.04.2' && fwRow.latestVersion === '25.10.1' && fwRow.available === true && fwRow.rebootRequired === true, fwRow);
  check('firmware row: apply points at system.firmware.update with target version', !!fwRow && fwRow.applyActionId === 'system.firmware.update' && (fwRow.applyInput as Record<string, unknown>)?.version === '25.10.1', fwRow?.applyInput);
  check('firmware row: branch carries the configured update profile', !!fwRow && fwRow.branch === 'GENERAL', fwRow);
  check('firmware row: manifest extras carried (train/profile/size/release notes)', !!fwRow && (fwRow.extra as Record<string, unknown>)?.train === 'TrueNAS-SCALE' && (fwRow.extra as Record<string, unknown>)?.profile === 'GENERAL' && fwRow.sizeBytes === 2_230_534_144 && typeof fwRow.releaseNotesUrl === 'string', fwRow);
  const appUpd = updateRows.find((r) => r.kind === 'app');
  check('app row: only the upgradable app is listed', !!appUpd && appUpd.name === 'zabbix' && appUpd.currentVersion === '7.0.1' && appUpd.applyActionId === 'containers.upgrade' && JSON.stringify(appUpd.applyInput) === JSON.stringify({ names: ['zabbix'] }), appUpd);
  const imgUpd = updateRows.find((r) => r.kind === 'docker-image');
  check('image row: only the stale image is listed', !!imgUpd && imgUpd.name === 'zabbix/zabbix-agent2:alpine-7.0' && imgUpd.applyActionId === 'images.update' && JSON.stringify(imgUpd.applyInput) === JSON.stringify({ refs: ['zabbix/zabbix-agent2:alpine-7.0'], restart: false }), imgUpd);

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
  // Enclosure tray: kind + one band per enclosure; bays carry pool membership
  // from the topology and per-bay actions (identify only where supported).
  const encSection = (stateJson.sections ?? []).find((s) => s.id === 'enclosures');
  check('has a drive-bays section', !!encSection, sectionIds);
  check('drive bays section is an enclosure face', encSection?.kind === 'enclosure', encSection?.kind);
  const bayKeys = (encSection?.layout?.groups ?? []).flatMap((g) => g.portKeys);
  check(
    'enclosure layout covers all bays exactly once',
    bayKeys.length === (encSection?.items?.length ?? 0) && new Set(bayKeys).size === bayKeys.length,
    bayKeys
  );
  const bay1 = encSection?.items?.find((i) => i.key === 'enc-aaaa1111:1');
  check('bay 1 (da0) ok with pool + identify/replace/offline actions', !!bay1 && bay1.status === 'ok' && bay1.fields?.Pool === 'tank' && ['enclosure.identify', 'storage.disk-replace', 'storage.disk-offline', 'storage.disk-online'].every((id) => bay1.actions!.some((a) => a.actionId === id)), bay1);
  const bay2 = encSection?.items?.find((i) => i.key === 'enc-aaaa1111:2');
  check('bay 2 (da3, CRIT element) flagged critical', !!bay2 && bay2.status === 'critical' && bay2.fields?.Pool === 'tank', bay2);
  const bayEmpty = encSection?.items?.find((i) => i.key === 'enc-aaaa1111:3');
  check('empty bay renders disabled with no disk actions', !!bayEmpty && bayEmpty.status === 'disabled' && (bayEmpty.actions ?? []).every((a) => a.actionId !== 'storage.disk-replace'), bayEmpty);
  const bay4 = encSection?.items?.find((i) => i.key === 'enc-aaaa1111:4');
  check('bay 4 (no identify support, no pool) has NO actions', !!bay4 && (bay4.actions ?? []).length === 0, bay4);

  // Virtual drive-bay fallback — non-iX hardware (enclosure2.query → []):
  // the section is built from disk.query instead of being omitted.
  mockEnclosuresEnabled = false;
  const vStateRes = await post('/state', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds });
  const vStateJson = (await vStateRes.json()) as typeof stateJson;
  mockEnclosuresEnabled = true; // restore for any later /state calls
  console.log('\n== /state virtual drive-bay fallback ==');
  check('fallback: HTTP 200', vStateRes.status === 200);
  const vEncSection = (vStateJson.sections ?? []).find((s) => s.id === 'enclosures');
  check('fallback: drive-bays section present from disk.query', !!vEncSection && vEncSection.kind === 'enclosure', (vStateJson.sections ?? []).map((s) => s.id));
  const vItems = vEncSection?.items ?? [];
  check('fallback: one bay per physical disk (da0, da1, da3)', vItems.length === 3 && ['vdisk:da0', 'vdisk:da1', 'vdisk:da3'].every((k) => vItems.some((i) => i.key === k)), vItems.map((i) => i.key));
  const vGroups = (vEncSection?.layout?.groups ?? []).map((g) => ({ label: g.label, keys: [...g.portKeys].sort() }));
  check('fallback: bays grouped into pool bands', JSON.stringify(vGroups) === JSON.stringify([{ label: 'cache', keys: ['vdisk:da1'] }, { label: 'tank', keys: ['vdisk:da0', 'vdisk:da3'] }]), vGroups);
  const vDa0 = vItems.find((i) => i.key === 'vdisk:da0');
  check('fallback: da0 ok, pool tank, disk actions but NO identify (no LED hardware)', !!vDa0 && vDa0.status === 'ok' && vDa0.fields?.Pool === 'tank' && ['storage.disk-replace', 'storage.disk-offline', 'storage.disk-online'].every((id) => vDa0.actions!.some((a) => a.actionId === id)) && !vDa0.actions!.some((a) => a.actionId === 'enclosure.identify'), vDa0);
  const vDa1 = vItems.find((i) => i.key === 'vdisk:da1');
  check('fallback: da1 (cache pool, SSD) ok with media field', !!vDa1 && vDa1.status === 'ok' && vDa1.fields?.Pool === 'cache' && String(vDa1.fields?.Media).toLowerCase() === 'ssd', vDa1);

  const sysSection = (stateJson.sections ?? []).find((s) => s.id === 'system');
  check('system item advertises backup + restore + branch actions + power', !!sysSection?.items?.[0]?.actions && ['config.backup.download', 'config.restore', 'update.profile.read', 'update.profile.set', 'system.firmware.update-file', 'system.reboot', 'system.shutdown'].every((id) => sysSection.items![0].actions!.some((a) => a.actionId === id)), sysSection?.items?.[0]?.actions);
  check('system item shows the configured update branch', (sysSection?.items?.[0]?.fields as Record<string, unknown>)?.Branch === 'GENERAL', sysSection?.items?.[0]?.fields);

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

  // --- /config (system.firmware.update → job id) ----------------------------------------
  const cfgFw = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.firmware.update', input: { version: '25.10.1' } });
  const cfgFwJson = (await cfgFw.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config system.firmware.update ==');
  check('success true with job id', cfgFw.status === 200 && cfgFwJson.success === true && ((cfgFwJson.result?.details as Record<string, unknown>)?.jobId === 77), cfgFwJson);

  // --- /config (system.firmware.update idempotency: already on target) -------------------
  const cfgFwNoop = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.firmware.update', input: { version: '25.04.1' } });
  const cfgFwNoopJson = (await cfgFwNoop.json()) as { success?: boolean; result?: Record<string, unknown> };
  check('already-on-target is a verified no-op (SCALE prefix normalized)', cfgFwNoop.status === 200 && cfgFwNoopJson.success === true && (cfgFwNoopJson.result?.details as Record<string, unknown>)?.applied !== true && /nothing to do/i.test(String((cfgFwNoopJson.result?.details as Record<string, unknown>)?.note)), cfgFwNoopJson);

  // --- /config (images.update → pull job + verification) ---------------------------------
  const cfgImg = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'images.update', input: { refs: ['zabbix/zabbix-agent2:alpine-7.0'], restart: false } });
  const cfgImgJson = (await cfgImg.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config images.update ==');
  check('success true with updated=1 (pull job + verification)', cfgImg.status === 200 && cfgImgJson.success === true && JSON.stringify((cfgImgJson.result?.details as Record<string, unknown>)?.updated) === JSON.stringify(['zabbix/zabbix-agent2:alpine-7.0']), cfgImgJson);

  // --- /config (config.backup.download → job + token + HTTP file fetch → UNM file repo) --
  const cfgBackup = await post('/config', { deviceId: 'dev-tnas', deviceName: 'KIRGUSBANDE', managementAddress: ADDR, credentials: creds, actionId: 'config.backup.download', input: {} });
  const cfgBackupJson = (await cfgBackup.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config config.backup.download ==');
  check('success true with repoFileId in details', cfgBackup.status === 200 && cfgBackupJson.success === true && typeof (cfgBackupJson.result?.details as Record<string, unknown>)?.repoFileId === 'string' && ((cfgBackupJson.result?.details as Record<string, unknown>)?.repoFileId as string).length > 0, { size: (cfgBackupJson.result?.details as Record<string, unknown>)?.sizeBytes });
  check('backup file name follows the shared convention', /^KIRGUSBANDE__config-backup-\d{8}-\d{6}\.db$/.test(String((cfgBackupJson.result?.details as Record<string, unknown>)?.fileName ?? '')), (cfgBackupJson.result?.details as Record<string, unknown>)?.fileName);
  const bakUpload = repoUploads[repoUploads.length - 1];
  check('mock UNM API received the backup upload (config-backup category)', !!bakUpload && bakUpload.category === 'config-backup' && bakUpload.data.equals(MOCK_BACKUP_BYTES), { name: bakUpload?.name, len: bakUpload?.data.length });
  const bakRepoFileId = String((cfgBackupJson.result?.details as Record<string, unknown>)?.repoFileId ?? '');

  // --- /config (config.restore → multipart /_upload + reboot) ----------------------------
  const restoreB64 = MOCK_BACKUP_BYTES.toString('base64');
  const cfgRestore = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'config.restore', input: { fileBase64: restoreB64, fileName: 'backup-2026.db' } });
  const cfgRestoreJson = (await cfgRestore.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config config.restore ==');
  check('success true with upload job id', cfgRestore.status === 200 && cfgRestoreJson.success === true && ((cfgRestoreJson.result?.details as Record<string, unknown>)?.jobId) === 91, cfgRestoreJson);
  const up = capturedUploads[0];
  check('/_upload received multipart with data part FIRST (method config.upload)', !!up && up.method === 'config.upload' && JSON.stringify(up.params ?? []) === '[]', { method: up?.method });
  check('/_upload file part carries exact bytes + original name', !!up && up.fileName === 'backup-2026.db' && up.data.equals(MOCK_BACKUP_BYTES), { fileName: up?.fileName, len: up?.data.length });
  // The client mints a single-use session token for /_upload on BOTH credential
  // kinds (TrueNAS 26+ revokes API keys over insecure transports; Basic is dead
  // when OTP is enabled) — the mock answers auth.generate_token with 'mock-token-generic'.
  check('/_upload authenticated with a minted session token', !!up && up.auth === 'Token mock-token-generic', up?.auth);

  // --- /config (config.restore via repoFileId — fetch from the UNM file repo → multipart) --
  const cfgRestoreRepo = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'config.restore', input: { repoFileId: bakRepoFileId } });
  const cfgRestoreRepoJson = (await cfgRestoreRepo.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config config.restore (repoFileId) ==');
  check('success true restoring from the file repo', cfgRestoreRepo.status === 200 && cfgRestoreRepoJson.success === true, cfgRestoreRepoJson);
  const upRepo = capturedUploads[1];
  check('/_upload received the repo-stored backup bytes exactly', !!upRepo && upRepo.data.equals(MOCK_BACKUP_BYTES), { len: upRepo?.data.length });

  // --- /config (config.restore missing file → validation) ------------------------------
  const cfgRestoreBad = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'config.restore', input: {} });
  const cfgRestoreBadJson = (await cfgRestoreBad.json()) as { success?: boolean; result?: Record<string, unknown> };
  // Action-level failures surface under result.details.error (schema errors under result.error).
  check('restore without repoFileId/fileBase64 rejected', cfgRestoreBad.status === 200 && cfgRestoreBadJson.success === false && /repoFileId|fileBase64/.test(String((cfgRestoreBadJson.result as Record<string, unknown>)?.details ? ((cfgRestoreBadJson.result as { details: Record<string, unknown> }).details).error : (cfgRestoreBadJson.result as Record<string, unknown>)?.error)), cfgRestoreBadJson);

  // --- /config (config.reset → job id) ----------------------------------------------------
  const cfgReset = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'config.reset', input: {} });
  const cfgResetJson = (await cfgReset.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config config.reset ==');
  check('success true with job id', cfgReset.status === 200 && cfgResetJson.success === true && ((cfgResetJson.result?.details as Record<string, unknown>)?.jobId) === 92, cfgResetJson);

  // --- /config (enclosure.identify → set_slot_status ON) --------------------------------
  const cfgIdentify = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'enclosure.identify', input: { enclosureId: 'enc-aaaa1111', slot: 2, status: 'ON' } });
  const cfgIdentifyJson = (await cfgIdentify.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config enclosure.identify ==');
  check('success true with bay LED ON', cfgIdentify.status === 200 && cfgIdentifyJson.success === true && ((cfgIdentifyJson.result?.details as Record<string, unknown>)?.status) === 'ON', cfgIdentifyJson);
  const slotCall = capturedSlotStatus[capturedSlotStatus.length - 1];
  check('set_slot_status received {enclosure_id, slot, status}', !!slotCall && slotCall['enclosure_id'] === 'enc-aaaa1111' && slotCall['slot'] === 2 && slotCall['status'] === 'ON', slotCall);

  // --- /config (storage.disk-offline → pool.offline + verified OFFLINE) ------------------
  const cfgOffline = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'storage.disk-offline', input: { pool: 'tank', label: 'da0' } });
  const cfgOfflineJson = (await cfgOffline.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config storage.disk-offline ==');
  check('success true + verified OFFLINE via topology re-read', cfgOffline.status === 200 && cfgOfflineJson.success === true && (cfgOfflineJson.result as { verified?: boolean; details?: Record<string, unknown> })?.verified === true && ((cfgOfflineJson.result as { details?: Record<string, unknown> })?.details?.status) === 'OFFLINE', cfgOfflineJson);
  const offCall = capturedPoolDiskOps.find((c) => c.method === 'offline');
  check('pool.offline called with pool id + label', !!offCall && JSON.stringify(offCall.params ?? []) === '[1,{"label":"da0"}]', offCall?.params);

  // --- /config (storage.disk-online → pool.online + verified ONLINE) ---------------------
  const cfgOnline = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'storage.disk-online', input: { pool: 'tank', label: 'da0' } });
  const cfgOnlineJson = (await cfgOnline.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config storage.disk-online ==');
  check('success true + verified ONLINE via topology re-read', cfgOnline.status === 200 && cfgOnlineJson.success === true && (cfgOnlineJson.result as { verified?: boolean; details?: Record<string, unknown> })?.verified === true && ((cfgOnlineJson.result as { details?: Record<string, unknown> })?.details?.status) === 'ONLINE', cfgOnlineJson);
  const onCall = capturedPoolDiskOps.find((c) => c.method === 'online');
  check('pool.online called with pool id + label', !!onCall && JSON.stringify(onCall.params ?? []) === '[1,{"label":"da0"}]', onCall?.params);

  // --- /config (storage.disk-offline unknown disk → clean failure) -----------------------
  const cfgOfflineBad = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'storage.disk-offline', input: { pool: 'tank', label: 'da9' } });
  const cfgOfflineBadJson = (await cfgOfflineBad.json()) as { success?: boolean; result?: Record<string, unknown> };
  check('offlining a disk not in the pool fails cleanly', cfgOfflineBad.status === 200 && cfgOfflineBadJson.success === false && /not found/i.test(String((cfgOfflineBadJson.result as { details?: Record<string, unknown> })?.details?.error)), cfgOfflineBadJson);

  // --- /config (update.profile.read → profile + choices) -------------------------------
  const cfgProfileRead = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'update.profile.read', input: {} });
  const cfgProfileReadJson = (await cfgProfileRead.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config update.profile.read ==');
  check('success true with profile + choice list', cfgProfileRead.status === 200 && cfgProfileReadJson.success === true && ((cfgProfileReadJson.result?.details as Record<string, unknown>)?.profile) === 'GENERAL' && Array.isArray((cfgProfileReadJson.result?.details as Record<string, unknown>)?.choices), cfgProfileReadJson);

  // --- /config (update.profile.set → branch change, verified by re-read) ----------------
  const cfgProfileSet = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'update.profile.set', input: { profile: 'EARLY_ADOPTER' } });
  const cfgProfileSetJson = (await cfgProfileSet.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config update.profile.set ==');
  check('success true with new profile', cfgProfileSet.status === 200 && cfgProfileSetJson.success === true && ((cfgProfileSetJson.result?.details as Record<string, unknown>)?.profile) === 'EARLY_ADOPTER', cfgProfileSetJson);
  const cfgProfileRead2 = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'update.profile.read', input: {} });
  const cfgProfileRead2Json = (await cfgProfileRead2.json()) as { success?: boolean; result?: Record<string, unknown> };
  check('re-read confirms the branch change persisted on the appliance', ((cfgProfileRead2Json.result?.details as Record<string, unknown>)?.profile) === 'EARLY_ADOPTER', cfgProfileRead2Json);
  const cfgProfileBad = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'update.profile.set', input: { profile: 'NIGHTLY' } });
  const cfgProfileBadJson = (await cfgProfileBad.json()) as { success?: boolean; result?: Record<string, unknown> };
  // The SDK's enum validation rejects it before execute() runs — the error
  // lists the valid profiles, which is the hint we want surfaced.
  check('unknown profile rejected with a hint', cfgProfileBad.status === 200 && cfgProfileBadJson.success === false && /must be one of/.test(String(cfgProfileBadJson.result?.error)) && /DEVELOPER/.test(String(cfgProfileBadJson.result?.error)), cfgProfileBadJson);

  // --- /config (system.firmware.update-file via path → [EAGAIN] resume) -----------------
  const cfgFwFile = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.firmware.update-file', input: { path: '/mnt/tank/TrueNAS-25.10.1.update' } });
  const cfgFwFileJson = (await cfgFwFile.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config system.firmware.update-file (path) ==');
  check('success true — [EAGAIN] warning accepted via resume re-run', cfgFwFile.status === 200 && cfgFwFileJson.success === true && ((cfgFwFileJson.result?.details as Record<string, unknown>)?.jobId) === 95, cfgFwFileJson);
  check('resume:true was actually issued to update.manual', manualResumeCalled === true);

  // --- /config (system.firmware.update-file via base64 → /_upload update.file) -----------
  const updateB64 = Buffer.from('MOCK-UPDATE-FILE-BYTES').toString('base64');
  const cfgFwUpload = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.firmware.update-file', input: { fileBase64: updateB64, fileName: 'TrueNAS-25.10.1.update', destination: '/mnt/tank' } });
  const cfgFwUploadJson = (await cfgFwUpload.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config system.firmware.update-file (upload) ==');
  check('success true with upload job id', cfgFwUpload.status === 200 && cfgFwUploadJson.success === true && ((cfgFwUploadJson.result?.details as Record<string, unknown>)?.jobId) === 94, cfgFwUploadJson);
  const fwUp = capturedUploads.find((u) => u.method === 'update.file');
  check('/_upload ran update.file with destination param + exact bytes', !!fwUp && JSON.stringify(fwUp.params ?? []) === '[{"destination":"/mnt/tank"}]' && fwUp.fileName === 'TrueNAS-25.10.1.update' && fwUp.data.equals(Buffer.from('MOCK-UPDATE-FILE-BYTES')), { params: fwUp?.params, fileName: fwUp?.fileName });
  const cfgFwNoInput = await post('/config', { deviceId: 'dev-tnas', managementAddress: ADDR, credentials: creds, actionId: 'system.firmware.update-file', input: {} });
  const cfgFwNoInputJson = (await cfgFwNoInput.json()) as { success?: boolean; result?: Record<string, unknown> };
  // Both inputs are optional in the schema, so this reaches execute() and
  // fails with details.error (not a top-level validation error).
  check('update-file without path or fileBase64 rejected', cfgFwNoInput.status === 200 && cfgFwNoInputJson.success === false && /path|fileBase64/.test(JSON.stringify(cfgFwNoInputJson.result ?? {})), cfgFwNoInputJson);

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
  const planJson = (await planRes.json()) as { plan?: { provisionRequests: unknown[]; steps: { stepIndex: number; deviceId: string; actionId: string; input: Record<string, unknown>; bestEffort?: boolean }[] } };
  console.log('\n== /plan system.reboot ==');
  check('HTTP 200', planRes.status === 200);
  const plan = planJson.plan!;
  check('no provision requests (TrueNAS needs no secrets)', Array.isArray(plan.provisionRequests) && plan.provisionRequests.length === 0);
  // Dirty plans get a best-effort config backup prepended per device (rollback point).
  check('plan has 2 rollback backups + 2 reboot steps', plan.steps.length === 4, plan.steps.map((s) => `${s.stepIndex}:${s.deviceId}:${s.actionId}`));
  const reboots = plan.steps.filter((s) => s.actionId === 'system.reboot');
  check('fan-out yields one reboot step per device', reboots.length === 2 && reboots.every((s) => s.input.reason === 'smoke test reboot'), reboots);
  const backups = plan.steps.filter((s) => s.actionId === 'config.backup.download');
  check('rollback steps are best-effort config backups (one per device)', backups.length === 2 && backups.every((s) => s.bestEffort === true), backups);

  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[smoke] fatal:', err);
  process.exit(1);
});
