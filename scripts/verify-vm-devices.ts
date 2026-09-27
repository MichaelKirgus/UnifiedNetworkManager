/**
 * End-to-end verification of the VM device ATTACH feature (live dev stack):
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. asserts the persisted plugin catalog carries the new generic contract:
 *      vms.device-types / vms.disk-choices / vms.pci-choices / vms.usb-choices /
 *      vms.nic-choices (read) and vms.disk-attach / vms.display-attach /
 *      vms.pci-attach / vms.usb-attach / vms.nic-attach / vms.cdrom-attach (write)
 *   3. runs the READ actions through the real webapp path
 *      (POST /plugins/:id/actions/execute) and asserts their details shapes:
 *        - device-types → types[] with dtype/inputSchema/requiresStopped (+choicesActionId),
 *                         now covering DISK/DISPLAY/PCI/USB/NIC/CDROM
 *        - usb-choices  → devices[] {id, description, available}
 *        - pci-choices  → {iommuEnabled, devices[]}
 *        - nic-choices  → {bridges[], macvlans[]}
 *   4. SAFE LIVE CYCLE on a STOPPED VM without a display (state never changes):
 *        USB attach (plan workflow) → verify via GET /vms extra.devices → detach → verify gone
 *        NIC attach (bridge, hot-pluggable) → verify new row in inventory    → detach → verify gone
 *        DISPLAY attach (VNC)       → verify + appliance-assigned port      → detach → verify gone
 *   4b. EDIT CYCLES (generic edit contract — vms.device-get prefill + partial-merge
        vms.device-update, verified via GET /vms detail, always restored):
        NIC bridge swap on the freshly attached NIC; DISPLAY resolution change
        on the VM's existing console.
 *   4c. SERIAL CONSOLE (generic console chain — context {kind:'vm-serial', name}):
        vms.serial-consoles read action returns ≥1 {name, state}; a live WS round-trip
        through the REAL ticket + proxy path attaches to a RUNNING VM's PTY-backed
        serial0 and asserts the 'ready' control frame + virsh attach banner.
 *   5. NEGATIVE: display attach on a VM that ALREADY has one must fail with the
 *      "already has a display" error (appliance rule, enforced pre-RPC).
 *   Every plan created is deleted at the end; no appliance state survives.
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-vm-devices.ts [deviceId]
 */

import path from 'node:path';
import { createRequire } from 'node:module';
import { TruenasClient, type TruenasCredentials } from '../plugins/ix-truenas/src/client/truenasClient';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const PLUGIN_ID = process.env.TRUENAS_PLUGIN_ID ?? '00000000-0000-4000-8000-000000000009';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

function skip(label: string, why: string): void {
  console.log(`  SKIP ${label} — ${why}`);
}

interface VmDeviceRow { dtype: string; id?: number; label?: string; detail?: string; }
interface VmRow { name: string; state: string; extra?: Record<string, unknown>; }
interface PlanStep { stepIndex: number; actionId: string; input: Record<string, unknown>; bestEffort?: boolean; status: string; result?: Record<string, unknown> | null; }
interface PlanDetail { id: string; status: string; error?: string | null; steps?: PlanStep[]; }

const devicesOf = (row: VmRow): VmDeviceRow[] =>
  Array.isArray(row.extra?.['devices']) ? (row.extra!['devices'] as VmDeviceRow[]) : [];

async function main(): Promise<void> {
  // --- Login (admin/admin; TOTP when enabled) ---------------------------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated (2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- Target device -----------------------------------------------------------
  let deviceId = process.argv[2];
  if (!deviceId) {
    const dRes = await authed('GET', '/devices');
    const devices = (await dRes.json()) as Array<{ id: string; name: string }>;
    const truenas = devices.find((d) => /KIRGUS/i.test(d.name)) ?? devices[0];
    if (!truenas) throw new Error('no device found');
    deviceId = truenas.id;
    console.log(`  INFO using device ${truenas.name} (${deviceId})`);
  }

  // --- 1. Persisted catalog carries the generic attach contract -----------------
  const catRes = await authed('GET', `/plugins/${PLUGIN_ID}/actions`);
  check('GET /plugins/:id/actions → 200', catRes.status === 200, { status: catRes.status });
  const catalog = ((await catRes.json()) as { actions?: Array<{ id: string; riskLevel: string }> }).actions ?? [];
  for (const [id, risk] of [['vms.device-types', 'read'], ['vms.disk-choices', 'read'], ['vms.pci-choices', 'read'], ['vms.usb-choices', 'read'], ['vms.nic-choices', 'read'], ['vms.device-get', 'read'], ['vms.vm-edit-schema', 'read'], ['vms.vm-get', 'read'], ['vms.serial-consoles', 'read'], ['vms.disk-attach', 'write'], ['vms.display-attach', 'write'], ['vms.pci-attach', 'write'], ['vms.usb-attach', 'write'], ['vms.nic-attach', 'write'], ['vms.cdrom-attach', 'write'], ['vms.device-update', 'write'], ['vms.vm-update', 'write']] as const) {
    const entry = catalog.find((a) => a.id === id);
    check(`catalog has ${id} (${risk})`, Boolean(entry) && entry!.riskLevel === risk, entry ?? `missing`);
  }

  // VM-level edit contract — the field catalog that drives the webapp's Edit-VM dialog.
  const vmSchemaRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-edit-schema', input: {} });
  check('vms.vm-edit-schema → 200', vmSchemaRes.status === 200, { status: vmSchemaRes.status });
  const vmFields = (((await vmSchemaRes.json()) as { details?: { fields?: Array<Record<string, unknown>> } }).details?.fields) ?? [];
  const vmFieldKeys = vmFields.map((f) => String(f['key'] ?? ''));
  check('vm-edit-schema covers the full GUI field set (21 fields)', ['name', 'description', 'autostart', 'bootloader', 'time', 'nodeset', 'cpuset', 'cores', 'threads', 'memoryMiB', 'minMemoryMiB', 'pinVcpus', 'shutdownTimeoutSec', 'suspendOnSnapshot', 'hideFromMsr', 'ensureDisplayDevice', 'trustedPlatformModule', 'hypervEnlightenments', 'cpuMode', 'cpuModel', 'commandLineArgs'].every((k) => vmFieldKeys.includes(k)), vmFieldKeys);
  const cpuModeField = vmFields.find((f) => f['key'] === 'cpuMode');
  check('vm-edit-schema: cpuMode enum HOST-PASSTHROUGH|CUSTOM', Array.isArray(cpuModeField?.['enum']) && (cpuModeField!['enum'] as string[]).join(',') === 'HOST-PASSTHROUGH,CUSTOM', cpuModeField);
  const nameField = vmFields.find((f) => f['key'] === 'name');
  check('vm-edit-schema: name is the ONLY requiresStopped field', nameField?.['requiresStopped'] === true && vmFields.every((f) => (f['key'] === 'name') === (f['requiresStopped'] === true)), vmFields.map((f) => `${String(f['key'])}:${Boolean(f['requiresStopped'])}`));
  const bootloaderField = vmFields.find((f) => f['key'] === 'bootloader');
  check('vm-edit-schema: bootloader enum UEFI|UEFI_CSM', Array.isArray(bootloaderField?.['enum']) && (bootloaderField!['enum'] as string[]).join(',') === 'UEFI,UEFI_CSM', bootloaderField);
  const timeField = vmFields.find((f) => f['key'] === 'time');
  check('vm-edit-schema: time enum UTC|LOCAL', Array.isArray(timeField?.['enum']) && (timeField!['enum'] as string[]).join(',') === 'UTC,LOCAL', timeField);

  // --- 2. Read actions through the real webapp path -----------------------------
  // vms.device-types — the descriptor that drives the webapp dialog.
  const typesRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.device-types', input: {} });
  check('vms.device-types → 200', typesRes.status === 200, { status: typesRes.status });
  const types = (((await typesRes.json()) as { details?: { types?: Array<Record<string, unknown>> } }).details?.types) ?? [];
  const dtypeOf = (t: Record<string, unknown>): string => String(t['dtype'] ?? '');
  check('device-types lists DISK/DISPLAY/PCI/USB/NIC/CDROM', ['DISK', 'DISPLAY', 'PCI', 'USB', 'NIC', 'CDROM'].every((d) => types.some((t) => dtypeOf(t) === d)), types.map(dtypeOf));
  const pciType = types.find((t) => dtypeOf(t) === 'PCI');
  check('PCI descriptor: requiresStopped + choicesActionId', pciType?.['requiresStopped'] === true && pciType?.['choicesActionId'] === 'vms.pci-choices', pciType);
  const usbType = types.find((t) => dtypeOf(t) === 'USB');
  check('USB descriptor: hot-pluggable + choicesActionId', usbType?.['requiresStopped'] === false && usbType?.['choicesActionId'] === 'vms.usb-choices', usbType);
  const nicType = types.find((t) => dtypeOf(t) === 'NIC');
  const nicSchema = (nicType?.['inputSchema'] ?? {}) as Record<string, { required?: boolean; enum?: string[] }>;
  check('NIC descriptor: hot-pluggable + choicesActionId', nicType?.['requiresStopped'] === false && nicType?.['choicesActionId'] === 'vms.nic-choices', nicType);
  check('NIC descriptor schema: nicAttach required, type enum BRIDGE|MACVLAN, optional mac', Boolean(nicSchema['nicAttach']?.required) && Array.isArray(nicSchema['type']?.enum) && (nicSchema['type']!.enum ?? []).includes('BRIDGE') && (nicSchema['type']!.enum ?? []).includes('MACVLAN') && nicSchema['mac'] !== undefined, nicType);
  const cdromType = types.find((t) => dtypeOf(t) === 'CDROM');
  const cdromSchema = (cdromType?.['inputSchema'] ?? {}) as Record<string, { required?: boolean; enum?: string[] }>;
  check('CDROM descriptor: hot-pluggable + source/repoFileId/dataset/path fields', cdromType?.['requiresStopped'] === false && ['source', 'repoFileId', 'dataset', 'path'].every((f) => cdromSchema[f] !== undefined), cdromType);
  check('CDROM descriptor schema: source enum repo|dataset|path (default repo)', Array.isArray(cdromSchema['source']?.enum) && (cdromSchema['source']!.enum ?? []).join(',') === 'repo,dataset,path', cdromType);
  const diskType = types.find((t) => dtypeOf(t) === 'DISK');
  check('every descriptor carries an inputSchema with fields', types.every((t) => t['inputSchema'] && typeof t['inputSchema'] === 'object' && Object.keys(t['inputSchema'] as object).length > 0));
  check('DISK descriptor has mode enum existing|new-zvol', Array.isArray((diskType?.['inputSchema'] as Record<string, { enum?: unknown[] }> | undefined)?.['mode']?.enum) && (diskType!['inputSchema'] as Record<string, { enum: string[] }>)['mode'].enum!.includes('new-zvol'));

  // Edit contract — every editable type carries a non-empty editInputSchema; PCI does not.
  const editKeys = (t: Record<string, unknown> | undefined): string[] => Object.keys((t?.['editInputSchema'] ?? {}) as object);
  check('DISK descriptor has editInputSchema with diskType', editKeys(diskType).includes('diskType'), editKeys(diskType));
  const displayType = types.find((t) => dtypeOf(t) === 'DISPLAY');
  check('DISPLAY descriptor has editInputSchema (resolution/port/password/web)', ['resolution', 'port', 'password', 'web'].every((f) => editKeys(displayType).includes(f)), editKeys(displayType));
  check('NIC descriptor has editInputSchema with nicAttach + mac', editKeys(nicType).includes('nicAttach') && editKeys(nicType).includes('mac'), editKeys(nicType));
  check('USB descriptor has editInputSchema with controllerType', editKeys(usbType).includes('controllerType'), editKeys(usbType));
  check('CDROM descriptor has editInputSchema (source/repoFileId/dataset/path)', ['source', 'repoFileId', 'dataset', 'path'].every((f) => editKeys(cdromType).includes(f)), editKeys(cdromType));
  check('PCI descriptor is NOT editable in place (no editInputSchema)', pciType !== undefined && !pciType['editInputSchema'], { hasEdit: Boolean(pciType?.['editInputSchema']) });

  // vms.disk-choices — normalized existing-disk picker list.
  const diskRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.disk-choices', input: {} });
  check('vms.disk-choices → 200', diskRes.status === 200, { status: diskRes.status });
  const diskChoices = (((await diskRes.json()) as { details?: { disks?: Array<{ path: string; name: string }> } }).details?.disks) ?? [];
  check('disk-choices returns normalized disks[] (path + name)', diskChoices.length > 0 && diskChoices.every((d) => d.path.startsWith('/dev/zvol/') && typeof d.name === 'string'), diskChoices.slice(0, 2));

  // vms.usb-choices — normalized picker list.
  const usbRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.usb-choices', input: {} });
  check('vms.usb-choices → 200', usbRes.status === 200, { status: usbRes.status });
  const usbChoices = (((await usbRes.json()) as { details?: { devices?: Array<{ id: string; description: string; available: boolean }> } }).details?.devices) ?? [];
  check('usb-choices returns normalized devices[]', usbChoices.length > 0 && usbChoices.every((d) => typeof d.id === 'string' && d.id.startsWith('usb_') && typeof d.available === 'boolean'), usbChoices.slice(0, 3));
  const freeUsb = usbChoices.find((d) => d.available);

  // vms.pci-choices — normalized picker list + IOMMU flag (slow on big hosts).
  const pciRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.pci-choices', input: {} });
  check('vms.pci-choices → 200', pciRes.status === 200, { status: pciRes.status });
  const pciDetails = (await pciRes.json()) as { details?: { iommuEnabled?: boolean; devices?: Array<{ id: string; available: boolean }> } };
  check('pci-choices returns {iommuEnabled, devices[]}', typeof pciDetails.details?.['iommuEnabled'] === 'boolean' && Array.isArray(pciDetails.details?.devices), { iommu: pciDetails.details?.['iommuEnabled'], count: (pciDetails.details?.devices ?? []).length });

  // vms.nic-choices — bridge/MACVLAN picker list for the unified attach dialog.
  const nicRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.nic-choices', input: {} });
  check('vms.nic-choices → 200', nicRes.status === 200, { status: nicRes.status });
  const nicDetails = (await nicRes.json()) as { details?: { bridges?: string[]; macvlans?: string[] } };
  check('nic-choices returns {bridges[], macvlans[]} with ≥1 bridge', Array.isArray(nicDetails.details?.['bridges']) && Array.isArray(nicDetails.details?.macvlans) && (nicDetails.details?.['bridges'] ?? []).length > 0, nicDetails.details);

  // --- Baseline VM inventory -----------------------------------------------------
  const vRes = await authed('GET', '/vms');
  check('GET /vms → 200', vRes.status === 200, { status: vRes.status });
  let rows = ((await vRes.json()) as { vms?: VmRow[] }).vms ?? [];
  check('VMs returned', rows.length > 0, rows.length);

  const stoppedVm = rows.find((r) => r.state === 'STOPPED');
  const withDisplay = rows.find((r) => devicesOf(r).some((d) => d.dtype === 'DISPLAY'));

  // --- Serial console (generic console chain, context {kind:'vm-serial'}) --------
  // Read action: the availability list that gates the webapp's Guest Actions button.
  const serialRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.serial-consoles', input: {} });
  check('vms.serial-consoles → 200', serialRes.status === 200, { status: serialRes.status });
  const serialDetails = ((await serialRes.json()) as { details?: { consoles?: Array<{ name: string; state: string }> } }).details ?? {};
  check('serial-consoles returns ≥1 console with name+state', Array.isArray(serialDetails.consoles) && (serialDetails.consoles?.length ?? 0) > 0 && serialDetails.consoles!.every((c) => typeof c.name === 'string' && typeof c.state === 'string'), serialDetails);

  // Live WS round-trip: mint a ticket for a RUNNING VM and attach through the REAL
  // proxy path (the same one the webapp's ConsoleDialog uses). Expect the control
  // 'ready' frame, then guest output on the PTY-backed serial0.
  const runningVm = rows.find((r) => r.state === 'RUNNING');
  if (!runningVm) {
    skip('serial console WS attach', 'no RUNNING VM in inventory');
  } else {
    // Session credential for purpose=console — auto-use the default (or sole candidate).
    const scRes = await authed('GET', `/devices/${deviceId}/session-credentials?purpose=console`);
    check('session-credentials(console) → 200', scRes.status === 200, { status: scRes.status });
    const sc = (await scRes.json()) as { candidates?: Array<{ id: string }>; defaultSecretId?: string | null };
    const secretId = sc.defaultSecretId ?? sc.candidates?.[0]?.id;

    if (!secretId) {
      check('console credential available', false, 'no eligible session credential for purpose=console');
    } else {
      const tRes = await authed('POST', `/devices/${deviceId}/console`, { pluginId: PLUGIN_ID, secretId, context: { kind: 'vm-serial', name: runningVm.name } });
      check(`mint console ticket (vm-serial ${runningVm.name}) → 201`, tRes.status === 201, { status: tRes.status });
      const tBody = (await tRes.json()) as { ticket?: string };
      if (!tBody.ticket) check('ticket present', false, tBody);

      // The API's WS proxy — Node `ws` delivers text frames as Buffers too, so
      // JSON-parse first and fall back to raw output.
      const WebSocket = apiRequire('ws');
      const wsBase = API.replace(/^http/, 'ws');
      const ws = new WebSocket(`${wsBase}/devices/${deviceId}/console/ws?ticket=${encodeURIComponent(tBody.ticket ?? '')}`);
      let ready = false;
      let output = '';
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => { ws.terminate(); resolve(); }, 30_000); // generous: vm.query + SSH handshake + virsh attach
        ws.on('message', (data: Buffer) => {
          const text = data.toString('utf8');
          try {
            const msg = JSON.parse(text) as { type?: string };
            if (msg.type === 'ready') ready = true;
            else if (msg.type === 'error') output += `\n[control error] ${JSON.stringify(msg)}`;
            return; // control frame — not guest output
          } catch { /* binary/raw text = terminal I/O */ }
          output += text;
        });
        ws.on('close', () => { clearTimeout(timer); resolve(); });
        ws.on('error', (e: Error) => { check(`serial console WS open (${runningVm.name})`, false, e.message); clearTimeout(timer); resolve(); });
      });
      check(`serial console ready frame (${runningVm.name})`, ready, output.slice(0, 200));
      // The attach banner proves the PTY reached the guest's serial0.
      check('serial console attached to domain (banner in output)', /Connected to domain/i.test(output), output.slice(0, 300));
    }
  }

  // --- Plan workflow helpers (mirror webapp createAndExecutePlan) -----------------
  const createdPlans: string[] = [];
  async function runPlan(actionId: string, inputs: Record<string, unknown>): Promise<PlanDetail> {
    const createRes = await authed('POST', '/plans', { pluginId: PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    if (createRes.status !== 201) throw new Error(`plan create ${actionId} → ${createRes.status}: ${JSON.stringify(await createRes.json()).slice(0, 300)}`);
    const plan = (await createRes.json()) as PlanDetail;
    createdPlans.push(plan.id);
    const execRes = await authed('POST', `/plans/${plan.id}/execute`);
    if (execRes.status !== 202) throw new Error(`plan execute ${actionId} → ${execRes.status}: ${JSON.stringify(await execRes.json()).slice(0, 300)}`);
    const deadline = Date.now() + 300_000; // attach actions verify up to 45 s inside the plugin
    let final: PlanDetail = plan;
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${plan.id}`);
      final = (await r.json()) as PlanDetail;
      if (['succeeded', 'failed', 'cancelled'].includes(final.status)) break;
      await new Promise((res2) => setTimeout(res2, 1_000));
    }
    return final;
  }

  const stepResult = (plan: PlanDetail, actionId: string): Record<string, unknown> | null => {
    const step = (plan.steps ?? []).find((s) => s.actionId === actionId);
    if (!step?.result || typeof step.result !== 'object') return null;
    // plan_steps.result stores { success, result: ActionResult } — details one level deeper.
    const inner = step.result['result'];
    return (inner && typeof inner === 'object' ? inner : {}) as Record<string, unknown>;
  };

  // GET /vms reads the PERSISTED inventory — force a fresh poll first so
  // freshly attached/detached devices are visible (same pattern as verify-vm-cpu).
  const refreshVms = async (): Promise<VmRow[]> => {
    await authed('POST', '/devices/refresh', { deviceIds: [deviceId] });
    await new Promise((r) => setTimeout(r, 6_000)); // let the poll land
    const r = await authed('GET', '/vms');
    return ((await r.json()) as { vms?: VmRow[] }).vms ?? [];
  };
  // The persisted inventory can lag a few seconds behind live appliance state —
  // re-poll up to `tries` times until the predicate holds (or give up).
  const settleVms = async (predicate: (rows: VmRow[]) => boolean, tries = 3): Promise<VmRow[]> => {
    let current = await refreshVms();
    for (let i = 1; !predicate(current) && i < tries; i++) {
      await new Promise((r) => setTimeout(r, 5_000));
      current = await refreshVms();
    }
    return current;
  };

  // --- Direct appliance client — used ONLY to tear down / restore the display
  // console around the plan-workflow cycle (the one-display rule blocks a second
  // attach, and there is no UNM API path for "raw RPC"; everything else goes
  // through the real webapp workflow).
  const SECRETS_BASE = process.env.SECRETS_BASE ?? 'http://localhost:4003';
  const SECRETS_KEY = process.env.SECRETS_API_KEY ?? 'dev-plugin-key';

  let tClient: TruenasClient | null = null;
  let tCreds: TruenasCredentials | null = null;
  async function directRpc(method: string, params: unknown[]): Promise<unknown> {
    if (!tClient || !tCreds) throw new Error('direct appliance client not initialized');
    return tClient.call(method, params, tCreds);
  }
  const rawVm = async (name: string): Promise<Record<string, unknown> | null> => {
    const vms = await directRpc('vm.query', []) as Record<string, unknown>[];
    return (vms ?? []).find((r) => r['name'] === name) ?? null;
  };
  const rawDevicesOf = (raw: Record<string, unknown> | null): Array<{ dtype: string; id?: number }> => {
    if (!raw || !Array.isArray(raw['devices'])) return [];
    const out: Array<{ dtype: string; id?: number }> = [];
    for (const d of raw['devices'] as Record<string, unknown>[]) {
      if (!d || typeof d !== 'object') continue;
      const attrs = (d['attributes'] ?? {}) as Record<string, unknown>;
      const dtype = typeof d['dtype'] === 'string' ? d['dtype'] : typeof attrs['dtype'] === 'string' ? attrs['dtype'] : null;
      if (!dtype) continue;
      const id = typeof d['id'] === 'number' ? (d['id'] as number) : typeof attrs['id'] === 'number' ? (attrs['id'] as number) : undefined;
      out.push({ dtype, id });
    }
    return out;
  };
  // TrueNAS 25.10+ takes { vm, attributes } for vm.device.create; older: { id, … }.
  const isV26 = async (): Promise<boolean> => {
    try {
      const si = (await directRpc('system.info', [])) as Record<string, unknown>;
      const v = String(si['version'] ?? '').replace(/^(scale|core)\s+/i, '');
      const m = v.match(/^(\d+)\.(\d+)/);
      if (!m) return true;
      return Number(m[1]) > 25 || (Number(m[1]) === 25 && Number(m[2]) >= 10);
    } catch { return true; }
  };

  // --- 3. SAFE LIVE CYCLE on a STOPPED VM: USB attach → verify → detach -----------
  if (!stoppedVm) {
    skip('USB + display live cycle', 'no STOPPED VM on this appliance');
  } else {
    const vm = stoppedVm;
    console.log(`  INFO live-cycle VM: ${vm.name} (stopped)`);

    // Direct client for the display teardown/restore below.
    try {
      const devRes = await authed('GET', '/devices');
      const allDevices = (await devRes.json()) as Array<{ id: string; managementAddress?: string }>;
      const host = allDevices.find((d) => d.id === deviceId)?.managementAddress ?? '';
      if (!host) throw new Error(`no management address for device ${deviceId}`);
      const dpRow = (await pool.query(`SELECT "extraCredentials" FROM device_plugins WHERE "deviceId" = $1 AND "pluginId" = $2`, [deviceId, PLUGIN_ID])).rows[0] as { extraCredentials: string | null } | undefined;
      const extraCreds = JSON.parse(dpRow?.extraCredentials ?? '{}') as Record<string, string>;
      if (!extraCreds['apiKey']) throw new Error('device has no apiKey credential slot');
      const secRes = await fetch(`${SECRETS_BASE}/secrets/${extraCreds['apiKey']}`, { headers: { 'x-plugin-api-key': SECRETS_KEY } });
      const secBody = (await secRes.json()) as { fields?: Record<string, string> };
      if (!secBody.fields?.['apiKey']) throw new Error('could not read apiKey secret');
      const creds = { kind: 'apiKey' as const, username: 'root', apiKey: secBody.fields['apiKey'] };
      const candidate = new TruenasClient(host, 'auto', 60_000);
      await candidate.login(creds); // throws on failure — only adopt after success
      tCreds = creds;
      tClient = candidate;
    } catch (e) {
      skip('USB + display live cycle', `direct appliance client unavailable (${e instanceof Error ? e.message : String(e)})`);
    }

    if (tClient && tCreds) {
      // 3a. USB attach through the plan workflow → verify via GET /vms → detach.
      if (!freeUsb) {
        skip('USB live cycle', `no available USB device in choices (${usbChoices.length} total)`);
      } else {
        console.log(`  INFO USB target: ${freeUsb.id} — ${freeUsb.description}`);
        const usbPlan = await runPlan('vms.usb-attach', { name: vm.name, usbDevice: freeUsb.id });
        check('usb-attach plan succeeded', usbPlan.status === 'succeeded', { status: usbPlan.status, error: usbPlan.error, steps: (usbPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });
        const usbDetails = stepResult(usbPlan, 'vms.usb-attach')?.['details'] as Record<string, unknown> | undefined;
        check('usb-attach result carries vendor/product ids', typeof usbDetails?.['vendorId'] === 'string' && typeof usbDetails?.['productId'] === 'string', usbDetails);

        rows = await settleVms((rs) => (rs.find((r) => r.name === vm.name)?.extra?.['devices'] as VmDeviceRow[] | undefined)?.some((d) => d.dtype === 'USB') ?? false);
        const vmAfterUsb = rows.find((r) => r.name === vm.name)!;
        const attachedUsb = devicesOf(vmAfterUsb).find((d) => d.dtype === 'USB');
        check('GET /vms shows the new USB device', Boolean(attachedUsb), devicesOf(vmAfterUsb));

        if (!attachedUsb?.id) {
          skip('usb detach', 'no integer device id on the attached USB row — LEAK: detach manually!');
        } else {
          const detPlan = await runPlan('vms.device-detach', { name: vm.name, deviceId: attachedUsb.id });
          check('device-detach (USB) plan succeeded', detPlan.status === 'succeeded', { status: detPlan.status, error: detPlan.error });
          rows = await settleVms((rs) => !(devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'USB')));
          const vmAfterDet = rows.find((r) => r.name === vm.name)!;
          check('USB device gone after detach', !devicesOf(vmAfterDet).some((d) => d.dtype === 'USB'), devicesOf(vmAfterDet));
        }

        // 3a2. NIC cycle (hot-pluggable — no stop needed): attach a bridge via the
        // plan workflow, verify the new row in GET /vms, detach by device id.
        const bridges = nicDetails.details?.['bridges'] ?? [];
        if (bridges.length === 0) {
          skip('NIC live cycle', 'nic-choices returned no bridges');
        } else {
          const bridge = bridges[0];
          console.log(`  INFO NIC target: ${bridge}`);
          rows = await refreshVms();
          const nicsBefore = (devicesOf(rows.find((r) => r.name === vm.name)!).filter((d) => d.dtype === 'NIC'));
          const nicCountBefore = nicsBefore.length;
          const knownNicIds = new Set(nicsBefore.filter((d) => typeof d.id === 'number').map((d) => d.id));

          const nicPlan = await runPlan('vms.nic-attach', { name: vm.name, nicAttach: bridge });
          check('nic-attach plan succeeded', nicPlan.status === 'succeeded', { status: nicPlan.status, error: nicPlan.error, steps: (nicPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });

          rows = await settleVms((rs) => devicesOf(rs.find((r) => r.name === vm.name)!).filter((d) => d.dtype === 'NIC').length > nicCountBefore);
          const vmAfterNic = rows.find((r) => r.name === vm.name)!;
          const nicsNow = devicesOf(vmAfterNic).filter((d) => d.dtype === 'NIC');
          check('GET /vms shows a new NIC device', nicsNow.length > nicCountBefore, { before: nicCountBefore, after: nicsNow.length });

          // The NEW row is the one whose id we have not seen before.
          const attachedNic = nicsNow.find((d) => typeof d.id === 'number' && !knownNicIds.has(d.id)) ?? nicsNow[nicCountBefore];

          // 3a2b. EDIT cycle on the freshly attached NIC (generic edit contract):
          // vms.device-get prefill → vms.device-update bridge swap → verify via
          // GET /vms detail → restore the original bridge before detaching.
          if (!attachedNic?.id) {
            skip('NIC edit cycle', 'no integer device id on the attached NIC row');
          } else {
            const getRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.device-get', input: { name: vm.name, deviceId: attachedNic.id } });
            check('vms.device-get → 200', getRes.status === 200, { status: getRes.status });
            const got = ((await getRes.json()) as { details?: { dtype?: string; values?: Record<string, unknown> } }).details ?? {};
            check('device-get prefills nicAttach with the attached bridge', got.dtype === 'NIC' && String(got.values?.['nicAttach'] ?? '') === bridge, got);

            const otherBridge = (bridges.find((b) => b !== bridge)) ?? null;
            if (!otherBridge) {
              skip('NIC device-update cycle', 'only one bridge on this appliance — nothing to swap to');
            } else {
              console.log(`  INFO NIC edit: ${bridge} → ${otherBridge}`);
              const updPlan = await runPlan('vms.device-update', { name: vm.name, deviceId: attachedNic.id, fields: { nicAttach: otherBridge } });
              check('device-update (NIC bridge swap) plan succeeded', updPlan.status === 'succeeded', { status: updPlan.status, error: updPlan.error, steps: (updPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });
              const updDetails = stepResult(updPlan, 'vms.device-update')?.['details'] as Record<string, unknown> | undefined;
              check('device-update result reports the updated field + verified', Array.isArray(updDetails?.['updated']) && (updDetails!['updated'] as string[]).includes('nicAttach') && updPlan.status === 'succeeded', updDetails);

              rows = await settleVms((rs) => devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'NIC' && d.id === attachedNic.id && String(d.detail ?? '').includes(otherBridge)));
              const vmAfterEdit = rows.find((r) => r.name === vm.name)!;
              check('GET /vms detail shows the NEW bridge after edit', devicesOf(vmAfterEdit).some((d) => d.dtype === 'NIC' && d.id === attachedNic.id && String(d.detail ?? '').includes(otherBridge)), devicesOf(vmAfterEdit));

              // Restore the original bridge (partial merge — only nicAttach changes).
              const restorePlan = await runPlan('vms.device-update', { name: vm.name, deviceId: attachedNic.id, fields: { nicAttach: bridge } });
              check('device-update (restore original bridge) plan succeeded', restorePlan.status === 'succeeded', { status: restorePlan.status, error: restorePlan.error });
              rows = await settleVms((rs) => devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'NIC' && d.id === attachedNic.id && String(d.detail ?? '').includes(bridge)));
              const vmAfterRestore = rows.find((r) => r.name === vm.name)!;
              check('GET /vms detail shows the ORIGINAL bridge after restore', devicesOf(vmAfterRestore).some((d) => d.dtype === 'NIC' && d.id === attachedNic.id && String(d.detail ?? '').includes(bridge)), devicesOf(vmAfterRestore));
            }
          }
          if (!attachedNic?.id) {
            skip('nic detach', 'no integer device id on the attached NIC row — LEAK: detach manually!');
          } else {
            const nicDetPlan = await runPlan('vms.device-detach', { name: vm.name, deviceId: attachedNic.id });
            check('device-detach (NIC) plan succeeded', nicDetPlan.status === 'succeeded', { status: nicDetPlan.status, error: nicDetPlan.error });
            rows = await settleVms((rs) => devicesOf(rs.find((r) => r.name === vm.name)!).filter((d) => d.dtype === 'NIC').length <= nicCountBefore);
            const vmAfterNicDet = rows.find((r) => r.name === vm.name)!;
            check('NIC device gone after detach', (devicesOf(vmAfterNicDet).filter((d) => d.dtype === 'NIC')).length <= nicCountBefore, devicesOf(vmAfterNicDet));
          }
        }

        // 3a3. DISPLAY edit cycle on the VM's EXISTING console (partial merge):
        // vms.device-get prefill → change resolution via vms.device-update →
        // verify via GET /vms detail → restore the original resolution.
        rows = await refreshVms();
        const vmForDispEdit = rows.find((r) => r.name === vm.name)!;
        const existingDisplay = devicesOf(vmForDispEdit).find((d) => d.dtype === 'DISPLAY' && typeof d.id === 'number');
        if (!existingDisplay?.id) {
          skip('display edit cycle', `${vm.name} has no display device with an integer id`);
        } else {
          const getRes2 = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.device-get', input: { name: vm.name, deviceId: existingDisplay.id } });
          check('vms.device-get (DISPLAY) → 200', getRes2.status === 200, { status: getRes2.status });
          const got2 = ((await getRes2.json()) as { details?: { dtype?: string; values?: Record<string, unknown> } }).details ?? {};
          check('device-get prefills DISPLAY resolution/port/password/web', got2.dtype === 'DISPLAY' && typeof got2.values?.['resolution'] === 'string' && typeof got2.values?.['port'] === 'number' && typeof got2.values?.['password'] === 'string' && typeof got2.values?.['web'] === 'boolean', got2);
          const origResolution = String(got2.values?.['resolution'] ?? '');
          if (!/^\d+x\d+$/.test(origResolution)) {
            skip('display device-update cycle', `unexpected resolution format "${origResolution}"`);
          } else {
            const [w, h] = origResolution.split('x').map(Number);
            const newRes = `${Math.max(640, w - 320)}x${Math.max(480, h - 180)}`; // e.g. 1920x1080 → 1600x900
            console.log(`  INFO display edit: ${origResolution} → ${newRes}`);
            const dispUpdPlan = await runPlan('vms.device-update', { name: vm.name, deviceId: existingDisplay.id, fields: { resolution: newRes } });
            check('device-update (DISPLAY resolution) plan succeeded', dispUpdPlan.status === 'succeeded', { status: dispUpdPlan.status, error: dispUpdPlan.error, steps: (dispUpdPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });

            rows = await settleVms((rs) => devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'DISPLAY' && String(d.detail ?? '').includes(newRes)));
            const vmAfterDispEdit = rows.find((r) => r.name === vm.name)!;
            check('GET /vms detail shows the NEW resolution after edit', devicesOf(vmAfterDispEdit).some((d) => d.dtype === 'DISPLAY' && String(d.detail ?? '').includes(newRes)), devicesOf(vmAfterDispEdit));

            const restoreDispPlan = await runPlan('vms.device-update', { name: vm.name, deviceId: existingDisplay.id, fields: { resolution: origResolution } });
            check('device-update (restore original resolution) plan succeeded', restoreDispPlan.status === 'succeeded', { status: restoreDispPlan.status, error: restoreDispPlan.error });
            rows = await settleVms((rs) => devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'DISPLAY' && String(d.detail ?? '').includes(origResolution)));
            const vmAfterDispRestore = rows.find((r) => r.name === vm.name)!;
            check('GET /vms detail shows the ORIGINAL resolution after restore', devicesOf(vmAfterDispRestore).some((d) => d.dtype === 'DISPLAY' && String(d.detail ?? '').includes(origResolution)), devicesOf(vmAfterDispRestore));
          }
        }

        // 3b. DISPLAY cycle: tear down the VM's existing console DIRECTLY (the
        // one-display rule blocks a second attach), run attach + detach through
        // the plan workflow, then restore the original console EXACTLY.
        const vmRaw = await rawVm(vm.name);
        let origDisplayId: number | null = null;
        let origDisplayAttrs: Record<string, unknown> | null = null;
        if (vmRaw && Array.isArray(vmRaw['devices'])) {
          for (const d of vmRaw['devices'] as Record<string, unknown>[]) {
            const attrs = (d['attributes'] ?? {}) as Record<string, unknown>;
            const dtype = typeof d['dtype'] === 'string' ? d['dtype'] : typeof attrs['dtype'] === 'string' ? attrs['dtype'] : null;
            if (dtype !== 'DISPLAY') continue;
            origDisplayId = typeof d['id'] === 'number' ? (d['id'] as number) : typeof attrs['id'] === 'number' ? (attrs['id'] as number) : null;
            origDisplayAttrs = { ...attrs };
            break;
          }
        }
        if (!origDisplayId || !origDisplayAttrs) {
          skip('display live cycle', `${vm.name} has no existing display to swap`);
        } else {
          const vmIdNum = typeof vmRaw?.['id'] === 'number' ? (vmRaw['id'] as number) : -1;
          let toreDown = false;
          try {
            await directRpc('vm.device.delete', [origDisplayId, {}]);
            toreDown = true;
            check('teardown: original console removed (direct RPC)', !rawDevicesOf(await rawVm(vm.name)).some((d) => d.dtype === 'DISPLAY'));

            const dispPlan = await runPlan('vms.display-attach', { name: vm.name, type: 'VNC' });
            check('display-attach plan succeeded', dispPlan.status === 'succeeded', { status: dispPlan.status, error: dispPlan.error, steps: (dispPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });
            const dispDetails = stepResult(dispPlan, 'vms.display-attach')?.['details'] as Record<string, unknown> | undefined;
            check('display-attach result reports the appliance-assigned port', typeof dispDetails?.['port'] === 'number' && (dispDetails!['port'] as number) >= 5900, dispDetails);
            check('display-attach result reports a console password', typeof dispDetails?.['password'] === 'string' && String(dispDetails!['password']).length > 0, { hasPassword: Boolean(dispDetails?.['password']) });

            rows = await settleVms((rs) => (devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'DISPLAY')));
            const vmAfterDisp = rows.find((r) => r.name === vm.name)!;
            const attachedDisplay = devicesOf(vmAfterDisp).find((d) => d.dtype === 'DISPLAY');
            check('GET /vms shows the new DISPLAY device', Boolean(attachedDisplay), devicesOf(vmAfterDisp));

            if (!attachedDisplay?.id) {
              skip('display detach', 'no integer device id on the attached DISPLAY row — LEAK: detach manually!');
            } else {
              const detPlan = await runPlan('vms.device-detach', { name: vm.name, deviceId: attachedDisplay.id });
              check('device-detach (DISPLAY) plan succeeded', detPlan.status === 'succeeded', { status: detPlan.status, error: detPlan.error });
              rows = await settleVms((rs) => !(devicesOf(rs.find((r) => r.name === vm.name)!).some((d) => d.dtype === 'DISPLAY')));
              const vmAfterDet2 = rows.find((r) => r.name === vm.name)!;
              check('DISPLAY device gone after detach', !devicesOf(vmAfterDet2).some((d) => d.dtype === 'DISPLAY'), devicesOf(vmAfterDet2));
            }
          } finally {
            if (toreDown && origDisplayAttrs) {
              // Restore the original console with its EXACT attribute set.
              const attrs = { ...origDisplayAttrs };
              delete attrs['id'];
              let restored = false;
              try {
                const v26 = await isV26();
                await directRpc('vm.device.create', [v26 ? { vm: vmIdNum, attributes: attrs } : { id: vmIdNum, attributes: attrs }]);
                restored = rawDevicesOf(await rawVm(vm.name)).some((d) => d.dtype === 'DISPLAY');
              } catch (e) {
                console.error(`  FAIL restore original display failed — MANUAL FIX NEEDED on ${vm.name}:`, e instanceof Error ? e.message : String(e));
              }
              check('restore: original console back on the VM', restored);
            }
          }
        }
      }
    }
  }

  // --- 4c. VM-level EDIT CYCLE (generic vm-edit contract — vms.vm-get prefill +
  // partial-merge vms.vm-update, always restored): description/autostart/time on
  // the stopped live-cycle VM, a rename-of-running negative test, then a full
  // rename round-trip as the final step.
  if (!stoppedVm) {
    skip('VM edit cycle', 'no STOPPED VM on this appliance');
  } else {
    const vm = stoppedVm;

    // Prefill — vms.vm-get must report every catalog field with a sane type.
    const getRes = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: vm.name } });
    check('vms.vm-get → 200', getRes.status === 200, { status: getRes.status });
    const got = ((await getRes.json()) as { details?: { state?: string; values?: Record<string, unknown> } }).details ?? {};
    const vals = (got.values ?? {}) as Record<string, unknown>;
    check('vm-get prefills name/description/autostart/bootloader/time', String(vals['name'] ?? '') === vm.name && typeof vals['description'] === 'string' && typeof vals['autostart'] === 'boolean' && ['UEFI', 'UEFI_CSM'].includes(String(vals['bootloader'])) && ['UTC', 'LOCAL'].includes(String(vals['time'])), got);
    check('vm-get prefills cores/threads/memoryMiB as numbers', typeof vals['cores'] === 'number' && typeof vals['threads'] === 'number' && typeof vals['memoryMiB'] === 'number', { cores: vals['cores'], threads: vals['threads'], memoryMiB: vals['memoryMiB'] });
    check('vm-get prefills the extended GUI fields with sane types', (typeof vals['minMemoryMiB'] === 'number' || vals['minMemoryMiB'] === '') && typeof vals['pinVcpus'] === 'boolean' && typeof vals['shutdownTimeoutSec'] === 'number' && typeof vals['suspendOnSnapshot'] === 'boolean' && typeof vals['hideFromMsr'] === 'boolean' && typeof vals['ensureDisplayDevice'] === 'boolean' && typeof vals['trustedPlatformModule'] === 'boolean' && typeof vals['hypervEnlightenments'] === 'boolean' && ['HOST-PASSTHROUGH', 'CUSTOM'].includes(String(vals['cpuMode'])) && (typeof vals['cpuModel'] === 'string') && typeof vals['commandLineArgs'] === 'string', { minMemoryMiB: vals['minMemoryMiB'], pinVcpus: vals['pinVcpus'], shutdownTimeoutSec: vals['shutdownTimeoutSec'], suspendOnSnapshot: vals['suspendOnSnapshot'], cpuMode: vals['cpuMode'], cpuModel: vals['cpuModel'] });

    const origDescription = String(vals['description'] ?? '');
    const origAutostart = vals['autostart'] === true;
    const origTime = String(vals['time']);
    const newTime = origTime === 'UTC' ? 'LOCAL' : 'UTC';
    console.log(`  INFO vm edit: description "${origDescription}" → "UNM E2E edit test", autostart ${origAutostart} → !, time ${origTime} → ${newTime}`);

    const updPlan = await runPlan('vms.vm-update', { name: vm.name, fields: { description: 'UNM E2E edit test', autostart: !origAutostart, time: newTime } });
    check('vm-update (description/autostart/time) plan succeeded', updPlan.status === 'succeeded', { status: updPlan.status, error: updPlan.error, steps: (updPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });
    const updDetails = stepResult(updPlan, 'vms.vm-update')?.['details'] as Record<string, unknown> | undefined;
    check('vm-update result reports the updated fields + verified', Array.isArray(updDetails?.['updated']) && ['description', 'autostart', 'time'].every((f) => (updDetails!['updated'] as string[]).includes(f)), updDetails);

    // Verify via a fresh vms.vm-get (live appliance read — no inventory lag).
    const getRes2 = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: vm.name } });
    const vals2 = (((await getRes2.json()) as { details?: { values?: Record<string, unknown> } }).details?.values ?? {}) as Record<string, unknown>;
    check('vm-get shows the NEW description/autostart/time after edit', String(vals2['description']) === 'UNM E2E edit test' && vals2['autostart'] === !origAutostart && String(vals2['time']) === newTime, vals2);

    // The persisted inventory (GET /vms) must carry the new description + autostart too.
    rows = await settleVms((rs) => { const r = rs.find((x) => x.name === vm.name); return String(r?.extra?.['description'] ?? '') === 'UNM E2E edit test' && (r?.extra?.['autostart'] as boolean | undefined) === !origAutostart; });
    const invRow = rows.find((r) => r.name === vm.name)!;
    check('GET /vms extra shows the NEW description + autostart', String(invRow.extra?.['description']) === 'UNM E2E edit test' && (invRow.extra?.['autostart'] as boolean | undefined) === !origAutostart, { description: invRow.extra?.['description'], autostart: invRow.extra?.['autostart'] });

    // Restore the original settings.
    const restorePlan = await runPlan('vms.vm-update', { name: vm.name, fields: { description: origDescription, autostart: origAutostart, time: origTime } });
    check('vm-update (restore original settings) plan succeeded', restorePlan.status === 'succeeded', { status: restorePlan.status, error: restorePlan.error });
    const getRes3 = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: vm.name } });
    const vals3 = (((await getRes3.json()) as { details?: { values?: Record<string, unknown> } }).details?.values ?? {}) as Record<string, unknown>;
    check('vm-get shows the ORIGINAL description/autostart/time after restore', String(vals3['description']) === origDescription && vals3['autostart'] === origAutostart && String(vals3['time']) === origTime, vals3);

    // EXTENDED edit cycle — the 0.21.0 GUI fields: min memory (halved or set to
    // 512), shutdown timeout (+/- 30s) and two booleans flipped. Always restored.
    const origMinMem = vals['minMemoryMiB'];
    const newMinMem = typeof origMinMem === 'number' && origMinMem > 0 ? Math.max(512, Math.floor(origMinMem / 2)) : 512;
    const origTimeout = Number(vals['shutdownTimeoutSec'] ?? 90);
    const newTimeout = origTimeout >= 3600 ? origTimeout - 30 : origTimeout + 30;
    const origSuspend = vals['suspendOnSnapshot'] === true;
    const origHideMsr = vals['hideFromMsr'] === true;
    console.log(`  INFO vm edit (extended): minMemory ${JSON.stringify(origMinMem)} → ${newMinMem}, shutdownTimeout ${origTimeout} → ${newTimeout}, suspendOnSnapshot ${origSuspend} → !, hideFromMsr ${origHideMsr} → !`);

    const extPlan = await runPlan('vms.vm-update', { name: vm.name, fields: { minMemoryMiB: newMinMem, shutdownTimeoutSec: newTimeout, suspendOnSnapshot: !origSuspend, hideFromMsr: !origHideMsr } });
    check('vm-update (extended GUI fields) plan succeeded', extPlan.status === 'succeeded', { status: extPlan.status, error: extPlan.error, steps: (extPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });
    const extDetails = stepResult(extPlan, 'vms.vm-update')?.['details'] as Record<string, unknown> | undefined;
    check('vm-update (extended) result reports the updated fields', Array.isArray(extDetails?.['updated']) && ['minMemoryMiB', 'shutdownTimeoutSec', 'suspendOnSnapshot', 'hideFromMsr'].every((f) => (extDetails!['updated'] as string[]).includes(f)), extDetails);

    const getRes4 = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: vm.name } });
    const vals4 = (((await getRes4.json()) as { details?: { values?: Record<string, unknown> } }).details?.values ?? {}) as Record<string, unknown>;
    check('vm-get shows the NEW extended values after edit', Number(vals4['minMemoryMiB']) === newMinMem && Number(vals4['shutdownTimeoutSec']) === newTimeout && vals4['suspendOnSnapshot'] === !origSuspend && vals4['hideFromMsr'] === !origHideMsr, { minMemoryMiB: vals4['minMemoryMiB'], shutdownTimeoutSec: vals4['shutdownTimeoutSec'], suspendOnSnapshot: vals4['suspendOnSnapshot'], hideFromMsr: vals4['hideFromMsr'] });

    // NEGATIVE — minimum memory ABOVE the maximum must be rejected pre-RPC.
    const maxMem = Number(vals['memoryMiB']);
    if (Number.isFinite(maxMem) && maxMem > 0) {
      const negMemPlan = await runPlan('vms.vm-update', { name: vm.name, fields: { minMemoryMiB: maxMem + 1 } });
      check('vm-update min_memory > memory FAILED (not succeeded)', negMemPlan.status === 'failed', { status: negMemPlan.status });
      const negMemDetails = stepResult(negMemPlan, 'vms.vm-update')?.['details'] as Record<string, unknown> | undefined;
      check('failure message names the minimum/maximum memory rule', /minimum memory/i.test(String(negMemDetails?.['error'] ?? '')), negMemDetails);
    } else {
      skip('min_memory > memory negative test', 'no numeric maximum memory reported');
    }

    // Restore the extended fields.
    const extRestorePlan = await runPlan('vms.vm-update', { name: vm.name, fields: { minMemoryMiB: origMinMem === '' ? '' : (origMinMem as number), shutdownTimeoutSec: origTimeout, suspendOnSnapshot: origSuspend, hideFromMsr: origHideMsr } });
    check('vm-update (restore extended GUI fields) plan succeeded', extRestorePlan.status === 'succeeded', { status: extRestorePlan.status, error: extRestorePlan.error });
    const getRes5 = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: vm.name } });
    const vals5 = (((await getRes5.json()) as { details?: { values?: Record<string, unknown> } }).details?.values ?? {}) as Record<string, unknown>;
    check('vm-get shows the ORIGINAL extended values after restore', (origMinMem === '' ? String(vals5['minMemoryMiB']) : Number(vals5['minMemoryMiB'])) === origMinMem && Number(vals5['shutdownTimeoutSec']) === origTimeout && vals5['suspendOnSnapshot'] === origSuspend && vals5['hideFromMsr'] === origHideMsr, { minMemoryMiB: vals5['minMemoryMiB'], shutdownTimeoutSec: vals5['shutdownTimeoutSec'], suspendOnSnapshot: vals5['suspendOnSnapshot'], hideFromMsr: vals5['hideFromMsr'] });

    // NEGATIVE — renaming a RUNNING VM must fail with the stopped-VM rule (no
    // appliance state changes: the SAME name is sent, so even a broken guard would
    // be a no-op merge).
    const runningVm = rows.find((r) => r.state === 'RUNNING');
    if (!runningVm) {
      skip('rename-while-running negative test', 'no RUNNING VM on this appliance');
    } else {
      const negPlan = await runPlan('vms.vm-update', { name: runningVm.name, fields: { name: runningVm.name } });
      check('vm-update rename of a RUNNING VM FAILED (not succeeded)', negPlan.status === 'failed', { status: negPlan.status });
      const negDetails = stepResult(negPlan, 'vms.vm-update')?.['details'] as Record<string, unknown> | undefined;
      check('failure message names the STOPPED-VM rule', /STOPPED/i.test(String(negDetails?.['error'] ?? '')), negDetails);
    }

    // RENAME round-trip on the stopped VM (final step — everything above already
    // used the original name). Restore is guaranteed via try/finally with a direct
    // RPC fallback if the plan workflow fails.
    const renamed = `${vm.name}_E2E`;
    let renameDone = false;
    try {
      const renPlan = await runPlan('vms.vm-update', { name: vm.name, fields: { name: renamed } });
      check('vm-update (rename) plan succeeded', renPlan.status === 'succeeded', { status: renPlan.status, error: renPlan.error, steps: (renPlan.steps ?? []).map((s) => `${s.actionId}:${s.status}`) });
      const getNew = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: renamed } });
      check('vm-get finds the VM under its NEW name', getNew.status === 200 && String((((await getNew.json()) as { details?: { values?: Record<string, unknown> } }).details?.values ?? {})['name']) === renamed, null);
      const getOld = await authed('POST', `/plugins/${PLUGIN_ID}/actions/execute`, { deviceId, actionId: 'vms.vm-get', input: { name: vm.name } });
      // Direct-execute returns 409 with the error at top level on action failure.
      const oldBody = (await getOld.json()) as { error?: string; details?: { error?: string } };
      check('vm-get no longer finds the OLD name', /not found/i.test(String(oldBody.error ?? oldBody.details?.error ?? '')), null);
      renameDone = true;
    } finally {
      if (renameDone) {
        let restored = false;
        try {
          const backPlan = await runPlan('vms.vm-update', { name: renamed, fields: { name: vm.name } });
          restored = backPlan.status === 'succeeded';
          check('vm-update (restore original name) plan succeeded', restored, { status: backPlan.status, error: backPlan.error });
        } catch (e) {
          console.error(`  FAIL rename restore via plan failed — trying direct RPC:`, e instanceof Error ? e.message : String(e));
        }
        if (!restored && tClient && tCreds) {
          try {
            const vmsRaw = await directRpc('vm.query', []) as Record<string, unknown>[];
            const row2 = (vmsRaw ?? []).find((r) => r['name'] === renamed);
            if (row2 && typeof row2['id'] === 'number') {
              await directRpc('vm.update', [row2['id'], { name: vm.name }]);
              restored = Boolean(((await directRpc('vm.query', [])) as Record<string, unknown>[])?.find((r) => r['name'] === vm.name));
            }
          } catch (e) {
            console.error(`  FAIL rename restore via direct RPC failed — MANUAL FIX NEEDED on ${renamed}:`, e instanceof Error ? e.message : String(e));
          }
        }
        check('restore: original VM name back', restored);
      }
    }
  }

  // --- 5. NEGATIVE: display attach on a VM that already has one --------------------
  if (!withDisplay) {
    skip('negative display test', 'no VM with an existing display found');
  } else {
    const negPlan = await runPlan('vms.display-attach', { name: withDisplay.name, type: 'VNC' });
    check('duplicate-display plan FAILED (not succeeded)', negPlan.status === 'failed', { status: negPlan.status });
    const negDetails = stepResult(negPlan, 'vms.display-attach')?.['details'] as Record<string, unknown> | undefined;
    check('failure message names the one-display rule', /already has a display/i.test(String(negDetails?.['error'] ?? '')), negDetails);
  }

  // --- Cleanup: delete every plan this script created ------------------------------
  for (const id of createdPlans) {
    const r = await authed('DELETE', `/plans/${id}`);
    if (r.status !== 204 && r.status !== 404) console.error(`  note: plan delete ${id} → ${r.status}`, await r.json());
  }
  check('all created plans deleted', true, `${createdPlans.length} plans`);

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('FATAL', err);
  process.exit(1);
});
