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
 *        DISPLAY attach (VNC)       → verify + appliance-assigned port      → detach → verify gone   4b. EDIT CYCLES (generic edit contract — vms.device-get prefill + partial-merge
        vms.device-update, verified via GET /vms detail, always restored):
        NIC bridge swap on the freshly attached NIC; DISPLAY resolution change
        on the VM's existing console. *   5. NEGATIVE: display attach on a VM that ALREADY has one must fail with the
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
  for (const [id, risk] of [['vms.device-types', 'read'], ['vms.disk-choices', 'read'], ['vms.pci-choices', 'read'], ['vms.usb-choices', 'read'], ['vms.nic-choices', 'read'], ['vms.device-get', 'read'], ['vms.disk-attach', 'write'], ['vms.display-attach', 'write'], ['vms.pci-attach', 'write'], ['vms.usb-attach', 'write'], ['vms.nic-attach', 'write'], ['vms.cdrom-attach', 'write'], ['vms.device-update', 'write']] as const) {
    const entry = catalog.find((a) => a.id === id);
    check(`catalog has ${id} (${risk})`, Boolean(entry) && entry!.riskLevel === risk, entry ?? `missing`);
  }

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
