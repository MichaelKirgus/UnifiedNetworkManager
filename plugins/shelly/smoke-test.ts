/**
 * Shelly plugin — end-to-end smoke test (LOCAL ONLY; not part of the CI
 * contract suite, which runs plugin-test-kit against dist/).
 *
 * Runs the REAL plugin in-process (src/index.ts via ts-node) against mock
 * Shelly devices that emulate all three profiles:
 *
 *   gen1         — legacy REST (GET /shelly auth-free, /status, /ota, /reboot)
 *   gen2-classic — JSON-RPC fw 1.x namespaces (Shelly.*, WiFi.*, Firmware.*)
 *   gen2-modern  — JSON-RPC fw 2.x+ namespaces (Sys.*, Wifi.*, Firmware.*)
 *
 * Covered: /discover contract, monitoring per generation (ok + updates row),
 * namespace separation in the RPC traffic, unreachable + auth-rejected
 * health, firmware update end-to-end (trigger → simulated reboot window →
 * version bump → authoritative empty updates), stable-only/URL guards on
 * Gen1, reboot, /plan fan-out with the settle-wait + inventory-refresh tail,
 * and the web-UI quick action.
 *
 * Usage: npm run smoke-test   (from plugins/shelly)
 */

// ts-node runs this file as CommonJS (tsconfig module: commonjs), so the
// built-in require is available — no createRequire needed.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { startMockShelly } = require('./test/mock-shelly.js');

const GEN1_PORT = 49320; // Gen1 mock (fw 4.5.0 → 4.5.1 pending)
const CLASSIC_PORT = 49321; // Gen2 classic mock (fw 1.4.1 → 1.4.2 pending)
const MODERN_PORT = 49322; // Gen2 modern mock (fw 2.0.5 → 2.0.6 pending)
const AUTH_GEN1_PORT = 49323; // Gen1 mock with local login enabled, no creds bound
const PLUGIN_PORT = 49324;
const CLOSED_PORT = 49398; // nothing listens here → unreachable target
const BASE = `http://localhost:${PLUGIN_PORT}`;

const REBOOT_WAIT_MS = 700; // mock reboot window
const SETTLE_AFTER_TRIGGER_MS = 1_200; // > REBOOT_WAIT_MS with margin

process.env.PORT = String(PLUGIN_PORT);

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) {
    console.log(`  ✅ ${label}`);
  } else {
    failures += 1;
    console.log(`  ❌ ${label}${extra !== undefined ? ` — got: ${JSON.stringify(extra)}` : ''}`);
  }
}

async function main(): Promise<void> {
  // --- Mock devices -----------------------------------------------------------
  const gen1 = startMockShelly({ port: GEN1_PORT, profile: 'gen1', name: 'Shelly Gen1 Mock', model: 'SHSW-1', mac: 'AABBCCDDEE01', fw: '4.5.0', latestFw: '4.5.1', rebootMs: REBOOT_WAIT_MS });
  const classic = startMockShelly({ port: CLASSIC_PORT, profile: 'gen2-classic', name: 'Shelly Plus Wave Mock', model: 'SWN-1PM', mac: 'AABBCCDDEE02', fw: '1.4.1', latestFw: '1.4.2', rebootMs: REBOOT_WAIT_MS });
  const modern = startMockShelly({ port: MODERN_PORT, profile: 'gen2-modern', name: 'Shelly Pro 4 Gen4 Mock', model: 'Pro4Gen4', mac: 'AABBCCDDEE03', fw: '2.0.5', latestFw: '2.0.6', rebootMs: REBOOT_WAIT_MS });
  const locked = startMockShelly({ port: AUTH_GEN1_PORT, profile: 'gen1', name: 'Shelly Locked Mock', model: 'SHSW-1', mac: 'AABBCCDDEE04', fw: '4.4.0', latestFw: null, authEnabled: true, rebootMs: REBOOT_WAIT_MS });

  for (const m of [gen1, classic, modern, locked]) await new Promise<void>((r) => m.server.listen(m.state.port, '127.0.0.1', () => r()));
  console.log(`mock devices up on ${GEN1_PORT}/${CLASSIC_PORT}/${MODERN_PORT}/${AUTH_GEN1_PORT}`);

  // --- Real plugin (in-process; PORT env set above) ---------------------------
  await import('./src/index');
  await new Promise((r) => setTimeout(r, 400)); // let the plugin listen

  const post = async (path: string, body: unknown): Promise<{ status: number; data: any }> => {
    const res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: (await res.json()) as any };
  };
  const mon = async (address: string) => post('/monitoring', { deviceId: 'smoke-device', managementAddress: address });
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

  // --- /discover ---------------------------------------------------------------
  console.log('\n/discover');
  const disc: any = await (await fetch(`${BASE}/discover`)).json();
  check('uuid is the reserved shelly uuid', disc.uuid === 'fba9d8ed-f84b-4da7-98e3-aeac38e37b0f', disc.uuid);
  check('name is Shelly Plugin', disc.name === 'Shelly Plugin', disc.name);
  check('vendors = [shelly]', JSON.stringify(disc.vendors) === '["shelly"]', disc.vendors);
  check(
    'capabilities include monitoring/updates/configuration/planning/quickActions',
    ['monitoring', 'updates', 'configuration', 'planning', 'quickActions'].every((c: string) => (disc.capabilities ?? []).includes(c)),
    disc.capabilities
  );
  check('requiredSecretType = null (credential-free monitoring)', disc.requiredSecretType === null, disc.requiredSecretType);
  const loginSlot = (disc.credentialSlots ?? []).find((s: any) => s.name === 'login');
  check(
    'optional login slot declared (usernamePassword, required:false)',
    !!loginSlot && loginSlot.required === false && JSON.stringify(loginSlot.secretTypes) === '["usernamePassword"]',
    disc.credentialSlots
  );
  check(
    'options declare transport/timeoutMs/logToApi',
    ['transport', 'timeoutMs', 'logToApi'].every((k: string) => (disc.options ?? []).some((o: any) => o.key === k)),
    disc.options?.map((o: any) => o.key)
  );
  check('iconUrl advertised', disc.iconUrl === '/icons/shelly.svg', disc.iconUrl);
  const fwAction = (disc.actions ?? []).find((a: any) => a.id === 'shelly.firmware.update');
  check(
    'firmware.update is dangerous + no retry on dispatch failure',
    fwAction?.riskLevel === 'dangerous' && fwAction?.retryOnDispatchFailure === false,
    fwAction
  );
  const rebootAction = (disc.actions ?? []).find((a: any) => a.id === 'shelly.reboot');
  check('reboot is write-level', rebootAction?.riskLevel === 'write', rebootAction);
  const setRelayAction = (disc.actions ?? []).find((a: any) => a.id === 'shelly.setRelay');
  check(
    'setRelay is write-level with a boolean on input',
    setRelayAction?.riskLevel === 'write' && setRelayAction?.inputSchema?.on?.type === 'boolean',
    setRelayAction
  );
  check('quick action webui advertised', (disc.quickActions ?? []).some((q: any) => q.id === 'webui' && q.kind === 'url'), disc.quickActions);
  check(
    'relay-on/relay-off quick actions target shelly.setRelay with prefill',
    (disc.quickActions ?? []).some((q: any) => q.id === 'relay-on' && q.kind === 'action' && q.actionId === 'shelly.setRelay' && q.prefill?.on === true) &&
      (disc.quickActions ?? []).some((q: any) => q.id === 'relay-off' && q.kind === 'action' && q.actionId === 'shelly.setRelay' && q.prefill?.on === false),
    disc.quickActions
  );

  // --- /monitoring — Gen1 happy path -------------------------------------------
  console.log('\n/monitoring (gen1 happy path)');
  let m = await mon(`localhost:${GEN1_PORT}`);
  check('HTTP 200', m.status === 200, m.status);
  check('health ok', m.data.health === 'ok', m.data.health);
  const g1 = m.data.metrics ?? {};
  check('swVersion 4.5.0 (live /shelly probe)', g1['system.swVersion'] === '4.5.0', g1['system.swVersion']);
  check('hostname from device name', g1['hostname'] === 'Shelly Gen1 Mock', g1['hostname']);
  check('model SHSW-1', g1['shelly.model'] === 'SHSW-1', g1['shelly.model']);
  check('mac reported', g1['shelly.mac'] === 'AABBCCDDEE01', g1['shelly.mac']);
  check('uptimeSeconds 3600 (/status.uptime is seconds, Gen1 docs)', g1['shelly.uptimeSeconds'] === 3600, g1['shelly.uptimeSeconds']);
  check('ramFreeBytes 45000 / ramTotalBytes 87300', g1['shelly.ramFreeBytes'] === 45000 && g1['shelly.ramTotalBytes'] === 87300, [g1['shelly.ramFreeBytes'], g1['shelly.ramTotalBytes']]);
  check('fsFreeBytes 200000', g1['shelly.fsFreeBytes'] === 200000, g1['shelly.fsFreeBytes']);
  check('wifiRssiDbm -62', g1['shelly.wifiRssiDbm'] === -62, g1['shelly.wifiRssiDbm']);
  check('wifiSsid reported', g1['shelly.wifiSsid'] === 'KirgusNET_IoT', g1['shelly.wifiSsid']);
  check('wifiStaIp reported', g1['shelly.wifiStaIp'] === '192.168.7.50', g1['shelly.wifiStaIp']);
  check('fwUpdateAvailable = 1 (update pending)', g1['shelly.fwUpdateAvailable'] === 1, g1['shelly.fwUpdateAvailable']);
  check('relay0On = 1', g1['shelly.relay0On'] === 1, g1['shelly.relay0On']);
  const g1rows: any[] = Array.isArray(g1['updates']) ? (g1['updates'] as any[]) : [];
  check('exactly one updates row', g1rows.length === 1, g1rows);
  check(
    'row: firmware 4.5.0 → 4.5.1, available, rebootRequired, applyActionId',
    g1rows[0]?.kind === 'firmware' &&
      g1rows[0]?.available === true &&
      g1rows[0]?.currentVersion === '4.5.0' &&
      g1rows[0]?.latestVersion === '4.5.1' &&
      g1rows[0]?.rebootRequired === true &&
      g1rows[0]?.applyActionId === 'shelly.firmware.update',
    g1rows[0]
  );
  check('activeSettings echo (http, 5000ms)', m.data.activeSettings?.transport === 'http' && m.data.activeSettings?.timeoutMs === 5000, m.data.activeSettings);

  // --- /monitoring — Gen2 classic ----------------------------------------------
  console.log('\n/monitoring (gen2 classic)');
  m = await mon(`localhost:${CLASSIC_PORT}`);
  check('health ok', m.data.health === 'ok', m.data.health);
  const gc = m.data.metrics ?? {};
  check('swVersion 1.4.1', gc['system.swVersion'] === '1.4.1', gc['system.swVersion']);
  check('model SWN-1PM', gc['shelly.model'] === 'SWN-1PM', gc['shelly.model']);
  check('wifiChannel 6', gc['shelly.wifiChannel'] === 6, gc['shelly.wifiChannel']);
  check('wifiBssid reported', gc['shelly.wifiBssid'] === 'AA:BB:CC:DD:EE:FF', gc['shelly.wifiBssid']);
  check('uptimeSeconds 3600 (sys.uptime is seconds, Gen2+ docs)', gc['shelly.uptimeSeconds'] === 3600, gc['shelly.uptimeSeconds']);
  check('ramFreeBytes 45000 / ramTotalBytes 87300 (sys.ram_free/ram_size)', gc['shelly.ramFreeBytes'] === 45000 && gc['shelly.ramTotalBytes'] === 87300, [gc['shelly.ramFreeBytes'], gc['shelly.ramTotalBytes']]);
  const crows: any[] = Array.isArray(gc['updates']) ? (gc['updates'] as any[]) : [];
  check('updates row 1.4.1 → 1.4.2', crows.length === 1 && crows[0]?.currentVersion === '1.4.1' && crows[0]?.latestVersion === '1.4.2', crows);

  // --- /monitoring — Gen2 modern + namespace separation -------------------------
  console.log('\n/monitoring (gen2 modern)');
  m = await mon(`localhost:${MODERN_PORT}`);
  check('health ok', m.data.health === 'ok', m.data.health);
  const gm = m.data.metrics ?? {};
  check('swVersion 2.0.5', gm['system.swVersion'] === '2.0.5', gm['system.swVersion']);
  check('model Pro4Gen4', gm['shelly.model'] === 'Pro4Gen4', gm['shelly.model']);
  const mrows: any[] = Array.isArray(gm['updates']) ? (gm['updates'] as any[]) : [];
  check('updates row 2.0.5 → 2.0.6', mrows.length === 1 && mrows[0]?.currentVersion === '2.0.5' && mrows[0]?.latestVersion === '2.0.6', mrows);
  // Detection probes the classic namespace first even on modern devices, so a
  // Shelly.GetDeviceInfo in the traffic log is expected — steady-state polling
  // (everything from the first successful Sys.GetDeviceInfo on) must be modern-only.
  const modernPollCalls = modern.state.rpcCalls.slice(Math.max(0, modern.state.rpcCalls.indexOf('Sys.GetDeviceInfo')));
  check(
    'modern namespace used in polling (no Shelly.* after detection)',
    modernPollCalls.includes('Sys.GetStatus') && !modernPollCalls.some((c: string) => c.startsWith('Shelly.')),
    modern.state.rpcCalls
  );
  check(
    'classic namespace used (Shelly.GetDeviceInfo, no Sys.* in traffic)',
    classic.state.rpcCalls.includes('Shelly.GetDeviceInfo') && !classic.state.rpcCalls.some((c: string) => c === 'Sys.GetStatus' || c === 'Sys.Reboot' || c === 'Firmware.Update'),
    classic.state.rpcCalls
  );

  // --- /monitoring — unreachable target ----------------------------------------
  console.log('\n/monitoring (unreachable)');
  m = await mon(`localhost:${CLOSED_PORT}`);
  check('HTTP 200 with critical health', m.status === 200 && m.data.health === 'critical', [m.status, m.data.health]);
  check('system.error mentions detection failure', /could not detect/i.test(String(m.data.metrics?.['system.error'] ?? '')), m.data.metrics?.['system.error']);

  // --- /monitoring — auth rejected (local login on, no creds bound) -------------
  console.log('\n/monitoring (auth rejected)');
  m = await mon(`localhost:${AUTH_GEN1_PORT}`);
  check('HTTP 200 with critical health', m.status === 200 && m.data.health === 'critical', [m.status, m.data.health]);
  check(
    'error names the auth rejection (not a misleading 404)',
    /authentication rejected by device \(HTTP 401\)/.test(String(m.data.metrics?.['system.error'] ?? '')),
    m.data.metrics?.['system.error']
  );
  check('updates key omitted on failure', !('updates' in (m.data.metrics ?? {})), Object.keys(m.data.metrics ?? {}));

  // --- /config — Gen1 firmware update end-to-end --------------------------------
  console.log('\n/config (gen1 firmware.update)');
  let c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.firmware.update', input: {} });
  check('trigger accepted', c.status === 200 && c.data.success === true, c.data);
  check('device saw the update trigger', gen1.state.updateTriggers === 1, gen1.state.updateTriggers);
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.firmware.update', input: { stage: 'beta' } });
  check('stage=beta rejected on Gen1 (stable-only)', c.data.success === false && /stable/i.test(String(c.data.result?.details?.error ?? '')), c.data);
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.firmware.update', input: { url: 'http://example.com/fw.bin' } });
  check('custom URL rejected on Gen1', c.data.success === false && /not supported on Gen1/i.test(String(c.data.result?.details?.error ?? '')), c.data);

  await wait(SETTLE_AFTER_TRIGGER_MS); // simulated reboot window
  m = await mon(`localhost:${GEN1_PORT}`);
  check('health ok after update', m.data.health === 'ok', m.data.health);
  check('swVersion bumped to 4.5.1 (live probe, no stale cache)', m.data.metrics?.['system.swVersion'] === '4.5.1', m.data.metrics?.['system.swVersion']);
  check('updates row wiped (authoritative empty)', Array.isArray(m.data.metrics?.['updates']) && (m.data.metrics['updates'] as unknown[]).length === 0, m.data.metrics?.['updates']);
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.firmware.update', input: {} });
  check('re-trigger with nothing pending is rejected', c.data.success === false, c.data);

  // --- /config — Gen2 classic + modern firmware update ---------------------------
  console.log('\n/config (gen2 classic firmware.update)');
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${CLASSIC_PORT}`, actionId: 'shelly.firmware.update', input: { stage: 'stable' } });
  check('trigger accepted', c.data.success === true, c.data);
  check('classic used Shelly.Update', classic.state.rpcCalls.includes('Shelly.Update'), classic.state.rpcCalls);
  await wait(SETTLE_AFTER_TRIGGER_MS);
  m = await mon(`localhost:${CLASSIC_PORT}`);
  check('swVersion bumped to 1.4.2', m.data.metrics?.['system.swVersion'] === '1.4.2', m.data.metrics?.['system.swVersion']);
  check('updates row wiped', Array.isArray(m.data.metrics?.['updates']) && (m.data.metrics['updates'] as unknown[]).length === 0, m.data.metrics?.['updates']);

  console.log('\n/config (gen2 modern firmware.update)');
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${MODERN_PORT}`, actionId: 'shelly.firmware.update', input: { stage: 'stable' } });
  check('trigger accepted', c.data.success === true, c.data);
  check('modern used Firmware.Update', modern.state.rpcCalls.includes('Firmware.Update'), modern.state.rpcCalls);
  await wait(SETTLE_AFTER_TRIGGER_MS);
  m = await mon(`localhost:${MODERN_PORT}`);
  check('swVersion bumped to 2.0.6', m.data.metrics?.['system.swVersion'] === '2.0.6', m.data.metrics?.['system.swVersion']);
  check('updates row wiped', Array.isArray(m.data.metrics?.['updates']) && (m.data.metrics['updates'] as unknown[]).length === 0, m.data.metrics?.['updates']);

  // --- /config — reboot -----------------------------------------------------------
  console.log('\n/config (gen1 reboot)');
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.reboot', input: {} });
  check('reboot accepted', c.data.success === true, c.data);
  check('device saw the reboot', gen1.state.reboots === 1, gen1.state.reboots);
  await wait(SETTLE_AFTER_TRIGGER_MS);
  m = await mon(`localhost:${GEN1_PORT}`);
  check('device back after reboot (health ok, version unchanged)', m.data.health === 'ok' && m.data.metrics?.['system.swVersion'] === '4.5.1', [m.data.health, m.data.metrics?.['system.swVersion']]);

  // --- /config — relay control (setRelay) ---------------------------------------
  console.log('\n/config (gen1 setRelay)');
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.setRelay', input: { on: false } });
  check('Gen1 relay-off accepted', c.data.success === true, c.data);
  m = await mon(`localhost:${GEN1_PORT}`);
  check('Gen1 relay0On flipped to 0 (monitoring reflects the toggle)', m.data.metrics?.['shelly.relay0On'] === 0, m.data.metrics?.['shelly.relay0On']);
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.setRelay', input: { on: true } });
  check('Gen1 relay-on accepted', c.data.success === true, c.data);
  m = await mon(`localhost:${GEN1_PORT}`);
  check('Gen1 relay0On flipped back to 1', m.data.metrics?.['shelly.relay0On'] === 1, m.data.metrics?.['shelly.relay0On']);
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${GEN1_PORT}`, actionId: 'shelly.setRelay', input: { on: true, relayId: 5 } });
  check('unknown relay rejected (Gen1 answers 404)', c.data.success === false && /HTTP 404/.test(String(c.data.result?.details?.error ?? '')), c.data);

  console.log('\n/config (gen2 classic setRelay)');
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${CLASSIC_PORT}`, actionId: 'shelly.setRelay', input: { on: false } });
  check('classic Switch.Set accepted', c.data.success === true, c.data);
  check('classic device saw Switch.Set', classic.state.rpcCalls.includes('Switch.Set'), classic.state.rpcCalls);
  m = await mon(`localhost:${CLASSIC_PORT}`);
  check('classic relay0On flipped to 0', m.data.metrics?.['shelly.relay0On'] === 0, m.data.metrics?.['shelly.relay0On']);

  console.log('\n/config (gen2 modern setRelay)');
  c = await post('/config', { deviceId: 'smoke-device', managementAddress: `localhost:${MODERN_PORT}`, actionId: 'shelly.setRelay', input: { on: false } });
  check('modern Switch.Set accepted', c.data.success === true, c.data);
  check('modern device saw Switch.Set', modern.state.rpcCalls.includes('Switch.Set'), modern.state.rpcCalls);
  m = await mon(`localhost:${MODERN_PORT}`);
  check('modern relay0On flipped to 0', m.data.metrics?.['shelly.relay0On'] === 0, m.data.metrics?.['shelly.relay0On']);

  // --- /plan ----------------------------------------------------------------------
  console.log('\n/plan');
  let p = await post('/plan', {
    intent: { actionId: 'shelly.firmware.update', inputs: {} },
    devices: [{ deviceId: 'dev-gen1', managementAddress: `localhost:${GEN1_PORT}`, credentials: {} }],
  });
  const steps: any[] = p.data?.plan?.steps ?? [];
  check('plan HTTP 200', p.status === 200, p.status);
  check(
    'firmware.update plan = update + settle wait + inventory refresh',
    JSON.stringify(steps.map((s) => s.actionId)) === JSON.stringify(['shelly.firmware.update', 'unm.wait', 'unm.inventory.refresh']),
    steps.map((s) => s.actionId)
  );
  check('settle wait is 120000ms, best-effort', steps[1]?.input?.ms === 120000 && steps[1]?.bestEffort === true, steps[1]);
  check(
    'inventory refresh depends on the wait step, best-effort',
    steps[2]?.actionId === 'unm.inventory.refresh' && JSON.stringify(steps[2]?.dependsOn) === '[1]' && steps[2]?.bestEffort === true,
    steps[2]
  );

  p = await post('/plan', {
    intent: { actionId: 'shelly.reboot', inputs: {} },
    devices: [{ deviceId: 'dev-gen1', managementAddress: `localhost:${GEN1_PORT}`, credentials: {} }],
  });
  check('reboot plan is a single step (no settle tail)', JSON.stringify((p.data?.plan?.steps ?? []).map((s: any) => s.actionId)) === '["shelly.reboot"]', p.data?.plan?.steps);

  p = await post('/plan', {
    intent: { actionId: 'shelly.setRelay', inputs: { on: false } },
    devices: [{ deviceId: 'dev-gen1', managementAddress: `localhost:${GEN1_PORT}`, credentials: {} }],
  });
  check('setRelay plan is a single step (no settle tail)', JSON.stringify((p.data?.plan?.steps ?? []).map((s: any) => s.actionId)) === '["shelly.setRelay"]', p.data?.plan?.steps);
  check('setRelay inputs land on the step', (p.data?.plan?.steps ?? [])[0]?.input?.on === false, p.data?.plan?.steps);

  p = await post('/plan', {
    intent: { actionId: 'shelly.firmware.update', inputs: {} },
    devices: [
      { deviceId: 'dev-classic', managementAddress: `localhost:${CLASSIC_PORT}`, credentials: {} },
      { deviceId: 'dev-modern', managementAddress: `localhost:${MODERN_PORT}`, credentials: {} },
    ],
  });
  const multiSteps: any[] = p.data?.plan?.steps ?? [];
  check(
    'multi-device fan-out: all update steps first, then per-device tail (6 steps)',
    JSON.stringify(multiSteps.map((s) => s.actionId)) ===
      JSON.stringify(['shelly.firmware.update', 'shelly.firmware.update', 'unm.wait', 'unm.inventory.refresh', 'unm.wait', 'unm.inventory.refresh']),
    multiSteps.map((s) => s.actionId)
  );
  check(
    'each refresh depends on its own wait step, both best-effort',
    JSON.stringify(multiSteps[3]?.dependsOn) === '[2]' && JSON.stringify(multiSteps[5]?.dependsOn) === '[4]' && multiSteps[3]?.bestEffort === true && multiSteps[5]?.bestEffort === true,
    [multiSteps[3], multiSteps[5]]
  );

  p = await post('/plan', { intent: { actionId: 'nope.nope', inputs: {} }, devices: [{ deviceId: 'd', managementAddress: `localhost:${GEN1_PORT}`, credentials: {} }] });
  check('unknown action → 400', p.status === 400, [p.status, p.data]);
  p = await post('/plan', { intent: { actionId: 'shelly.firmware.update', inputs: { stage: 'nightly' } }, devices: [{ deviceId: 'd', managementAddress: `localhost:${GEN1_PORT}`, credentials: {} }] });
  check('invalid stage enum → 400', p.status === 400, [p.status, p.data]);
  p = await post('/plan', { intent: { actionId: 'shelly.firmware.update', inputs: {} }, devices: [] });
  check('zero devices → 400', p.status === 400, [p.status, p.data]);

  // --- /quick-action ----------------------------------------------------------------
  console.log('\n/quick-action');
  const qa = await post('/quick-action', { actionId: 'webui', managementAddress: `localhost:${GEN1_PORT}` });
  check('webui resolves to the device web UI', JSON.stringify(qa.data).includes(`http://localhost:${GEN1_PORT}`), qa.data);

  // --- Summary ----------------------------------------------------------------------
  console.log('');
  for (const m2 of [gen1, classic, modern, locked]) m2.server.close();
  if (failures > 0) {
    console.log(`❌ ${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('✅ all shelly smoke checks passed');
  process.exit(0);
}

main().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});
