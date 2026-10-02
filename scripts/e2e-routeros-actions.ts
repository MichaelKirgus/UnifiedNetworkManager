/**
 * End-to-end validation of the RouterOS plugin's full action surface (v0.4.0).
 *
 * Runs against the live dev stack (API :3000) and a real RouterOS device — by
 * default ROUTEROS01, the QEMU x86_64 test router at 10.25.2.1 (RouterOS 7.21.5
 * LTS; override with ROS_DEVICE_ID / ROS_PLUGIN_ID env vars). For every action
 * it creates a one-device plan via POST /plans, executes it, polls to a
 * terminal state and asserts the step result. Every write is paired with its
 * cleanup counterpart so the device ends in its pre-test state (the script also
 * restores identity/DNS/ether1 comment itself — see CLEANUP section).
 *
 * Deliberately NOT exercised here: system.reboot, system.halt, firmware.update,
 * config.restore, gateway.add/delete, dhcp.reconfigure (management-network risk).
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-routeros-actions.ts [only-action-id ...]
 */

import crypto from 'node:crypto';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_ID = process.env.ROS_DEVICE_ID ?? '5c6e5d9a-1ad4-4ddd-82f3-508991d3ce15';
const PLUGIN_ID = process.env.ROS_PLUGIN_ID ?? '00000000-0000-4000-8000-00000000000a';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg');
const { authenticator } = apiRequire('otplib');

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

interface StepRow {
  id: string; stepIndex: number; actionId: string; status: string;
  result?: Record<string, unknown> | null;
}
interface PlanDto { id?: string; status?: string; steps?: StepRow[]; error?: string | null; }

/** ActionResult as stored one level inside step.result ({ success, result }). */
function actionResult(step: StepRow): { success?: boolean; applied?: boolean; details?: Record<string, unknown>; error?: string } | null {
  const outer = step.result ?? null;
  if (!outer || typeof outer !== 'object') return null;
  const inner = (outer as Record<string, unknown>)['result'];
  const src: Record<string, unknown> = (inner && typeof inner === 'object' ? inner : outer) as Record<string, unknown>;
  return { success: src['success'] as boolean | undefined, applied: src['applied'] as boolean | undefined, details: src['details'] as Record<string, unknown> | undefined, error: src['error'] as string | undefined };
}

async function main(): Promise<void> {
  const only = process.argv.slice(2);
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Login (admin has a real TOTP enrolled) ---------------------------------
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
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

  // --- Plan runner -------------------------------------------------------------
  const TERMINAL = ['succeeded', 'failed', 'cancelled', 'unverified'];
  async function runAction(actionId: string, inputs: Record<string, unknown>, timeoutMs = 120_000): Promise<{ planStatus?: string; step?: StepRow }> {
    const createRes = await authed('POST', '/plans', { pluginId: PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId: DEVICE_ID }] });
    if (createRes.status !== 201) {
      console.error(`  !! plan creation for ${actionId} → ${createRes.status}:`, JSON.stringify(await createRes.json()).slice(0, 300));
      return {};
    }
    const created = (await createRes.json()) as PlanDto;
    const execRes = await authed('POST', `/plans/${created.id}/execute`);
    if (execRes.status !== 202) {
      console.error(`  !! execute for ${actionId} → ${execRes.status}:`, JSON.stringify(await execRes.json()).slice(0, 300));
      return {};
    }
    const deadline = Date.now() + timeoutMs;
    let final: PlanDto = {};
    while (Date.now() < deadline) {
      const r = await authed('GET', `/plans/${created.id}`);
      final = (await r.json()) as PlanDto;
      if (TERMINAL.includes(final.status ?? '')) break;
      await new Promise((res2) => setTimeout(res2, 750));
    }
    return { planStatus: final.status, step: final.steps?.[0] };
  }

  /** Runs an action and asserts the step succeeded (or was a clean idempotent skip). */
  async function expectOk(actionId: string, inputs: Record<string, unknown>, timeoutMs?: number): Promise<{ planStatus?: string; result: ReturnType<typeof actionResult> }> {
    const t0 = Date.now();
    const { planStatus, step } = await runAction(actionId, inputs, timeoutMs);
    const ms = ((Date.now() - t0) / 1000).toFixed(1);
    const result = step ? actionResult(step) : null;
    const ok = planStatus === 'succeeded' && !!result?.success;
    check(`${actionId} (${ms}s)`, ok, { planStatus, step: step?.status, error: result?.error ?? undefined });
    if (!ok && result?.details) console.log('     details:', JSON.stringify(result.details).slice(0, 400));
    return { planStatus, result };
  }

  // --- READS -------------------------------------------------------------------
  console.log('\n== READ actions ==');
  const reads: Array<[string, Record<string, unknown>]> = [
    ['system.info.read', {}],
    ['system.status.read', {}],
    ['system.users.read', {}],
    ['system.services.read', {}],
    ['system.scripts.read', {}],
    ['system.scheduler.read', {}],
    ['system.logging.read', {}],
    ['interfaces.read', {}],
    ['routes.read', {}],
    ['gateways.read', {}],
    ['dhcp.staticMappings.read', {}],
    ['dns.hosts.read', {}],
    ['firewall.rules.read', {}],
    ['firewall.aliases.read', {}],
    ['wireguard.servers.read', {}],
    ['wireguard.peers.read', {}],
    ['ipsec.read', {}],
    ['firmware.status.read', {}],
  ];
  for (const [id, inputs] of reads) {
    if (only.length && !only.includes(id)) continue;
    const { result } = await expectOk(id, inputs);
    // Spot-check a few payloads.
    if (id === 'system.info.read') check('info: version 7.x', String(result?.details?.['version'] ?? '').startsWith('7.'), result?.details);
    if (id === 'interfaces.read') {
      const ifaces = (result?.details?.['interfaces'] as Array<Record<string, unknown>> | undefined) ?? [];
      check('interfaces: ether1 present', ifaces.some((i) => i['name'] === 'ether1'), ifaces.map((i) => i['name']));
    }
  }

  // --- WRITES (each paired with its cleanup) ------------------------------------
  console.log('\n== WRITE actions ==');

  // 1. Identity round-trip.
  await expectOk('system.identity.set', { name: 'unm-v04-test' });
  const infoAfter = await runAction('system.info.read', {});
  check('identity applied (hostname changed)', String(actionResult(infoAfter.step ?? { result: null })?.details?.['hostname'] ?? '') === 'unm-v04-test');

  // 2. Interface comment round-trip (ether1).
  await expectOk('interface.settings.set', { interface: 'ether1', comment: 'unm-v04-comment' });

  // 3. User add/delete.
  await expectOk('system.user.add', { name: 'unmv04user', password: 'V04test!pw', group: 'read' });
  const usersMid = actionResult((await runAction('system.users.read', {})).step ?? { result: null })?.details;
  check('user visible in system.users.read', ((usersMid?.['users'] as Array<Record<string, unknown>> | undefined) ?? []).some((u) => u['name'] === 'unmv04user'));
  await expectOk('system.user.delete', { name: 'unmv04user' });

  // 4. Script + scheduler round-trip (scheduler disabled so it never fires).
  await expectOk('system.script.add', { name: 'unm-v04-script', source: 'put log info "v04 validation"' });
  await expectOk('system.scheduler.add', { name: 'unm-v04-job', onEvent: 'unm-v04-script', interval: '1h', disabled: true });
  const schedMid = actionResult((await runAction('system.scheduler.read', {})).step ?? { result: null })?.details;
  check('scheduler job visible + disabled', ((schedMid?.['jobs'] as Array<Record<string, unknown>> | undefined) ?? []).some((j) => j['name'] === 'unm-v04-job' && j['disabled'] === true));
  await expectOk('system.scheduler.delete', { name: 'unm-v04-job' });
  await expectOk('system.script.delete', { name: 'unm-v04-script' });

  // 5. Service lifecycle on telnet (already disabled in the running config).
  await expectOk('services.start', { name: 'telnet' });
  const svcMid = actionResult((await runAction('system.services.read', {})).step ?? { result: null })?.details;
  check('telnet enabled after services.start', ((svcMid?.['services'] as Array<Record<string, unknown>> | undefined) ?? []).some((s) => s['name'] === 'telnet' && s['disabled'] === false));
  await expectOk('services.stop', { name: 'telnet' });

  // 6. Firewall alias + rule lifecycle (add → toggle ×2 → update → delete).
  await expectOk('firewall.alias.add', { name: 'unm-v04-list', address: '192.0.2.7/32' });
  const aliasesMid = actionResult((await runAction('firewall.aliases.read', {})).step ?? { result: null })?.details;
  check('alias visible in firewall.aliases.read', JSON.stringify(aliasesMid).includes('unm-v04-list'), aliasesMid);
  await expectOk('firewall.rule.add', { table: 'filter', chain: 'input', action: 'accept', protocol: 'tcp', dstPort: '8899', comment: 'unm-v04-rule' });
  const rulesMid = actionResult((await runAction('firewall.rules.read', {})).step ?? { result: null })?.details;
  check('rule visible in firewall.rules.read', JSON.stringify(rulesMid).includes('unm-v04-rule'), undefined);
  await expectOk('firewall.rule.toggle', { comment: 'unm-v04-rule', disabled: true });
  await expectOk('firewall.rule.toggle', { comment: 'unm-v04-rule', disabled: false });
  await expectOk('firewall.rule.update', { comment: 'unm-v04-rule', dstPort: '8898' });
  const rulesMid2 = actionResult((await runAction('firewall.rules.read', {})).step ?? { result: null })?.details;
  check('rule updated (dst-port 8898)', JSON.stringify(rulesMid2).includes('8898'), undefined);
  await expectOk('firewall.rule.delete', { comment: 'unm-v04-rule' });
  await expectOk('firewall.alias.delete', { name: 'unm-v04-list', address: '192.0.2.7/32' });

  // 7. VLAN round-trip.
  await expectOk('vlan.add', { name: 'unm-v04-vlan', vlanId: 42, parent: 'ether1' });
  const ifacesMid = actionResult((await runAction('interfaces.read', {})).step ?? { result: null })?.details;
  check('VLAN visible in interfaces.read', JSON.stringify(ifacesMid).includes('unm-v04-vlan'), undefined);
  await expectOk('vlan.delete', { name: 'unm-v04-vlan' });

  // 8. Static route round-trip (next hop = the DHCP gateway on ether1's L2).
  await expectOk('route.add', { destination: '192.0.2.0/24', gateway: '10.25.0.1' });
  const routesMid = actionResult((await runAction('routes.read', {})).step ?? { result: null })?.details;
  check('route visible in routes.read', JSON.stringify(routesMid).includes('192.0.2.0/24'), undefined);
  await expectOk('route.delete', { destination: '192.0.2.0/24' });

  // 9. DNS static host round-trip.
  await expectOk('dns.host.add', { name: 'unm-v04.local', address: '198.51.100.78' });
  const hostsMid = actionResult((await runAction('dns.hosts.read', {})).step ?? { result: null })?.details;
  check('DNS host visible in dns.hosts.read', JSON.stringify(hostsMid).includes('unm-v04.local'), undefined);
  await expectOk('dns.host.delete', { name: 'unm-v04.local' });

  // 10. DHCP static lease round-trip (synthetic MAC — no real client owns it).
  // RouterOS stores the MAC UPPERCASE, so search case-insensitively.
  await expectOk('dhcp.staticMapping.add', { macAddress: 'aa:bb:cc:dd:ee:f4', address: '10.25.2.99' });
  const leasesMid = actionResult((await runAction('dhcp.staticMappings.read', {})).step ?? { result: null })?.details;
  check('lease visible in dhcp.staticMappings.read', JSON.stringify(leasesMid).toLowerCase().includes('aa:bb:cc:dd:ee:f4'), undefined);
  await expectOk('dhcp.staticMapping.delete', { macAddress: 'aa:bb:cc:dd:ee:f4' });

  // 11. DNS servers (restored to the pre-test empty state via SSH in CLEANUP).
  await expectOk('dns.servers.set', { servers: ['1.1.1.1', '9.9.9.9'] });

  // 12. WireGuard server + peer round-trip (peer key generated locally, throwaway).
  const wgPair = crypto.generateKeyPairSync('x25519');
  const peerPubB64 = wgPair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const wgSet = await expectOk('wireguard.server.set', { name: 'unm-v04-wg', listenPort: 51820 });
  check('WG server returned a generated public key', typeof wgSet.result?.details?.['publicKey'] === 'string' && String(wgSet.result!.details!['publicKey']).length > 30, wgSet.result?.details);
  await expectOk('wireguard.peer.add', { interface: 'unm-v04-wg', publicKey: peerPubB64, allowedAddress: '192.0.2.50/32' });
  const peersMid = actionResult((await runAction('wireguard.peers.read', {})).step ?? { result: null })?.details;
  check('peer visible in wireguard.peers.read', JSON.stringify(peersMid).includes(peerPubB64), undefined);
  await expectOk('wireguard.peer.delete', { interface: 'unm-v04-wg', publicKey: peerPubB64 });
  await expectOk('wireguard.server.delete', { name: 'unm-v04-wg' });

  // 13. Config backup over SSH → file repo (also proves the SSH/SFTP transport).
  const backup = await expectOk('config.backup.download', {}, 240_000);
  const repoFileId = String(backup.result?.details?.['repoFileId'] ?? '');
  check('backup returned a repoFileId', Boolean(repoFileId), backup.result?.details);
  if (repoFileId) {
    // GET /files/:id streams the raw bytes; the LIST endpoint carries metadata.
    const listRes = await authed('GET', '/files');
    const body = (await listRes.json()) as { files?: Array<Record<string, unknown>> } | null;
    const files = body?.files ?? [];
    const entry = files.find((f) => f['id'] === repoFileId);
    check('backup present in the UNM file repo', !!entry && typeof entry?.['name'] === 'string' && String(entry['name']).includes('config-backup'), { status: listRes.status, count: files.length, entry });
  }

  // --- CLEANUP (restore pre-test state) ------------------------------------------
  console.log('\n== CLEANUP ==');
  await expectOk('system.identity.set', { name: 'MikroTik' });
  await expectOk('interface.settings.set', { interface: 'ether1', comment: '' });

  // DNS servers — baseline was EMPTY (dynamic via DHCP). The dns.servers.set action
  // requires ≥1 server, so restore the empty state with a direct REST call.
  try {
    const devRow = (await pool.query(`SELECT "managementAddress" FROM devices WHERE id = $1`, [DEVICE_ID])).rows[0] as { managementAddress: string } | undefined;
    const host = String(devRow?.['managementAddress'] ?? '10.25.2.1').replace(/^https?:\/\//i, '');
    const authHeader = `Basic ${Buffer.from('admin:admin').toString('base64')}`;
    const res = await fetch(`http://${host}/rest/ip/dns/set`, {
      method: 'POST',
      headers: { Authorization: authHeader, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ servers: '' }),
    });
    const after = await fetch(`http://${host}/rest/ip/dns`, { headers: { Authorization: authHeader, Accept: 'application/json' } }).then((r) => r.json()) as Array<Record<string, unknown>>;
    check('DNS servers restored to empty (dynamic)', res.status === 200 && String(after[0]?.['servers'] ?? '') === '', { status: res.status, servers: after[0]?.['servers'] });
  } catch (e) {
    check('DNS servers restored to empty (dynamic)', false, e instanceof Error ? e.message : e);
  }

  // Final state audit.
  const finalInfo = actionResult((await runAction('system.info.read', {})).step ?? { result: null })?.details;
  check('hostname restored to MikroTik', String(finalInfo?.['hostname'] ?? '') === 'MikroTik', finalInfo);
  const finalRules = actionResult((await runAction('firewall.rules.read', {})).step ?? { result: null })?.details;
  check('no leftover firewall rules from the test', !JSON.stringify(finalRules).includes('unm-v04'), undefined);
  const finalWg = actionResult((await runAction('wireguard.servers.read', {})).step ?? { result: null })?.details;
  check('no leftover WireGuard servers', ((finalWg?.['servers'] as Array<Record<string, unknown>> | undefined) ?? []).length === 0, finalWg);

  await pool.end();
  console.log(failures === 0 ? '\nALL ROUTEROS v0.4.0 VALIDATION CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('HARNESS ERROR:', err);
  process.exit(2);
});
