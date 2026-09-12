/**
 * End-to-end verification for the OpenWRT plugin that needs NO live appliance.
 *
 * Validates the pure-logic + transport-enforcement paths against the deployed
 * container (host port 4014):
 *   1. /discover — identity, capabilities, options, action catalog.
 *   2. /plan     — wireguard.tunnel.create builds a correct multi-device plan
 *                  (provisioning requests + dependency ordering).
 *   3. Forced-transport enforcement (the plugin's defining feature):
 *        - transport=luci  → write actions are REJECTED with an actionable error
 *                            (LuCI has no stable save endpoint; writes need SSH).
 *        - transport=ssh   → the same action is ACCEPTED as a valid dispatch
 *                            (it then fails only because the TEST-NET host is
 *                            unreachable — proving the write path was entered).
 *
 * Usage (from the repo root, with the stack up):
 *   node scripts/e2e-openwrt.cjs
 */
'use strict';

const BASE = process.env.OPENWRT_PLUGIN_BASE ?? 'http://localhost:4014';

let failures = 0;
function check(label, cond, extra) {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

async function post(path, body, settings) {
  const headers = { 'Content-Type': 'application/json' };
  if (settings) headers['x-unm-settings'] = JSON.stringify(settings); // how the API injects per-device options
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
  let json;
  try { json = await res.json(); } catch { json = null; }
  return { status: res.status, json };
}

async function main() {
  console.log(`\nOpenWRT plugin e2e (no-appliance) → ${BASE}\n`);

  // --- 1. /discover -----------------------------------------------------------
  const disc = await fetch(`${BASE}/discover`).then((r) => r.json());
  check('discover: uuid', disc.uuid === 'aa9f941c-f63c-432c-adef-19049b320d03', disc.uuid);
  check('discover: vendors=openwrt', Array.isArray(disc.vendors) && disc.vendors.includes('openwrt'), disc.vendors);
  const caps = new Set(disc.capabilities ?? []);
  for (const c of ['monitoring', 'inventory', 'configuration', 'planning', 'deviceState', 'ssh', 'probe', 'sshConsole']) {
    check(`discover: capability ${c}`, caps.has(c));
  }
  const optKeys = new Set((disc.options ?? []).map((o) => o.key));
  for (const k of ['transport', 'httpsPort', 'httpPort', 'sshPort']) check(`discover: option ${k}`, optKeys.has(k));
  const transportOpt = (disc.options ?? []).find((o) => o.key === 'transport');
  check('discover: transport pattern auto|luci|ssh', /auto\|luci\|ssh/.test(transportOpt?.pattern ?? ''), transportOpt?.pattern);
  const actionIds = new Set((disc.actions ?? []).map((a) => a.id));
  for (const id of ['wireguard.tunnel.create', 'openvpn.sitesite.create', 'routes.backRoute.create']) {
    check(`discover: intent ${id}`, actionIds.has(id));
  }

  // --- 2. /plan — wireguard tunnel -------------------------------------------
  const plan = await post('/plan', {
    intent: { actionId: 'wireguard.tunnel.create', inputs: { name: 'wg-e2e', subnet: '10.255.0.0/24' } },
    devices: [
      { deviceId: 'devA', managementAddress: '192.0.2.10', credentials: {} },
      { deviceId: 'devB', managementAddress: '192.0.2.11', credentials: {} },
    ],
  });
  check('plan: HTTP 200', plan.status === 200, plan.json);
  const p = plan.json?.plan;
  check('plan: has id + steps', !!p && Array.isArray(p.steps) && p.steps.length >= 6, p ? { n: p.steps.length } : null);
  const provRefs = new Set((p?.provisionRequests ?? []).map((r) => r.ref));
  check('plan: provisions keyA + keyB', provRefs.has('keyA') && provRefs.has('keyB'), [...provRefs]);
  // Dependency ordering: each peer.add depends on its own server.set; reconfigure depends on peer.
  const byAction = (p?.steps ?? []).map((s) => s.actionId);
  check('plan: two server.set steps', byAction.filter((a) => a === 'wireguard.server.set').length === 2, byAction);
  check('plan: two peer.add steps', byAction.filter((a) => a === 'wireguard.peer.add').length === 2, byAction);
  const peerStep = (p?.steps ?? []).find((s) => s.actionId === 'wireguard.peer.add');
  check('plan: peer.add has dependsOn', Array.isArray(peerStep?.dependsOn) && peerStep.dependsOn.length > 0, peerStep?.dependsOn);

  // --- 3. Forced-transport enforcement ---------------------------------------
  // Uses 127.0.0.1 (the plugin container's own loopback) so every probe fails
  // FAST and deterministically (connection refused, not a blackholed TEST-NET
  // timeout). The point is to prove the FORCED modes do not silently fall back:
  const writeBody = {
    deviceId: 'devA',
    managementAddress: '127.0.0.1',
    actionId: 'dns.host.add',
    input: { name: 'e2e.example.com', ip: '10.0.0.5' },
    credentials: { username: 'root', password: 'x' },
  };

  // (a) transport=luci, no LuCI reachable → Backend.create must THROW the
  //     "forced to 'luci'" error — it must NOT fall back to SSH and run the write.
  const luci = await post('/config', writeBody, { transport: 'luci' });
  check('enforce: forced-luci returns HTTP 200 (error envelope)', luci.status === 200, luci.status);
  check('enforce: forced-luci write NOT executed (success=false)', luci.json?.success === false, luci.json);
  const luciErr = String(luci.json?.result?.error ?? '');
  check("enforce: forced-luci error is the 'no LuCI reachable' guard", /forced to ['"]?luci['"]?/i.test(luciErr), luciErr);

  // (b) transport=ssh → the write path IS entered; it fails only on the SSH
  //     connect (loopback :22 refused) — NOT a "requires SSH" rejection and not
  //     the forced-luci guard. Proves ssh mode goes down the shell data path.
  const ssh = await post('/config', writeBody, { transport: 'ssh' });
  check('enforce: forced-ssh returns HTTP 200 (error envelope)', ssh.status === 200, ssh.status);
  const sshErr = String(ssh.json?.result?.error ?? '');
  check("enforce: forced-ssh entered the shell path (no 'requires SSH' rejection)", !/require.*SSH transport/i.test(sshErr), { success: ssh.json?.success, err: sshErr });
  check('enforce: forced-ssh is NOT the luci guard', !/forced to ['"]?luci['"]?/i.test(sshErr), sshErr);

  console.log(`\n${failures === 0 ? '✅ ALL CHECKS PASSED' : `❌ ${failures} check(s) failed`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('e2e crashed:', err);
  process.exit(1);
});
