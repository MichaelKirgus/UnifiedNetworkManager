/**
 * Interface ASSIGNMENT writes (per-interface IP config) for OPNsense ≤26.4.
 *
 * The REST API has NO endpoint to assign an IP address to a logical interface:
 *   - 26.7+ exposes `/api/interfaces/assignment/*` (AssignmentController, added
 *     to master June 2026) — used automatically when present (probed on demand).
 *   - ≤26.4 the UI saves per-ifc IPs via the legacy web form only. The config
 *     lives in /conf/config.xml under `<interfaces><<identifier>>` with fields
 *     `if` (device name, e.g. vlan0042/lagg0), `descr`, `enable`, `ipaddr`,
 *     `subnet`, `ipaddrv6`, `subnetv6`. Applying one interface is the shipped
 *     script `/usr/local/etc/rc.configure_interface <identifier>` (verified in
 *     stable/26.1 source — it calls interface_configure(true, $if, true)),
 *     followed by `configd filter reload` so firewall rules see the new ifc.
 *
 * The SSH path edits config.xml with plain SimpleXML under an exclusive flock
 * (no OPNsense class bootstrap needed) and applies via rc.configure_interface.
 * Requires a bound `ssh` credential slot — without one, assignment writes are
 * unavailable on ≤26.4 devices (the action reports that clearly).
 *
 * Quoting strategy: the PHP script is base64-encoded into the shell command
 * (`echo <b64> | base64 -d > tmp && php tmp`) — immune to any shell/PHP quoting
 * hazards, and the JSON payload rides inside the PHP source as a base64 string.
 */

import { resolveSshCredentials, resolveSshPort } from '@unm/plugin-sdk';
import type { AxiosInstance } from 'axios';
import { getAssignments, reconfigureAssignments, setAssignmentItem } from './client/interfaces';
import { post } from './client/http';

/** How an interface assignment can be written on this appliance. */
export type AssignmentPath = 'rest' | 'ssh' | null;

/** The one interface-assignment write the network intents need. */
export interface AssignmentWrite {
  /** Logical identifier (lan/optN) — the `<interfaces>` key in config.xml. */
  identifier: string;
  /** Device name the address binds to (vlan0042, lagg0, vtnet1…). */
  device: string;
  descr: string;
  ipaddr?: string;
  subnet?: string;
  ipaddrv6?: string;
  subnetv6?: string;
}

/** Probes which write path is available (REST first — it exists on 26.7+). */
export async function resolveAssignmentPath(client: AxiosInstance, credentials: Record<string, unknown>): Promise<AssignmentPath> {
  try {
    const r = await getAssignments(client);
    if (r.ok) return 'rest';
  } catch { /* fall through to SSH */ }
  const ssh = resolveSshCredentials(credentials, { slotOnly: true });
  return ssh ? 'ssh' : null;
}

/** PHP source that UPSERTs one `<interfaces><identifier>` node (idempotent). */
function phpUpsertSource(payloadB64: string): string {
  return [
    '<?php',
    '$j = json_decode(base64_decode("' + payloadB64 + '"), true);',
    'if (!is_array($j)) { fwrite(STDERR, "bad payload\\n"); exit(2); }',
    '$id = preg_replace("/[^A-Za-z0-9_]/", "", (string)$j["identifier"]);',
    'if ($id === "") { fwrite(STDERR, "empty identifier\\n"); exit(6); }',
    '$f = "/conf/config.xml"; $fp = fopen($f, "r+");',
    'if (!$fp) { fwrite(STDERR, "open failed\\n"); exit(2); }',
    'flock($fp, LOCK_EX);',
    '$xml = simplexml_load_file($f);',
    'if ($xml === false) { fwrite(STDERR, "parse failed\\n"); exit(3); }',
    'if (!isset($xml->interfaces)) { $xml->addChild("interfaces"); }',
    '$node = null;',
    'if (isset($xml->interfaces->{$id})) { $node = $xml->interfaces->{$id}; } else { $node = $xml->interfaces->addChild($id); }',
    'if ($node === null) { fwrite(STDERR, "create node failed\\n"); exit(5); }',
    '$set = function ($parent, $name, $value) { $c = $parent->{$name}; if ($c === null || !is_object($c)) { $c = $parent->addChild($name); } $c[0] = (string)$value; };',
    '$set($node, "if", $j["device"]);',
    '$set($node, "descr", $j["descr"]);',
    '$set($node, "enable", "1");',
    'foreach ([["ipaddr","ipaddr"],["subnet","subnet"],["ipaddrv6","ipaddrv6"],["subnetv6","subnetv6"]] as $pair) { if (!empty($j[$pair[0]])) { $set($node, $pair[1], $j[$pair[0]]); } }',
    'if (!$xml->save($f)) { fwrite(STDERR, "save failed\\n"); exit(4); }',
    'echo "saved $id -> {$j["device"]}\\n";',
  ].join('\n');
}

/** PHP source that REMOVES one `<interfaces><identifier>` node (no-op if absent). */
function phpRemoveSource(payloadB64: string): string {
  return [
    '<?php',
    '$j = json_decode(base64_decode("' + payloadB64 + '"), true);',
    'if (!is_array($j)) { fwrite(STDERR, "bad payload\\n"); exit(2); }',
    '$id = preg_replace("/[^A-Za-z0-9_]/", "", (string)$j["identifier"]);',
    'if ($id === "") { fwrite(STDERR, "empty identifier\\n"); exit(6); }',
    '$f = "/conf/config.xml"; $fp = fopen($f, "r+");',
    'if (!$fp) { fwrite(STDERR, "open failed\\n"); exit(2); }',
    'flock($fp, LOCK_EX);',
    '$xml = simplexml_load_file($f);',
    'if ($xml === false) { fwrite(STDERR, "parse failed\\n"); exit(3); }',
    'if (isset($xml->interfaces->{$id})) { unset($xml->interfaces->{$id}); if (!$xml->save($f)) { fwrite(STDERR, "save failed\\n"); exit(4); } echo "removed $id\\n"; } else { echo "not present: $id (no-op)\\n"; }',
  ].join('\n');
}

/** Wraps a PHP source into the base64 shell command (quoting-proof). */
function phpShellCommand(phpSource: string): string {
  const b64 = Buffer.from(phpSource, 'utf8').toString('base64');
  return [
    'um=$(mktemp /tmp/unm-ifc.XXXXXX) || exit 9',
    `echo '${b64}' | base64 -d > "$um"`,
    'rc=0; php "$um" || rc=$?',
    'rm -f "$um"',
    'exit $rc',
  ].join('\n');
}

/** Runs one SSH command via the bound `ssh` slot (throws when unusable). */
async function sshExec(
  credentials: Record<string, unknown>,
  host: string,
  script: string,
  timeoutMs: number,
  sshPort?: number,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const { execViaSshSlot } = await import('./zfsSsh');
  const r = await execViaSshSlot(host, credentials, script, { port: sshPort ?? resolveSshPort(undefined), timeoutMs });
  if (!r) throw new Error('SSH session unavailable (no usable `ssh` slot) — bind an SSH credential to this plugin for interface-assignment writes on ≤26.4 appliances');
  return r;
}

/**
 * Writes one interface assignment (upsert). Returns the path used + detail.
 * Throws with a clear message when no path is available or the write fails.
 */
export async function writeInterfaceAssignment(
  client: AxiosInstance,
  credentials: Record<string, unknown>,
  host: string,
  w: AssignmentWrite,
  sshPort?: number,
): Promise<{ path: 'rest' | 'ssh'; detail: string }> {
  const path = await resolveAssignmentPath(client, credentials);

  if (path === 'rest') {
    // 26.7+ REST model — staged like every other item controller; reconfigure applies it.
    const item: Record<string, unknown> = { if: w.device, descr: w.descr };
    if (w.ipaddr) { item.ipaddr = w.ipaddr; item.subnet = w.subnet ?? ''; }
    if (w.ipaddrv6) { item.ipaddrv6 = w.ipaddrv6; item.subnetv6 = w.subnetv6 ?? ''; }
    const set = await setAssignmentItem(client, w.identifier, item);
    if (!set.ok) throw new Error(`assignment REST set failed: HTTP ${set.status}`);
    const reconf = await reconfigureAssignments(client);
    if (!reconf.ok) throw new Error(`assignment REST reconfigure failed: HTTP ${reconf.status}`);
    return { path, detail: `assigned ${w.identifier} → ${w.device} via REST (26.7+ model)` };
  }

  if (path !== 'ssh') {
    throw new Error(
      'no write path for interface assignment: this appliance predates the /api/interfaces/assignment REST model (≤26.4) and no `ssh` credential slot is bound to the plugin',
    );
  }

  const payload = Buffer.from(JSON.stringify({ identifier: w.identifier, device: w.device, descr: w.descr, ipaddr: w.ipaddr ?? null, subnet: w.subnet ?? null, ipaddrv6: w.ipaddrv6 ?? null, subnetv6: w.subnetv6 ?? null }), 'utf8').toString('base64');
  const script = [
    phpShellCommand(phpUpsertSource(payload)),
    // Apply the single interface (shipped per-ifc apply) + filter reload.
    `/usr/local/etc/rc.configure_interface ${w.identifier} >/dev/null 2>&1 || true`,
    'configd filter reload >/dev/null 2>&1 || true',
  ].join('\n');

  const r = await sshExec(credentials, host, script, 90_000, sshPort);
  if (r.code !== 0) throw new Error(`SSH assignment write exited ${r.code}: ${(r.stderr || r.stdout).slice(0, 300)}`);
  return { path: 'ssh', detail: `assigned ${w.identifier} → ${w.device} via SSH config edit + rc.configure_interface` };
}

/** Removes one interface assignment (unassigns the identifier; no-op if absent). */
export async function removeInterfaceAssignment(
  client: AxiosInstance,
  credentials: Record<string, unknown>,
  host: string,
  identifier: string,
  /** Running addresses to tear down on the device (≤26.4 only — interface_configure skips removed nodes). */
  teardown?: { device: string; v4: string[]; v6: string[] },
  sshPort?: number,
): Promise<{ path: 'rest' | 'ssh'; detail: string }> {
  const path = await resolveAssignmentPath(client, credentials);

  if (path === 'rest') {
    // 26.7+: del_item removes the node; reconfigure applies it (tears down addresses).
    const del = await post(client, `/api/interfaces/assignment/del_item/${encodeURIComponent(identifier)}`, {});
    if (!del.ok) throw new Error(`assignment REST delete failed: HTTP ${del.status}`);
    const reconf = await reconfigureAssignments(client);
    if (!reconf.ok) throw new Error(`assignment REST reconfigure failed: HTTP ${reconf.status}`);
    return { path, detail: `unassigned ${identifier} via REST (26.7+ model)` };
  }

  if (path !== 'ssh') {
    throw new Error(
      'no write path for interface assignment: this appliance predates the /api/interfaces/assignment REST model (≤26.4) and no `ssh` credential slot is bound to the plugin',
    );
  }

  const payload = Buffer.from(JSON.stringify({ identifier }), 'utf8').toString('base64');
  // Teardown: interface_configure() returns early for a REMOVED node (verified in
  // stable/26.1 interfaces.inc), so strip the running addresses explicitly first.
  const teardownCmds: string[] = [];
  if (teardown) {
    for (const ip of teardown.v4) teardownCmds.push(`ifconfig ${teardown.device} inet remove ${ip} >/dev/null 2>&1 || true`);
    for (const ip6 of teardown.v6) teardownCmds.push(`ifconfig ${teardown.device} inet6 remove ${ip6} >/dev/null 2>&1 || true`);
  }
  const script = [
    ...teardownCmds,
    phpShellCommand(phpRemoveSource(payload)),
    'configd filter reload >/dev/null 2>&1 || true',
  ].join('\n');

  const r = await sshExec(credentials, host, script, 90_000, sshPort);
  if (r.code !== 0) throw new Error(`SSH assignment removal exited ${r.code}: ${(r.stderr || r.stdout).slice(0, 300)}`);
  return { path: 'ssh', detail: `unassigned ${identifier} via SSH config edit` };
}
