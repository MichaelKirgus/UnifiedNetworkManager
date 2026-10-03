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
import { getAssignments, opnsenseWriteOk, reconfigureAssignments, setAssignmentItem } from './client/interfaces';
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

/**
 * Resolves the write path for interface assignments on this appliance:
 *   - REST when the endpoint exists AND its model can hold an L3 address
 *     (the full assignment model — master/27.x+ builds);
 *   - otherwise SSH config edit, whenever a `ssh` slot is bound. This covers
 *     BOTH ≤26.4 appliances (no endpoint at all) and 26.7.x appliances whose
 *     minimal model cannot hold an address — the same DOMDocument upsert +
 *     rc.configure_interface works on every firmware line, so a bound slot
 *     makes 26.7.x fully configurable too;
 *   - null when neither is available (the caller reports that clearly).
 */
export async function resolveAssignmentPath(client: AxiosInstance, credentials: Record<string, unknown>): Promise<AssignmentPath> {
  const cap = await probeAssignmentCapability(client);
  if (cap.restPresent && cap.restIpCapable) return 'rest';
  const ssh = resolveSshCredentials(credentials, { slotOnly: true });
  return ssh ? 'ssh' : null;
}

/**
 * Resolves the path for REMOVING an interface assignment. Node removal works
 * via REST on every build that has the endpoint (del_item + reconfigure is part
 * of even the minimal 26.7.x model — verified live), so only ≤26.4 appliances
 * need the SSH config edit here.
 */
export async function resolveAssignmentRemovePath(client: AxiosInstance, credentials: Record<string, unknown>): Promise<AssignmentPath> {
  const cap = await probeAssignmentCapability(client);
  if (cap.restPresent) return 'rest';
  const ssh = resolveSshCredentials(credentials, { slotOnly: true });
  return ssh ? 'ssh' : null;
}

/**
 * Whether the assignment REST model can hold an L3 ADDRESS (not just create a
 * node). The endpoint exists on all of 26.7+, but the 26.7.x NetworkInterface
 * model only carries `descr/identifier/if/lock` — no type4/ipaddr/subnet fields
 * (verified against tag 26.7.1 source AND live on GWST04: set_item with an IP
 * returns {"result":"saved"} yet the address never reaches config.xml). The full
 * model landed on master only. Detection is field-based, not version-based:
 * read one existing assignment row and look for an IP-related field.
 */
export async function probeAssignmentCapability(client: AxiosInstance): Promise<{ restPresent: boolean; restIpCapable: boolean }> {
  try {
    const r = await getAssignments(client);
    if (!r.ok) return { restPresent: false, restIpCapable: false };
    const rows = Object.values(((r.data as { interface?: { interface?: Record<string, unknown> } })?.interface?.interface ?? {}));
    if (rows.length === 0) {
      // No existing assignments to inspect — assume the full model (a device
      // with zero interfaces is not a realistic write target anyway).
      return { restPresent: true, restIpCapable: true };
    }
    const ipFields = new Set(['type4', 'type6', 'ipaddr', 'ipaddrv6', 'subnet', 'subnetv6']);
    const capable = rows.some((row) => typeof row === 'object' && row !== null && Object.keys(row as Record<string, unknown>).some((k) => ipFields.has(k)));
    return { restPresent: true, restIpCapable: capable };
  } catch {
    return { restPresent: false, restIpCapable: false };
  }
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
    // Pure DOMDocument — no SimpleXML. config.xml contains SEVERAL <interfaces>
    // elements (system/ssh allowlist, Netflow capture, FRR/BGP …) and the
    // interface-ASSIGNMENTS section is the ROOT-level one; SimpleXML property
    // access resolves to the first in document order (the ssh allowlist), and its
    // asXML() round-trip has been observed dropping child elements on this
    // appliance. DOMDocument targets the exact element and serializes verbatim.
    '$dom = new DOMDocument("1.0"); $dom->preserveWhiteSpace = true;',
    'if (!$dom->load($f)) { fwrite(STDERR, "parse failed\\n"); exit(3); }',
    '$sec = null; foreach ($dom->documentElement->childNodes as $ch) { if ($ch instanceof DOMElement && $ch->tagName === "interfaces") { $sec = $ch; break; } }',
    'if ($sec === null) { $sec = $dom->createElement("interfaces"); $dom->documentElement->appendChild($sec); }',
    '$node = null; foreach ($sec->childNodes as $ch) { if ($ch instanceof DOMElement && $ch->tagName === $id) { $node = $ch; break; } }',
    'if ($node === null) { $node = $dom->createElement($id); $sec->appendChild($node); }',
    '$set = function (DOMElement $parent, string $name, string $value) use ($dom) { $c = null; foreach ($parent->childNodes as $ch) { if ($ch instanceof DOMElement && $ch->tagName === $name) { $c = $ch; break; } } if ($c === null) { $c = $dom->createElement($name); $parent->appendChild($c); } while ($c->firstChild) { $c->removeChild($c->firstChild); } $c->appendChild($dom->createTextNode($value)); };',
    '$set($node, "if", (string)$j["device"]);',
    '$set($node, "descr", (string)$j["descr"]);',
    '$set($node, "enable", "1");',
    'foreach ([["ipaddr","ipaddr"],["subnet","subnet"],["ipaddrv6","ipaddrv6"],["subnetv6","subnetv6"]] as $pair) { if (!empty($j[$pair[0]])) { $set($node, $pair[1], (string)$j[$pair[0]]); } }',
    'if (!$dom->save($f)) { fwrite(STDERR, "save failed\\n"); exit(4); }',
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
    // Pure DOMDocument — see phpUpsertSource for why SimpleXML is not used here.
    '$dom = new DOMDocument("1.0"); $dom->preserveWhiteSpace = true;',
    'if (!$dom->load($f)) { fwrite(STDERR, "parse failed\\n"); exit(3); }',
    '$sec = null; foreach ($dom->documentElement->childNodes as $ch) { if ($ch instanceof DOMElement && $ch->tagName === "interfaces") { $sec = $ch; break; } }',
    '$node = null; if ($sec !== null) { foreach ($sec->childNodes as $ch) { if ($ch instanceof DOMElement && $ch->tagName === $id) { $node = $ch; break; } } }',
    'if ($node === null) { echo "not present: $id (no-op)\\n"; exit(0); }',
    '$sec->removeChild($node);',
    'if (!$dom->save($f)) { fwrite(STDERR, "save failed\\n"); exit(4); }',
    'echo "removed $id\\n";',
  ].join('\n');
}

/** Wraps a PHP source into the base64 shell command (quoting-proof).
 *  `postApply` lines run ONLY when the config edit succeeded — they must sit
 *  before the final exit, or they are dead code that never executes. */
function phpShellCommand(phpSource: string, postApply: string[] = []): string {
  const b64 = Buffer.from(phpSource, 'utf8').toString('base64');
  return [
    'um=$(mktemp /tmp/unm-ifc.XXXXXX) || exit 9',
    `echo '${b64}' | base64 -d > "$um"`,
    'rc=0; php "$um" || rc=$?',
    'rm -f "$um"',
    ...(postApply.length ? ['if [ $rc -eq 0 ]; then', ...postApply, 'fi'] : []),
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
    // resolveAssignmentPath only returns 'rest' when the model can hold an L3
    // address — on 26.7.x (minimal model) it already fell back to SSH here.
    // Full REST model (master/27.x+) — staged like every other item controller;
    // reconfigure applies it.
    const item: Record<string, unknown> = { if: w.device, descr: w.descr };
    if (w.ipaddr) { item.ipaddr = `${w.ipaddr}/${w.subnet ?? 24}`; }
    if (w.ipaddrv6) { item.ipaddrv6 = `${w.ipaddrv6}/${w.subnetv6 ?? 64}`; }
    const set = await setAssignmentItem(client, w.identifier, item);
    if (!set.ok || !opnsenseWriteOk(set)) throw new Error(`assignment REST set failed: HTTP ${set.status} ${JSON.stringify(set.data).slice(0, 200)}`);
    const reconf = await reconfigureAssignments(client);
    if (!reconf.ok || !opnsenseWriteOk(reconf)) throw new Error(`assignment REST reconfigure failed: HTTP ${reconf.status} ${JSON.stringify(reconf.data).slice(0, 200)}`);
    return { path, detail: `assigned ${w.identifier} → ${w.device} via REST (full assignment model)` };
  }

  if (path !== 'ssh') {
    throw new Error(
      'no write path for interface assignments: the assignment REST model on this firmware cannot hold an L3 address and no `ssh` credential slot is bound to the plugin — bind one to enable config-edit writes',
    );
  }

  const payload = Buffer.from(JSON.stringify({ identifier: w.identifier, device: w.device, descr: w.descr, ipaddr: w.ipaddr ?? null, subnet: w.subnet ?? null, ipaddrv6: w.ipaddrv6 ?? null, subnetv6: w.subnetv6 ?? null }), 'utf8').toString('base64');
  const script = phpShellCommand(phpUpsertSource(payload), [
    // Apply the single interface (shipped per-ifc apply) + filter reload.
    `/usr/local/etc/rc.configure_interface ${w.identifier} >/dev/null 2>&1 || true`,
    'configd filter reload >/dev/null 2>&1 || true',
  ]);

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
  const path = await resolveAssignmentRemovePath(client, credentials);

  if (path === 'rest') {
    // del_item works on every build that has the endpoint (node removal is part
    // of even the minimal 26.7.x model); reconfigure applies it.
    const del = await post(client, `/api/interfaces/assignment/del_item/${encodeURIComponent(identifier)}`, {});
    if (!del.ok || !opnsenseWriteOk(del)) throw new Error(`assignment REST delete failed: HTTP ${del.status} ${JSON.stringify(del.data).slice(0, 200)}`);
    const reconf = await reconfigureAssignments(client);
    if (!reconf.ok || !opnsenseWriteOk(reconf)) throw new Error(`assignment REST reconfigure failed: HTTP ${reconf.status} ${JSON.stringify(reconf.data).slice(0, 200)}`);
    return { path, detail: `unassigned ${identifier} via REST (assignment API)` };
  }

  if (path !== 'ssh') {
    throw new Error(
      'no write path for interface assignments: the assignment REST model on this firmware cannot hold an L3 address and no `ssh` credential slot is bound to the plugin — bind one to enable config-edit writes',
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
    phpShellCommand(phpRemoveSource(payload), ['configd filter reload >/dev/null 2>&1 || true']),
  ].join('\n');

  const r = await sshExec(credentials, host, script, 90_000, sshPort);
  if (r.code !== 0) throw new Error(`SSH assignment removal exited ${r.code}: ${(r.stderr || r.stdout).slice(0, 300)}`);
  return { path: 'ssh', detail: `unassigned ${identifier} via SSH config edit` };
}
