/**
 * Monitoring collection for netcup SCP devices.
 *
 * One UNM device = one SCP account (token). Each poll:
 *   1. ping (no auth) — API reachability;
 *   2. listServers (auth probe) — the server inventory table;
 *   3. per-server getServer (live info: state, CPUs, RAM, interfaces/IPs);
 *   4. recent tasks table;
 *   5. generic vms[] + vmHosts[] — the same servers mapped to UNM's VMs page
 *      (normalized vms table) and Hosts page (NIC MAC rows);
 *   6. inventory propagation: networks[] (every IP alias of every interface)
 *      and firewallRules[] (unified rows from each interface's firewall).
 *
 * Budget discipline: everything after the auth probe runs in parallel with a
 * hard cap on fan-out, and any sub-read failure degrades to `warning` + partial
 * data — never critical. A failed firewall read OMITS that interface's rules
 * (null-on-failure contract) so stale rows are not wiped by one flaky call.
 */

import { Health } from '@unm/plugin-sdk';
import type { ScpClient, ScpServer, ScpServerMinimal, ScpInterface, ScpFirewallRule, ScpFirewallPolicy, ScpServerFirewall } from './client/scpClient';
import { isAuthError } from './client/scpClient';

/** Cap on per-server detail fetches per poll (a huge fleet must not blow the 10 s budget). */
const MAX_SERVER_DETAILS = 25;
/** Cap on firewall reads per poll. */
const MAX_FIREWALL_READS = 40;

export interface ScpMonitoringOptions {
  /** When false, skip the per-interface firewall reads (faster polls, no firewallRules key). */
  collectFirewall: boolean;
}

export interface ScpMonitoringResult {
  health: Health;
  metrics: Record<string, unknown>;
  errors: string[];
}

// --- Inventory row shapes (consumed by the API's ingestInventory) -----------------

interface NetworkRow {
  name: string;
  ip: string;
  prefix: number | null;
  version: '4' | '6';
  vlanId: number | null;
  mac: string | null;
  status: string | null;
}

/** Unified firewall-rule row (same shape the API's Firewall page ingests). */
interface FirewallRuleRow {
  ruleType: 'filter';
  vendorRuleId: string;
  position: number;
  protocol: string; // lowercase name ('tcp','udp',…); '' = any
  sourceIp: string; // '' = any
  destIp: string; // '' = any
  sourcePort: string | null;
  destPort: string | null;
  action: 'allow' | 'deny' | 'other';
  enabled: boolean;
  description: string;
  scope: string;
  ipVersion: 'v4' | 'v6' | 'both';
  packets: number | null;
  bytes: number | null;
  extra: Record<string, unknown>;
}

/** "255.255.255.0" → 24 (null when unparseable). */
function netmaskToPrefix(netmask?: string): number | null {
  if (!netmask) return null;
  const parts = netmask.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return null;
  let prefix = 0;
  for (const octet of parts) {
    if (octet === 255) prefix += 8;
    else if (octet === 0) break;
    else return null; // non-contiguous — not a plain prefix
  }
  return prefix;
}

function ipVersionOf(...addrs: string[]): 'v4' | 'v6' | 'both' {
  const hasV4 = addrs.some((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a));
  const hasV6 = addrs.some((a) => a.includes(':'));
  if (hasV4 && hasV6) return 'both';
  return hasV6 ? 'v6' : 'v4';
}

/** Normalizes one SCP firewall rule into the unified row shape. */
function toUnifiedRule(rule: ScpFirewallRule, serverName: string, mac: string, position: number): FirewallRuleRow {
  const sources = Array.isArray(rule.sources) ? rule.sources.filter((s) => typeof s === 'string' && s.trim() !== '') : [];
  const destinations = Array.isArray(rule.destinations) ? rule.destinations.filter((d) => typeof d === 'string' && d.trim() !== '') : [];
  return {
    ruleType: 'filter',
    vendorRuleId: `${serverName}/${mac.toLowerCase()}/pos-${position}`,
    position,
    protocol: (rule.protocol ?? '').toLowerCase(),
    sourceIp: sources.join(', '),
    destIp: destinations.join(', '),
    sourcePort: typeof rule.sourcePorts === 'string' && rule.sourcePorts !== '' ? rule.sourcePorts : null,
    destPort: typeof rule.destinationPorts === 'string' && rule.destinationPorts !== '' ? rule.destinationPorts : null,
    action: rule.action === 'ACCEPT' ? 'allow' : rule.action === 'DROP' ? 'deny' : 'other',
    enabled: true, // SCP has no per-rule disable flag — every listed rule is active
    description: typeof rule.description === 'string' ? rule.description : '',
    scope: `${serverName} ${mac.toLowerCase()} ${rule.direction ?? ''}`.trim(),
    ipVersion: ipVersionOf(...sources, ...destinations),
    packets: null, // SCP does not expose per-rule hit counters via the REST API
    bytes: null,
    extra: { direction: rule.direction ?? null },
  };
}

/** Collects networks[] rows from one server's interfaces. */
function networkRowsForServer(serverName: string, ifaces: ScpInterface[]): NetworkRow[] {
  const rows: NetworkRow[] = [];
  for (const iface of ifaces) {
    const mac = typeof iface.mac === 'string' ? iface.mac.toLowerCase() : null;
    for (const v4 of iface.ipv4Addresses ?? []) {
      if (!v4?.ip) continue;
      rows.push({ name: serverName, ip: v4.ip, prefix: netmaskToPrefix(v4.netmask), version: '4', vlanId: null, mac, status: 'up' });
    }
    for (const v6 of iface.ipv6Addresses ?? []) {
      if (!v6?.networkPrefix) continue;
      rows.push({ name: serverName, ip: v6.networkPrefix, prefix: typeof v6.networkPrefixLength === 'number' ? v6.networkPrefixLength : null, version: '6', vlanId: null, mac, status: 'up' });
    }
  }
  return rows;
}

/** Generic UNM VM row (ingested by the API's telemetry worker into the vms table). */
interface VmRow {
  name: string;
  state?: string;
  vcpus?: number | null;
  memoryMiB?: number | null;
  archType?: string | null;
  extra?: Record<string, unknown>;
}

/** Maps SCP server states to the canonical uppercase VM states the webapp badges. */
function normalizeVmState(state: string | undefined): string {
  switch (state) {
    case 'RUNNING': return 'RUNNING';
    case 'SHUTOFF':
    case 'SHUTDOWN':
    case 'NOSTATE': return 'STOPPED';
    case 'PMSUSPENDED': return 'SUSPENDED';
    case 'PAUSED': return 'PAUSED';
    case 'CRASHED': return 'ERROR';
    default: return state && state !== '' ? state.toUpperCase() : 'UNKNOWN';
  }
}

/** One generic vms[] row per SCP server — feeds UNM's VMs page. NIC MACs ride in
 * extra.devices (child rows) and vmHosts (Hosts page), same contract as TrueNAS. */
function buildVmRows(servers: ScpServerMinimal[], byId: Map<number, ScpServer>): VmRow[] {
  const rows: VmRow[] = [];
  for (const s of servers) {
    const full = byId.get(s.id);
    const live = full?.serverLiveInfo;
    const state = normalizeVmState(live?.state);

    // NICs — MAC + driver/speed detail, one child row per interface.
    const devices: { dtype: string; label?: string; detail?: string }[] = [];
    for (const iface of live?.interfaces ?? []) {
      if (!iface.mac) continue;
      const speed = typeof iface.speedInMBits === 'number' ? `${iface.speedInMBits} MBit/s` : '';
      devices.push({ dtype: 'NIC', label: iface.mac.toLowerCase(), detail: [iface.driver, speed].filter(Boolean).join(' · ') || undefined });
    }

    rows.push({
      name: s.name,
      state,
      vcpus: typeof live?.cpuCount === 'number' ? live.cpuCount : null,
      memoryMiB: typeof live?.currentServerMemoryInMiB === 'number' ? live.currentServerMemoryInMiB : null,
      archType: live?.machineType ?? null,
      extra: {
        devices,
        ...(full?.nickname || s.nickname ? { description: full?.nickname || s.nickname } : {}),
        autostart: typeof live?.autostart === 'boolean' ? live.autostart : undefined,
        ...(typeof live?.uptimeInSeconds === 'number' && state === 'RUNNING' ? { uptimeSeconds: live.uptimeInSeconds } : {}),
      },
    });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

/** vmHosts[] rows — one per NIC MAC of a RUNNING server (feeds the Hosts page). */
function buildVmHostRows(servers: ScpServerMinimal[], byId: Map<number, ScpServer>): { mac: string; ip?: string; hostname?: string }[] {
  const out: { mac: string; ip?: string; hostname?: string }[] = [];
  for (const s of servers) {
    const full = byId.get(s.id);
    const live = full?.serverLiveInfo;
    if (!live || normalizeVmState(live.state) !== 'RUNNING') continue; // stopped VMs: no live IP
    for (const iface of live.interfaces ?? []) {
      if (!iface.mac) continue;
      const v4 = (iface.ipv4Addresses ?? []).map((a) => a.ip).find(Boolean);
      out.push({ mac: iface.mac.toLowerCase(), ...(v4 ? { ip: v4 } : {}), hostname: s.name });
    }
  }
  return out;
}

// --- Main collection -----------------------------------------------------------------

export async function collectScpMonitoring(client: ScpClient, opts: ScpMonitoringOptions): Promise<ScpMonitoringResult> {
  const errors: string[] = [];
  const metrics: Record<string, unknown> = {};

  // 1. Liveness (no auth).
  try {
    await client.ping();
  } catch (err) {
    return { health: 'critical', metrics: { 'system.error': `SCP API unreachable: ${errMsg(err)}` }, errors };
  }

  // 2. Auth probe + inventory list.
  let servers;
  try {
    servers = await client.listServers();
  } catch (err) {
    if (isAuthError(err)) {
      const msg = errMsg(err);
      // Keycloak realms are PER-HOST: a refresh token minted against www.
      // servercontrolpanel.de is rejected by the non-www realm and vice versa.
      const hint = /token issuer/i.test(msg)
        ? ' The token was issued by another host — set the management address to the SAME host you logged in with (the netcup CLI uses www.servercontrolpanel.de).' : '';
      return { health: 'critical', metrics: { 'system.error': `Invalid or expired SCP credential (${msg}). For a static access token: re-create it in your netcup account and update the bound secret. For a refresh token: log in again (e.g. via the netcup CLI) and replace the "netcup SCP Refresh Token" secret.${hint}` }, errors };
    }
    return { health: 'critical', metrics: { 'system.error': `SCP server list failed: ${errMsg(err)}` }, errors };
  }

  // 3. Per-server detail (live info + IPs), capped & parallel.
  const details = servers.slice(0, MAX_SERVER_DETAILS);
  const detailResults = await Promise.allSettled(details.map((s) => client.getServer(s.id)));
  const byId = new Map<number, ScpServer>();
  for (let i = 0; i < detailResults.length; i++) {
    const r = detailResults[i];
    if (r.status === 'fulfilled') byId.set(details[i].id, r.value);
    else errors.push(`server ${details[i].name}: ${errMsg(r.reason)}`);
  }

  // Servers table — one row per server in the account.
  const rows = servers.map((s) => {
    const full = byId.get(s.id);
    const live = full?.serverLiveInfo;
    return {
      name: s.name,
      nickname: (full?.nickname ?? s.nickname) || '',
      state: live?.state ?? 'unknown',
      cpu: typeof live?.cpuCount === 'number' ? `${live.cpuCount} vCPU` : (typeof full?.maxCpuCount === 'number' ? `${full.maxCpuCount} vCPU max` : ''),
      ramMiB: typeof live?.currentServerMemoryInMiB === 'number' ? String(live.currentServerMemoryInMiB) : '',
      ips: summarizeIps(full),
    };
  });
  metrics['netcup.servers'] = rows;

  // Generic vms[] — the same servers mapped to UNM's VMs page (the telemetry
  // worker ingests this into the normalized vms table). Present-but-empty is
  // authoritative: an account with zero servers must clear stale rows.
  metrics['vms'] = buildVmRows(servers, byId);
  metrics['vmHosts'] = buildVmHostRows(servers, byId);

  // 4. Recent tasks (account-wide — shows what SCP is doing right now).
  try {
    const tasks = await client.listTasks({ limit: 10 });
    metrics['netcup.tasks'] = tasks.map((t) => ({ task: t.name || t.uuid, state: t.state, startedAt: t.startedAt ?? '' }));
  } catch (err) {
    errors.push(`tasks: ${errMsg(err)}`);
  }

  // 5. Inventory propagation — networks[] + firewallRules[].
  const networks: NetworkRow[] = [];
  const firewallRules: FirewallRuleRow[] = [];
  let firewallReadsFailed = false;

  // The interface-firewall endpoint returns POLICY IDS (+ implicit rules); the
  // actual rule definitions live in the user's firewall policies. Resolve the
  // policy set ONCE per poll, then map each interface's policy IDs onto it.
  let policyById: Map<number, ScpFirewallPolicy> | null = null;
  if (opts.collectFirewall) {
    const userId = await client.resolveUserId();
    if (userId !== null) {
      try {
        const policies = await client.listFirewallPolicies(userId);
        policyById = new Map(policies.map((p) => [p.id, p]));
      } catch (err) {
        errors.push(`firewall policies: ${errMsg(err)}`);
        firewallReadsFailed = true;
      }
    } else {
      // No task with an executing user yet — policy rules cannot be resolved.
      // Treat as a failed read so previously ingested rows are preserved.
      firewallReadsFailed = true;
    }
  }

  // networks[] rows for every server (cheap — already fetched).
  const firewallTargets: { serverId: number; mac: string; serverName: string }[] = [];
  for (const s of details) {
    const full = byId.get(s.id);
    const ifaces = full?.serverLiveInfo?.interfaces ?? [];
    networks.push(...networkRowsForServer(full?.name || s.name, ifaces));
    if (!opts.collectFirewall) continue;
    for (const iface of ifaces) {
      if (!iface.mac) continue;
      if (firewallTargets.length >= MAX_FIREWALL_READS) break; // cap across the whole poll
      firewallTargets.push({ serverId: s.id, mac: iface.mac, serverName: full?.name || s.name });
    }
  }

  // Firewall reads — parallel (a sequential loop would blow the 10 s budget).
  if (opts.collectFirewall && firewallTargets.length > 0) {
    const fwResults = await Promise.allSettled(firewallTargets.map((t) => readFirewallSafe(client, t.serverId, t.mac)));
    for (let i = 0; i < fwResults.length; i++) {
      const r = fwResults[i];
      if (r.status === 'rejected') { firewallReadsFailed = true; continue; } // omit — keep previous rows for this interface
      const fw = r.value;
      if (fw === null) { firewallReadsFailed = true; continue; }
      let pos = 0;
      for (const rule of rulesForInterface(fw, policyById)) {
        firewallRules.push(toUnifiedRule(rule, firewallTargets[i].serverName, firewallTargets[i].mac, pos++));
      }
    }
  }

  if (networks.length > 0) metrics['networks'] = networks;
  // Present-but-empty is authoritative ONLY when every read succeeded — a failed
  // read must not wipe previously ingested rules.
  if (!firewallReadsFailed) metrics['firewallRules'] = firewallRules;

  const health: Health = errors.length > 0 ? 'warning' : 'ok';
  if (errors.length > 0 && !('system.error' in metrics)) metrics['system.error'] = errors.slice(0, 3).join('; ');
  return { health, metrics, errors };
}

/** Firewall read with null-on-failure semantics. */
async function readFirewallSafe(client: ScpClient, serverId: number, mac: string): Promise<ScpServerFirewall | null> {
  try {
    return await client.getInterfaceFirewall(serverId, mac);
  } catch {
    return null;
  }
}

/** Expands an interface firewall's policy IDs into concrete rules (user policies first). */
function rulesForInterface(fw: ScpServerFirewall, policyById: Map<number, ScpFirewallPolicy> | null): ScpFirewallRule[] {
  const out: ScpFirewallRule[] = [];
  if (!policyById) return out;
  for (const ref of [...(fw.userPolicies ?? []), ...(fw.copiedPolicies ?? [])]) {
    const id = typeof ref === 'number' ? ref : (ref as { id?: number }).id;
    if (typeof id !== 'number') continue;
    const policy = policyById.get(id);
    for (const rule of policy?.rules ?? []) out.push(rule);
  }
  return out;
}

function summarizeIps(full: ScpServer | undefined): string {
  if (!full) return '';
  const v4 = (full.ipv4Addresses ?? []).map((a) => a.ip).filter(Boolean);
  const v6 = (full.ipv6Addresses ?? []).map((a) => a.networkPrefix).filter(Boolean);
  return [...v4, ...v6].slice(0, 4).join(', ');
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
