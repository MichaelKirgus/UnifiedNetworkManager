/**
 * LCOS gap-fill read actions — firewall rules, static routes, DHCP networks.
 *
 * These close the "thinnest config catalog" gaps identified in the cross-plugin
 * audit: LCOS had no way to READ its firewall filter rules, IP routing table, or
 * DHCP server pool configuration through UNM. All three are exposed as CLI
 * `dir -a` tables (verified live on WLC01 vRouter + GW_Ralf physical, LCOS 10.94):
 *
 *   /Setup/IP-Router/Firewall/Rules    — filter rules (Name, Prot., Source, Dst, Action, Prio, …)
 *   /Setup/IP-Router/IP-Routing-Table  — static routes (IP, Mask, Rtg-tag, Peer, Active, …)
 *   /Setup/DHCP/Network-list           — DHCP pools (Network-name, Start, End, Netmask, Gateway, DNS, …)
 *
 * All three are READ-ONLY (`riskLevel: 'read'`) — they open a CLI session, `cd`
 * into the table directory, run `dir -a`, and parse the fixed-width output. No
 * configuration is changed. They require a bound `ssh` credential slot (same as
 * every other CLI action in this plugin).
 */

import { cliTableRows, sshCreds } from './networkIntents';
import type { ActionContext, ActionDescriptor, ActionResult } from './types';

const NO_SSH_SLOT_ERROR =
  'No `ssh` credential slot bound — bind a usernamePassword or sshKeyPair secret to the assignment\'s "ssh" slot for CLI actions.';

// --- Column-aware row parsing -------------------------------------------------------

/**
 * Splits one LCOS `dir -a` data row into exactly `colCount` fields.
 *
 * LCOS uses fixed-width columns separated by 2+ spaces; the LAST column (usually
 * a free-text Comment) may contain single spaces, so we split on /\s{2,}/ and
 * re-join any overflow tokens back into the final field. Rows with fewer real
 * fields than expected get empty strings for the missing trailing columns.
 */
function splitRow(row: string, colCount: number): string[] {
  const trimmed = row.trim();
  if (trimmed.length === 0) return new Array(colCount).fill('');
  // Split on 2+ spaces — single spaces are intra-field (e.g. in comments).
  let parts = trimmed.split(/\s{2,}/);
  // If the split produced more tokens than columns, the excess belongs to the
  // last field (a comment with internal double-spaces is rare but possible when
  // LCOS wraps a very long row and parseDirARows already merged it).
  if (parts.length > colCount) {
    const head = parts.slice(0, colCount - 1);
    const tail = parts.slice(colCount - 1).join(' ');
    parts = [...head, tail];
  }
  // Pad short rows.
  while (parts.length < colCount) parts.push('');
  return parts.map((p) => p.trim());
}

// --- Firewall rules -----------------------------------------------------------------

export interface LcosFirewallRule {
  name: string | null;
  protocol: string | null;
  source: string | null;
  destination: string | null;
  action: string | null;
  priority: number | null;
  stateful: boolean | null;
  comment: string | null;
}

/** Parses IP-Router/Firewall/Rules rows (14 columns in dir -a order). */
export function parseFirewallRuleRows(rows: string[]): LcosFirewallRule[] {
  // Columns: Name Prot. Source Destination Action LB-Policy LB-Switchover Linked
  //           Prio Firewall-Rule Stateful Src-Tag Rtg-tag Comment
  const COLS = 14;
  return rows.map((row) => {
    const f = splitRow(row, COLS);
    return {
      name: f[0] || null,
      protocol: f[1] || null,
      source: f[2] || null,
      destination: f[3] || null,
      action: f[4] || null,
      priority: /^\d+$/.test(f[8]) ? Number(f[8]) : null,
      stateful: f[10] === 'Yes' ? true : f[10] === 'No' ? false : null,
      comment: f[13] || null,
    };
  }).filter((r) => r.name !== null);
}

const firewallRulesRead: ActionDescriptor = {
  id: 'firewall.rules.read',
  label: 'Read firewall filter rules',
  description:
    "Read-only list of this device's IP-Router firewall filter rules (CLI `dir -a` on /Setup/IP-Router/Firewall/Rules). Returns each rule's name, protocol, source/destination objects, action (ACCEPT/REJECT/DROP), priority, stateful flag and comment. Requires a bound `ssh` credential slot.",
  module: 'Firewall',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };
    try {
      const rows = await cliTableRows(ctx, creds, 'IP-Router/Firewall/Rules');
      const rules = parseFirewallRuleRows(rows);
      return { success: true, details: { count: rules.length, rules } };
    } catch (e) {
      return { success: false, error: `CLI read failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  },
};

// --- Static routes ------------------------------------------------------------------

export interface LcosStaticRoute {
  ipAddress: string | null;
  netmask: string | null;
  routeTag: number | null;
  adminDistance: number | null;
  peerOrIp: string | null;
  active: boolean | null;
  comment: string | null;
}

/** Parses IP-Router/IP-Routing-Table rows (9 columns in dir -a order). */
export function parseStaticRouteRows(rows: string[]): LcosStaticRoute[] {
  // Columns: IP-Address IP-Netmask Rtg-tag Admin-Distance Peer-or-IP Distance Masquerade Active Comment
  const COLS = 9;
  return rows.map((row) => {
    const f = splitRow(row, COLS);
    return {
      ipAddress: f[0] || null,
      netmask: f[1] || null,
      routeTag: /^\d+$/.test(f[2]) ? Number(f[2]) : null,
      adminDistance: /^\d+$/.test(f[3]) ? Number(f[3]) : null,
      peerOrIp: f[4] || null,
      active: f[7] === 'Yes' ? true : f[7] === 'No' ? false : null,
      comment: f[8] || null,
    };
  }).filter((r) => r.ipAddress !== null);
}

const routingStaticRead: ActionDescriptor = {
  id: 'routing.static.read',
  label: 'Read static IP routes',
  description:
    "Read-only list of this device's static IP routing table entries (CLI `dir -a` on /Setup/IP-Router/IP-Routing-Table). Returns each route's destination network, netmask, route tag, admin distance, peer/gateway address, active state and comment. Requires a bound `ssh` credential slot.",
  module: 'Routing',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };
    try {
      const rows = await cliTableRows(ctx, creds, 'IP-Router/IP-Routing-Table');
      const routes = parseStaticRouteRows(rows);
      return { success: true, details: { count: routes.length, routes } };
    } catch (e) {
      return { success: false, error: `CLI read failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  },
};

// --- DHCP networks ------------------------------------------------------------------

export interface LcosDhcpNetwork {
  networkName: string | null;
  startAddress: string | null;
  endAddress: string | null;
  netmask: string | null;
  gateway: string | null;
  dnsDefault: string | null;
  operating: boolean | null;
}

/** Parses DHCP/Network-list rows (21 columns in dir -a order). */
export function parseDhcpNetworkRows(rows: string[]): LcosDhcpNetwork[] {
  // Columns: Network-name Start-Address-Pool End-Address-Pool Netmask Broadcast-Address
  //           Gateway-Address DNS-Default DNS-Backup Operating Broadcast-Bit Master-Server
  //           2nd-Master-Server 3rd-Master-Server 4th-Master-Server Loopback-Address Cache
  //           Adaption Cluster Max.-Lease Def.-Lease Suppress-ARP-check
  const COLS = 21;
  return rows.map((row) => {
    const f = splitRow(row, COLS);
    return {
      networkName: f[0] || null,
      startAddress: f[1] || null,
      endAddress: f[2] || null,
      netmask: f[3] || null,
      gateway: f[5] || null,
      dnsDefault: f[6] || null,
      operating: f[8] === 'Yes' ? true : f[8] === 'No' ? false : null,
    };
  }).filter((r) => r.networkName !== null);
}

const dhcpNetworksRead: ActionDescriptor = {
  id: 'dhcp.networks.read',
  label: 'Read DHCP server networks (pools)',
  description:
    "Read-only list of this device's DHCP server network/pool configuration (CLI `dir -a` on /Setup/DHCP/Network-list). Returns each pool's network name, address range (start/end), netmask, gateway and default DNS. Requires a bound `ssh` credential slot.",
  module: 'DHCP',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };
    try {
      const rows = await cliTableRows(ctx, creds, 'DHCP/Network-list');
      const networks = parseDhcpNetworkRows(rows);
      return { success: true, details: { count: networks.length, networks } };
    } catch (e) {
      return { success: false, error: `CLI read failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  },
};

export const GAP_READ_ACTIONS: ActionDescriptor[] = [firewallRulesRead, routingStaticRead, dhcpNetworksRead];
