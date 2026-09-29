/**
 * Canonical fleet intents for LCOS routers — `network.create` / `network.delete`.
 *
 * These implement the cross-vendor contract from @unm/plugin-sdk (intents.ts):
 * one intent fans out to every router in a site/tag via the UNM plan machinery,
 * and each plugin renders it against its own config surface. On LCOS the write
 * transport is the INTERACTIVE CLI over SSH PTY — verified on both vRouter
 * (WLC01) and physical hardware (GW_Ralf):
 *   - SNMP SET cannot create rows in lcsSetupTcpIpNetworkListTable (family
 *     1.2.7.30) — probed live: `NotWritable` on a new row's col .1, while the
 *     same table is also not SNMP-readable per-row. Only a handful of setup
 *     scalars (DNS/NTP/LAN-ifc/timezone) are SET-writable.
 *   - SFTP /config is EMPTY on physical devices — LCF edit is vRouter-only.
 * The CLI works everywhere, so it is the universal transport for table rows.
 *
 * Table grammars (validated from `readscript -d` dumps of both devices):
 *   Setup/VLAN/Networks          tab Name VLAN-ID Ports
 *                                add "NAME" <vlanId> "<iface>"
 *   Setup/TCP-IP/Network-list    tab Network-name IP-Address IP-Netmask VLAN-ID
 *                                 Interface Src-check Type Rtg-tag Comment
 *                                add "NAME" <ip> <mask> <vlanId> <iface> loose Intranet 0 ""
 *   Setup/DHCP/Network-list      tab (21 cols) Network-name Start End Netmask
 *                                 Broadcast-Address Gateway DNS-Default DNS-Backup
 *                                 Operating Broadcast-Bit Master..4th Loopback Cache
 *                                 Adaption Cluster Max.-Lease Def.-Lease Suppress-ARP-check
 *   Setup/Interfaces/WLAN/Network  per-slot rows (WLAN-N / WLAN-N-M) — SSID slots
 *                                 are FIXED; a slot is configured via targeted
 *                                 `set <path> <col> <value>` commands.
 * Row deletion: single-key tables delete by name from the root prompt:
 *   del Setup/VLAN/Networks/<name>
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, resolveSshCredentials } from '@unm/plugin-sdk';
import type { SshCredentials } from '@unm/plugin-sdk';
import { snmpWalk } from '@unm/snmp-client';
import { NET_LIST } from '../lcosOids';
import { runLcosCliCommands, stripCommandEcho } from '../lcosCli';
import { readWlanTable, writeWlanSlot } from './wlanSlots';
import { ActionContext, ActionDescriptor, ActionResult } from './types';

// --- Shared CLI table helpers ------------------------------------------------------

/** Resolves the bound `ssh` slot (same contract as registry.ts). */
export function sshCreds(ctx: ActionContext): SshCredentials | undefined {
  return resolveSshCredentials(ctx.credentials as Record<string, unknown>, { slotOnly: true });
}

const NO_SSH_SLOT_ERROR =
  'No `ssh` credential slot bound — bind a usernamePassword or sshKeyPair secret to the assignment\'s "ssh" slot for CLI-based network intents.';

/** Quotes an LCOS CLI value in double quotes. */
function q(v: string): string {
  return `"${v}"`;
}

/**
 * Runs `cd <table>` + `dir -a` and returns the DATA rows (one string each).
 * Data rows start at column 0; header/separator lines are indented or made of
 * '='/'-'; prompt lines contain '@'.
 */
export async function cliTableRows(ctx: ActionContext, creds: SshCredentials, tablePath: string): Promise<string[]> {
  const results = await runLcosCliCommands(
    ctx.terminalPool,
    { host: ctx.address, port: ctx.sshPort ?? 22, creds },
    [`cd /Setup/${tablePath}`, 'dir -a']
  );
  if (!results[1]?.completed) return [];
  const text = stripCommandEcho(results[1].raw, 'dir -a');
  const rows: string[] = [];
  for (const line of text.split('\n')) {
    const l = line.replace(/\r/g, '').trimEnd();
    if (l.length === 0) continue;
    if (/^\s/.test(l)) continue; // header / separator indentation
    if (l.includes('@')) continue; // prompt lines
    if (/^[=|-]+$/.test(l.trim())) continue;
    rows.push(l);
  }
  return rows;
}

/** True when a table has a row whose first quoted/bare token equals `name`.
 *  LCOS upper-cases network names in the TCP-IP/DHCP tables, so compare case-insensitively. */
function tableHasName(rows: string[], name: string): boolean {
  const needle = name.toUpperCase();
  for (const row of rows) {
    const m = /^"([^"]+)"|^\S+/.exec(row.trim());
    if (!m) continue;
    if ((m[1] ?? m[0]).toUpperCase() === needle) return true;
  }
  return false;
}

/** Adds one row to a table and verifies it appeared. Returns { ok, detail }. */
async function cliAddRow(
  ctx: ActionContext,
  creds: SshCredentials,
  tablePath: string,
  values: string[],
  name: string
): Promise<{ ok: boolean; detail: string }> {
  const results = await runLcosCliCommands(
    ctx.terminalPool,
    { host: ctx.address, port: ctx.sshPort ?? 22, creds },
    [`cd /Setup/${tablePath}`, `add ${values.join(' ')}`]
  );
  if (!results[1]?.completed) return { ok: false, detail: `${tablePath}: CLI session timed out during add` };
  const rows = await cliTableRows(ctx, creds, tablePath);
  if (tableHasName(rows, name)) return { ok: true, detail: `row added to ${tablePath}` };
  // The row is missing — surface the raw add output for diagnosis.
  const rawAdd = stripCommandEcho(results[1].raw, undefined).split('\n').slice(-4).join(' | ');
  return { ok: false, detail: `${tablePath}: row not present after add (CLI said: ${rawAdd || 'no output'})` };
}

/** Deletes a single-key table row by name from the root prompt; idempotent. */
async function cliDelRow(
  ctx: ActionContext,
  creds: SshCredentials,
  tablePath: string,
  name: string
): Promise<{ ok: boolean; detail: string }> {
  const before = await cliTableRows(ctx, creds, tablePath);
  if (!tableHasName(before, name)) return { ok: true, detail: `${tablePath}: no row named ${name} — nothing to do` };
  const results = await runLcosCliCommands(
    ctx.terminalPool,
    { host: ctx.address, port: ctx.sshPort ?? 22, creds },
    ['cd /', `del Setup/${tablePath}/${name}`]
  );
  if (!results[1]?.completed) return { ok: false, detail: `${tablePath}: CLI session timed out during del` };
  const after = await cliTableRows(ctx, creds, tablePath);
  if (tableHasName(after, name)) {
    const rawDel = stripCommandEcho(results[1].raw, undefined).split('\n').slice(-4).join(' | ');
    return { ok: false, detail: `${tablePath}: row still present after del (CLI said: ${rawDel || 'no output'})` };
  }
  return { ok: true, detail: `row removed from ${tablePath}` };
}

/** Splits a CIDR into [ip, netmask] (v4 only). */
function cidrToIpMask(cidr: string): [string, string] | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  const prefix = Number(m[2]);
  if (prefix < 8 || prefix > 30) return null;
  // /n → n/8 octets of 255, next octet 2^(8-(n%8))-1, rest 0.
  const full = Math.floor(prefix / 8);
  const rem = prefix % 8;
  const parts: number[] = [];
  for (let i = 0; i < 4; i++) {
    if (i < full) parts.push(255);
    else if (i === full) parts.push(rem === 0 ? 0 : 256 - Math.pow(2, rem));
    else parts.push(0);
  }
  return [m[1], parts.join('.')];
}

// --- network.create ------------------------------------------------------------------

const networkCreate: ActionDescriptor = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN + L3 + DHCP + optional SSID)',
  description:
    "Canonical fleet intent — creates a named VLAN on this device and, when given, its L3 address (TCP-IP Network-list), an optional DHCP pool, and an optional WLAN SSID slot. Idempotent: existing rows are left untouched. Transport: LCOS CLI over SSH (SNMP SET cannot create these table rows; SFTP /config is empty on physical devices).",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 180_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device)' },
    vlanId: { type: 'number', required: true, min: 1, max: 4094, description: 'VLAN ID to create/attach' },
    cidr: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'L3 address as CIDR (e.g. 10.42.0.1/24) — alternative to ip+netmask' },
    ip: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'L3 address (alternative to cidr)' },
    netmask: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Netmask for `ip`' },
    interface: { type: 'string', maxLength: 64, default: 'LAN-1', description: 'Device-local L2 interface to attach the VLAN to (e.g. LAN-1)' },
    dhcpPool: {
      type: 'object',
      description: 'Optional DHCP pool served on this network',
      properties: {
        start: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$' },
        end: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$' },
      },
    },
    ssid: {
      type: 'object',
      description: 'Optional WLAN SSID to expose on a local radio slot (devices with built-in radios only)',
      properties: {
        name: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'Broadcast SSID name' },
        passphrase: { type: 'string', minLength: 8, maxLength: 63, description: 'WPA2-PSK passphrase (sets the slot to WPA2-PSK when given)' },
        slot: { type: 'string', pattern: '^WLAN-[12](?:-[2-7])?$', description: 'Radio slot to use (e.g. WLAN-1, WLAN-1-3); auto-picked when omitted' },
      },
    },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const name = String(input.name ?? '').trim();
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : NaN;
    if (name.length === 0 || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {
      return { success: false, error: '`name` must be 1..64 chars of [A-Za-z0-9_-] (LCOS table names).' };
    }
    if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) {
      return { success: false, error: '`vlanId` must be an integer 1..4094.' };
    }
    const iface = String(input.interface ?? 'LAN-1').trim() || 'LAN-1';

    // L3 address — cidr or ip+netmask.
    let l3Ip: string | null = null;
    let l3Mask: string | null = null;
    if (typeof input.cidr === 'string' && input.cidr) {
      const pair = cidrToIpMask(input.cidr);
      if (!pair) return { success: false, error: `Invalid CIDR '${input.cidr}' (expected IPv4 /8..30).` };
      [l3Ip, l3Mask] = pair;
    } else if (typeof input.ip === 'string' && input.ip && typeof input.netmask === 'string' && input.netmask) {
      l3Ip = input.ip;
      l3Mask = input.netmask;
    }

    const steps: string[] = [];
    let applied = false;

    // 1. L2 VLAN network (always).
    {
      const rows = await cliTableRows(ctx, creds, 'VLAN/Networks');
      if (tableHasName(rows, name)) {
        steps.push(`VLAN/Networks: row ${name} already exists — left untouched`);
      } else {
        const r = await cliAddRow(ctx, creds, 'VLAN/Networks', [q(name), String(vlanId), q(iface)], name);
        if (!r.ok) return { success: false, error: `Failed to create VLAN network: ${r.detail}` };
        steps.push(r.detail);
        applied = true;
      }
    }

    // 2. L3 address (optional).
    if (l3Ip && l3Mask) {
      const rows = await cliTableRows(ctx, creds, 'TCP-IP/Network-list');
      if (tableHasName(rows, name)) {
        steps.push(`TCP-IP/Network-list: row ${name} already exists — left untouched`);
      } else {
        // Columns: Name IP-Address IP-Netmask VLAN-ID Interface Src-check Type Rtg-tag Comment.
        const r = await cliAddRow(ctx, creds, 'TCP-IP/Network-list', [q(name), l3Ip, l3Mask, String(vlanId), iface, 'loose', 'Intranet', '0', q('')], name);
        if (!r.ok) return { success: false, error: `VLAN network created but L3 address failed: ${r.detail}` };
        steps.push(r.detail);
        applied = true;
      }
    }

    // 3. DHCP pool (optional).
    const pool = input.dhcpPool as Record<string, unknown> | undefined;
    if (pool && typeof pool.start === 'string' && typeof pool.end === 'string') {
      const mask = l3Mask ?? '0.0.0.0';
      const rows = await cliTableRows(ctx, creds, 'DHCP/Network-list');
      if (tableHasName(rows, name)) {
        steps.push(`DHCP/Network-list: row ${name} already exists — left untouched`);
      } else {
        // 21 columns in tab-header order (validated against GW_Ralf readscript rows).
        const values = [
          q(name), pool.start, pool.end, mask, '0.0.0.0', '0.0.0.0', '0.0.0.0', '0.0.0.0',
          'Yes', 'No', '0.0.0.0', '0.0.0.0', '0.0.0.0', '0.0.0.0', q(''), 'No', 'No', 'No', '0', '0', 'No',
        ];
        const r = await cliAddRow(ctx, creds, 'DHCP/Network-list', values, name);
        if (!r.ok) return { success: false, error: `VLAN network created but DHCP pool failed: ${r.detail}` };
        steps.push(r.detail);
        applied = true;
      }
    }

    // 4. WLAN SSID (optional — local radios only). LCOS SSIDs are FIXED slots
    //    (WLAN-N / WLAN-N-M) — configured by rewriting the slot's full row
    //    positionally (read-modify-write; targeted column sets do not exist).
    const ssid = input.ssid as Record<string, unknown> | undefined;
    if (ssid && typeof ssid.name === 'string' && ssid.name) {
      let slot = typeof ssid.slot === 'string' && ssid.slot ? ssid.slot : '';
      try {
        if (!slot) {
          // Auto-pick: first sub-slot still at factory defaults (name LANCOM, off).
          const t = await readWlanTable(ctx, creds, 'Network');
          slot = ['WLAN-1-2', 'WLAN-1-3', 'WLAN-1-4', 'WLAN-1-5', 'WLAN-1-6', 'WLAN-1-7', 'WLAN-2-2', 'WLAN-2-3']
            .find((c) => {
              const row = t.rows.get(c);
              return !!row && row[1] === 'No' && row[2].toUpperCase() === 'LANCOM';
            }) ?? '';
        }
      } catch (e) {
        if (!slot) return { success: false, error: `VLAN network created but SSID auto-slot detection failed (no local WLAN table?): ${e instanceof Error ? e.message : String(e)}` };
      }
      if (!slot) {
        steps.push(`SSID: no free WLAN slot found — SSID '${ssid.name}' NOT created (all slots in use or no local radios)`);
      } else {
        const ssidName = String(ssid.name).slice(0, 32);
        const netRes = await writeWlanSlot(ctx, creds, 'Network', slot, { Operating: 'Yes', 'Network-Name': ssidName });
        if (!netRes.ok) return { success: false, error: `VLAN network created but SSID slot ${slot} failed: ${netRes.detail}` };
        steps.push(netRes.detail);
        const passphrase = typeof ssid.passphrase === 'string' ? ssid.passphrase : '';
        if (passphrase.length >= 8) {
          const encRes = await writeWlanSlot(ctx, creds, 'Encryption', slot, {
            Encryption: 'Yes',
            Method: '802.11i-WPA-PSK',
            'WPA-Version': 'WPA2',
            Key: passphrase,
          });
          if (!encRes.ok) return { success: false, error: `SSID slot ${slot} named but encryption failed: ${encRes.detail}` };
          steps.push(encRes.detail);
        }
        steps.push(`SSID '${ssidName}' on slot ${slot}${passphrase.length >= 8 ? ' (WPA2-PSK)' : ''} — VLAN binding follows the device's WLAN-VLAN mapping`);
        applied = true;
      }
    }

    return {
      success: true,
      applied,
      verified: true,
      details: { name, vlanId, interface: iface, l3: l3Ip ? `${l3Ip}/${l3Mask}` : null, steps },
    };
  },
};

// --- network.delete ------------------------------------------------------------------

const networkDelete: ActionDescriptor = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network (VLAN + L3 + DHCP rows)',
  description:
    "Canonical fleet intent — removes the named network's rows from VLAN/Networks, TCP-IP/Network-list and DHCP/Network-list. Idempotent: missing rows are skipped. Transport: LCOS CLI over SSH (`del Setup/<table>/<name>`). NOTE: WLAN SSID slots are fixed hardware slots and are NOT touched by this intent.",
  module: 'Network',
  riskLevel: 'dangerous',
  deviceCount: 'N' as const,
  timeoutMs: 180_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name to remove' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const name = String(input.name ?? '').trim();
    if (name.length === 0 || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {
      return { success: false, error: '`name` must be 1..64 chars of [A-Za-z0-9_-] (LCOS table names).' };
    }

    // L3 + DHCP first (they reference the VLAN), then the L2 row.
    const tables = ['TCP-IP/Network-list', 'DHCP/Network-list', 'VLAN/Networks'];
    const steps: string[] = [];
    let removedAny = false;
    for (const t of tables) {
      const r = await cliDelRow(ctx, creds, t, name);
      if (!r.ok) return { success: false, error: `Deletion incomplete: ${r.detail}` };
      steps.push(r.detail);
      if (!/nothing to do/.test(r.detail)) removedAny = true;
    }

    return {
      success: true,
      applied: removedAny,
      verified: true,
      details: { name, steps },
    };
  },
};

// --- vlan.networks.read (SNMP status — verification + discovery) ----------------------

/** Decodes a length-prefixed decimal-octet text index ("6.87.76.…" → "WLAN-1"). */
export function decodeTextIndex(idx: string[]): string | null {
  if (idx.length < 2) return null;
  const len = Number(idx[0]);
  if (!Number.isInteger(len) || len <= 0 || len !== idx.length - 1) return null;
  try {
    return Buffer.from(idx.slice(1, 1 + len).map(Number)).toString('utf8');
  } catch {
    return null;
  }
}

/** Reads the L3 network list from lcsStatusTcpIpNetworkListTable (SNMP walk — read-only). */
const vlanNetworksRead: ActionDescriptor = {
  id: 'vlan.networks.read',
  label: 'Read configured networks (L3 + VLAN)',
  description:
    "Walks lcsStatusTcpIpNetworkListTable (status MIB, SNMP): every L3 network with its IP address, netmask, VLAN ID and interface. Read-only — use to verify a network.create rollout.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    const networks: Array<{ name: string; ip: string | null; netmask: string | null; vlanId: number | null; ifc: number | null }> = [];
    try {
      const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [NET_LIST.base], ctx.opts);
      // Row shape: <base>.1.<col>.<textIndex…> — group by decoded name.
      const rows = new Map<string, Record<number, string>>();
      for (const [oid, value] of m) {
        if (!oid.startsWith(`${NET_LIST.base}.1.`)) continue;
        const rel = oid.slice(`${NET_LIST.base}.1.`.length).split('.');
        const col = Number(rel[0]);
        const key = decodeTextIndex(rel.slice(1));
        if (key === null || !Number.isInteger(col)) continue;
        let row = rows.get(key);
        if (!row) { row = {}; rows.set(key, row); }
        row[col] = String(value);
      }
      for (const [name, cols] of rows.entries()) {
        networks.push({
          name,
          ip: cols[NET_LIST.COL_IP] ?? null,
          netmask: cols[NET_LIST.COL_NETMASK] ?? null,
          vlanId: cols[NET_LIST.COL_VLAN] !== undefined ? Number(cols[NET_LIST.COL_VLAN]) : null,
          ifc: cols[NET_LIST.COL_IFC] !== undefined ? Number(cols[NET_LIST.COL_IFC]) : null,
        });
      }
    } catch { /* no status tree on this model — empty result */ }
    networks.sort((a, b) => (a.vlanId ?? 0) - (b.vlanId ?? 0));
    return { success: true, details: { count: networks.length, networks } };
  },
};

export const NETWORK_INTENT_ACTIONS: ActionDescriptor[] = [networkCreate, networkDelete, vlanNetworksRead];
