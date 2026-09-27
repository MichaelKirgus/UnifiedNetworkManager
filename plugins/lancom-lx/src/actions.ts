/**
 * LCOS-LX configuration action registry — executed over the web-UI ubus API
 * (see webapi.ts). The vendor MIB is read-only, so EVERY write goes through a
 * `handleTransactionStream` transaction.
 *
 * Read strategy: all reads parse the GetConfig text dump (parseLcosConfigText)
 * — it carries human-readable values for every cell and explicit row indices.
 * The ubus getTable endpoint returns SPARSE rows without index values and with
 * numeric enum indices, so it is not used for display data.
 *
 * Safety policy (user requirement: no destructive actions on production APs):
 *  - NO factory reset (13.4.1), NO reboot (13.4.2).
 *  - Writes are single-scalar / single-row updates only, each verified by a
 *    re-read after the transaction.
 *  - Flash persistence is an EXPLICIT separate action (`config.persist`) — a
 *    plan that changes settings does not silently make them permanent.
 *  - `config.restore` (full-config overwrite via SetConfig) IS exposed but only
 *    as riskLevel 'dangerous' with retryOnDispatchFailure=false — it must be an
 *    explicit user choice, never a re-dispatched step. Every mutating plan gets
 *    a best-effort `config.backup.download` rollback point prepended (plan.ts).
 */

import { ActionResult, ActionDescriptor, configBackupFileName, createFileRepoClient, createRegistry, FileRepoClient } from '@unm/plugin-sdk';
import { isWriteOk, LcosWebClient, parseLcosConfigText, REDACTED, redactConfig, tableCell, type ParsedLcosConfig } from './webapi';

// --- Context ------------------------------------------------------------------

/** Executor context — built by index.ts's /config route. */
export interface LxActionContext {
  host: string;
  address: string;
  deviceId?: string;
  /** UNM device display name (sent by the API on /config) — labels artifacts like config backups. */
  deviceName?: string | null;
  /** Decrypted `web` credential slot (username/password for the ubus login). */
  web: { username: string; password: string };
  timeoutMs: number;
}

function client(ctx: LxActionContext): LcosWebClient {
  return new LcosWebClient(ctx.address, ctx.web.username, ctx.web.password, { timeoutMs: ctx.timeoutMs });
}

// Shared UNM file-repo client (SDK) — config backups land in the central repo
// so they are downloadable/archivable from the Files page and referenceable by
// id from a later restore step. One instance per plugin process is fine.
let repoClient: FileRepoClient | null = null;
function fileRepo(): FileRepoClient {
  if (!repoClient) repoClient = createFileRepoClient();
  return repoClient;
}

/** Reads the full running config once and parses it (shared by read actions). */
async function loadConfig(ctx: LxActionContext): Promise<ParsedLcosConfig> {
  const c = client(ctx);
  try {
    return parseLcosConfigText(await c.getConfigText());
  } finally {
    await c.destroy().catch(() => undefined);
  }
}

/** The row-index path of the i-th parsed row of a table (from its cell keys). */
function rowIndexPath(parsed: ParsedLcosConfig, tableOid: string, i: number): string {
  const rows = parsed.tables.get(tableOid);
  const row = rows?.[i];
  if (!row) return '0';
  for (const k of row.keys()) {
    if (k.startsWith(`${tableOid}.`)) {
      // Cell key = <table>.<idx…>.<col> — the index path is everything but the last segment.
      const rest = k.slice(tableOid.length + 1).split('.');
      return rest.slice(0, -1).join('.') || '0';
    }
  }
  return '0';
}

/** Finds the row-index path of a table row whose index column (col 1) equals `value`. */
function findRowByIndex(parsed: ParsedLcosConfig, tableOid: string, value: string): string | null {
  const rows = parsed.tables.get(tableOid);
  if (!rows) return null;
  for (let i = 0; i < rows.length; i++) {
    const idx = rowIndexPath(parsed, tableOid, i);
    if (tableCell(parsed, tableOid, '1', idx) === value) return idx;
  }
  return null;
}

// --- Read actions -----------------------------------------------------------------

const configRead: ActionDescriptor<LxActionContext> = {
  id: 'config.read',
  label: 'Read full configuration',
  description: 'Fetches the complete running LCOS configuration (GetConfig) with all passwords/hashes redacted.',
  module: 'Configuration',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const parsed = await loadConfig(ctx);
    const redacted = redactConfig(parsed);
    // Re-serialize to a compact OID → value listing (the raw text is ~32 KB).
    const lines: string[] = [];
    for (const [k, v] of [...redacted.scalars].sort()) lines.push(`${k} = ${v}`);
    for (const [, rows] of redacted.tables) {
      for (const row of rows) for (const [k, v] of row) lines.push(`(${k}) = ${v}`);
    }
    return { success: true, details: { scalarCount: parsed.scalars.size, tableCount: parsed.tables.size, config: lines.join('\n') } };
  },
};

const wlanNetworksRead: ActionDescriptor<LxActionContext> = {
  id: 'wlan.networks.read',
  label: 'Read WLAN networks (SSIDs)',
  description: 'Lists all configured WLAN networks — SSID name, VLAN, encryption profile, closed flag.',
  module: 'WLAN',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const rows = p.tables.get('13.2.20.1') ?? [];
    const networks = rows.map((_, i) => {
      const idx = rowIndexPath(p, '13.2.20.1', i);
      return {
        network: tableCell(p, '13.2.20.1', '1', idx) ?? '',
        ssid: tableCell(p, '13.2.20.1', '2', idx) ?? '',
        closedNetwork: tableCell(p, '13.2.20.1', '4', idx) || 'No',
        maxStations: tableCell(p, '13.2.20.1', '10', idx) || '0',
        encryptionProfile: tableCell(p, '13.2.20.1', '102', idx) || '',
        vlanId: tableCell(p, '13.2.20.1', '200', idx) || '0',
      };
    });
    return { success: true, details: { count: networks.length, networks } };
  },
};

const radiosRead: ActionDescriptor<LxActionContext> = {
  id: 'radios.read',
  label: 'Read radio settings',
  description: 'Lists per-radio configuration — band, channel, mode, bandwidth, transmit power.',
  module: 'WLAN',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const rows = p.tables.get('13.2.20.8') ?? [];
    const radios = rows.map((_, i) => {
      const idx = rowIndexPath(p, '13.2.20.8', i);
      return {
        ifc: tableCell(p, '13.2.20.8', '1', idx) ?? '',
        band: tableCell(p, '13.2.20.8', '6', idx) || '—',
        channel: (tableCell(p, '13.2.20.8', '8', idx) === '0' ? 'auto' : tableCell(p, '13.2.20.8', '8', idx)) ?? 'auto',
        mode2g: tableCell(p, '13.2.20.8', '9', idx) || 'Auto',
        mode5g: tableCell(p, '13.2.20.8', '3', idx) || 'Auto',
        bandwidth: tableCell(p, '13.2.20.8', '24', idx) || 'Auto',
        powerSetting: tableCell(p, '13.2.20.8', '33', idx) || 'Automatic',
        eirpDbm: tableCell(p, '13.2.20.8', '34', idx) || '—',
      };
    });
    return { success: true, details: { count: radios.length, radios } };
  },
};

const encryptionProfilesRead: ActionDescriptor<LxActionContext> = {
  id: 'encryption.profiles.read',
  label: 'Read encryption profiles',
  description: 'Lists all WLAN encryption profiles — cipher, method, WPA version. Keys are never returned.',
  module: 'WLAN',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const rows = p.tables.get('13.2.20.3') ?? [];
    const profiles = rows.map((_, i) => {
      const idx = rowIndexPath(p, '13.2.20.3', i);
      return {
        name: tableCell(p, '13.2.20.3', '1', idx) ?? '',
        encryption: tableCell(p, '13.2.20.3', '2', idx) || '—',
        method: tableCell(p, '13.2.20.3', '4', idx) || '—',
        wpaVersion: tableCell(p, '13.2.20.3', '9', idx) || '—',
        radiusProfile: tableCell(p, '13.2.20.3', '21', idx) || null,
      };
    });
    return { success: true, details: { count: profiles.length, profiles } };
  },
};

const ipInterfacesRead: ActionDescriptor<LxActionContext> = {
  id: 'ip.interfaces.read',
  label: 'Read interfaces & VLANs',
  description: 'Lists LAN interfaces with their VLAN assignment and IPv4/IPv6 addressing.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const rows = p.tables.get('13.2.70.6') ?? [];
    // Gateway/DNS parameters are a separate table keyed by the same interface name.
    const paramsByName = new Map<string, Record<string, string | null>>();
    for (let i = 0; i < (p.tables.get('13.2.70.4')?.length ?? 0); i++) {
      const idx = rowIndexPath(p, '13.2.70.4', i);
      paramsByName.set(tableCell(p, '13.2.70.4', '1', idx) ?? '', {
        ipv4Gateway: tableCell(p, '13.2.70.4', '2', idx) || null,
        ipv6Gateway: (tableCell(p, '13.2.70.4', '3', idx) ?? '').replace(/^:+$/, '') || null,
        primaryIpv4Dns: tableCell(p, '13.2.70.4', '4', idx) || null,
        secondaryIpv4Dns: tableCell(p, '13.2.70.4', '5', idx) || null,
      });
    }
    // 802.1X LAN supplicant — password is NEVER returned.
    const supplicantByName = new Map<string, { methodIndex: string; username: string | null }>();
    for (let i = 0; i < (p.tables.get('13.2.30.11')?.length ?? 0); i++) {
      const idx = rowIndexPath(p, '13.2.30.11', i);
      supplicantByName.set(tableCell(p, '13.2.30.11', '1', idx) ?? '', {
        methodIndex: tableCell(p, '13.2.30.11', '2', idx) ?? '', // numeric enum — label mapping not published by the vendor
        username: tableCell(p, '13.2.30.11', '3', idx) || null,
      });
    }
    const interfaces = rows.map((_, i) => {
      const idx = rowIndexPath(p, '13.2.70.6', i);
      const name = tableCell(p, '13.2.70.6', '1', idx) ?? '';
      return {
        name,
        ifname: tableCell(p, '13.2.70.6', '2', idx) || '—',
        vlanId: (tableCell(p, '13.2.70.6', '3', idx) === '0' ? null : tableCell(p, '13.2.70.6', '3', idx)) ?? null,
        ipv4SourceIndex: tableCell(p, '13.2.70.6', '4', idx) ?? '', // numeric enum (observed on this platform: 2 = static) — pass back unchanged to keep it
        ipv6SourceIndex: tableCell(p, '13.2.70.6', '5', idx) ?? '', // numeric enum (observed: 1 = auto/SLAAC)
        staticIpv4: tableCell(p, '13.2.70.6', '6', idx) || null, // CIDR notation, e.g. "10.25.1.2/16"
        staticIpv6: (tableCell(p, '13.2.70.6', '7', idx) ?? '').replace(/^:+$/, '') || null,
        comment: tableCell(p, '13.2.70.6', '9', idx) || null,
        parameters: paramsByName.get(name) ?? null,
        supplicant: supplicantByName.get(name) ?? null, // password redacted by design
      };
    });
    return { success: true, details: { count: interfaces.length, interfaces } };
  },
};

const wlcRead: ActionDescriptor<LxActionContext> = {
  id: 'wlc.read',
  label: 'Read WLC/CAPWAP settings',
  description: 'Shows the configured WLAN controller address, port and operating state.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const rows = p.tables.get('13.2.59.1') ?? [];
    return {
      success: true,
      details: {
        operating: p.scalars.get('13.2.59.2') ?? 'No',
        capwapPort: p.scalars.get('13.2.59.4') ?? null,
        controllers: rows.map((_, i) => ({
          address: tableCell(p, '13.2.59.1', '1', rowIndexPath(p, '13.2.59.1', i)) || '',
          port: tableCell(p, '13.2.59.1', '2', rowIndexPath(p, '13.2.59.1', i)) || '',
        })),
      },
    };
  },
};

// --- Switch / protocol read actions -------------------------------------------------------
// Physical port status lives in LIVE status OIDs (13.1.x) that are NOT part of the
// GetConfig text dump — they come from getTable (see LcosWebClient.getStatusTable).
// Config-side facts (untagged VLANs, LAN-bridge membership, NTP/SNMP/STP/LACP settings)
// come from the parsed config. Enum columns store NUMERIC indices on this platform
// (verified live: NoYes → 0/1, SnmpStatus "Active" → 1, StpVersion "Rapid" → 1).

const portsRead: ActionDescriptor<LxActionContext> = {
  id: 'ports.read',
  label: 'Read switch port status',
  description:
    'Live per-port link state, connector type, MAC address and traffic counters (status OIDs), plus LACP bundle membership/state, untagged VLAN assignments, LAN-bridge (L2M) membership and the PoE input type. LLDP is not configurable on LX devices — it only appears as a status column.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const [portRows, lacpRows, counterRows] = await Promise.all([
        c.getStatusTable('13.1.5.99'), // Ports: 1 Port, 2 Link-Active, 3 Connector, 4 MAC
        c.getStatusTable('13.1.5.44'), // LACP status: 1 Bundle, 2 State, 3 Speed, 4 Priority, 6 Local-MAC, 8 Partner-MAC, 10 Local-Ports, 11 Bundle-State
        c.getStatusTable('13.1.5.52'), // ByteTransport: 1 Port, 2 Tx-Bytes, 3 Rx-Bytes, 4 Rx-CRC-Errors
      ]);
      const poeInputType = await c.getScalar('13.1.47.42.1');
      const p = parseLcosConfigText(await c.getConfigText());

      // LACP membership: bundle row → set of member ports (col 10 "ETH2, ETH1").
      const bundles = (lacpRows ?? []).map((r) => {
        const members = (r.cells.get('10') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        return {
          bundle: r.cells.get('1') ?? '',
          state: r.cells.get('2') || 'down',
          speed: r.cells.get('3') || null,
          priority: r.cells.get('4') || null,
          localMac: r.cells.get('6') || null,
          partnerMac: r.cells.get('8') || null,
          bundleState: r.cells.get('11') || null,
          ports: members,
        };
      });
      const portBundle = new Map<string, { bundle: string; state: string }>();
      for (const b of bundles) for (const m of b.ports) portBundle.set(m, { bundle: b.bundle, state: b.state });

      // Config-side per-port facts.
      const untaggedByPort = new Map<string, number[]>();
      for (let i = 0; i < (p.tables.get('13.2.70.8')?.length ?? 0); i++) {
        const idx = rowIndexPath(p, '13.2.70.8', i);
        const port = tableCell(p, '13.2.70.8', '1', idx) ?? '';
        const vlan = Number(tableCell(p, '13.2.70.8', '2', idx) ?? 0);
        if (!untaggedByPort.has(port)) untaggedByPort.set(port, []);
        untaggedByPort.get(port)!.push(vlan);
      }
      const l2mByPort = new Map<string, string>(); // port → Active (stored '1'/'0')
      for (let i = 0; i < (p.tables.get('13.2.11.50.2')?.length ?? 0); i++) {
        const idx = rowIndexPath(p, '13.2.11.50.2', i);
        l2mByPort.set(tableCell(p, '13.2.11.50.2', '1', idx) ?? '', tableCell(p, '13.2.11.50.2', '2', idx) ?? '');
      }

      const ports = (portRows ?? []).map((r) => {
        const name = r.cells.get('1') ?? '';
        const counters = counterRows?.find((x) => x.cells.get('1') === name);
        return {
          port: name,
          linkActive: r.cells.get('2') === '1',
          connector: r.cells.get('3') || null, // numeric enum index — label mapping not published by the vendor
          macAddress: (r.cells.get('4') ?? '').replace(/^0+$/, '') || null,
          txBytes: counters ? Number(counters.cells.get('2') ?? 0) : null,
          rxBytes: counters ? Number(counters.cells.get('3') ?? 0) : null,
          rxCrcErrors: counters ? Number(counters.cells.get('4') ?? 0) : null,
          lacp: portBundle.get(name) ?? null,
          untaggedVlans: untaggedByPort.get(name) ?? [],
          lanBridgeMember: l2mByPort.has(name) ? l2mByPort.get(name) === '1' : false,
        };
      });

      return {
        success: true,
        details: {
          count: ports.length,
          ports,
          bundles,
          poe: {
            // The LX-6500 is a PoE INPUT device — it reports the type of its own power feed.
            inputType: poeInputType ?? null,
            passthroughConfigured: p.scalars.has('13.2.11.130') ? p.scalars.get('13.2.11.130') : null,
          },
        },
      };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ntpRead: ActionDescriptor<LxActionContext> = {
  id: 'ntp.read',
  label: 'Read NTP settings',
  description: 'Shows the NTP operating state and all configured time servers with their active flag.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const rows = p.tables.get('13.2.14.21.3') ?? [];
    return {
      success: true,
      details: {
        operating: (p.scalars.get('13.2.14.21.1') ?? '0') === '1',
        servers: rows.map((_, i) => {
          const idx = rowIndexPath(p, '13.2.14.21.3', i);
          return { server: tableCell(p, '13.2.14.21.3', '1', idx) ?? '', active: (tableCell(p, '13.2.14.21.3', '2', idx) ?? '0') === '1' };
        }),
      },
    };
  },
};

const snmpRead: ActionDescriptor<LxActionContext> = {
  id: 'snmp.read',
  label: 'Read SNMP settings',
  description: 'Shows the SNMP operating state, traps, port and admitted protocols, plus communities and v3 users. User passwords are redacted.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    const communities = (p.tables.get('13.2.9.27') ?? []).map((_, i) => {
      const idx = rowIndexPath(p, '13.2.9.27', i);
      return { name: tableCell(p, '13.2.9.27', '1', idx) ?? '', securityName: tableCell(p, '13.2.9.27', '3', idx) ?? '', statusIndex: tableCell(p, '13.2.9.27', '8', idx) ?? '' };
    });
    const users = (p.tables.get('13.2.9.32') ?? []).map((_, i) => {
      const idx = rowIndexPath(p, '13.2.9.32', i);
      return {
        username: tableCell(p, '13.2.9.32', '2', idx) ?? '',
        authProtocolIndex: tableCell(p, '13.2.9.32', '5', idx) ?? '',
        authPassword: REDACTED, // never returned — see webapi.ts SENSITIVE handling
        privProtocolIndex: tableCell(p, '13.2.9.32', '8', idx) ?? '',
        privPassword: REDACTED,
      };
    });
    return {
      success: true,
      details: {
        operating: (p.scalars.get('13.2.9.41') ?? '0') === '1',
        sendTraps: (p.scalars.get('13.2.9.1') ?? '0') === '1',
        port: Number(p.scalars.get('13.2.9.21') ?? 161),
        admittedProtocolsBitmask: p.scalars.get('13.2.9.37') ?? null, // bit 0=v1, 1=v2c, 2=v3 (observed)
        allowAdmins: (p.scalars.get('13.2.9.38') ?? '0') === '1',
        communities,
        users,
      },
    };
  },
};

const stpRead: ActionDescriptor<LxActionContext> = {
  id: 'stp.read',
  label: 'Read STP settings',
  description: 'Shows the spanning-tree operating state, bridge priority, protocol version and timers, plus per-port STP data.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const p = await loadConfig(ctx);
    return {
      success: true,
      details: {
        operating: (p.scalars.get('13.2.62.3.1') ?? '0') === '1',
        bridgePriority: Number(p.scalars.get('13.2.62.3.3') ?? 8),
        protocolVersionIndex: p.scalars.get('13.2.62.3.4') ?? null, // numeric enum (observed: 1 = Rapid) — label mapping not published
        forwardDelay: Number(p.scalars.get('13.2.62.3.5') ?? 15),
        helloTime: Number(p.scalars.get('13.2.62.3.6') ?? 2),
        maxAge: Number(p.scalars.get('13.2.62.3.7') ?? 20),
        transmitHoldCount: Number(p.scalars.get('13.2.62.3.8') ?? 6),
        ports: (p.tables.get('13.2.62.3.2') ?? []).map((_, i) => {
          const idx = rowIndexPath(p, '13.2.62.3.2', i);
          return {
            port: tableCell(p, '13.2.62.3.2', '1', idx) ?? '',
            priority: Number(tableCell(p, '13.2.62.3.2', '2', idx) ?? 8),
            edgePort: (tableCell(p, '13.2.62.3.2', '3', idx) ?? '0') === '1',
            pathCostOverride: Number(tableCell(p, '13.2.62.3.2', '4', idx) ?? 0),
          };
        }),
      },
    };
  },
};

const lacpRead: ActionDescriptor<LxActionContext> = {
  id: 'lacp.read',
  label: 'Read LACP settings',
  description: 'Shows configured LACP bundles (priority, distribution policy), per-port LACP advertisement settings and the live bundle status.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const lacpStatus = await c.getStatusTable('13.1.5.44');

      const bundles = (p.tables.get('13.2.62.1') ?? []).map((_, i) => {
        const idx = rowIndexPath(p, '13.2.62.1', i);
        return {
          name: tableCell(p, '13.2.62.1', '1', idx) ?? '',
          operating: (tableCell(p, '13.2.62.1', '2', idx) ?? '0') === '1',
          priority: Number(tableCell(p, '13.2.62.1', '3', idx) ?? 32768),
          distributionPolicyIndex: tableCell(p, '13.2.62.1', '4', idx) ?? '', // numeric enum — pass back unchanged to keep it
        };
      });
      const ports = (p.tables.get('13.2.62.2') ?? []).map((_, i) => {
        const idx = rowIndexPath(p, '13.2.62.2', i);
        return {
          port: tableCell(p, '13.2.62.2', '1', idx) ?? '',
          advertisedRates: tableCell(p, '13.2.62.2', '2', idx) ?? '', // LinkRatesBitSet — raw value (observed "auto"/"0")
          powerSaving: (tableCell(p, '13.2.62.2', '3', idx) ?? '0') === '1',
        };
      });

      return {
        success: true,
        details: {
          bundles,
          ports,
          status: (lacpStatus ?? []).map((r) => ({
            bundle: r.cells.get('1') ?? '',
            state: r.cells.get('2') || 'down',
            speed: r.cells.get('3') || null,
            localPorts: (r.cells.get('10') ?? '').split(',').map((s) => s.trim()).filter(Boolean),
            bundleState: r.cells.get('11') || null, // e.g. "Degraded" when one member is down
          })),
        },
      };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

// --- Write actions (safe, verified by re-read) ------------------------------------------

const systemNameSet: ActionDescriptor<LxActionContext> = {
  id: 'system.name.set',
  label: 'Set device name',
  description: 'Changes the LCOS device name (13.2.1). Verified by re-read.',
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'New device name (max 32 chars)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const name = String(input.name);
    const c = client(ctx);
    try {
      const before = await c.getScalar('13.2.1');
      const tag = await c.setScalar('13.2.1', name);
      if (!isWriteOk(tag)) return { success: false, error: `setScalar 13.2.1 failed with errortag ${tag}` };
      const after = await c.getScalar('13.2.1');
      return { success: true, applied: true, verified: after === name, details: { before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const systemCommentSet: ActionDescriptor<LxActionContext> = {
  id: 'system.comment.set',
  label: 'Set device comment',
  description: 'Sets the free-text device comment (13.2.11.1). Verified by re-read.',
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    // Setting the CURRENT value is accepted as a no-op (per-command errortag
    // 1020, top-level ErrorTag stays 0). Clearing via an empty string is not
    // verified on hardware — keep minLength 1.
    comment: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Free-text comment (max 64 chars)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const comment = String(input.comment);
    const c = client(ctx);
    try {
      const before = await c.getScalar('13.2.11.1');
      const tag = await c.setScalar('13.2.11.1', comment);
      if (!isWriteOk(tag)) return { success: false, error: `setScalar 13.2.11.1 failed with errortag ${tag}` };
      const after = await c.getScalar('13.2.11.1');
      return { success: true, applied: true, verified: (after ?? '') === comment, details: { before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const radioChannelSet: ActionDescriptor<LxActionContext> = {
  id: 'radio.channel.set',
  label: 'Set radio channel',
  description: 'Pins a radio to a fixed channel (0 = auto). Verified by re-read.',
  module: 'WLAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    ifc: { type: 'string', required: true, description: 'Radio interface name (e.g. WLAN-1)' },
    channel: { type: 'number', required: true, min: 0, max: 255, description: 'Channel number; 0 = automatic' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const ifc = String(input.ifc);
    const channel = Number(input.channel);
    const c = client(ctx);
    try {
      // Locate the row index via the config-text parse (explicit indices).
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.20.8', ifc);
      if (rowIndex == null) return { success: false, error: `Radio "${ifc}" not found in table 13.2.20.8` };

      const before = tableCell(p, '13.2.20.8', '8', rowIndex) ?? 'auto';
      const tag = await c.updateTableRow('13.2.20.8', rowIndex, { 8: channel });
      if (!isWriteOk(tag)) return { success: false, error: `updateTableRow 13.2.20.8 failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const after = tableCell(p2, '13.2.20.8', '8', rowIndex) ?? null;
      return { success: true, applied: true, verified: after == null || Number(after) === channel, details: { ifc, before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const radioPowerSet: ActionDescriptor<LxActionContext> = {
  id: 'radio.power.set',
  label: 'Set radio transmit power',
  description: 'Sets automatic or manual EIRP for a radio. Verified by re-read.',
  module: 'WLAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    ifc: { type: 'string', required: true, description: 'Radio interface name (e.g. WLAN-1)' },
    mode: { type: 'string', required: true, enum: ['Automatic', 'Manual'], description: 'Power control mode' },
    eirpDbm: { type: 'number', min: 0, max: 36, description: 'EIRP in dBm (required when mode = Manual)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const ifc = String(input.ifc);
    const mode = String(input.mode);
    const eirp = input.eirpDbm == null ? undefined : Number(input.eirpDbm);
    if (mode === 'Manual' && eirp == null) return { success: false, error: 'eirpDbm is required when mode is Manual' };

    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.20.8', ifc);
      if (rowIndex == null) return { success: false, error: `Radio "${ifc}" not found in table 13.2.20.8` };

      const cells: Record<string, string | number> = { 33: mode };
      if (mode === 'Manual' && eirp != null) cells[34] = eirp;
      const tag = await c.updateTableRow('13.2.20.8', rowIndex, cells);
      if (!isWriteOk(tag)) return { success: false, error: `updateTableRow 13.2.20.8 failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const after = tableCell(p2, '13.2.20.8', '33', rowIndex) ?? null;
      return { success: true, applied: true, verified: after === mode, details: { ifc, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ssidVlanSet: ActionDescriptor<LxActionContext> = {
  id: 'ssid.vlan.set',
  label: 'Set SSID VLAN',
  description: 'Changes the VLAN ID of a WLAN network (0 = untagged/bridge). Verified by re-read.',
  module: 'WLAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    network: { type: 'string', required: true, description: 'Network name (index of table 13.2.20.1)' },
    vlanId: { type: 'number', required: true, min: 0, max: 4094, description: 'VLAN ID; 0 = no VLAN tagging' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const network = String(input.network);
    const vlanId = Number(input.vlanId);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.20.1', network);
      if (rowIndex == null) return { success: false, error: `WLAN network "${network}" not found in table 13.2.20.1` };

      const before = tableCell(p, '13.2.20.1', '200', rowIndex) ?? '0';
      const tag = await c.updateTableRow('13.2.20.1', rowIndex, { 200: vlanId });
      if (!isWriteOk(tag)) return { success: false, error: `updateTableRow 13.2.20.1 failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const after = tableCell(p2, '13.2.20.1', '200', rowIndex) ?? null;
      return { success: true, applied: true, verified: after == null || Number(after) === vlanId, details: { network, before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const wlanNetworkAdd: ActionDescriptor<LxActionContext> = {
  id: 'wlan.network.add',
  label: 'Add WLAN network (SSID)',
  description: 'Adds a new WLAN network with SSID, encryption profile and VLAN. Additive only — never modifies existing networks.',
  module: 'WLAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    ssidName: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'Broadcast SSID name (max 32 chars)' },
    encryptionProfile: { type: 'string', required: true, description: 'Existing encryption profile name (see encryption.profiles.read)' },
    vlanId: { type: 'number', min: 0, max: 4094, description: 'VLAN ID; default 0 = untagged' },
    closedNetwork: { type: 'string', enum: ['Yes', 'No'], description: 'Hide the SSID (closed network); default No' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const ssidName = String(input.ssidName);
    const encryptionProfile = String(input.encryptionProfile);
    const vlanId = input.vlanId == null ? 0 : Number(input.vlanId);
    const closedNetwork = input.closedNetwork == null ? 'No' : String(input.closedNetwork);

    const c = client(ctx);
    try {
      // Validate the encryption profile exists.
      const p = parseLcosConfigText(await c.getConfigText());
      const profiles = p.tables.get('13.2.20.3') ?? [];
      if (!profiles.some((_, i) => tableCell(p, '13.2.20.3', '1', rowIndexPath(p, '13.2.20.3', i)) === encryptionProfile)) {
        return { success: false, error: `Encryption profile "${encryptionProfile}" does not exist on this device` };
      }

      // The network name (row index) is a free-form label — derive an unused one.
      const existing = new Set((p.tables.get('13.2.20.1') ?? []).map((_, i) => tableCell(p, '13.2.20.1', '1', rowIndexPath(p, '13.2.20.1', i))));
      let n = 1;
      while (existing.has(`NETWORK-${n}`)) n++;
      const networkName = `NETWORK-${n}`;

      const tag = await c.addTableRow('13.2.20.1', { 1: networkName, 2: ssidName, 4: closedNetwork, 102: encryptionProfile, 200: vlanId });
      if (!isWriteOk(tag)) return { success: false, error: `addTableRow 13.2.20.1 failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const createdIdx = findRowByIndex(p2, '13.2.20.1', networkName);
      return { success: true, applied: true, verified: createdIdx != null && tableCell(p2, '13.2.20.1', '2', createdIdx) === ssidName, details: { network: networkName } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const wlcAddressSet: ActionDescriptor<LxActionContext> = {
  id: 'wlc.address.set',
  label: 'Set WLC address',
  description: 'Points the AP at a (new) WLAN controller. Use to migrate away from LANCOM WLC — set operating=No afterwards for standalone mode.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    address: { type: 'string', required: true, description: 'WLAN controller IP address or DNS name (0.0.0.0 = none)' },
    port: { type: 'number', min: 1, max: 65535, description: 'CAPWAP port; default keeps the current value' },
    operating: { type: 'string', enum: ['Yes', 'No'], description: 'Enable/disable CAPWAP operation (scalar 13.2.59.2)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const address = String(input.address);
    const port = input.port == null ? undefined : Number(input.port);
    const operating = input.operating == null ? undefined : String(input.operating);

    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rows = p.tables.get('13.2.59.1') ?? [];
      const cells: Record<string, string | number> = { 1: address };
      if (port != null) cells[2] = port;

      let tag: number;
      if (rows.length > 0) {
        const rowIndex = rowIndexPath(p, '13.2.59.1', 0);
        tag = await c.updateTableRow('13.2.59.1', rowIndex, cells);
      } else {
        tag = await c.addTableRow('13.2.59.1', cells);
      }
      if (!isWriteOk(tag)) return { success: false, error: `WLC table update failed with errortag ${tag}` };

      let opTag: number | null = null;
      if (operating != null) {
        opTag = await c.setScalar('13.2.59.2', operating);
        if (!isWriteOk(opTag)) return { success: false, error: `setScalar 13.2.59.2 failed with errortag ${opTag}` };
      }

      const p2 = parseLcosConfigText(await c.getConfigText());
      const after = tableCell(p2, '13.2.59.1', '1', rowIndexPath(p2, '13.2.59.1', 0)) ?? null;
      const opAfter = operating != null ? await c.getScalar('13.2.59.2') : null;
      return { success: true, applied: true, verified: after === address && (operating == null || opAfter === operating), details: { after, operating: opAfter } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const configPersist: ActionDescriptor<LxActionContext> = {
  id: 'config.persist',
  label: 'Persist configuration to flash',
  description: 'Writes the running configuration to flash (makeChangesPermanent) so it survives a reboot. Run AFTER applying changes.',
  module: 'Configuration',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const tag = await c.makePersistent();
      if (!isWriteOk(tag)) return { success: false, error: `setFlashMode failed with errortag ${tag}` };
      return { success: true, applied: true, verified: true, details: { persisted: true } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

// --- IP addressing write actions --------------------------------------------------------------
// These change the AP's OWN management interface (table 13.2.70.6 + parameters
// 13.2.70.4 + 802.1X supplicant 13.2.30.11). A wrong or unreachable result
// locks you out of the web UI, so all three are riskLevel 'dangerous' with
// retryOnDispatchFailure=false — an explicit user choice that is never re-run.
// Verification is best-effort: when the management IP itself changed, the AP is
// no longer reachable at the old address and a failed re-read is EXPECTED (the
// write was accepted by the device) — it is reported as verified:false with a
// note instead of a failure.

/** Best-effort post-write config re-read: retries while the AP may be re-initializing its network stack. */
async function rereadConfigBestEffort(c: LcosWebClient, attempts = 5, delayMs = 2_000): Promise<ParsedLcosConfig | null> {
  for (let i = 0; i < attempts; i++) {
    try {
      return parseLcosConfigText(await c.getConfigText());
    } catch {
      if (i === attempts - 1) return null;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  return null;
}

const ipInterfaceSet: ActionDescriptor<LxActionContext> = {
  id: 'ip.interface.set',
  label: 'Set interface IP addressing (DANGEROUS)',
  description:
    "Changes the AP's OWN management addressing on a LAN interface (table 13.2.70.6) — IPv4/IPv6 address source and static addresses. DANGEROUS: if you change the address of the interface the web UI is reached over, the AP becomes unreachable at its old address afterwards; verify from the NEW address. Source values are numeric enum indices (observed on this platform: v4 2 = static — pass back the value from ip.interfaces.read to keep it). Only provided fields change.",
  module: 'Network',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 90_000, // re-read retries while the network stack re-initializes
  retryOnDispatchFailure: false,
  inputSchema: {
    interface: { type: 'string', required: true, description: 'Interface name (row index; e.g. INTRANET — see ip.interfaces.read)' },
    ipv4SourceIndex: { type: 'number', min: 0, max: 255, description: 'IPv4 address source enum index (observed: 2 = static); pass back the read value to keep it' },
    staticIpv4: { type: 'string', minLength: 7, maxLength: 18, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}(\\/\\d{1,2})?$', description: 'Static IPv4 address in CIDR notation (e.g. 10.25.1.2/16)' },
    ipv6SourceIndex: { type: 'number', min: 0, max: 255, description: 'IPv6 address source enum index (observed: 1 = auto); pass back the read value to keep it' },
    staticIpv6: { type: 'string', minLength: 3, maxLength: 80, description: 'Static IPv6 address in CIDR notation (e.g. 2003:e9::5/64)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const iface = String(input.interface);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.70.6', iface);
      if (rowIndex == null) return { success: false, error: `Interface "${iface}" not found in table 13.2.70.6` };

      const cells: Record<string, string | number> = {};
      if (input.ipv4SourceIndex != null) cells[4] = Number(input.ipv4SourceIndex);
      if (typeof input.staticIpv4 === 'string' && input.staticIpv4.length > 0) cells[6] = String(input.staticIpv4);
      if (input.ipv6SourceIndex != null) cells[5] = Number(input.ipv6SourceIndex);
      if (typeof input.staticIpv6 === 'string' && input.staticIpv6.length > 0) cells[7] = String(input.staticIpv6);
      if (Object.keys(cells).length === 0) return { success: false, error: 'Nothing to change — provide at least one of ipv4SourceIndex/staticIpv4/ipv6SourceIndex/staticIpv6' };

      const before: Record<string, string | null> = {};
      for (const col of Object.keys(cells)) before[col] = tableCell(p, '13.2.70.6', col, rowIndex) ?? null;

      const tag = await c.updateTableRow('13.2.70.6', rowIndex, cells);
      if (!isWriteOk(tag)) return { success: false, error: `updateTableRow 13.2.70.6 failed with errortag ${tag}` };

      // Best-effort verification — a changed management IP makes the AP unreachable at the old address.
      const p2 = await rereadConfigBestEffort(c);
      if (p2 == null) {
        return {
          success: true, applied: true, verified: false,
          details: { interface: iface, before, note: 'Write accepted by the device, but the AP was not reachable for verification — expected when the management address itself changed. Verify from the NEW address.' },
        };
      }
      const idx2 = findRowByIndex(p2, '13.2.70.6', iface);
      const verified = idx2 != null && Object.entries(cells).every(([col, val]) => (tableCell(p2, '13.2.70.6', col, idx2) ?? '') === String(val));
      return { success: true, applied: true, verified, details: { interface: iface, before } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ipParametersSet: ActionDescriptor<LxActionContext> = {
  id: 'ip.parameters.set',
  label: 'Set interface gateway/DNS (DANGEROUS)',
  description:
    "Changes the AP's OWN management routing parameters on a LAN interface (table 13.2.70.4) — IPv4/IPv6 gateways and primary/secondary DNS. DANGEROUS: wrong values can make the AP unreachable; this action is never re-dispatched automatically. Only provided fields change.",
  module: 'Network',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 90_000,
  retryOnDispatchFailure: false,
  inputSchema: {
    interface: { type: 'string', required: true, description: 'Interface name (row index; e.g. INTRANET — see ip.interfaces.read)' },
    ipv4Gateway: { type: 'string', minLength: 7, maxLength: 15, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'IPv4 default gateway' },
    ipv6Gateway: { type: 'string', minLength: 2, maxLength: 39, description: 'IPv6 default gateway (full address)' },
    primaryIpv4Dns: { type: 'string', minLength: 7, maxLength: 15, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Primary IPv4 DNS server' },
    secondaryIpv4Dns: { type: 'string', minLength: 7, maxLength: 15, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Secondary IPv4 DNS server' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const iface = String(input.interface);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      let rowIndex = findRowByIndex(p, '13.2.70.4', iface);

      const cells: Record<string, string | number> = {};
      if (typeof input.ipv4Gateway === 'string' && input.ipv4Gateway.length > 0) cells[2] = String(input.ipv4Gateway);
      if (typeof input.ipv6Gateway === 'string' && input.ipv6Gateway.length > 0) cells[3] = String(input.ipv6Gateway);
      if (typeof input.primaryIpv4Dns === 'string' && input.primaryIpv4Dns.length > 0) cells[4] = String(input.primaryIpv4Dns);
      if (typeof input.secondaryIpv4Dns === 'string' && input.secondaryIpv4Dns.length > 0) cells[5] = String(input.secondaryIpv4Dns);
      if (Object.keys(cells).length === 0) return { success: false, error: 'Nothing to change — provide at least one of ipv4Gateway/ipv6Gateway/primaryIpv4Dns/secondaryIpv4Dns' };

      const before: Record<string, string | null> = {};
      if (rowIndex != null) for (const col of Object.keys(cells)) before[col] = tableCell(p, '13.2.70.4', col, rowIndex) ?? null;

      let tag: number;
      if (rowIndex != null) {
        tag = await c.updateTableRow('13.2.70.4', rowIndex, cells);
      } else {
        // No parameter row yet — create it keyed by the interface name.
        tag = await c.addTableRow('13.2.70.4', { 1: iface, ...cells });
      }
      if (!isWriteOk(tag)) return { success: false, error: `Static-Parameters update failed with errortag ${tag}` };

      const p2 = await rereadConfigBestEffort(c);
      if (p2 == null) {
        return {
          success: true, applied: true, verified: false,
          details: { interface: iface, before, note: 'Write accepted by the device, but the AP was not reachable for verification — expected when routing/DNS changes break reachability. Verify from the network side.' },
        };
      }
      const idx2 = findRowByIndex(p2, '13.2.70.4', iface);
      const verified = idx2 != null && Object.entries(cells).every(([col, val]) => (tableCell(p2, '13.2.70.4', col, idx2) ?? '') === String(val));
      return { success: true, applied: true, verified, details: { interface: iface, before } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ipSupplicantSet: ActionDescriptor<LxActionContext> = {
  id: 'ip.supplicant.set',
  label: 'Set 802.1X LAN supplicant (DANGEROUS)',
  description:
    "Configures the AP's OWN 802.1X client on a LAN interface (table 13.2.30.11) — method, username and password for port-based network authentication. DANGEROUS: wrong credentials can drop the management link; never re-dispatched automatically. The password is write-only — it is never returned by any read action.",
  module: 'Network',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 90_000,
  retryOnDispatchFailure: false,
  inputSchema: {
    interface: { type: 'string', required: true, description: 'Interface name (row index; e.g. INTRANET — see ip.interfaces.read)' },
    methodIndex: { type: 'number', min: 0, max: 255, description: 'Supplicant method enum index (LanSupplicantMethodInpSet); pass back the read value to keep it' },
    username: { type: 'string', minLength: 1, maxLength: 64, description: '802.1X username' },
    password: { type: 'string', minLength: 1, maxLength: 128, description: '802.1X password (write-only — never returned)' },
    remove: { type: 'boolean', default: false, description: 'true = remove the supplicant configuration from this interface' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const iface = String(input.interface);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.30.11', iface);

      let tag: number;
      if (input.remove) {
        if (rowIndex == null) return { success: false, error: `Interface "${iface}" has no 802.1X supplicant configuration` };
        tag = await c.delTableRow('13.2.30.11', rowIndex);
      } else {
        const cells: Record<string, string | number> = {};
        if (input.methodIndex != null) cells[2] = Number(input.methodIndex);
        if (typeof input.username === 'string' && input.username.length > 0) cells[3] = String(input.username);
        if (typeof input.password === 'string' && input.password.length > 0) cells[4] = String(input.password);
        if (Object.keys(cells).length === 0) return { success: false, error: 'Nothing to change — provide at least one of methodIndex/username/password (or remove=true)' };
        if (rowIndex != null) {
          tag = await c.updateTableRow('13.2.30.11', rowIndex, cells);
        } else {
          // New row needs a usable method — the vendor default is not published.
          if (input.methodIndex == null) return { success: false, error: 'methodIndex is required when creating a new supplicant entry (no existing value to keep)' };
          tag = await c.addTableRow('13.2.30.11', { 1: iface, ...cells });
        }
      }
      if (!isWriteOk(tag)) return { success: false, error: `LAN-Supplicant update failed with errortag ${tag}` };

      const p2 = await rereadConfigBestEffort(c);
      if (p2 == null) {
        return {
          success: true, applied: true, verified: false,
          details: { interface: iface, removed: !!input.remove, note: 'Write accepted by the device, but the AP was not reachable for verification — expected when 802.1X changes break the management link.' },
        };
      }
      const idx2 = findRowByIndex(p2, '13.2.30.11', iface);
      let verified: boolean;
      if (input.remove) {
        verified = idx2 == null;
      } else {
        // Verify only the non-secret cells — the password is never compared/returned.
        const checkable: Record<string, string> = {};
        if (input.methodIndex != null) checkable[2] = String(input.methodIndex);
        if (typeof input.username === 'string' && input.username.length > 0) checkable[3] = String(input.username);
        verified = idx2 != null && Object.entries(checkable).every(([col, val]) => (tableCell(p2, '13.2.30.11', col, idx2) ?? '') === val);
      }
      return { success: true, applied: true, verified, details: { interface: iface, removed: !!input.remove } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

// --- Switch / protocol write actions --------------------------------------------------------
// Same safety policy as the WLAN writes: single-cell updates, verified by re-read.
// Enum/NoYes cells store NUMERIC indices on this platform (verified live) — inputs
// are therefore 0/1 flags or raw enum indices that get passed back unchanged.

/** Finds the row-index path of a table row matching ALL given index-column values (dual-index tables). */
function findRowByIndexCells(parsed: ParsedLcosConfig, tableOid: string, cells: Record<string, string>): string | null {
  const rows = parsed.tables.get(tableOid);
  if (!rows) return null;
  for (let i = 0; i < rows.length; i++) {
    const idx = rowIndexPath(parsed, tableOid, i);
    let match = true;
    for (const [col, val] of Object.entries(cells)) {
      if ((tableCell(parsed, tableOid, col, idx) ?? '') !== val) { match = false; break; }
    }
    if (match) return idx;
  }
  return null;
}

/** Validates a port name against the live status Ports table (13.1.5.99). */
async function assertPortExists(c: LcosWebClient, port: string): Promise<string | null> {
  const rows = await c.getStatusTable('13.1.5.99');
  if (!rows) return 'Could not read the port status table (13.1.5.99) — check web credentials';
  if (!rows.some((r) => r.cells.get('1') === port)) {
    return `Port "${port}" does not exist on this device (known: ${rows.map((r) => r.cells.get('1')).join(', ') || 'none'})`;
  }
  return null;
}

const ntpServerAdd: ActionDescriptor<LxActionContext> = {
  id: 'ntp.server.add',
  label: 'Add NTP server',
  description: 'Adds a time server to the NTP configuration (table 13.2.14.21.3). Additive only — never modifies existing servers.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    server: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'NTP server IP address or DNS name' },
    active: { type: 'boolean', default: false, description: 'Mark the server active immediately (default false)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const server = String(input.server);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      if ((p.tables.get('13.2.14.21.3') ?? []).some((_, i) => tableCell(p, '13.2.14.21.3', '1', rowIndexPath(p, '13.2.14.21.3', i)) === server)) {
        return { success: false, error: `NTP server "${server}" already exists` };
      }
      const tag = await c.addTableRow('13.2.14.21.3', { 1: server, 2: input.active ? '1' : '0' });
      if (!isWriteOk(tag)) return { success: false, error: `addTableRow 13.2.14.21.3 failed with errortag ${tag}` };
      const p2 = parseLcosConfigText(await c.getConfigText());
      const idx = findRowByIndex(p2, '13.2.14.21.3', server);
      return { success: true, applied: true, verified: idx != null, details: { server } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ntpServerRemove: ActionDescriptor<LxActionContext> = {
  id: 'ntp.server.remove',
  label: 'Remove NTP server',
  description: 'Removes a time server from the NTP configuration (table 13.2.14.21.3).',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    server: { type: 'string', required: true, minLength: 1, description: 'NTP server name/IP to remove (see ntp.read)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const server = String(input.server);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.14.21.3', server);
      if (rowIndex == null) return { success: false, error: `NTP server "${server}" not found` };
      const tag = await c.delTableRow('13.2.14.21.3', rowIndex);
      if (!isWriteOk(tag)) return { success: false, error: `delTableRow 13.2.14.21.3 failed with errortag ${tag}` };
      const p2 = parseLcosConfigText(await c.getConfigText());
      const stillThere = findRowByIndex(p2, '13.2.14.21.3', server) != null;
      return { success: true, applied: true, verified: !stillThere, details: { server } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ntpServerSetActive: ActionDescriptor<LxActionContext> = {
  id: 'ntp.server.set-active',
  label: 'Set NTP server active flag',
  description: 'Enables or disables an existing time server (table 13.2.14.21.3, Active column).',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    server: { type: 'string', required: true, minLength: 1, description: 'NTP server name/IP (see ntp.read)' },
    active: { type: 'boolean', required: true, description: 'Active = true or false' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const server = String(input.server);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.14.21.3', server);
      if (rowIndex == null) return { success: false, error: `NTP server "${server}" not found` };
      const before = tableCell(p, '13.2.14.21.3', '2', rowIndex) ?? '0';
      const tag = await c.updateTableRow('13.2.14.21.3', rowIndex, { 2: input.active ? '1' : '0' });
      if (!isWriteOk(tag)) return { success: false, error: `updateTableRow 13.2.14.21.3 failed with errortag ${tag}` };
      const p2 = parseLcosConfigText(await c.getConfigText());
      const after = tableCell(p2, '13.2.14.21.3', '2', rowIndex) ?? null;
      return { success: true, applied: true, verified: after === (input.active ? '1' : '0'), details: { server, before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const ntpOperatingSet: ActionDescriptor<LxActionContext> = {
  id: 'ntp.operating.set',
  label: 'Enable/disable NTP',
  description: 'Toggles the global NTP operating state (scalar 13.2.14.21.1).',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    operating: { type: 'boolean', required: true, description: 'true = NTP enabled, false = disabled' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const before = await c.getScalar('13.2.14.21.1');
      const tag = await c.setScalar('13.2.14.21.1', input.operating ? '1' : '0');
      if (!isWriteOk(tag)) return { success: false, error: `setScalar 13.2.14.21.1 failed with errortag ${tag}` };
      const after = await c.getScalar('13.2.14.21.1');
      return { success: true, applied: true, verified: (after ?? '0') === (input.operating ? '1' : '0'), details: { before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const snmpSettingsSet: ActionDescriptor<LxActionContext> = {
  id: 'snmp.settings.set',
  label: 'Set SNMP settings',
  description: 'Updates the global SNMP scalars — operating state, trap sending, UDP port and admitted-protocols bitmask (bit 0=v1, bit 1=v2c, bit 2=v3). Only provided fields change.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    operating: { type: 'boolean', description: 'Enable/disable the SNMP agent (scalar 13.2.9.41)' },
    sendTraps: { type: 'boolean', description: 'Send traps (scalar 13.2.9.1)' },
    port: { type: 'number', min: 1, max: 65535, description: 'SNMP UDP port (scalar 13.2.9.21)' },
    admittedProtocolsBitmask: { type: 'number', min: 0, max: 7, description: 'Admitted protocol versions bitmask (scalar 13.2.9.37); e.g. 5 = v1+v2c' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const before: Record<string, string | null> = {};
      const after: Record<string, string | null> = {};
      const writes: Array<[string, string]> = [];
      if (input.operating != null) writes.push(['13.2.9.41', input.operating ? '1' : '0']);
      if (input.sendTraps != null) writes.push(['13.2.9.1', input.sendTraps ? '1' : '0']);
      if (input.port != null) writes.push(['13.2.9.21', String(Number(input.port))]);
      if (input.admittedProtocolsBitmask != null) writes.push(['13.2.9.37', String(Number(input.admittedProtocolsBitmask))]);
      if (writes.length === 0) return { success: false, error: 'Nothing to change — provide at least one of operating/sendTraps/port/admittedProtocolsBitmask' };

      for (const [oid] of writes) before[oid] = await c.getScalar(oid);
      for (const [oid, val] of writes) {
        const tag = await c.setScalar(oid, val);
        if (!isWriteOk(tag)) return { success: false, error: `setScalar ${oid} failed with errortag ${tag}` };
      }
      for (const [oid] of writes) after[oid] = await c.getScalar(oid);
      const verified = writes.every(([oid, val]) => (after[oid] ?? '') === val);
      return { success: true, applied: true, verified, details: { before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const snmpCommunityAdd: ActionDescriptor<LxActionContext> = {
  id: 'snmp.community.add',
  label: 'Add SNMP community',
  description: 'Adds an SNMPv1/v2c community (table 13.2.9.27). Additive only.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'Community string (row index)' },
    securityName: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'Security name; default = same as the community' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const name = String(input.name);
    const securityName = typeof input.securityName === 'string' && input.securityName.length > 0 ? String(input.securityName) : name;
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      if ((p.tables.get('13.2.9.27') ?? []).some((_, i) => tableCell(p, '13.2.9.27', '1', rowIndexPath(p, '13.2.9.27', i)) === name)) {
        return { success: false, error: `SNMP community "${name}" already exists` };
      }
      const tag = await c.addTableRow('13.2.9.27', { 1: name, 3: securityName });
      if (!isWriteOk(tag)) return { success: false, error: `addTableRow 13.2.9.27 failed with errortag ${tag}` };
      const p2 = parseLcosConfigText(await c.getConfigText());
      const idx = findRowByIndex(p2, '13.2.9.27', name);
      return { success: true, applied: true, verified: idx != null && tableCell(p2, '13.2.9.27', '3', idx) === securityName, details: { name } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const stpSettingsSet: ActionDescriptor<LxActionContext> = {
  id: 'stp.settings.set',
  label: 'Set STP settings',
  description: 'Updates the spanning-tree scalars — operating state, bridge priority (multiple of 4096), protocol version index and timers. Only provided fields change.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    operating: { type: 'boolean', description: 'Enable/disable STP (scalar 13.2.62.3.1)' },
    bridgePriority: { type: 'number', min: 0, max: 65535, description: 'Bridge priority — multiples of 4096 (default 8 on this platform)' },
    protocolVersionIndex: { type: 'number', min: 0, max: 255, description: 'Protocol version enum index; pass back the value from stp.read to keep it (observed: 1 = Rapid)' },
    forwardDelay: { type: 'number', min: 4, max: 30, description: 'Forward delay in seconds' },
    helloTime: { type: 'number', min: 1, max: 10, description: 'Hello time in seconds' },
    maxAge: { type: 'number', min: 6, max: 40, description: 'Max age in seconds' },
    transmitHoldCount: { type: 'number', min: 1, max: 6, description: 'Transmit hold count' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const before: Record<string, string | null> = {};
      const after: Record<string, string | null> = {};
      const writes: Array<[string, string]> = [];
      if (input.operating != null) writes.push(['13.2.62.3.1', input.operating ? '1' : '0']);
      if (input.bridgePriority != null) writes.push(['13.2.62.3.3', String(Number(input.bridgePriority))]);
      if (input.protocolVersionIndex != null) writes.push(['13.2.62.3.4', String(Number(input.protocolVersionIndex))]);
      if (input.forwardDelay != null) writes.push(['13.2.62.3.5', String(Number(input.forwardDelay))]);
      if (input.helloTime != null) writes.push(['13.2.62.3.6', String(Number(input.helloTime))]);
      if (input.maxAge != null) writes.push(['13.2.62.3.7', String(Number(input.maxAge))]);
      if (input.transmitHoldCount != null) writes.push(['13.2.62.3.8', String(Number(input.transmitHoldCount))]);
      if (writes.length === 0) return { success: false, error: 'Nothing to change — provide at least one STP field' };

      for (const [oid] of writes) before[oid] = await c.getScalar(oid);
      for (const [oid, val] of writes) {
        const tag = await c.setScalar(oid, val);
        if (!isWriteOk(tag)) return { success: false, error: `setScalar ${oid} failed with errortag ${tag}` };
      }
      for (const [oid] of writes) after[oid] = await c.getScalar(oid);
      const verified = writes.every(([oid, val]) => (after[oid] ?? '') === val);
      return { success: true, applied: true, verified, details: { before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const stpPortSet: ActionDescriptor<LxActionContext> = {
  id: 'stp.port.set',
  label: 'Set STP port data',
  description: 'Updates per-port STP settings (table 13.2.62.3.2) — priority, edge-port flag and path-cost override for one physical port.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    port: { type: 'string', required: true, description: 'Physical port name (e.g. ETH1 — see ports.read)' },
    priority: { type: 'number', min: 0, max: 255, description: 'Port STP priority' },
    edgePort: { type: 'boolean', description: 'Edge-port (portfast) flag' },
    pathCostOverride: { type: 'number', min: 0, max: 2147483647, description: 'Path cost override; 0 = automatic' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const port = String(input.port);
    const c = client(ctx);
    try {
      const badPort = await assertPortExists(c, port);
      if (badPort) return { success: false, error: badPort };

      const p = parseLcosConfigText(await c.getConfigText());
      let rowIndex = findRowByIndex(p, '13.2.62.3.2', port);
      const cells: Record<string, string | number> = {};
      if (input.priority != null) cells[2] = Number(input.priority);
      if (input.edgePort != null) cells[3] = input.edgePort ? '1' : '0';
      if (input.pathCostOverride != null) cells[4] = Number(input.pathCostOverride);
      if (Object.keys(cells).length === 0) return { success: false, error: 'Nothing to change — provide at least one of priority/edgePort/pathCostOverride' };

      let tag: number;
      if (rowIndex != null) {
        tag = await c.updateTableRow('13.2.62.3.2', rowIndex, cells);
      } else {
        // Port has no STP row yet — create it with the port as index.
        tag = await c.addTableRow('13.2.62.3.2', { 1: port, ...cells });
      }
      if (!isWriteOk(tag)) return { success: false, error: `STP port update failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const idx2 = findRowByIndex(p2, '13.2.62.3.2', port);
      const verified = idx2 != null && Object.entries(cells).every(([col, val]) => (tableCell(p2, '13.2.62.3.2', col, idx2) ?? '') === String(val));
      return { success: true, applied: true, verified, details: { port } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const lacpBundleSet: ActionDescriptor<LxActionContext> = {
  id: 'lacp.bundle.set',
  label: 'Set LACP bundle settings',
  description: 'Updates an existing LACP bundle (table 13.2.62.1) — operating state, priority and distribution-policy index. Port membership is managed by the LAN-bridge (L2M) table — see l2m.port.set.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    bundle: { type: 'string', required: true, description: 'Bundle name (row index; e.g. BUNDLE-0 — see lacp.read)' },
    operating: { type: 'boolean', description: 'Enable/disable the bundle' },
    priority: { type: 'number', min: 1, max: 65535, description: 'LACP system priority (default 32768)' },
    distributionPolicyIndex: { type: 'number', min: 0, max: 255, description: 'Distribution policy enum index; pass back the value from lacp.read to keep it' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const bundle = String(input.bundle);
    const c = client(ctx);
    try {
      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.62.1', bundle);
      if (rowIndex == null) return { success: false, error: `LACP bundle "${bundle}" not found` };

      const cells: Record<string, string | number> = {};
      if (input.operating != null) cells[2] = input.operating ? '1' : '0';
      if (input.priority != null) cells[3] = Number(input.priority);
      if (input.distributionPolicyIndex != null) cells[4] = Number(input.distributionPolicyIndex);
      if (Object.keys(cells).length === 0) return { success: false, error: 'Nothing to change — provide at least one of operating/priority/distributionPolicyIndex' };

      const tag = await c.updateTableRow('13.2.62.1', rowIndex, cells);
      if (!isWriteOk(tag)) return { success: false, error: `updateTableRow 13.2.62.1 failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const idx2 = findRowByIndex(p2, '13.2.62.1', bundle);
      const verified = idx2 != null && Object.entries(cells).every(([col, val]) => (tableCell(p2, '13.2.62.1', col, idx2) ?? '') === String(val));
      return { success: true, applied: true, verified, details: { bundle } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const lacpPortSet: ActionDescriptor<LxActionContext> = {
  id: 'lacp.port.set',
  label: 'Set LACP port advertisement',
  description: 'Updates per-port LACP settings (table 13.2.62.2) — advertised link rates and power-saving for one physical port.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    port: { type: 'string', required: true, description: 'Physical port name (e.g. ETH1 — see ports.read)' },
    advertisedRates: { type: 'string', minLength: 1, maxLength: 32, description: 'Advertised link rates (LinkRatesBitSet); pass back the value from lacp.read to keep it' },
    powerSaving: { type: 'boolean', description: 'Enable/disable LACP power saving on this port' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const port = String(input.port);
    const c = client(ctx);
    try {
      const badPort = await assertPortExists(c, port);
      if (badPort) return { success: false, error: badPort };

      const p = parseLcosConfigText(await c.getConfigText());
      let rowIndex = findRowByIndex(p, '13.2.62.2', port);
      const cells: Record<string, string | number> = {};
      if (input.advertisedRates != null) cells[2] = String(input.advertisedRates);
      if (input.powerSaving != null) cells[3] = input.powerSaving ? '1' : '0';
      if (Object.keys(cells).length === 0) return { success: false, error: 'Nothing to change — provide at least one of advertisedRates/powerSaving' };

      let tag: number;
      if (rowIndex != null) {
        tag = await c.updateTableRow('13.2.62.2', rowIndex, cells);
      } else {
        tag = await c.addTableRow('13.2.62.2', { 1: port, ...cells });
      }
      if (!isWriteOk(tag)) return { success: false, error: `LACP port update failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const idx2 = findRowByIndex(p2, '13.2.62.2', port);
      const verified = idx2 != null && Object.entries(cells).every(([col, val]) => (tableCell(p2, '13.2.62.2', col, idx2) ?? '') === String(val));
      return { success: true, applied: true, verified, details: { port } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const vlanUntaggedSet: ActionDescriptor<LxActionContext> = {
  id: 'vlan.untagged.set',
  label: 'Add/remove untagged VLAN on port',
  description: 'Manages the Untagged-VLAN table (13.2.70.8, dual-indexed by Port + VLAN) — assigns or removes an untagged VLAN on a physical port.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    port: { type: 'string', required: true, description: 'Physical port name (e.g. ETH1 — see ports.read)' },
    vlanId: { type: 'number', required: true, min: 1, max: 4094, description: 'VLAN ID to assign untagged on the port' },
    remove: { type: 'boolean', default: false, description: 'true = remove the assignment instead of adding it' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const port = String(input.port);
    const vlanId = Number(input.vlanId);
    const c = client(ctx);
    try {
      const badPort = await assertPortExists(c, port);
      if (badPort) return { success: false, error: badPort };

      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndexCells(p, '13.2.70.8', { 1: port, 2: String(vlanId) });

      let tag: number;
      if (input.remove) {
        if (rowIndex == null) return { success: false, error: `Port ${port} has no untagged VLAN ${vlanId}` };
        // Dual-index row — address it with BOTH index cells explicitly.
        tag = await c.delTableRow('13.2.70.8', rowIndex, { 1: port, 2: String(vlanId) });
      } else {
        if (rowIndex != null) return { success: false, error: `Port ${port} already has untagged VLAN ${vlanId}` };
        tag = await c.addTableRow('13.2.70.8', { 1: port, 2: vlanId });
      }
      if (!isWriteOk(tag)) return { success: false, error: `Untagged-VLAN update failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const stillThere = findRowByIndexCells(p2, '13.2.70.8', { 1: port, 2: String(vlanId) }) != null;
      return { success: true, applied: true, verified: input.remove ? !stillThere : stillThere, details: { port, vlanId, removed: !!input.remove } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const l2mPortSet: ActionDescriptor<LxActionContext> = {
  id: 'l2m.port.set',
  label: 'Add/remove port to LAN bridge (L2M)',
  description:
    'Manages the Layer-2-mesh interface table (13.2.11.50.2) — the ports that make up the device\'s LAN bridge (on this AP: BUNDLE-0 / br-lan). Removing a port from the bridge takes it out of LACP and the default VLAN — use with care.',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    port: { type: 'string', required: true, description: 'Physical port name (e.g. ETH2 — see ports.read)' },
    remove: { type: 'boolean', default: false, description: 'true = remove the port from the LAN bridge' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const port = String(input.port);
    const c = client(ctx);
    try {
      const badPort = await assertPortExists(c, port);
      if (badPort) return { success: false, error: badPort };

      const p = parseLcosConfigText(await c.getConfigText());
      const rowIndex = findRowByIndex(p, '13.2.11.50.2', port);

      let tag: number;
      if (input.remove) {
        if (rowIndex == null) return { success: false, error: `Port ${port} is not a LAN-bridge member` };
        tag = await c.delTableRow('13.2.11.50.2', rowIndex);
      } else {
        if (rowIndex != null) {
          // Already present — make sure it is active.
          const active = tableCell(p, '13.2.11.50.2', '2', rowIndex) ?? '0';
          if (active === '1') return { success: true, applied: false, verified: true, details: { port, note: 'Port is already an active LAN-bridge member' } };
          tag = await c.updateTableRow('13.2.11.50.2', rowIndex, { 2: '1' });
        } else {
          tag = await c.addTableRow('13.2.11.50.2', { 1: port, 2: '1' });
        }
      }
      if (!isWriteOk(tag)) return { success: false, error: `L2M update failed with errortag ${tag}` };

      const p2 = parseLcosConfigText(await c.getConfigText());
      const idx2 = findRowByIndex(p2, '13.2.11.50.2', port);
      const verified = input.remove ? idx2 == null : idx2 != null && (tableCell(p2, '13.2.11.50.2', '2', idx2) ?? '') === '1';
      return { success: true, applied: true, verified, details: { port, removed: !!input.remove } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

const poePassthroughSet: ActionDescriptor<LxActionContext> = {
  id: 'poe.passthrough.set',
  label: 'Set PoE passthrough',
  description: 'Sets the PoE passthrough scalar (13.2.11.130) — forwards received PoE power to a connected device. The LX-6500 is a PoE INPUT device; this AP reports its input type via ports.read (poe.inputType).',
  module: 'Network',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    enabled: { type: 'boolean', required: true, description: 'true = passthrough on, false = off' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    const c = client(ctx);
    try {
      const before = await c.getScalar('13.2.11.130');
      if (before == null) return { success: false, error: 'The PoE passthrough OID (13.2.11.130) is not available on this device — it may lack the hardware feature' };
      const tag = await c.setScalar('13.2.11.130', input.enabled ? '1' : '0');
      if (!isWriteOk(tag)) return { success: false, error: `setScalar 13.2.11.130 failed with errortag ${tag}` };
      const after = await c.getScalar('13.2.11.130');
      return { success: true, applied: true, verified: (after ?? '0') === (input.enabled ? '1' : '0'), details: { before, after } };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

// --- Configuration backup / restore ---------------------------------------------------------
// The LCOS-LX web API has no separate "backup file" endpoint — the running
// configuration IS a text document (GetConfig, ~32 KB). A backup is that text
// stored in UNM's central file repository; a restore pushes it back with
// SetConfig (the same call the vendor UI's config import performs).

const MAX_CONFIG_BYTES = 4 * 1024 * 1024; // LCOS configs are tens of KB — bound the payload anyway.

/** Decodes a base64 file payload from plan input (same contract as SwOS/TrueNAS restore actions). */
function decodeFilePayload(input: Record<string, unknown>): { data: Buffer; fileName: string } | { error: string } {
  const b64 = input['fileBase64'];
  if (typeof b64 !== 'string' || b64.length === 0) return { error: 'fileBase64 is required — the configuration backup as base64' };
  let data: Buffer;
  try {
    data = Buffer.from(b64, 'base64');
  } catch (e) {
    return { error: `Invalid base64 in fileBase64: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (data.length === 0) return { error: 'fileBase64 decoded to an empty file' };
  if (data.length > MAX_CONFIG_BYTES) return { error: `File is ${(data.length / 1024).toFixed(0)} KB — exceeds the ${MAX_CONFIG_BYTES / 1024} KB limit for LCOS configs` };
  const fileName = typeof input['fileName'] === 'string' && (input.fileName as string).length > 0 ? (input.fileName as string) : 'config-backup';
  return { data, fileName };
}

const configBackupDownload: ActionDescriptor<LxActionContext> = {
  id: 'config.backup.download',
  label: 'Download configuration backup',
  description:
    "Fetches the AP's complete running configuration (GetConfig — the same LCOS text document the vendor web UI exports) and stores it in UNM's central file repository, downloadable/archivable from the Files page. Named with the shared convention (<device>__config-backup-<UTC-ts>.cfg). Read-only on the device; use as a rollback point before risky changes — reference it later via details.repoFileId.",
  module: 'Configuration',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {},
  execute: async (ctx: LxActionContext): Promise<ActionResult> => {
    const c = client(ctx);
    let text: string;
    try {
      text = await c.getConfigText();
    } finally {
      await c.destroy().catch(() => undefined);
    }

    // Store the backup in UNM's central file repository so it is downloadable /
    // archivable from the Files page — no base64 blobs buried in step results.
    const fileName = configBackupFileName({ device: ctx.deviceName, host: ctx.host, ext: 'cfg' });
    let repoFileId: string | null = null;
    try {
      const entry = await fileRepo().upload(Buffer.from(text, 'utf8'), { name: fileName, category: 'config-backup' }, 120_000);
      repoFileId = entry.id;
      void fileRepo().recordUse(entry.id, { deviceId: ctx.deviceId ?? undefined, note: `config backup of ${ctx.host} (GetConfig)` }).catch(() => undefined);
    } catch (e) {
      // The repo is a convenience — a failed store must not fail the backup itself.
      return {
        success: true,
        verified: true,
        details: {
          sizeBytes: Buffer.byteLength(text, 'utf8'),
          fileName,
          warning: `Backup fetched but could NOT be stored in the UNM file repository: ${e instanceof Error ? e.message : String(e)}`,
          // Fallback so a restore can still reference the bytes (legacy contract).
          backupBase64: Buffer.from(text, 'utf8').toString('base64'),
        },
      };
    }

    return {
      success: true,
      verified: true,
      details: {
        sizeBytes: Buffer.byteLength(text, 'utf8'),
        fileName,
        // Reference the stored backup by repo id — restore it with config.restore {repoFileId}.
        repoFileId,
      },
    };
  },
};

const configRestore: ActionDescriptor<LxActionContext> = {
  id: 'config.restore',
  label: 'Restore configuration from backup file',
  description:
    "DANGEROUS — replaces the AP's ENTIRE running configuration with the given LCOS text document (ubus SetConfig, exactly what the vendor web UI's config import does). Every setting not present in the file reverts to defaults; WLAN clients disconnect while the radio stack re-initializes. Pair with config.backup.download as a rollback point first. Source: a UNM file-repo id in `repoFileId` (preferred — e.g. ${steps[N].result.details.repoFileId} from an earlier backup step) or raw base64 in `fileBase64`. The AP stays reachable over the web UI afterwards; verification re-reads the device name.",
  module: 'Configuration',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000, // SetConfig of a ~32 KB document + re-read; radio stack re-init is async on the AP
  // Flapping guard — a failed restore must never be re-dispatched (it would
  // overwrite the running config again). The socket drop after SetConfig is expected.
  retryOnDispatchFailure: false,
  inputSchema: {
    repoFileId: { type: 'string', required: false, minLength: 1, description: 'UNM file-repo id of a backup (e.g. from config.backup.download details.repoFileId) — preferred over fileBase64' },
    fileBase64: { type: 'string', required: false, minLength: 8, description: 'The LCOS configuration text as base64 (legacy path; use repoFileId when the file is in the UNM repository)' },
    fileName: { type: 'string', required: false, maxLength: 200, description: 'Original file name (informational only)' },
    persist: { type: 'boolean', required: false, default: true, description: 'Also write the restored config to flash so it survives a reboot (default true; SetConfig with noflash=0 already persists — kept for explicitness)' },
  },
  execute: async (ctx: LxActionContext, input): Promise<ActionResult> => {
    // Preferred source: a backup already in UNM's central file repository.
    const repoFileId = typeof input.repoFileId === 'string' && input.repoFileId.length > 0 ? input.repoFileId : null;
    let payload: { data: Buffer; fileName: string };
    if (repoFileId) {
      try {
        const meta = await fileRepo().getMeta(repoFileId);
        if (!meta) return { success: false, error: `Unknown file-repo id ${repoFileId}` };
        payload = { data: await fileRepo().get(repoFileId), fileName: (typeof input.fileName === 'string' && input.fileName.length > 0 ? input.fileName : meta.name) as string };
      } catch (e) {
        return { success: false, error: `Could not fetch repo file ${repoFileId}: ${e instanceof Error ? e.message : String(e)}` };
      }
    } else {
      const decoded = decodeFilePayload(input);
      if ('error' in decoded) return { success: false, error: decoded.error };
      payload = decoded;
    }

    // Sanity-check the document before pushing it — a truncated or non-LCOS file
    // would leave the AP with an unusable config.
    const text = payload.data.toString('utf8');
    if (!/^\s*13\.2\.\d/m.test(text)) {
      return { success: false, error: 'The backup does not look like an LCOS configuration document (no 13.2.* OIDs found) — refusing to restore' };
    }

    const c = client(ctx);
    try {
      // Capture the current name for post-restore verification + reporting.
      const beforeName = await c.getScalar('13.2.1');
      try {
        await c.setConfigText(text, false);
      } catch (e) {
        return { success: false, error: `SetConfig failed: ${e instanceof Error ? e.message : String(e)} — the AP's running config was NOT replaced` };
      }

      // Verification: re-read the device name and compare it with the one the
      // restored document declares. The radio stack may still be re-initializing
      // on the AP; a transport blip here must not be reported as a failed restore
      // (the SetConfig itself succeeded).
      const expectedName = (/^\s*13\.2\.1\s*=\s*(.+)$/m.exec(text)?.[1] ?? '').trim();
      let afterName: string | null = null;
      try {
        afterName = await c.getScalar('13.2.1');
      } catch { /* AP briefly unreachable while re-initializing — expected */ }

      if (repoFileId) void fileRepo().recordUse(repoFileId, { deviceId: ctx.deviceId ?? undefined, note: `restored on ${ctx.host} (SetConfig)` }).catch(() => undefined);

      return {
        success: true,
        applied: true,
        verified: afterName != null && (expectedName === '' || afterName === expectedName),
        details: {
          source: repoFileId ?? 'fileBase64',
          fileName: payload.fileName,
          sizeBytes: payload.data.length,
          deviceNameBefore: beforeName,
          deviceNameAfter: afterName,
          note: afterName == null ? 'SetConfig succeeded but the AP was not reachable for verification (radio stack re-initializing) — check it shortly.' : undefined,
        },
      };
    } finally {
      await c.destroy().catch(() => undefined);
    }
  },
};

// --- Registry -----------------------------------------------------------------------------

export const registry = createRegistry<LxActionContext>([
  configRead,
  wlanNetworksRead,
  radiosRead,
  encryptionProfilesRead,
  ipInterfacesRead,
  wlcRead,
  portsRead,
  ntpRead,
  snmpRead,
  stpRead,
  lacpRead,
  systemNameSet,
  systemCommentSet,
  radioChannelSet,
  radioPowerSet,
  ssidVlanSet,
  wlanNetworkAdd,
  wlcAddressSet,
  ipInterfaceSet,
  ipParametersSet,
  ipSupplicantSet,
  ntpServerAdd,
  ntpServerRemove,
  ntpServerSetActive,
  ntpOperatingSet,
  snmpSettingsSet,
  snmpCommunityAdd,
  stpSettingsSet,
  stpPortSet,
  lacpBundleSet,
  lacpPortSet,
  vlanUntaggedSet,
  l2mPortSet,
  poePassthroughSet,
  configPersist,
  configBackupDownload,
  configRestore,
]);
