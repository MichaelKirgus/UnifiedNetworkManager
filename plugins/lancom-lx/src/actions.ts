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
import { isWriteOk, LcosWebClient, parseLcosConfigText, redactConfig, tableCell, type ParsedLcosConfig } from './webapi';

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
    const interfaces = rows.map((_, i) => {
      const idx = rowIndexPath(p, '13.2.70.6', i);
      return {
        name: tableCell(p, '13.2.70.6', '1', idx) ?? '',
        ifname: tableCell(p, '13.2.70.6', '2', idx) || '—',
        vlanId: (tableCell(p, '13.2.70.6', '3', idx) === '0' ? null : tableCell(p, '13.2.70.6', '3', idx)) ?? null,
        ipv4Source: tableCell(p, '13.2.70.6', '4', idx) || 'DHCP',
        staticIpv4: tableCell(p, '13.2.70.6', '6', idx) || null,
        comment: tableCell(p, '13.2.70.6', '9', idx) || null,
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
  systemNameSet,
  systemCommentSet,
  radioChannelSet,
  radioPowerSet,
  ssidVlanSet,
  wlanNetworkAdd,
  wlcAddressSet,
  configPersist,
  configBackupDownload,
  configRestore,
]);
