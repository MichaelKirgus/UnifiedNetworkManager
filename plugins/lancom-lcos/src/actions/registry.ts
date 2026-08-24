/**
 * The LANCOM LCOS router action registry — single source of truth for everything
 * this plugin can do. Serves three entry points (same contract as OPNsense/SwOS):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /plan     → buildPlan() fans out single-device actions per device
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * Write semantics: every SNMP-SET action follows read → set → re-read-verify.
 * The web-UI backup/restore actions use the optional `web` credential slot
 * (`usernamePassword`) under ctx.credentials.slots.web over HTTP(S).
 */

import http from 'http';
import https from 'https';
import { snmpGet, snmpSet, snmpWalk } from '@unm/snmp-client';
import { SETUP } from '../lcosOids';
import { ActionContext, ActionDescriptor, ActionResult, InputSchema, RiskLevel } from './types';

// --- Small helpers --------------------------------------------------------------------

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/**
 * Encodes a text value as an LCOS OCTET STRING index run — LENGTH-PREFIXED
 * decimal octets (the inverse of decodePrefixedText in lcosClient.ts):
 *   "ntp1" → "4.110.116.112.49"  (len=4, then ASCII bytes as decimals).
 */
function encodeTextIndex(text: string): string {
  const octets = [...text].map((c) => c.charCodeAt(0));
  return [octets.length, ...octets].join('.');
}

/** Reads one scalar OID and returns its value (or null when absent). */
async function readScalar(ctx: ActionContext, oid: string): Promise<string | null> {
  try {
    const m = await snmpGet(ctx.host, ctx.credentials.snmp, [oid], ctx.opts);
    return m.get(oid) ?? null;
  } catch {
    return null;
  }
}

/** Reads the current NTP server list (column .1 rows of the RqAddress table). */
async function readNtpServers(ctx: ActionContext): Promise<string[]> {
  try {
    const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [SETUP.ntpRqAddressTableBase], ctx.opts);
    const out: string[] = [];
    for (const [oid, value] of m) {
      // Row shape relative to the table base: `.1.<col>.<index…>` — col 1 only.
      if (!oid.startsWith(`${SETUP.ntpRqAddressTableBase}.1.1.`)) continue;
      if (value && !out.includes(value)) out.push(value);
    }
    return out;
  } catch {
    return [];
  }
}

/** Resolves the web-UI slot credentials, or throws a clear error when unbound. */
function webCreds(ctx: ActionContext): { username: string; password: string } {
  const web = ctx.credentials.slots?.['web'];
  const username = typeof web?.username === 'string' ? web.username : '';
  const password = typeof web?.password === 'string' ? web.password : '';
  if (!username) {
    throw new Error('No `web` credential slot bound — bind a usernamePassword secret to the assignment\'s "web" slot for backup/restore.');
  }
  return { username, password };
}

/**
 * Performs one HTTP(S) GET against the router's web UI with Basic auth.
 * Uses raw node:http/https (fresh connection per call, `Connection: close`) —
 * embedded web servers are finicky about pooled sockets. Follows at most ONE
 * redirect and accepts self-signed certificates. Returns the body as a Buffer.
 */
function httpGet(
  address: string,
  path: string,
  transport: 'auto' | 'http' | 'https',
  auth: { username: string; password: string },
  timeoutMs: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let start: URL;
    try {
      const base = address.includes('://') ? address : `https://${address}`;
      start = new URL(path.startsWith('/') ? path : `/${path}`, base);
    } catch (err) {
      return reject(new Error(`Invalid management address "${address}": ${(err as Error).message}`));
    }

    // 'auto' prefers HTTPS but falls back to HTTP if the router has no TLS.
    const preferHttps = transport !== 'http';
    const token = Buffer.from(`${auth.username}:${auth.password}`, 'utf8').toString('base64');

    let settled = false;
    const done = (fn: () => void) => {
      if (!settled) {
        settled = true;
        fn();
      }
    };

    const attempt = (url: URL, onFallback: boolean, followedRedirect: boolean) => {
      const scheme = url.protocol === 'http:' ? 'http' : 'https';
      const clientLib = scheme === 'https' ? https : http;
      const req = clientLib.get(
        {
          hostname: url.hostname,
          port: url.port || (scheme === 'https' ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method: 'GET',
          headers: { Authorization: `Basic ${token}`, Connection: 'close', Accept: '*/*' },
          // LCOS web UIs commonly ship self-signed certs — accept them.
          rejectUnauthorized: false,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          if (!followedRedirect && status >= 300 && status < 400 && res.headers.location) {
            // Follow a single redirect (relative or absolute), keeping auth.
            let next: URL;
            try {
              next = new URL(res.headers.location, url);
            } catch {
              res.resume();
              return done(() => reject(new Error(`Bad redirect from web UI: ${res.headers.location}`)));
            }
            res.resume();
            attempt(next, onFallback, true);
            return;
          }
          if (status !== 200) {
            res.resume();
            return done(() => reject(new Error(`Web UI returned HTTP ${status} for ${path}`)));
          }
          collect(res).then((b) => done(() => resolve(b)));
        }
      );
      req.on('error', (err) => {
        // 'auto': an HTTPS failure falls back to plain HTTP once.
        if (!onFallback && preferHttps && !followedRedirect) {
          const httpUrl = new URL(url);
          httpUrl.protocol = 'http:';
          attempt(httpUrl, true, followedRedirect);
        } else {
          done(() => reject(new Error(`Web UI request failed: ${err.message}`)));
        }
      });
      req.setTimeout(timeoutMs, () => req.destroy(new Error(`Web UI request timed out after ${timeoutMs}ms`)));
    };

    attempt(start, false, false);
  });
}

/** Streams a response into a Buffer. */
function collect(res: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    res.on('data', (c: Buffer) => chunks.push(c));
    res.on('end', () => resolve(Buffer.concat(chunks)));
    res.on('error', () => resolve(Buffer.concat(chunks)));
  });
}

// --- Actions ----------------------------------------------------------------------------

/** Download the router's running configuration backup over the web UI. */
const configBackupDownload: ActionDescriptor = {
  id: 'config.backup.download',
  label: 'Download configuration backup',
  description:
    "Downloads the router's running configuration via its web UI (HTTP + Basic auth from the `web` credential slot). The file is returned base64-encoded in details — use it as a rollback point before risky changes. Read-only on the device. Requires the `backupPath` option to be set to the router's backup endpoint.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx) {
    if (!ctx.backupPath) {
      return { success: false, error: 'Backup endpoint not configured — set the plugin\'s `backupPath` option to the router\'s web-UI backup URL.' };
    }
    const auth = webCreds(ctx);
    const data = await httpGet(ctx.address, ctx.backupPath, ctx.webTransport, auth, 55_000);
    if (data.length === 0) {
      return { success: false, error: 'Router returned an empty backup — check the `backupPath` option and web-UI credentials.' };
    }
    return {
      success: true,
      details: { sizeBytes: data.length, backupBase64: data.toString('base64') },
    };
  },
};

/** Set the NTP server list + operating flag over SNMP. */
const ntpServersSet: ActionDescriptor = {
  id: 'ntp.servers.set',
  label: 'Set NTP servers',
  description:
    "Enables/disables the NTP client and upserts each listed server address into lcsSetupNtpRqAddressTable (SNMP SET). Rows are added if missing; existing rows are left untouched. Removal of a server is not expressible via this MIB table (no RowStatus column) — use the web UI for that.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    servers: { type: 'array', required: true, items: { type: 'string', pattern: '^([a-zA-Z0-9.-]{1,63}|\\d{1,3}(\\.\\d{1,3}){3})$' }, description: 'NTP server hostnames or IPs to configure' },
    enabled: { type: 'boolean', default: true, description: 'Enable (true) or disable (false) the NTP client' },
  },
  async execute(ctx, input) {
    const servers = Array.isArray(input.servers) ? (input.servers as unknown[]).map(String).filter(Boolean) : [];
    if (servers.length === 0) return { success: false, error: 'At least one NTP server is required' };
    const enabled = typeof input.enabled === 'boolean' ? input.enabled : true;

    // 1. Operating flag (eNo(0)/eYes(1)).
    await snmpSet(ctx.host, ctx.credentials.snmp, SETUP.ntpOperating, 'i', enabled ? '1' : '0', ctx.opts);

    // 2. Upsert each server row: <table>.1.<col=1>.<encoded-address> = address.
    const existing = await readNtpServers(ctx);
    for (const addr of servers) {
      if (existing.includes(addr)) continue;
      const oid = `${SETUP.ntpRqAddressTableBase}.1.${SETUP.NTP_COL_ADDRESS}.${encodeTextIndex(addr)}`;
      await snmpSet(ctx.host, ctx.credentials.snmp, oid, 's', addr, ctx.opts);
    }

    // 3. Re-read to verify.
    const verifiedFlag = (await readScalar(ctx, SETUP.ntpOperating)) === (enabled ? '1' : '0');
    const nowServers = await readNtpServers(ctx);
    const allPresent = servers.every((s) => nowServers.includes(s));
    return {
      success: verifiedFlag && allPresent,
      applied: true,
      verified: verifiedFlag && allPresent,
      details: { enabled, requested: servers, presentOnDevice: nowServers },
    };
  },
};

/** Set the default + backup DNS server over SNMP. */
const dnsServersSet: ActionDescriptor = {
  id: 'dns.servers.set',
  label: 'Set DNS servers',
  description: 'Sets the router\'s primary (lcsSetupTcpIpDnsDefault) and optional backup (lcsSetupTcpIpDnsBackup) DNS server via SNMP SET, then re-reads to verify.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    primary: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Primary DNS server IPv4 address' },
    backup: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Backup DNS server IPv4 address (optional)' },
  },
  async execute(ctx, input) {
    const primary = str(input, 'primary')!;
    const backup = str(input, 'backup');

    await snmpSet(ctx.host, ctx.credentials.snmp, SETUP.dnsDefault, 'a', primary, ctx.opts);
    if (backup) await snmpSet(ctx.host, ctx.credentials.snmp, SETUP.dnsBackup, 'a', backup, ctx.opts);

    const gotPrimary = await readScalar(ctx, SETUP.dnsDefault);
    const gotBackup = backup ? await readScalar(ctx, SETUP.dnsBackup) : null;
    const verified = gotPrimary === primary && (backup === undefined || gotBackup === backup);
    return {
      success: verified,
      applied: true,
      verified,
      details: { primary, backup: backup ?? null, readBack: { primary: gotPrimary, backup: gotBackup } },
    };
  },
};

/** Enable/disable a LAN interface over SNMP (inverted Operating enum). */
const lanIfcStateSet: ActionDescriptor = {
  id: 'lan.ifc.state.set',
  label: 'Enable / disable a LAN port',
  description:
    "Sets the operating state of one LAN port via lcsSetupInterfacesLanInterfacesTable column .7 (SNMP SET). NOTE the MIB's INVERTED enum: eYes(0)/eNo(1) — so enabling sends 0, disabling sends 1. Re-reads to verify.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 16, description: 'LAN port number (1-based)' },
    enabled: { type: 'boolean', required: true, description: 'true = enable the port, false = disable it' },
  },
  async execute(ctx, input) {
    const port = typeof input.port === 'number' ? Math.floor(input.port) : NaN;
    if (!Number.isInteger(port) || port < 1 || port > 16) return { success: false, error: `Invalid LAN port ${input.port} (expected 1..16)` };
    const enabled = typeof input.enabled === 'boolean' ? input.enabled : true;

    // Inverted semantics: operating ON = eYes(0), OFF = eNo(1).
    const value = enabled ? '0' : '1';
    const oid = `${SETUP.lanIfcTableBase}.1.${SETUP.LAN_COL_OPERATING}.${port}`;
    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', value, ctx.opts);

    const got = await readScalar(ctx, oid);
    const verified = got === value;
    return {
      success: verified,
      applied: true,
      verified,
      details: { port, enabled, rawOperatingValue: got ?? null },
    };
  },
};

/** Read the current NTP/DNS/LAN-ifc state (read-only diagnostics). */
const networkStateRead: ActionDescriptor = {
  id: 'network.state.read',
  label: 'Read NTP / DNS / LAN port state',
  description: 'Reads the current NTP operating flag + server list, primary/backup DNS servers, and per-LAN-port operating state. Read-only.',
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  async execute(ctx) {
    const ntpOperating = await readScalar(ctx, SETUP.ntpOperating);
    const ntpServers = await readNtpServers(ctx);
    const dnsDefault = await readScalar(ctx, SETUP.dnsDefault);
    const dnsBackup = await readScalar(ctx, SETUP.dnsBackup);

    // LAN port operating states: walk the setup table's column .7.
    const lanPorts: Record<string, string> = {};
    try {
      const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [`${SETUP.lanIfcTableBase}.1.${SETUP.LAN_COL_OPERATING}`], ctx.opts);
      for (const [oid] of m) {
        // <base>.1.<col=7>.<port> → port is the trailing sub-identifier.
        const tail = oid.split('.').pop();
        if (tail && /^\d+$/.test(tail)) lanPorts[`LAN-${tail}`] = 'up';
      }
    } catch {
      // best-effort — some models may not expose the setup table readably
    }

    return {
      success: true,
      details: {
        ntp: { operating: ntpOperating === null ? null : ntpOperating === '1', servers: ntpServers },
        dns: { primary: dnsDefault ?? null, backup: dnsBackup ?? null },
        lanPorts,
      },
    };
  },
};

// --- Registry ---------------------------------------------------------------------------

const ALL_ACTIONS: ActionDescriptor[] = [configBackupDownload, ntpServersSet, dnsServersSet, lanIfcStateSet, networkStateRead];
const byId = new Map<string, ActionDescriptor>(ALL_ACTIONS.map((a) => [a.id, a]));

/** Returns the action for an id, or undefined. */
export function getAction(id: string): ActionDescriptor | undefined {
  return byId.get(id);
}

/** All actions (the full catalog). */
export function listActions(): ActionDescriptor[] {
  return ALL_ACTIONS;
}

/** Distinct module names, for catalog grouping in the webapp. */
export function listModules(): string[] {
  return [...new Set(ALL_ACTIONS.map((a) => a.module))];
}

/** A serializable catalog entry (what /discover advertises + the API persists). */
export interface CatalogEntry {
  id: string;
  label: string;
  description?: string;
  module: string;
  riskLevel: RiskLevel;
  deviceCount: number | 'N';
  timeoutMs?: number;
  inputSchema: InputSchema;
}

/** The full action catalog (single-device actions only in v1). */
export function listCatalog(): CatalogEntry[] {
  return ALL_ACTIONS.map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    module: a.module,
    riskLevel: a.riskLevel,
    deviceCount: 1 as const,
    timeoutMs: a.timeoutMs,
    inputSchema: a.inputSchema,
  }));
}
