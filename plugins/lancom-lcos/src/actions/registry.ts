/**
 * The LANCOM LCOS router action registry — single source of truth for everything
 * this plugin can do. Serves three entry points (same contract as OPNsense/SwOS):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /plan     → buildPlan() fans out single-device actions per device
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * Transports:
 *  - SNMP SET — NTP/DNS/LAN-ifc/timezone (read → set → re-read-verify),
 *  - SFTP     — config backup/restore over the LCOS virtual `/config` file
 *               (the same LCF document `readconfig` prints; read AND write per
 *               the vendor Refmanual "File Names for SCP File Transfer"),
 *  - CLI      — interactive-CLI actions (`set <path> <value>` + re-read verify)
 *               over an SSH PTY, for settings the MIB does not expose as SET.
 * All three ride the bound `ssh` credential slot (usernamePassword/sshKeyPair).
 */

import http from 'http';
import https from 'https';
import {
  configBackupFileName,
  createFileRepoClient,
  FileRepoClient,
  ianaZoneToOffsetMinutes,
  createRegistry,
  resolveSshCredentials,
  dynamicSshHostVerifier,
} from '@unm/plugin-sdk';
import type { SshCredentials } from '@unm/plugin-sdk';
import { snmpGet, snmpSet, snmpWalk, SnmpValue } from '@unm/snmp-client';
import { SETUP, SETUP_TIME, SYS, WLAN_NET, WLAN_RADIO, WLAN_SETUP, lcosMinutesToTimezoneEnum, wlanIfcToEnum } from '../lcosOids';
import { runLcosCliCommands, stripCommandEcho } from '../lcosCli';
import { isLcfDocument, lcfScalar, parseLcf } from '../lcf';
import { ActionContext, ActionDescriptor, ActionResult } from './types';

// --- SSH/SFTP helpers -----------------------------------------------------------

/** Resolves the bound `ssh` slot credentials (slot-only — never the SNMP primary). */
function sshCreds(ctx: ActionContext): SshCredentials | undefined {
  return resolveSshCredentials(ctx.credentials as Record<string, unknown>, { slotOnly: true });
}

const NO_SSH_SLOT_ERROR =
  'No `ssh` credential slot bound — bind a usernamePassword or sshKeyPair secret to the assignment\'s "ssh" slot for config backup/restore and CLI actions.';

/** Opens (or reuses) a pooled SFTP session with UNM host-key pinning. */
async function sftpSession(ctx: ActionContext, creds: SshCredentials) {
  const port = ctx.sshPort ?? 22;
  return ctx.sftpPool.get(ctx.host, port, creds, {
    timeoutMs: 60_000,
    hostKeyVerifier: dynamicSshHostVerifier(ctx.host, port),
  });
}

/** LCOS configs are tens of KB (WLC01 live: ~327 KB) — bound the payload anyway. */
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;

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

/** Quotes an LCOS CLI value in double quotes (the allowed charsets contain no `"` or backtick). */
function cliQuote(v: string): string {
  return `"${v}"`;
}

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

/** Reads one scalar OID and returns its typed value (or null when absent). */
async function readScalar(ctx: ActionContext, oid: string): Promise<SnmpValue | null> {
  try {
    const m = await snmpGet(ctx.host, ctx.credentials.snmp, [oid], ctx.opts);
    return m.get(oid) ?? null;
  } catch {
    return null;
  }
}

/** Decodes a length-prefixed decimal-octet text index ("6.87.76.…" → "WLAN-1"). */
function decodeTextIndex(idx: string[]): string | null {
  if (idx.length < 2) return null;
  const len = Number(idx[0]);
  if (!Number.isInteger(len) || len <= 0 || len !== idx.length - 1) return null;
  try {
    return Buffer.from(idx.slice(1, 1 + len).map(Number)).toString('utf8');
  } catch {
    return null;
  }
}

/** Reads the running LCF configuration from the SFTP virtual `/config` file. */
async function readConfigFile(ctx: ActionContext): Promise<Buffer> {
  const creds = sshCreds(ctx);
  if (!creds) throw new Error(NO_SSH_SLOT_ERROR);
  const session = await sftpSession(ctx, creds);
  return session.readFile('/config', creds, MAX_CONFIG_BYTES);
}

/** Writes the LCF configuration back to the SFTP virtual `/config` file (applied live by LCOS). */
async function writeConfigFile(ctx: ActionContext, data: Buffer): Promise<void> {
  const creds = sshCreds(ctx)!;
  const session = await sftpSession(ctx, creds);
  await session.writeFile('/config', data, creds);
}

/**
 * Replaces the value of ONE LCF table cell — `(oid) = old` → `(oid) = new` — in
 * the raw document text. Line endings (CRLF), indentation and every other byte
 * are preserved; when the cell line is absent (the agent omits cells at their
 * default value) it is inserted right after the row's first column line, which
 * always exists. Returns { text, replaced } or an error string. Exported for
 * offline verification against captured configs.
 */
export function replaceLcfCell(
  raw: string,
  oid: string,
  expectedOld: string | null,
  newValue: string
): { text: string; replaced: boolean } | { error: string } {
  const esc = (s: string) => s.replace(/\./g, '\\.');
  const lines = raw.split('\r\n');
  const re = new RegExp(`^(\\s*\\(${esc(oid)}\\)\\s*=\\s*)(.*)$`);
  let found = -1;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) { found = i; break; }
  }

  if (found >= 0) {
    const m = re.exec(lines[found])!;
    const cur = m[2].trim();
    if (expectedOld !== null && cur !== expectedOld) {
      return { error: `Concurrent-change guard: cell ${oid} is "${cur}" on the device, expected "${expectedOld}" — aborting without writing.` };
    }
    lines[found] = `${m[1]}${newValue}`;
    return { text: lines.join('\r\n'), replaced: true };
  }

  // Cell absent (the agent omits cells at their default value) — insert it right
  // after the row's first column line. The cell OID is <family>.<table>.<rowIdx>.<col>;
  // dropping the last segment yields the row prefix, whose col .1 always exists.
  const parts = oid.split('.');
  if (parts.length < 4) return { error: `Cell OID ${oid} does not look like a table cell (<family>.<table>.<row>.<col>).` };
  const firstColOid = `${parts.slice(0, -1).join('.')}.1`;
  const firstColRe = new RegExp(`^(\\s*\\(${esc(firstColOid)}\\)\\s*=\\s*)(.*)$`);
  let anchor = -1;
  for (let i = 0; i < lines.length; i++) {
    if (firstColRe.test(lines[i])) { anchor = i; break; }
  }
  if (anchor < 0) return { error: `Cell ${oid} and its row's first column (${firstColOid}) are both absent — the table row does not exist in this configuration.` };
  const indentMatch = /^(\s*)/.exec(lines[anchor])!;
  lines.splice(anchor + 1, 0, `${indentMatch[1]}(${oid}) = ${newValue}`);
  return { text: lines.join('\r\n'), replaced: false };
}

/** Reads one LCF table cell value ("" when the agent omitted it as default). */
function lcfCell(doc: ReturnType<typeof parseLcf>, oid: string): string {
  return doc.cells.get(oid) ?? '';
}

/** Reads the current NTP server list (column .1 rows of the RqAddress table). */
async function readNtpServers(ctx: ActionContext): Promise<string[]> {
  try {
    const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [SETUP.ntpRqAddressTableBase], ctx.opts);
    const out: string[] = [];
    for (const [oid, value] of m) {
      // Row shape relative to the table base: `.1.<col>.<index…>` — col 1 only.
      if (!oid.startsWith(`${SETUP.ntpRqAddressTableBase}.1.1.`)) continue;
      const v = String(value).trim();
      if (v && !out.includes(v)) out.push(v);
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
  timeoutMs: number,
  ports?: { httpsPort?: number; httpPort?: number }
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let start: URL;
    try {
      // An explicit port in the address wins over the configured default.
      const base = address.includes('://')
        ? address
        : transport === 'http'
          ? `http://${address}${ports?.httpPort && ports.httpPort !== 80 ? `:${ports.httpPort}` : ''}`
          : `https://${address}${ports?.httpsPort && ports.httpsPort !== 443 ? `:${ports.httpsPort}` : ''}`;
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
        // 'auto': an HTTPS failure falls back to plain HTTP once (configured port).
        if (!onFallback && preferHttps && !followedRedirect) {
          const httpUrl = new URL(url);
          httpUrl.protocol = 'http:';
          if (ports?.httpPort && ports.httpPort !== 80) httpUrl.port = String(ports.httpPort);
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

/** Lazily-built shared UNM file-repo client (the SDK's ONE implementation). */
let repoClient: FileRepoClient | null = null;
function fileRepo(): FileRepoClient {
  if (!repoClient) repoClient = createFileRepoClient();
  return repoClient;
}

/** Download the router's running configuration backup over SFTP (`/config`). */
const configBackupDownload: ActionDescriptor = {
  id: 'config.backup.download',
  label: 'Download configuration backup',
  description:
    "Downloads the router's complete running configuration from the LCOS virtual `/config` SFTP file (the same LCF document `readconfig` prints — verified live on WLC01) and stores it in UNM's central file repository, downloadable/archivable from the Files page. Named with the shared convention (<device>__config-backup-<UTC-ts>.cfg). Read-only on the device; use as a rollback point before risky changes — reference it later via details.repoFileId (restore it with config.restore). Requires a bound `ssh` credential slot.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 90_000,
  inputSchema: {},
  async execute(ctx) {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    let data: Buffer;
    try {
      const session = await sftpSession(ctx, creds);
      data = await session.readFile('/config', creds, MAX_CONFIG_BYTES);
    } catch (e) {
      // Legacy fallback: the old web-UI GET path (only when a `web` slot + backupPath exist).
      if (ctx.backupPath && ctx.credentials.slots?.['web']?.username) {
        try {
          const auth = webCreds(ctx);
          data = await httpGet(ctx.address, ctx.backupPath, ctx.webTransport, auth, 55_000, { httpsPort: ctx.httpsPort, httpPort: ctx.httpPort });
          if (data.length === 0) throw new Error('empty backup');
        } catch (e2) {
          return { success: false, error: `SFTP /config read failed (${e instanceof Error ? e.message : String(e)}) and the web-UI fallback also failed (${e2 instanceof Error ? e2.message : String(e2)}).` };
        }
      } else {
        return { success: false, error: `Could not read the LCOS /config file over SFTP: ${e instanceof Error ? e.message : String(e)}` };
      }
    }

    if (data.length === 0) {
      return { success: false, error: 'Router returned an empty configuration backup.' };
    }

    // Store the backup in UNM's central file repository so it is downloadable /
    // archivable from the Files page — no more base64 blobs buried in step results.
    const fileName = configBackupFileName({ device: ctx.deviceName, host: ctx.host, ext: 'cfg' });
    try {
      const entry = await fileRepo().upload(data, { name: fileName, category: 'config-backup' }, 120_000);
      void fileRepo().recordUse(entry.id, { deviceId: ctx.deviceId ?? undefined, note: `config backup of ${ctx.host} (SFTP /config)` }).catch(() => undefined);
      return {
        success: true,
        details: {
          sizeBytes: data.length,
          fileName,
          // Reference the stored backup by repo id.
          repoFileId: entry.id,
        },
      };
    } catch (e) {
      // The repo is a convenience — a failed store must not fail the backup itself.
      return {
        success: true,
        details: {
          sizeBytes: data.length,
          fileName,
          warning: `Backup downloaded but could NOT be stored in the UNM file repository: ${e instanceof Error ? e.message : String(e)}`,
          // Fallback so the bytes are still available (legacy contract).
          backupBase64: data.toString('base64'),
        },
      };
    }
  },
};

/** Restore a previously backed-up configuration onto the router (SFTP /config write). */
const configRestore: ActionDescriptor = {
  id: 'config.restore',
  label: 'Restore configuration backup',
  description:
    "Restores an LCF configuration file onto the router by writing it to the LCOS virtual `/config` SFTP file (the documented import/export mountpoint — equivalent of the web UI's loadconf). The file is fetched from UNM's central repository (repoFileId, e.g. one produced by config.backup.download) or supplied inline as base64. Sanity-checked: only well-formed LCF documents are accepted. DANGEROUS — replaces the entire running configuration; take a fresh backup first and never restore a config whose management IP/VLAN differs from how you reach this device.",
  module: 'System',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 120_000,
  retryOnDispatchFailure: false,
  inputSchema: {
    repoFileId: { type: 'string', description: 'UNM file-repo id of the backup to restore (preferred).' },
    fileBase64: { type: 'string', description: 'Inline base64-encoded LCF document (alternative to repoFileId).' },
    fileName: { type: 'string', description: 'Optional label for logging.' },
  },
  async execute(ctx, input) {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    let payload: Buffer;
    let source: string;
    try {
      if (input.repoFileId) {
        const [data, meta] = await Promise.all([fileRepo().get(String(input.repoFileId)), fileRepo().getMeta(String(input.repoFileId))]);
        payload = data;
        source = `repo:${meta?.name ?? input.repoFileId}`;
      } else if (input.fileBase64) {
        payload = Buffer.from(String(input.fileBase64), 'base64');
        source = input.fileName ? `inline:${String(input.fileName)}` : 'inline';
      } else {
        return { success: false, error: 'Provide repoFileId (preferred) or fileBase64.' };
      }
    } catch (e) {
      return { success: false, error: `Could not fetch the configuration to restore: ${e instanceof Error ? e.message : String(e)}` };
    }

    const text = payload.toString('utf8');
    if (!isLcfDocument(text)) {
      return { success: false, error: 'Refusing to restore: the file is not a well-formed LCOS LCF configuration document (expected "[TYPE: LCF" header and OID rows).' };
    }

    // Capture the current setup name so we can report what changed.
    const beforeName = await readScalar(ctx, SYS.setupName);

    try {
      const session = await sftpSession(ctx, creds);
      await session.writeFile('/config', payload, creds);
    } catch (e) {
      return { success: false, error: `Writing /config over SFTP failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    // Verify the router picked up the new document.
    await new Promise((r) => setTimeout(r, 3_000));
    const afterName = await readScalar(ctx, SYS.setupName);
    const expectedName = lcfScalar(parseLcf(text), '1.2.1');

    if (input.repoFileId) {
      void fileRepo().recordUse(String(input.repoFileId), { deviceId: ctx.deviceId ?? undefined, note: `restored on ${ctx.host} (SFTP /config)` }).catch(() => undefined);
    }
    return {
      success: true,
      details: {
        source,
        sizeBytes: payload.length,
        beforeName: beforeName ?? null,
        afterName: afterName ?? null,
        expectedName,
        note: 'Configuration written to /config. LCOS applies it live; verify reachability and key settings (management IP, NTP, DNS).',
      },
    };
  },
};

/** Read a single CLI parameter's current value + input set via `set <name> ?`. */
const cliParamRead: ActionDescriptor = {
  id: 'cli.param.read',
  label: 'Read CLI parameter (set ?)',
  description:
    "Runs the LCOS interactive-CLI command `set <name> ?` inside a directory and returns the current value plus the allowed input set. Read-only on the device — no configuration is changed. Example: dir='Setup/Time', name='Timezone'. Requires a bound `ssh` credential slot.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {
    dir: { type: 'string', description: "CLI directory to cd into first (e.g. 'Setup/Time')." },
    name: { type: 'string', description: "Parameter name relative to the directory (e.g. 'Timezone' or 'NTP/RqAddress{1}')." },
  },
  async execute(ctx, input) {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };
    const dir = String(input.dir ?? '').trim();
    const name = String(input.name ?? '').trim();
    if (!dir || !name) return { success: false, error: 'Both `dir` and `name` are required.' };

    try {
      const cmd = `set ${cliQuote(name)} ?`;
      const results = await runLcosCliCommands(ctx.terminalPool, { host: ctx.address, port: ctx.sshPort ?? 22, creds }, [`cd ${dir}`, cmd]);
      const result = results[results.length - 1];
      if (!result?.completed) return { success: false, error: 'CLI session timed out before the command finished.' };

      const raw = stripCommandEcho(result.raw, cmd);
      if (/Path name wrong/i.test(raw)) {
        return { success: false, error: `LCOS reports "Path name wrong" for ${dir}/${name} — check the directory and parameter name.` };
      }
      // The `set X ?` output shows the current value line followed by the input set.
      const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
      const hintIdx = lines.findIndex((l) => /input|possible values/i.test(l));
      return { success: true, details: { dir, name, output: lines.slice(0, Math.max(hintIdx + 1, 8)).join('\n'), raw } };
    } catch (e) {
      return { success: false, error: `CLI read failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  },
};

/** Set the router's setup name via CLI (`cd Setup` + `set Name <value>`). */
const systemNameSet: ActionDescriptor = {
  id: 'system.name.set',
  label: 'Set device (setup) name',
  description:
    "Sets the LCOS setup name (the hostname shown in menus and SNMP lcsSetupName) via the interactive CLI (`cd Setup` + `set Name <value>`). Changes apply live and are persisted to flash by default — no reboot. No-op if already set to the requested value.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', description: "New setup name (LCOS charset: letters, digits, '.', '-', max 64 chars).", pattern: '^[A-Za-z0-9][A-Za-z0-9.\\-]{0,63}$' },
  },
  async execute(ctx, input) {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };
    const name = String(input.name ?? '').trim();
    if (!name) return { success: false, error: '`name` is required.' };

    const before = await readScalar(ctx, SYS.setupName);
    if (before === name) return { success: true, details: { noOp: true, name } };

    try {
      const results = await runLcosCliCommands(ctx.terminalPool, { host: ctx.address, port: ctx.sshPort ?? 22, creds }, ['cd Setup', `set Name ${cliQuote(name)}`]);
      if (!results[results.length - 1]?.completed) return { success: false, error: 'CLI session timed out before the command finished.' };
    } catch (e) {
      return { success: false, error: `CLI set failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = await readScalar(ctx, SYS.setupName);
    if (after !== name) {
      return { success: false, error: `Verification failed — lcsSetupName is '${after ?? 'unreadable'}' after setting to '${name}'.` };
    }
    return { success: true, details: { before: before ?? null, after } };
  },
};

/** Set the timezone via CLI (`cd Setup` + `set Time/Timezone <enum>`). */
const systemTimezoneCliSet: ActionDescriptor = {
  id: 'system.timezone.cli.set',
  label: 'Set timezone (CLI)',
  description:
    "Sets the LCOS timezone via the interactive CLI (`cd Setup` + `set Time/Timezone <enum>`), mapping an IANA zone or UTC offset to the lcsSetupTimeTimezone enum. Changes apply live and persist to flash — no reboot. Alternative to system.timezone.set (SNMP); use this when SNMP SET is unavailable.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {
    timezone: { type: 'string', description: "IANA zone (e.g. 'Europe/Berlin') — mapped to the nearest whole-hour LCOS enum." },
    utcOffsetMinutes: { type: 'number', description: 'Alternative: explicit UTC offset in minutes (whole hours only).' },
  },
  async execute(ctx, input) {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    let minutes: number;
    try {
      if (input.timezone) {
        const m = ianaZoneToOffsetMinutes(String(input.timezone));
        if (m === null) return { success: false, error: `Unknown IANA timezone '${input.timezone}'.` };
        minutes = m;
      } else if (typeof input.utcOffsetMinutes === 'number') {
        minutes = input.utcOffsetMinutes;
      } else {
        return { success: false, error: 'Provide either `timezone` (IANA) or `utcOffsetMinutes`.' };
      }
    } catch (e) {
      return { success: false, error: e instanceof Error ? e.message : 'Invalid timezone input.' };
    }
    const enumVal = lcosMinutesToTimezoneEnum(minutes);
    if (enumVal === null) {
      return { success: false, error: `UTC offset ${minutes} min is outside the LCOS whole-hour range −12h..+14h.` };
    }

    const beforeRaw = await readScalar(ctx, SETUP_TIME.timezone);
    if (beforeRaw === String(enumVal)) return { success: true, details: { noOp: true, enumValue: enumVal } };

    try {
      const results = await runLcosCliCommands(ctx.terminalPool, { host: ctx.address, port: ctx.sshPort ?? 22, creds }, ['cd Setup', `set Time/Timezone ${enumVal}`]);
      if (!results[results.length - 1]?.completed) return { success: false, error: 'CLI session timed out before the command finished.' };
    } catch (e) {
      return { success: false, error: `CLI set failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const afterRaw = await readScalar(ctx, SETUP_TIME.timezone);
    if (afterRaw !== String(enumVal)) {
      return { success: false, error: `Verification failed — lcsSetupTimeTimezone is '${afterRaw ?? 'unreadable'}' after setting enum ${enumVal}.` };
    }
    return { success: true, details: { beforeEnum: beforeRaw ?? null, afterEnum: afterRaw, minutes } };
  },
};

/** Enable/disable a WLAN SSID via CLI (`cd Setup/Interfaces/WLAN` + `set Network <ifc> <Yes|No>`). */
// NOTE (v0.4): the former `wlan.ssid.state.set` CLI action was removed — its
// premise was wrong. The LCF Network table's Operating cell is 1 for ALL SSIDs
// (verified: an operating and a non-operating SSID have byte-identical config
// rows), so per-SSID enable/disable is runtime state, not expressible in the
// configuration document. Per-SSID state can only be read via the status MIB
// (wlan.networks.read).

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
    await snmpSet(ctx.host, ctx.credentials.snmp, SETUP.ntpOperating, 'i', enabled ? 1 : 0, ctx.opts);

    // 2. Upsert each server row: <table>.1.<col=1>.<encoded-address> = address.
    const existing = await readNtpServers(ctx);
    for (const addr of servers) {
      if (existing.includes(addr)) continue;
      const oid = `${SETUP.ntpRqAddressTableBase}.1.${SETUP.NTP_COL_ADDRESS}.${encodeTextIndex(addr)}`;
      await snmpSet(ctx.host, ctx.credentials.snmp, oid, 's', addr, ctx.opts);
    }

    // 3. Re-read to verify.
    const gotFlag = await readScalar(ctx, SETUP.ntpOperating);
    const verifiedFlag = gotFlag !== null && Number(gotFlag) === (enabled ? 1 : 0);
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
    const verified = String(gotPrimary ?? '') === primary && (backup === undefined || String(gotBackup ?? '') === backup);
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
    const value = enabled ? 0 : 1;
    const oid = `${SETUP.lanIfcTableBase}.1.${SETUP.LAN_COL_OPERATING}.${port}`;
    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', value, ctx.opts);

    const got = await readScalar(ctx, oid);
    const verified = got !== null && Number(got) === value;
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
        ntp: { operating: ntpOperating === null ? null : Number(ntpOperating) === 1, servers: ntpServers },
        dns: { primary: dnsDefault !== null && dnsDefault !== '' ? String(dnsDefault) : null, backup: dnsBackup !== null && dnsBackup !== '' ? String(dnsBackup) : null },
        lanPorts,
      },
    };
  },
};

// --- WLAN (built-in radios only) ------------------------------------------------------

/** Walks one column-first status table and groups values by decoded text index. */
async function walkWlanTable(ctx: ActionContext, base: string): Promise<Map<string, Map<number, string>>> {
  const out = new Map<string, Map<number, string>>();
  try {
    const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [base], ctx.opts);
    for (const [oid, value] of m) {
      if (!oid.startsWith(`${base}.1.`)) continue;
      const rel = oid.slice(`${base}.1.`.length).split('.'); // <col>.<idx…>
      const col = Number(rel[0]);
      const key = decodeTextIndex(rel.slice(1));
      if (key === null || !Number.isInteger(col)) continue;
      let row = out.get(key);
      if (!row) { row = new Map(); out.set(key, row); }
      row.set(col, String(value));
    }
  } catch { /* no WLAN tree on this model — empty result */ }
  return out;
}

/** Read all WLAN networks (SSIDs): broadcast name, operating state, stations, BSSID, VLAN. */
const wlanNetworksRead: ActionDescriptor = {
  id: 'wlan.networks.read',
  label: 'Read WLAN networks (SSIDs)',
  description:
    "Reads every WLAN network from lcsStatusWlanNetworksTable (SNMP): broadcast SSID name, operating state, connected-station count, BSSID and VLAN. Read-only; empty on models without a built-in radio. NOTE the broadcast names exist ONLY in this status MIB — they are not stored anywhere in the LCF config document.",
  module: 'Wireless',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {},
  async execute(ctx) {
    const rows = await walkWlanTable(ctx, WLAN_NET.base);
    const networks = [...rows.entries()].map(([ifc, cols]) => ({
      ifc,
      name: cols.get(WLAN_NET.COL_NAME) ?? '',
      operating: cols.has(WLAN_NET.COL_OPERATING) ? Number(cols.get(WLAN_NET.COL_OPERATING)) === 1 : null,
      stations: cols.has(WLAN_NET.COL_STATIONS) ? Number(cols.get(WLAN_NET.COL_STATIONS)) : null,
      bssid: (cols.get(WLAN_NET.COL_BSSID) ?? '').trim(),
      vlanId: cols.has(WLAN_NET.COL_VLAN) ? Number(cols.get(WLAN_NET.COL_VLAN)) : null,
    }));
    return { success: true, details: { count: networks.length, networks } };
  },
};

/** Read per-radio RF state: band, channel, mode, bandwidth, TX power / EIRP. */
const wlanRadiosRead: ActionDescriptor = {
  id: 'wlan.radios.read',
  label: 'Read WLAN radio RF state',
  description:
    "Reads every built-in radio from lcsStatusWlanRadiosTable (SNMP): band, current channel (0 = auto), mode enum, channel bandwidth, TX power and EIRP as reported by the agent. Read-only; empty on models without a built-in radio.",
  module: 'Wireless',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {},
  async execute(ctx) {
    const rows = await walkWlanTable(ctx, WLAN_RADIO.base);
    const radios = [...rows.entries()].map(([ifc, cols]) => ({
      ifc,
      band: cols.has(WLAN_RADIO.COL_BAND) ? Number(cols.get(WLAN_RADIO.COL_BAND)) : null, // 1=2.4GHz, 2=5GHz
      channel: cols.has(WLAN_RADIO.COL_CHANNEL) ? Number(cols.get(WLAN_RADIO.COL_CHANNEL)) : null,
      mode: cols.has(WLAN_RADIO.COL_MODE) ? Number(cols.get(WLAN_RADIO.COL_MODE)) : null, // raw enum — mapping not stable across firmware
      bandwidth: cols.has(WLAN_RADIO.COL_BANDWIDTH) ? Number(cols.get(WLAN_RADIO.COL_BANDWIDTH)) : null, // 0=20MHz, 1=40MHz, 2=80MHz
      txPower: (cols.get(WLAN_RADIO.COL_TX_POWER) ?? '').trim(),
      eirp: (cols.get(WLAN_RADIO.COL_EIRP) ?? '').trim(),
    }));
    return { success: true, details: { count: radios.length, radios } };
  },
};

/**
 * Sets a radio's channel by replacing ONE cell in the LCF config over SFTP
 * `/config` (the proven v0.3.0 transport). The WLAN setup tree is SNMP-read-only
 * (NoAccess on SET) and the interactive-CLI table-set grammar for column
 * targeting could not be determined safely, so a single-cell text replacement —
 * everything else byte-identical — is used instead of a whole-config restore.
 */
const radioChannelSet: ActionDescriptor = {
  id: 'wlan.radio.channel.set',
  label: 'Set WLAN radio channel',
  description:
    "Pins a built-in radio to a fixed channel (0 = automatic) by updating the Radio-Settings table's Radio-Channel cell in the LCF config over SFTP /config. Reads the current value first (no-op when unchanged), writes back, then verifies via an LCF re-read and the status MIB. Applies live; persists to flash.",
  module: 'Wireless',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 90_000,
  inputSchema: {
    ifc: { type: 'string', required: true, pattern: '^WLAN-[12]$', description: 'Radio interface (WLAN-1 or WLAN-2 — physical radios only)' },
    channel: { type: 'number', required: true, min: 0, max: 255, description: 'Channel number; 0 = automatic' },
  },
  async execute(ctx, input) {
    const ifc = String(input.ifc ?? '').trim();
    const channel = typeof input.channel === 'number' ? Math.floor(input.channel as number) : NaN;
    if (!/^(WLAN-1|WLAN-2)$/.test(ifc)) return { success: false, error: '`ifc` must be WLAN-1 or WLAN-2 (physical radios).' };
    if (!Number.isInteger(channel) || channel < 0 || channel > 255) return { success: false, error: '`channel` must be an integer 0..255.' };

    const rowIdx = wlanIfcToEnum(ifc)!; // 1 or 2
    const oid = `${WLAN_SETUP.lcfFamily}.${WLAN_SETUP.radioTable}.${rowIdx}.${WLAN_SETUP.RADIO_COL_CHANNEL}`;

    let raw: string;
    try {
      const doc = parseLcf((await readConfigFile(ctx)).toString('utf8'));
      if (!doc.complete) return { success: false, error: 'The /config document is truncated (missing [END: LCF]) — refusing to modify it.' };
      raw = doc.raw;
    } catch (e) {
      return { success: false, error: `Could not read the current configuration: ${e instanceof Error ? e.message : String(e)}` };
    }

    const before = lcfCell(parseLcf(raw), oid);
    if (before === String(channel)) {
      return { success: true, applied: false, verified: true, details: { ifc, channel, note: 'Already set — no change.' } };
    }

    const res = replaceLcfCell(raw, oid, before || null, String(channel));
    if ('error' in res) return { success: false, error: res.error };
    try {
      await writeConfigFile(ctx, Buffer.from(res.text, 'utf8'));
    } catch (e) {
      return { success: false, error: `Writing /config failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    // Verify: LCF re-read + status MIB.
    await new Promise((r) => setTimeout(r, 3_000));
    let lcfAfter: string | null = null;
    try {
      const doc2 = parseLcf((await readConfigFile(ctx)).toString('utf8'));
      lcfAfter = lcfCell(doc2, oid);
    } catch { /* best-effort */ }

    let mibChannel: number | null = null;
    try {
      const idx = [ifc.length, ...[...ifc].map((c) => c.charCodeAt(0))].join('.');
      const v = await readScalar(ctx, `${WLAN_RADIO.base}.1.${WLAN_RADIO.COL_CHANNEL}.${idx}`);
      mibChannel = v === null ? null : Number(v);
    } catch { /* best-effort */ }

    const verified = lcfAfter !== null && Number(lcfAfter) === channel;
    return {
      success: verified,
      applied: true,
      verified,
      details: { ifc, channel, before: before || '(default/auto)', lcfAfter, statusMibChannel: mibChannel },
    };
  },
};

/** Sets a radio's power mode (Automatic) or manual EIRP via the same LCF single-cell transport. */
const radioPowerSet: ActionDescriptor = {
  id: 'wlan.radio.power.set',
  label: 'Set WLAN radio transmit power',
  description:
    "Sets automatic or manual EIRP for a built-in radio by updating the Radio-Settings table's Power-Setting (and, when Manual, EIRP) cells in the LCF config over SFTP /config. Reads current values first (no-op when unchanged), writes back, verifies via LCF re-read + status MIB. Applies live; persists to flash.",
  module: 'Wireless',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 90_000,
  inputSchema: {
    ifc: { type: 'string', required: true, pattern: '^WLAN-[12]$', description: 'Radio interface (WLAN-1 or WLAN-2)' },
    mode: { type: 'string', required: true, enum: ['Automatic', 'Manual'], description: 'Power control mode' },
    eirpDbm: { type: 'number', min: 0, max: 36, description: 'EIRP in dBm (required when mode = Manual)' },
  },
  async execute(ctx, input) {
    const ifc = String(input.ifc ?? '').trim();
    const mode = String(input.mode ?? '');
    const eirp = input.eirpDbm == null ? undefined : Number(input.eirpDbm);
    if (!/^(WLAN-1|WLAN-2)$/.test(ifc)) return { success: false, error: '`ifc` must be WLAN-1 or WLAN-2 (physical radios).' };
    if (mode !== 'Automatic' && mode !== 'Manual') return { success: false, error: '`mode` must be "Automatic" or "Manual".' };
    if (mode === 'Manual' && (!Number.isInteger(eirp) || (eirp as number) < 0 || (eirp as number) > 36)) {
      return { success: false, error: '`eirpDbm` is required when mode = Manual (integer 0..36).' };
    }

    const rowIdx = wlanIfcToEnum(ifc)!; // 1 or 2
    const powerOid = `${WLAN_SETUP.lcfFamily}.${WLAN_SETUP.radioTable}.${rowIdx}.${WLAN_SETUP.RADIO_COL_POWER_SETTING}`;
    const eirpOid = `${WLAN_SETUP.lcfFamily}.${WLAN_SETUP.radioTable}.${rowIdx}.${WLAN_SETUP.RADIO_COL_EIRP}`;

    let raw: string;
    try {
      const doc = parseLcf((await readConfigFile(ctx)).toString('utf8'));
      if (!doc.complete) return { success: false, error: 'The /config document is truncated (missing [END: LCF]) — refusing to modify it.' };
      raw = doc.raw;
    } catch (e) {
      return { success: false, error: `Could not read the current configuration: ${e instanceof Error ? e.message : String(e)}` };
    }

    const beforePower = lcfCell(parseLcf(raw), powerOid);
    const targetPower = mode === 'Automatic' ? '0' : '1';
    // EIRP is stored as a plain number in the LCF (the CLI shows it 4-digit zero-padded).
    const eirpStr = eirp != null ? String(eirp) : '';

    if (beforePower === targetPower && (mode !== 'Manual' || lcfCell(parseLcf(raw), eirpOid) === eirpStr)) {
      return { success: true, applied: false, verified: true, details: { ifc, mode, eirpDbm: eirp ?? null, note: 'Already set — no change.' } };
    }

    let text = raw;
    const r1 = replaceLcfCell(text, powerOid, beforePower || null, targetPower);
    if ('error' in r1) return { success: false, error: r1.error };
    text = r1.text;
    if (mode === 'Manual') {
      // The EIRP cell's current value comes from the ORIGINAL document — after
      // replacing the power cell it is unchanged.
      const beforeEirp = lcfCell(parseLcf(raw), eirpOid);
      const r2 = replaceLcfCell(text, eirpOid, beforeEirp || null, eirpStr);
      if ('error' in r2) return { success: false, error: r2.error };
      text = r2.text;
    }

    try {
      await writeConfigFile(ctx, Buffer.from(text, 'utf8'));
    } catch (e) {
      return { success: false, error: `Writing /config failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    // Verify: LCF re-read + status MIB EIRP.
    await new Promise((r) => setTimeout(r, 3_000));
    let lcfPower: string | null = null;
    let lcfEirp: string | null = null;
    try {
      const doc2 = parseLcf((await readConfigFile(ctx)).toString('utf8'));
      lcfPower = lcfCell(doc2, powerOid);
      lcfEirp = lcfCell(doc2, eirpOid);
    } catch { /* best-effort */ }

    let mibEirp: string | null = null;
    try {
      const idx = [ifc.length, ...[...ifc].map((c) => c.charCodeAt(0))].join('.');
      const v = await readScalar(ctx, `${WLAN_RADIO.base}.1.${WLAN_RADIO.COL_EIRP}.${idx}`);
      mibEirp = v === null ? null : String(v).trim();
    } catch { /* best-effort */ }

    const verified = lcfPower !== null && Number(lcfPower) === (mode === 'Automatic' ? 0 : 1)
      && (mode !== 'Manual' || (lcfEirp !== null && Number(lcfEirp) === eirp));
    return {
      success: verified,
      applied: true,
      verified,
      details: { ifc, mode, eirpDbm: eirp ?? null, beforePower: beforePower || '(default)', lcfPower, lcfEirp, statusMibEirp: mibEirp },
    };
  },
};

/** Set the router's timezone — a whole-hour UTC offset over SNMP SET. */
const systemTimezoneSet: ActionDescriptor = {
  id: 'system.timezone.set',
  label: 'Set device timezone (UTC offset)',
  description:
    "Sets the router's timezone via lcsSetupTimeTimezone (SNMP SET). The MIB is whole-hour granularity, so an IANA zone is resolved to its current UTC offset and rounded. Pass a zone name or explicit minutes. Re-reads to verify.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    timezone: { type: 'string', required: false, description: 'IANA zone (e.g. "Europe/Berlin") — resolved to its current UTC offset' },
    utcOffsetMinutes: { type: 'number', required: false, min: -720, max: 840, description: 'Explicit UTC offset in minutes (wins over timezone)' },
  },
  async execute(ctx, input) {
    let minutes: number | null = null;
    if (typeof input.utcOffsetMinutes === 'number' && Number.isFinite(input.utcOffsetMinutes)) {
      minutes = Math.round(input.utcOffsetMinutes as number);
    } else if (str(input, 'timezone')) {
      minutes = ianaZoneToOffsetMinutes(str(input, 'timezone')!);
      if (minutes === null) return { success: false, error: `Unknown IANA timezone "${str(input, 'timezone')}".` };
    } else {
      return { success: false, error: 'Provide either "timezone" or "utcOffsetMinutes".' };
    }

    const enumVal = lcosMinutesToTimezoneEnum(minutes);
    if (enumVal === null) return { success: false, error: `Offset ${minutes}m is not representable (whole hours −12..+14 only).` };

    const before = await readScalar(ctx, SETUP_TIME.timezone);
    if (before !== null && Number(before) === enumVal) {
      return { success: true, applied: false, verified: true, details: { timezoneMinutes: minutes, note: 'Already set — no change.' } };
    }
    await snmpSet(ctx.host, ctx.credentials.snmp, SETUP_TIME.timezone, 'i', enumVal, ctx.opts);
    const after = await readScalar(ctx, SETUP_TIME.timezone);
    const verified = after !== null && Number(after) === enumVal;
    return { success: verified, applied: true, verified, details: { timezoneMinutes: minutes, before: before === null ? null : String(before), after: after === null ? null : String(after) } };
  },
};

// --- Registry ---------------------------------------------------------------------------

const ALL_ACTIONS: ActionDescriptor[] = [
  configBackupDownload,
  configRestore,
  cliParamRead,
  systemNameSet,
  systemTimezoneCliSet,
  ntpServersSet,
  dnsServersSet,
  lanIfcStateSet,
  networkStateRead,
  systemTimezoneSet,
  wlanNetworksRead,
  wlanRadiosRead,
  radioChannelSet,
  radioPowerSet,
];

/** The shared registry factory (@unm/plugin-sdk) — one source for /discover, /plan and /config. */
export const registry = createRegistry(ALL_ACTIONS);

/** Returns the action for an id, or undefined. */
export function getAction(id: string): ActionDescriptor | undefined {
  return registry.getAction(id);
}

/** All actions (the full catalog). */
export function listActions(): ActionDescriptor[] {
  return registry.listActions();
}

/** Distinct module names, for catalog grouping in the webapp. */
export function listModules(): string[] {
  return registry.listModules();
}

/** The full action catalog (single-device actions only in v1). */
export function listCatalog() {
  return registry.listCatalog();
}
