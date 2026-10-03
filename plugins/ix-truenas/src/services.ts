/**
 * Services inventory for the cross-device Services page (TrueNAS).
 *
 * PRIMARY source is the middleware JSON-RPC API — `service.query []` returns
 * EVERY service the appliance's own UI lists, including the special services
 * the middleware manages OUTSIDE the init system (smb/nfs/iscsi/s3/vm/docker/…):
 * each row carries { service, enable } plus the live state injected by the
 * datastore extend ({ state: 'RUNNING' | 'STOPPED' | 'UNKNOWN', pids: number[] }).
 * Verified against truenas/middleware (plugins/service/__init__.py — ServiceService).
 *
 * FALLBACK for older releases without `service.query` (-32601): read the init
 * system over SSH (SCALE: systemd units; CORE: /etc/rc.d scripts) using the
 * plugin's pooled session + host port. A missing ssh slot or a failed login
 * simply yields NO rows — the caller omits the `services` key entirely, so a
 * transient outage never wipes previously stored rows (absent = no wipe).
 */

import type { ServiceRow } from '@unm/plugin-sdk';
import { resolveSshCredentials, dynamicSshHostVerifier } from '@unm/plugin-sdk';
import { TruenasClient, TruenasCredentials, TruenasRpcError } from './client/truenasClient';
import { hostSshPort, sshPool } from './ssh';

/** One raw `service.query` row (datastore prefix stripped by the extend). */
interface ServiceQueryRow {
  service?: unknown;
  enable?: unknown;
  state?: unknown;
  pids?: unknown;
}

function pickPid(pids: unknown): number | null {
  if (!Array.isArray(pids)) return null;
  for (const p of pids) {
    const n = typeof p === 'number' ? p : Number(p);
    if (Number.isFinite(n) && n > 0) return Math.trunc(n);
  }
  return null;
}

/** Maps one `service.query` row into a unified ServiceRow (type 'truenas'). */
function normalizeApiRow(r: ServiceQueryRow): ServiceRow | null {
  const name = typeof r.service === 'string' ? r.service.trim() : '';
  if (!name) return null;
  const stateRaw = typeof r.state === 'string' ? r.state.toUpperCase() : '';
  let status: ServiceRow['status'];
  if (stateRaw === 'RUNNING') status = 'running';
  else if (stateRaw === 'STOPPED') status = 'stopped';
  else status = 'unknown'; // UNKNOWN / missing — state probe timed out or the service is unregistered
  return {
    name,
    type: 'truenas',
    status,
    enabled: typeof r.enable === 'boolean' ? r.enable : null,
    pid: pickPid(r.pids),
    description: null, // service.query carries no human description
  };
}

/** True when the RPC error means "method does not exist" (older release). */
function isMethodNotFound(e: unknown): boolean {
  return e instanceof TruenasRpcError && (e.code === -32601 || /method does not exist/i.test(e.message));
}

// ---------------------------------------------------------------------------
// SSH fallback (pre-`service.query` releases) — same commands as before.
// ---------------------------------------------------------------------------

/** The combined read-only command (single exec round-trip). */
const SERVICES_SSH_COMMAND = [
  // SCALE / any systemd box: name + active/sub state for every service unit.
  'echo __SYSTEMD__',
  "systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | head -n 400",
  // CORE (FreeBSD) fallback: the rc scripts that exist on the box.
  'echo __RC__',
  "ls /etc/rc.d/ 2>/dev/null | grep -v '^\\.\\.' | head -n 400",
].join('\n');

/** Parses `systemctl list-units` output into ServiceRows (type 'truenas'). */
function parseSystemdUnits(out: string): ServiceRow[] {
  const rows: ServiceRow[] = [];
  for (const line of out.split('\n')) {
    // "sshd.service loaded active running OpenSSH server daemon"
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;
    let name = parts[0];
    if (!name || !name.endsWith('.service')) continue;
    name = name.slice(0, -'.service'.length);
    // Columns: UNIT LOAD ACTIVE SUB DESCRIPTION...
    const active = parts[2]?.toLowerCase() ?? '';
    const sub = parts[3]?.toLowerCase() ?? '';
    let status: ServiceRow['status'];
    if (active === 'failed') status = 'failed';
    else if (active === 'active' && (sub === 'running' || sub === 'exited')) status = 'running';
    else if (active === 'inactive' || active === 'dead') status = 'stopped';
    else status = 'unknown';
    rows.push({ name, type: 'truenas', status, enabled: null, pid: null, description: parts.slice(4).join(' ') || null });
  }
  return rows;
}

/** Parses the FreeBSD rc-script listing into ServiceRows (best-effort state). */
function parseRcScripts(out: string): ServiceRow[] {
  const rows: ServiceRow[] = [];
  for (const line of out.split('\n')) {
    const name = line.trim();
    if (!name || name.startsWith('.')) continue;
    // We can't cheaply probe each script's state in one round-trip — report the
    // configured set as 'unknown' so the page still shows what the box manages.
    rows.push({ name, type: 'truenas', status: 'unknown', enabled: null, pid: null, description: null });
  }
  return rows;
}

/** SSH-based collection — returns [] when no ssh slot is bound or it fails. */
async function collectServicesOverSsh(
  host: string,
  credentials: Record<string, unknown> | undefined,
): Promise<ServiceRow[]> {
  const sshCreds = resolveSshCredentials(credentials, { slotOnly: true });
  if (!sshCreds) return [];

  try {
    const conn = await sshPool.get(host, hostSshPort(host), sshCreds, {
      hostKeyVerifier: dynamicSshHostVerifier(host, hostSshPort(host)),
    });
    const res = await conn.exec(SERVICES_SSH_COMMAND, sshCreds);
    if (!res || res.code !== 0) return [];

    // Split the marker-delimited sections.
    const out = res.stdout ?? '';
    const systemdIdx = out.indexOf('__SYSTEMD__');
    const rcIdx = out.indexOf('__RC__');
    let rows: ServiceRow[] = [];
    if (systemdIdx !== -1 && rcIdx > systemdIdx) {
      const systemdOut = out.slice(systemdIdx + '__SYSTEMD__'.length, rcIdx);
      rows = parseSystemdUnits(systemdOut);
    } else if (rcIdx !== -1) {
      rows = parseRcScripts(out.slice(rcIdx + '__RC__'.length));
    }
    return rows;
  } catch {
    // No ssh slot / login failed / box unreachable — best-effort, no rows.
    return [];
  }
}

/**
 * Collects TrueNAS services. API-first (`service.query`); falls back to SSH
 * ONLY when the method does not exist on this release (-32601) — never when it
 * merely failed transiently (that would double-report or drop rows). Returns []
 * when neither source yields data; the caller omits the `services` key in that
 * case so stored rows survive a bad poll.
 */
export async function collectServices(
  host: string,
  client: TruenasClient,
  creds: TruenasCredentials,
  credentials: Record<string, unknown> | undefined,
): Promise<ServiceRow[]> {
  let rawRows: ServiceQueryRow[];
  try {
    // service.query probes every registered service's live state (15 s server-
    // side budget) — give it a dedicated 20 s round-trip budget.
    rawRows = await client.call<ServiceQueryRow[]>('service.query', [], creds, 20_000);
  } catch (e) {
    if (!isMethodNotFound(e)) throw e; // transient API failure → let the caller omit the key
    // Older release without service.query — SSH fallback.
    return collectServicesOverSsh(host, credentials);
  }
  if (!Array.isArray(rawRows)) return [];
  const rows: ServiceRow[] = [];
  for (const r of rawRows) {
    if (!r || typeof r !== 'object') continue;
    const row = normalizeApiRow(r as ServiceQueryRow);
    if (row) rows.push(row);
  }
  return rows;
}
