/**
 * Shared SSH transport for the TrueNAS plugin.
 *
 * One pooled session per appliance (RE-USED across polls, probes and actions)
 * plus a per-host registry of the configured `sshPort` (plugin option, default
 * 22). Request entry points (/monitoring, /probe, /config, /filesystem, console)
 * call setHostSshPort() with their effective value; every internal sshPool.get()
 * reads it via hostSshPort(). This avoids threading a port parameter through the
 * deep collector call graph (enrichment waves run in the background and are
 * re-entered from several entry points). Bare hostname is the key — matches how
 * the pools themselves are keyed.
 */

import { createSshPool } from '@unm/plugin-sdk';

/** Process-wide SSH pool — one session per appliance, RE-USED across polls.
 *  Exported so the action registry (containers.logs.read) can reuse the SAME
 *  pooled sessions instead of opening a fresh connection per log read. */
export const sshPool = createSshPool();
process.on('SIGTERM', () => sshPool.closeAll());
process.on('SIGINT', () => sshPool.closeAll());

/** Bare hostname for the registry key — strips scheme + :port so every caller
 *  (https://host, host:8443, bare host) resolves the SAME per-appliance port. */
function bareHostKey(host: string): string {
  let h = String(host ?? '').trim().toLowerCase();
  const m = h.match(/^https?:\/\//i);
  if (m) h = h.slice(m[0].length);
  return h.split('/')[0].split(':')[0];
}

const hostSshPorts = new Map<string, number>();

export function setHostSshPort(host: string, port: number): void {
  const k = bareHostKey(host);
  if (k && Number.isFinite(port) && port > 0) hostSshPorts.set(k, Math.floor(port));
}

export function hostSshPort(host: string): number {
  return hostSshPorts.get(bareHostKey(host)) ?? 22;
}
