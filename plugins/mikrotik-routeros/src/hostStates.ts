/**
 * Per-host connection-table walk for the cross-device "Hosts" / "Networks"
 * pages (open states now + created/destroyed churn over a window).
 *
 * RouterOS keeps its stateful-connection table at `/ip/firewall/connection` —
 * one row per tracked 5-tuple. Unlike OPNsense's query_states (a full scan of
 * ~240k rows taking ~30 s), this table is small on typical routers (thousands
 * of rows) and the REST print endpoint returns it in a single fast GET, so the
 * walk can run at a comfortable cadence. The walk runs FIRE-AND-FORGET from
 * /monitoring (never blocks or fails the poll), diffs each snapshot against the
 * previous one in memory to derive per-endpoint created/destroyed deltas, and
 * pushes only aggregated per-host rows to the API's POST /plugin/host-states
 * endpoint. Public internet destinations are filtered out — only internal hosts
 * are tracked (same contract as the OPNsense plugin).
 */

import { ipScope } from '@unm/plugin-sdk';
import type { RouterOsClient } from './routerosClient';

/** One aggregated per-endpoint row pushed to the API for a single walk. */
export interface HostStateRow {
  /** The endpoint address (src-address or dst-address) — internal only. */
  ip: string;
  /** Open connections touching this endpoint in THIS snapshot. */
  openStates: number;
  /** Connections created since the previous walk (null = no baseline). */
  created: number | null;
  /** Connections destroyed since the previous walk (null = no baseline). */
  destroyed: number | null;
}

/** A single connection's identity + endpoints, as needed for diffing. */
interface ConnectionIdentity {
  id: string;
  srcIp: string;
  dstIp: string;
}

/** One big page size — comfortably above any realistic connection-table total. */
const WALK_COUNT = 100_000;

/** True when an address is an internal endpoint worth tracking as a "host". */
function isInternalEndpoint(addr: string): boolean {
  if (typeof addr !== 'string') return false;
  const t = addr.trim();
  if (t === '' || t === '*') return false; // RouterOS uses '*' for wildcard/any
  return ipScope(t) === 'private';
}

/**
 * Reads one string field from a RouterOS row, tolerating the hyphenated REST
 * naming (`src-address`) and falling back to alternates. Returns '' when absent.
 */
function rosStr(row: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

/**
 * Walks the router's full live connection table in ONE REST GET and returns
 * each connection's identity + internal endpoints. Returns NULL on any failure
 * so the caller can tell a dead endpoint apart from a genuinely EMPTY table —
 * an empty result is a real observation (e.g. right after a reboot) and must
 * still be diffed. Public internet destinations are dropped here so only
 * internal hosts reach the aggregation step.
 */
export async function fetchConnectionIdentities(client: RouterOsClient): Promise<ConnectionIdentity[] | null> {
  let raw: unknown;
  try {
    raw = await client.get(`/ip/firewall/connection/print?count=${WALK_COUNT}`);
  } catch {
    return null; // transport/auth failure — best-effort
  }
  if (!Array.isArray(raw)) return null;

  const out: ConnectionIdentity[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const r = entry as Record<string, unknown>;
    // Identity: the internal `.id` when present, else a stable composite of the
    // tracked tuple (+ direction/state fields where the version exposes them).
    let id = rosStr(r, ['.id']);
    if (id === '') {
      const parts = [
        rosStr(r, ['src-address', 'src_address']),
        rosStr(r, ['dst-address', 'dst_address']),
        rosStr(r, ['proto', 'protocol']),
        rosStr(r, ['src-port', 'src_port']),
        rosStr(r, ['dst-port', 'dst_port']),
        rosStr(r, ['connection-state', 'state']),
        rosStr(r, ['direction']),
      ];
      id = parts.join('|');
    }
    if (id === '') continue; // no stable identity — can't diff reliably
    const srcIp = rosStr(r, ['src-address', 'src_address']);
    const dstIp = rosStr(r, ['dst-address', 'dst_address']);
    if (!isInternalEndpoint(srcIp) && !isInternalEndpoint(dstIp)) continue; // internet-only connection
    out.push({ id, srcIp: isInternalEndpoint(srcIp) ? srcIp : '', dstIp: isInternalEndpoint(dstIp) ? dstIp : '' });
  }
  return out; // [] = genuinely empty table (a real observation)
}

/** Per-endpoint open-connection counts for one snapshot (internal endpoints only). */
export function countOpenStates(states: ConnectionIdentity[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const s of states) {
    if (s.srcIp !== '') counts.set(s.srcIp, (counts.get(s.srcIp) ?? 0) + 1);
    if (s.dstIp !== '' && s.dstIp !== s.srcIp) counts.set(s.dstIp, (counts.get(s.dstIp) ?? 0) + 1);
  }
  return counts;
}

/**
 * Diffs two consecutive snapshots into per-endpoint created/destroyed deltas.
 * A connection "created" since the last walk is one whose id was NOT in
 * `before`; a connection "destroyed" is one that WAS in `before` but is gone
 * now. Each delta is attributed to BOTH of the connection's internal endpoints.
 * Returns null deltas when there was no baseline (`before === null`) — the
 * caller must not treat those as 0.
 */
export function diffStates(
  before: Map<string, { srcIp: string; dstIp: string }> | null,
  now: ConnectionIdentity[]
): { created: Map<string, number>; destroyed: Map<string, number> } | null {
  if (before === null) return null; // first walk — no baseline to diff against

  const nowIds = new Set(now.map((s) => s.id));
  const created = new Map<string, number>();
  const destroyed = new Map<string, number>();

  for (const s of now) {
    if (!before.has(s.id)) {
      if (s.srcIp !== '') created.set(s.srcIp, (created.get(s.srcIp) ?? 0) + 1);
      if (s.dstIp !== '' && s.dstIp !== s.srcIp) created.set(s.dstIp, (created.get(s.dstIp) ?? 0) + 1);
    }
  }
  for (const [id, s] of before.entries()) {
    if (!nowIds.has(id)) {
      if (s.srcIp !== '') destroyed.set(s.srcIp, (destroyed.get(s.srcIp) ?? 0) + 1);
      if (s.dstIp !== '' && s.dstIp !== s.srcIp) destroyed.set(s.dstIp, (destroyed.get(s.dstIp) ?? 0) + 1);
    }
  }
  return { created, destroyed };
}

/** Merges open-state counts + churn deltas into the push rows for one walk. */
export function buildHostStateRows(
  open: Map<string, number>,
  diff: { created: Map<string, number>; destroyed: Map<string, number> } | null
): HostStateRow[] {
  const ips = new Set<string>([...open.keys()]);
  if (diff) {
    for (const ip of diff.created.keys()) ips.add(ip);
    for (const ip of diff.destroyed.keys()) ips.add(ip);
  }
  return Array.from(ips).map((ip) => ({
    ip,
    openStates: open.get(ip) ?? 0,
    // Baseline exists → a missing delta is a real zero. No baseline (first
    // walk / restart) → null so the API's window SUM skips it instead of
    // counting a bogus spike.
    created: diff ? (diff.created.get(ip) ?? 0) : null,
    destroyed: diff ? (diff.destroyed.get(ip) ?? 0) : null,
  }));
}
