/**
 * FRR/OSPF monitoring — routing-protocol state over the optional SSH slot
 * (LEGACY FALLBACK PATH since v0.10.0).
 *
 * Why this exists: a dead or flapping FRR daemon silently drops every
 * OSPF-learned route from the kernel table while the appliance keeps answering
 * ICMP + REST — dNAT'd and transit traffic then follows the WAN default route
 * into the void (a real incident: FRR died, segment routes vanished, all
 * forwarded TCP to internal segments timed out for hours while ping worked).
 * "Device reachable" can never catch that; only adjacency/route state can.
 *
 * Since v0.10.0 the PRIMARY data path is REST (frrRest.ts): OPNsense's own
 * Diagnostics → Routing screen proves /api/quagga/* exposes neighbor + route
 * state — configd runs vtysh as root on the appliance, so no SSH slot and no frr
 * group membership are required. This module remains for firmware without the
 * quagga REST area (or an ACL-blocked one): it is only invoked when the REST
 * path returns null AND a bound SSH slot exists. Note OPNsense locks ALL FRR
 * state to user/group `frr`, so the SSH fallback needs a root slot (or a member
 * of group frr) — see deriveFrrConditions' permission warning.
 *
 * Protocol scope: since v0.11.0 BGP monitoring (peers + learned routes) exists
 * ONLY on the REST path (frrRest.ts reads /api/quagga/diagnostics/bgpsummary,
 * bgpneighbors and searchBgproute4/6). This SSH fallback stays OSPF-only — a box
 * that needs the legacy path AND runs BGP simply gets no `bgp` section in its
 * result (deriveFrrConditions treats an absent section as "BGP not reported").
 *
 * Data collected in ONE SSH exec (section markers, same style as zfsSsh.ts):
 *   - FRR installed?        [ -d /usr/local/etc/frr ] (permission-free) + ls listing
 *                           (read access only — OPNsense locks the dir to frr:frr,
 *                           so a non-root slot yields "installed but not inspectable")
 *   - OSPF configured?      grep '^router (ospf|ospfv3)' over the frr confs
 *   - v4 neighbors          vtysh "show ip ospf neighbor"
 *   - v6 neighbors          vtysh "show ipv6 ospf6 neighbor"
 *   - learned routes        vtysh "show ip route ospf" / "show ipv6 route ospf6":
 *                           a format-agnostic line count (awk, drives the alerting)
 *                           PLUS the actual table rows (head-capped at 400 per
 *                           family — display detail for the Routes page)
 *   - router ID             vtysh "show ip ospf"
 *
 * Contract:
 *   - Returns null ONLY when the script could not run at all (no ssh slot
 *     bound, login failure, exec threw). A FRR that is DOWN still yields a
 *     RESULT — with frrReachable=false — because THAT is the data point we
 *     alert on. Callers keep their previous cache on null (anti-flap).
 *   - BEST-EFFORT: never throws into /monitoring.
 *   - Cadence + in-flight gating live in decideFrrCollection() (pure, tested);
 *     the caller runs this at most every `frrMonitorIntervalSec` per host.
 */

import { execViaSshSlot } from './zfsSsh';

/** One OSPF adjacency as reported by vtysh (v4 or v6). */
export interface OspfNeighborRow {
  /** 'ospf' (IPv4) | 'ospfv6'. */
  version: 'ospf' | 'ospfv6';
  /** Neighbor's router ID. */
  neighborId: string;
  /** Interface the adjacency sits on ('wg0', 'vtnet1', ... — suffixes stripped). */
  interfaceName: string;
  /** Raw state as printed by vtysh ('Full/-', 'Down', 'Init/Sequenc…', ...). */
  state: string;
  /** True when the adjacency is fully established (state starts with "Full"). */
  full: boolean;
  /** Seconds the adjacency has been up, or null when not parseable. */
  upTimeSeconds?: number | null;
  /** Neighbor's address (v4 only). */
  address?: string | null;
}

/** One learned route entry (OSPF or BGP) as parsed from the quagga diagnostics
 * API or vtysh. Field names match the API's cross-device `routes` table contract
 * exactly, so rows can be merged into the plugin's `routes` metric verbatim —
 * protocol 'ospf'/'bgp' keeps them distinct from static/connected rows in the PK. */
export interface OspfRouteRow {
  /** Destination network as CIDR ("198.51.100.10/24", "fe80::/64"). */
  destination: string;
  /** Next-hop gateway address ('' = summary / directly connected / unknown). */
  gateway: string;
  protocol: 'ospf' | 'bgp';
  /** Administrative distance from the "[dist/metric]" token (null when absent). */
  distance?: number | null;
  /** Route metric/cost from the "[dist/metric]" token (null when absent). */
  metric?: number | null;
  status: 'active';
  extra?: Record<string, unknown>;
}

/** One BGP peer session as reported by the quagga diagnostics API (v0.11.0). */
export interface BgpPeerRow {
  /** Peer address — the key of FRR's `peers` map (IP or neighbor name). */
  neighborId: string;
  /** Remote AS number, when reported. */
  remoteAs?: number | null;
  /** Raw session state ('Established', 'Active', 'Connect', ...); '' when absent. */
  state: string;
  /** True when the session is fully established. */
  established: boolean;
  /** Prefixes received from this peer (only meaningful when established). */
  prefixesReceived?: number | null;
}

/** BGP section of an FRR collection result (v0.11.0, REST path only — the legacy
 * SSH fallback remains OSPF-only). Absent on results that came from the SSH path. */
export interface FrrBgpSection {
  /** At least one peer is reported (or a local AS / router ID is present) = BGP runs here. */
  configured: boolean;
  /** All BGP sessions across address families, deduped by peer. */
  peers: BgpPeerRow[];
  /** Count of BGP-learned routes in the FRR RIB per family (0 when none). */
  v4RoutesLearned?: number | null;
  v6RoutesLearned?: number | null;
  /** This box's local AS, when reported. */
  localAs?: number | null;
}

/** One complete FRR/OSPF collection for a host. */
export interface FrrOspfResult {
  /** /usr/local/etc/frr exists (os-frr package installed) — false = box has no FRR at all (out of scope, silent). */
  frrInstalled: boolean;
  /** We could actually READ the FRR state with this SSH user (config listing or a live vtysh answer).
   * OPNsense locks /usr/local/etc/frr + /var/run/frr to user/group `frr`, so a non-root slot
   * sees an installed-but-uninspectable box — that is its own condition, NOT "no OSPF configured". */
  frrInspectable: boolean;
  /** A `router ospf`/`router ospfv3` block exists in the frr configs (only meaningful when inspectable). */
  ospfConfigured: boolean;
  /** vtysh answered with a recognizable OSPF table — false = FRR stack not responding (the alert case). */
  frrReachable: boolean;
  /** This box's router ID, when parseable. */
  routerId?: string | null;
  /** All adjacencies (v4 + v6 combined), empty when unreachable or none configured. */
  neighbors: OspfNeighborRow[];
  /** Count of OSPF-learned routes in the FRR RIB (null = not parseable / unreachable). */
  v4RoutesLearned?: number | null;
  v6RoutesLearned?: number | null;
  /** All learned route entries — OSPF (both families) plus BGP (v0.11.0, REST
   * path only), each family head-capped — empty when FRR is unreachable. */
  routes: OspfRouteRow[];
  /** BGP state (v0.11.0) — present on REST-path results; absent on the legacy SSH fallback. */
  bgp?: FrrBgpSection;
}

/** One actionable FRR/OSPF condition (drives health reasons + notification mirroring). */
export interface FrrCondition {
  severity: 'warning' | 'critical';
  /** Short one-line message for the status-badge tooltip (≤ ~120 chars, label-prefixed). */
  message: string;
  /** Longer action hint used as the notification-center message body. */
  detail?: string;
  /** Stable dedupe key for the notification center. */
  dedupeKey: string;
}

/** Per-host cadence state for the FRR collection (keyed by management address). */
export interface FrrOspfEntry {
  /** Epoch ms of the last SUCCESSFUL script run — a failed exec retries on the next beat. */
  lastRunAt: number;
  /** A collection is currently in flight for this host (prevents overlap). */
  inFlight: boolean;
}

/** Why the gate allowed or denied an FRR/OSPF collection. */
export type FrrCollectionDecision = 'run' | 'skip-disabled' | 'skip-cadence' | 'skip-inflight';

/** Default interval — 5 min. One ~2–4 s SSH exec per device per 5 min is trivial load; 0 disables the feature entirely. */
export const DEFAULT_FRR_MONITOR_INTERVAL_SEC = 300;

// --- The combined read-only command (single exec round-trip) -----------------
// Runs under /bin/sh via execViaSshSlot's base64 wrapper (csh-safe). Each vtysh
// call is guarded by `timeout 3` so a hung FRR can't hold the SSH channel open
// forever; on healthy boxes every call returns in well under a second.

const FRR_SSH_COMMAND = [
  'echo __FRR_INSTALLED__',
  // Existence test FIRST — stat needs no read permission, so ANY user can tell
  // us the os-frr package is present. The listing below only succeeds for users
  // who may READ the dir (OPNsense locks it to frr:frr) — that distinction is
  // what separates "no FRR" from "FRR present but not inspectable by this user".
  '[ -d /usr/local/etc/frr ] && echo dir-present',
  'ls /usr/local/etc/frr/ 2>/dev/null | head -10',
  'echo __OSPF_CONFIGURED__',
  "grep -lE '^router (ospf|ospfv3)' /usr/local/etc/frr/*.conf 2>/dev/null | head -5",
  'echo __V4_NEIGH__',
  'timeout 3 vtysh -c "show ip ospf neighbor" 2>&1',
  'echo __V6_NEIGH__',
  'timeout 3 vtysh -c "show ipv6 ospf6 neighbor" 2>&1',
  // One vtysh call per family into a temp file, then read it twice: an awk
  // line count (format-agnostic — drives the alerting) and the table itself
  // (head-capped at 400 rows — display detail for the Routes page). Keeping
  // exactly two route vtysh calls preserves today's worst-case time budget.
  'echo __V4_ROUTES__',
  'timeout 3 vtysh -c "show ip route ospf" 2>/dev/null > /tmp/unm_frr_v4.txt',
  "awk 'BEGIN{n=0} /^O/{n++} END{print n}' /tmp/unm_frr_v4.txt 2>/dev/null || echo 0",
  'head -400 /tmp/unm_frr_v4.txt 2>/dev/null',
  'rm -f /tmp/unm_frr_v4.txt',
  'echo __V6_ROUTES__',
  'timeout 3 vtysh -c "show ipv6 route ospf6" 2>/dev/null > /tmp/unm_frr_v6.txt',
  "awk 'BEGIN{n=0} /^O/{n++} END{print n}' /tmp/unm_frr_v6.txt 2>/dev/null || echo 0",
  'head -400 /tmp/unm_frr_v6.txt 2>/dev/null',
  'rm -f /tmp/unm_frr_v6.txt',
  'echo __ROUTER_ID__',
  'timeout 3 vtysh -c "show ip ospf" 2>&1 | head -4',
].join('\n');

/** Splits the combined output into its sections (marker lines). */
export function splitFrrSections(stdout: string): {
  frrInstalled: string;
  ospfConfigured: string;
  v4Neigh: string;
  v6Neigh: string;
  v4Routes: string;
  v6Routes: string;
  routerId: string;
} {
  const out = { frrInstalled: '', ospfConfigured: '', v4Neigh: '', v6Neigh: '', v4Routes: '', v6Routes: '', routerId: '' };
  let current: keyof typeof out | null = null;
  for (const line of stdout.split('\n')) {
    if (line === '__FRR_INSTALLED__') { current = 'frrInstalled'; continue; }
    if (line === '__OSPF_CONFIGURED__') { current = 'ospfConfigured'; continue; }
    if (line === '__V4_NEIGH__') { current = 'v4Neigh'; continue; }
    if (line === '__V6_NEIGH__') { current = 'v6Neigh'; continue; }
    if (line === '__V4_ROUTES__') { current = 'v4Routes'; continue; }
    if (line === '__V6_ROUTES__') { current = 'v6Routes'; continue; }
    if (line === '__ROUTER_ID__') { current = 'routerId'; continue; }
    if (!current) continue;
    out[current] += line + '\n';
  }
  return out;
}

/** True for FRR's own log noise lines that vtysh prints into its output. */
function isNoiseLine(line: string): boolean {
  // "2026-11-15 17:05:02 [H0DHT-S9KF2][EC 100663299] setsockopt_so_recvbuf: ..."
  return /^\d{4}\/\d{2}\/\d{2}\s/.test(line) || line.includes('setsockopt');
}

/** Parses FRR duration strings into seconds. Handles "43m16s", "1h2m3s",
 * "2d5h", "00:43:11" (hh:mm:ss), "90s". Returns null for "-" / unparseable. */
export function parseFrrDuration(v: string | undefined): number | null {
  if (!v) return null;
  const s = v.trim();
  if (s === '' || s === '-') return null;
  // hh:mm:ss or mm:ss
  const clock = s.match(/^(\d+):([0-5]?\d)(?::([0-5]?\d))?$/);
  if (clock) {
    const h = parseInt(clock[1], 10);
    const m = parseInt(clock[2], 10);
    const sec = clock[3] !== undefined ? parseInt(clock[3], 10) : 0;
    // "43:16" is mm:ss in FRR output; "00:43:11" is hh:mm:ss.
    return s.includes(':') && clock[3] !== undefined ? h * 3600 + m * 60 + sec : h * 60 + m;
  }
  // w/d/h/m/s parts (any order, any subset)
  const total = { w: 0, d: 0, h: 0, m: 0, s: 0 };
  let matchedAny = false;
  for (const m of s.matchAll(/(\d+)([wdhms])/gi)) {
    const n = parseInt(m[1], 10);
    if (!Number.isFinite(n)) continue;
    total[m[2].toLowerCase() as keyof typeof total] += n;
    matchedAny = true;
  }
  if (!matchedAny) return null;
  return total.w * 604800 + total.d * 86400 + total.h * 3600 + total.m * 60 + total.s;
}

/** Parses a vtysh "show ip ospf neighbor" section into rows. */
export function parseOspfV4Neighbors(section: string): OspfNeighborRow[] {
  const rows: OspfNeighborRow[] = [];
  for (const rawLine of section.split('\n')) {
    if (!rawLine.trim() || isNoiseLine(rawLine)) continue;
    if (rawLine.includes('Neighbor ID')) continue; // header
    const t = rawLine.trim().split(/\s+/);
    // Neighbor ID, Pri, State, Up Time, Dead Time, Address, Interface[:local], RXmtL RqstL DBsmL
    if (t.length < 7) continue;
    if (!isIpLike(t[0])) continue;
    const state = t[2];
    rows.push({
      version: 'ospf',
      neighborId: t[0],
      interfaceName: (t[6] ?? '').split(':')[0],
      state,
      full: /^full\b/i.test(state),
      upTimeSeconds: parseFrrDuration(t[3]),
      address: isIpLike(t[5]) ? t[5] : null,
    });
  }
  return rows;
}

/** Parses a vtysh "show ipv6 ospf6 neighbor" section into rows. */
export function parseOspfV6Neighbors(section: string): OspfNeighborRow[] {
  const rows: OspfNeighborRow[] = [];
  for (const rawLine of section.split('\n')) {
    if (!rawLine.trim() || isNoiseLine(rawLine)) continue;
    if (rawLine.includes('Neighbor ID')) continue; // header
    const t = rawLine.trim().split(/\s+/);
    // Neighbor ID, Pri, DeadTime, State/IfState, Duration, I/F[State]
    if (t.length < 6) continue;
    if (!isIpLike(t[0])) continue;
    const state = t[3];
    rows.push({
      version: 'ospfv6',
      neighborId: t[0],
      interfaceName: (t[5] ?? '').replace(/\[.*\]$/, ''),
      state,
      full: /^full\b/i.test(state),
      upTimeSeconds: parseFrrDuration(t[4]),
    });
  }
  return rows;
}

/** Loose IP check for neighbor/router IDs (v4 dotted or v6 colon form). */
function isIpLike(v: string): boolean {
  if (!/^[\da-fA-F.:]+$/.test(v)) return false;
  return v.includes('.') || v.includes(':');
}

/** Parses the `show ip ospf` section for "Router ID: x.x.x.x". */
export function parseRouterId(section: string): string | null {
  const m = section.match(/Router ID:\s*([\da-fA-F.:]+)/i);
  return m ? m[1] : null;
}

/** Parses a route-count line (single integer from the script's awk count). */
export function parseRouteCount(section: string): number | null {
  const s = section.trim();
  if (!/^\d+$/.test(s)) return null;
  return parseInt(s, 10);
}

/** Splits a combined route section into its awk count line and the remaining
 * table rows. The script emits the count FIRST (before `head` of the vtysh
 * output), so the first non-empty line is always the count — even when the
 * table itself starts with FRR log noise. */
export function splitRouteSection(section: string): { countLine: string; table: string } {
  const lines = section.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() !== '') return { countLine: lines[i], table: lines.slice(i + 1).join('\n') };
  }
  return { countLine: '', table: '' };
}

/** Parses one OSPF route-table section into rows. Accepts raw vtysh output of
 * "show ip route ospf" / "show ipv6 route ospf6":
 *   O>* 198.51.100.10/24 [110/2] via 203.0.113.78, wg0, 00:43:11
 *   O    198.51.100.0/16 [110/1] is a summary, 02:00:00
 * Route lines start with the protocol code "O" plus optional flag chars (">",
 * "*"). After the destination CIDR comes an optional "[dist/metric]" token and
 * either "via <gw>, <iface>, <age>" or "is a summary"/"is directly connected".
 * The "Codes: …" header, FRR log noise and any non-CIDR line are skipped. */
export function parseOspfRouteTable(section: string, version: 'ospf' | 'ospfv6'): OspfRouteRow[] {
  const rows: OspfRouteRow[] = [];
  for (const rawLine of section.split('\n')) {
    if (!rawLine.trim() || isNoiseLine(rawLine)) continue;
    const t = rawLine.trim().split(/\s+/);
    // Route lines start with the protocol code "O" plus optional flag chars.
    if (!/^O[>*]*$/.test(t[0])) continue;
    const destination = (t[1] ?? '').replace(/,+$/, '');
    if (!destination.includes('/')) continue; // require a CIDR — rejects header noise
    let distance: number | null = null;
    let metric: number | null = null;
    for (const tok of t) {
      const m = tok.match(/^\[(\d+)\/(\d+)\]$/);
      if (m) {
        distance = parseInt(m[1], 10);
        metric = parseInt(m[2], 10);
        break;
      }
    }
    let gateway = '';
    let interfaceName: string | undefined;
    const viaIdx = t.indexOf('via');
    if (viaIdx >= 0) {
      // "via <gw>, <iface>, <age>" — FRR prints trailing commas on the tokens.
      const gwTok = (t[viaIdx + 1] ?? '').replace(/,+$/, '');
      if (isIpLike(gwTok)) gateway = gwTok;
      const ifaceTok = (t[viaIdx + 2] ?? '').replace(/,+$/, '').replace(/[()]/g, '');
      // Interface names start with a letter — this rejects the age token when
      // no interface is printed ("via <gw>, <age>").
      if (ifaceTok !== '' && !/^\d/.test(ifaceTok)) interfaceName = ifaceTok;
    } else {
      // "O <cidr> [d/m] is a summary, 02:00:00" / "is directly connected, wg0".
      // The token after the comma may be an interface OR an age — interface
      // names start with a letter, ages with a digit.
      const m = rawLine.match(/is (?:a summary|directly connected)\s*,\s*([\w.\-]+)/i);
      if (m && !/^\d/.test(m[1])) interfaceName = m[1];
    }
    rows.push({
      destination,
      gateway,
      protocol: 'ospf',
      ...(distance !== null ? { distance } : {}),
      ...(metric !== null ? { metric } : {}),
      status: 'active',
      extra: { version, ...(interfaceName ? { interfaceName } : {}) },
    });
  }
  return rows;
}

/**
 * Collects FRR/OSPF state over the bound `ssh` slot. Returns null when no ssh
 * slot is bound or the exec itself failed (the caller keeps its previous cache
 * and leaves live conditions untouched). A FRR that is DOWN yields a real
 * result with frrReachable=false — that IS the alert case, not an error.
 */
export async function collectFrrOspfViaSsh(
  host: string,
  credentials: Record<string, unknown> | undefined,
  log?: (level: 'info' | 'warn', message: string) => void,
  opts?: { port?: number; timeoutMs?: number },
): Promise<FrrOspfResult | null> {
  const r = await execViaSshSlot(host, credentials, FRR_SSH_COMMAND, {
    port: opts?.port,
    // The script's own `timeout 3` guards bound each vtysh call; the outer
    // budget covers four of them plus overhead on a hung box.
    timeoutMs: opts?.timeoutMs ?? 15_000,
  });
  if (r === null) return null; // no ssh slot / login failed — feature skipped

  const sections = splitFrrSections(r.stdout);
  if (!sections.v4Neigh && !sections.v6Neigh && !sections.routerId) {
    log?.('warn', `FRR/OSPF collection on ${host}: unexpected output (exit ${r.code}): ${r.stderr.slice(0, 200)}`);
    return null;
  }

  // dir-present comes from the permission-free existence test; any OTHER line in
  // the section is a file listing — which only appears when this user may READ
  // the FRR state (OPNsense locks /usr/local/etc/frr to frr:frr).
  const frrInstalled = sections.frrInstalled.includes('dir-present');
  const frrStateReadable = sections.frrInstalled
    .split('\n')
    .some((line) => line.trim() !== '' && line !== 'dir-present');
  const ospfConfigured = sections.ospfConfigured.trim() !== '';
  // vtysh answered when it prints the neighbor-table header (even with zero
  // neighbors) or a parseable router ID — connection errors print neither.
  const frrReachable = /Neighbor ID/.test(sections.v4Neigh + sections.v6Neigh) || parseRouterId(sections.routerId) !== null;

  const neighbors = [
    ...parseOspfV4Neighbors(sections.v4Neigh),
    ...parseOspfV6Neighbors(sections.v6Neigh),
  ];

  // Route sections carry the awk count line FIRST, then the (head-capped)
  // table. The count is format-agnostic and drives alerting; the parsed rows
  // feed the cross-device Routes page via the plugin's `routes` metric.
  const v4RouteSection = splitRouteSection(sections.v4Routes);
  const v6RouteSection = splitRouteSection(sections.v6Routes);

  return {
    frrInstalled,
    // Read access to the configs OR a live vtysh answer — either proves this
    // user can inspect FRR state; neither = installed-but-uninspectable.
    frrInspectable: frrStateReadable || frrReachable,
    ospfConfigured,
    frrReachable,
    routerId: parseRouterId(sections.routerId) ?? null,
    neighbors,
    v4RoutesLearned: frrReachable ? parseRouteCount(v4RouteSection.countLine) : null,
    v6RoutesLearned: frrReachable ? parseRouteCount(v6RouteSection.countLine) : null,
    routes: frrReachable
      ? [...parseOspfRouteTable(v4RouteSection.table, 'ospf'), ...parseOspfRouteTable(v6RouteSection.table, 'ospfv6')]
      : [],
  };
}

/**
 * Pure cadence gate for the FRR/OSPF collection (unit-tested in isolation).
 * - `everyMs === 0` → disabled by setting, never runs.
 * - a collection already in flight → skip (overlapping polls must not stack SSH execs).
 * - cadence not elapsed since the last SUCCESSFUL run → skip. A "successful run"
 *   is any non-null result — INCLUDING a FRR-down result (frrReachable=false),
 *   which is exactly the data point we alert on, so a down FRR re-checks on the
 *   normal schedule. Only a null result (no SSH slot / login failure) does NOT
 *   advance lastRunAt → those retry on every beat until SSH recovers.
 */
export function decideFrrCollection(
  entry: FrrOspfEntry | undefined,
  nowMs: number,
  everyMs: number,
): FrrCollectionDecision {
  if (everyMs === 0) return 'skip-disabled';
  if (entry?.inFlight) return 'skip-inflight';
  if (entry !== undefined && nowMs - entry.lastRunAt < everyMs) return 'skip-cadence';
  return 'run';
}

/**
 * Derives the actionable conditions from one fresh FRR/OSPF result. Pure —
 * all state lives in the caller's notification known-sets. Returns [] (not
 * null) when there is nothing to report; callers pass `null` upstream instead
 * when they have NO fresh data at all (anti-flap contract).
 */
export function deriveFrrConditions(result: FrrOspfResult | null, hostname?: string): FrrCondition[] {
  if (!result) return []; // no fresh data — caller must not touch known-sets
  const label = hostname && hostname.trim() !== '' ? hostname : 'appliance';
  const conditions: FrrCondition[] = [];

  // Box without FRR at all → out of scope, stay silent.
  if (!result.frrInstalled) return [];

  // FRR is installed but this SSH user cannot read its state (OPNsense locks
  // /usr/local/etc/frr + the vtysh sockets to user/group `frr`). We must NOT
  // call that "OSPF not configured" — say what we actually know.
  if (!result.frrInspectable) {
    conditions.push({
      severity: 'warning',
      message: `${label}: OSPF state not inspectable with the bound SSH user`,
      detail:
        "OPNsense locks FRR config and vtysh sockets to user/group 'frr'. Bind a root SSH slot (or add the slot user to group frr) to monitor routing-protocol state.",
      dedupeKey: `frr-permissions:${label}`,
    });
    return conditions;
  }

  // FRR installed but NO routing protocol configured (neither OSPF nor BGP):
  // nothing to monitor here — the box doesn't participate in a routing domain.
  if (!result.ospfConfigured && !result.bgp?.configured) return [];

  if (!result.frrReachable) {
    conditions.push({
      severity: 'critical',
      message: `${label}: FRR routing daemons not responding (down?)`,
      detail:
        'Routing-protocol state (OSPF/BGP) is unreachable — learned routes are likely missing from the kernel table and traffic to routed segments can blackhole while the box still answers ping. Check FRR on the appliance.',
      dedupeKey: `frr-ospf:${label}`,
    });
    return conditions; // no adjacency/peer data to evaluate while unreachable
  }

  // OSPF block — only when this box participates in an OSPF domain.
  if (result.ospfConfigured) {
    for (const n of result.neighbors) {
      if (n.full) continue;
      conditions.push({
        severity: 'warning',
        message: `${label}: OSPF${n.version === 'ospfv6' ? 'v6' : ''} neighbor ${n.neighborId} on ${n.interfaceName} is ${n.state} (not Full)`,
        detail: `Adjacency not fully established — routes via ${n.interfaceName} are at risk. Check the link and OSPF configuration.`,
        dedupeKey: `ospf-neighbor:${n.version}:${n.interfaceName}:${n.neighborId}`,
      });
    }

    const fullCount = result.neighbors.filter((n) => n.full).length;
    if (fullCount > 0 && (result.v4RoutesLearned ?? 0) === 0 && (result.v6RoutesLearned ?? 0) === 0) {
      conditions.push({
        severity: 'warning',
        message: `${label}: OSPF adjacencies up but zero routes learned`,
        detail: 'All adjacencies are Full yet no routes were learned — check area membership, authentication and network statements.',
        dedupeKey: `ospf-routes-zero:${label}`,
      });
    }
  }

  // BGP block (v0.11.0) — only when this box runs BGP (REST path).
  const bgp = result.bgp;
  if (bgp?.configured && bgp.peers.length > 0) {
    for (const p of bgp.peers) {
      if (p.established) continue;
      conditions.push({
        severity: 'warning',
        message: `${label}: BGP peer ${p.neighborId} is ${p.state || 'down'} (not Established)`,
        detail: `BGP session not established — routes via this peer are at risk. Check reachability, AS numbers and peering configuration.`,
        dedupeKey: `bgp-peer:${p.neighborId}`,
      });
    }

    const estCount = bgp.peers.filter((p) => p.established).length;
    if (estCount === 0) {
      conditions.push({
        severity: 'critical',
        message: `${label}: all ${bgp.peers.length} BGP session(s) down`,
        detail:
          'No BGP session is established — BGP-learned routes (often the WAN default route) are missing from the kernel table. Traffic can blackhole while the box still answers ping.',
        dedupeKey: `bgp-all-down:${label}`,
      });
    }
  }

  return conditions;
}
