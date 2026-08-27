/**
 * LCOS-SX collection for Lancom SX-Series switches (GS / IGS / XS).
 *
 * Two firmware lines, two OID trees — auto-detected per device:
 *   sx4: unified lcosSX tree (.1.3.6.1.4.1.2356.14)  — full feature set
 *   sx3: legacy GS-2310 tree (…2356.800.3.2313)      — system + ports only
 *
 * Two tiers (mirrors the lancom-lcos router plugin):
 *  - SLOW path: targeted parallel walks over exactly the subtrees we use,
 *    TTL-cached per host. A broad walk of the whole tree is NOT viable — it
 *    drags in ACL/MVR/MEP tables we never read and would blow the API's 10s
 *    poll budget on a 52-port switch; the targeted set below completes fast.
 *  - FAST path (every poll): port byte-counter walk → rx/tx rates via
 *    per-host baseline deltas (reset/wrap ⇒ skip).
 *
 * The MIB is read-only here; the writable port/PoE/LACP/VLAN objects are used
 * by the config actions in src/actions/, never by this module.
 */

import { SnmpCredentials, TransportOptions, snmpGet, snmpWalk, suffixOf, normalizeMac } from '@unm/snmp-client';
import { CounterTracker, TtlCache } from '@unm/plugin-sdk';
import {
  DETECT, SX4_BASE, SX3_BASE,
  SX4_SYS, SX4_PSU, SX4_PORT_CONF, SX4_PORT_TRAFFIC, SX4_VLAN, SX4_SVI, SX4_NEIGHBOR,
  SX4_IP_ROUTES, SX4_IP_STATUS_ROUTES,
  SX4_POE_STATUS, SX4_POE_TOTALS, SX4_LACP_STATUS,
  SX3_SYS, SX3_PORT_CONF, SX3_PORT_TRAFFIC, QB_FDB,
} from './sxOids';

/* ------------------------------------------------------------------ *
 * Options + result types
 * ------------------------------------------------------------------ */

export interface SxOptions extends TransportOptions {
  /** How long the slow-path snapshot stays fresh. */
  inventoryTtlMs: number;
  /** Walk Q-BRIDGE FDB to enrich host rows with their learned-on port.
   *  OFF by default — on a populated switch this walk takes ~15-20s and
   *  blows the API's poll budget; enable per-device only when wanted. */
  enrichHostPorts: boolean;
}

/** Which LCOS-SX MIB tree a device answers on. */
export type SxVariant = 'sx4' | 'sx3';

/** One switch port (config + VLAN view). */
export interface SxPort {
  port: number; // panel port number (= ifIndex)
  label: string; // description when set, else "Port <n>"
  linkUp: boolean | null;
  speedStatus: string; // DisplayString as reported ("1G FDX"), '' when unknown
  media: string; // sx3 only — copper/SFP hint, '' otherwise
  vlanModeLabel: string; // 'access'/'trunk'/'hybrid', '' on 3.x or when absent
  pvid: number | null;
  allowedVlans: string; // DisplayString list "1,10-13", '-' or '' when empty
}

/** One PoE port from lcsPoeStatusTable (4.x only). */
export interface SxPoePort {
  port: number;
  pdClass: string;
  powerRequestedWatts: number | null;
  powerAllocatedWatts: number | null;
  powerUsedWatts: number | null;
  currentUsedAmps: number | null;
  priorityLabel: string; // 'low'/'high'/'critical', '' when unknown
  portStatusLabel: string; // DisplayString as reported, '' when unknown
}

/** Switch-wide PoE totals (4.x only). */
export interface SxPoeTotals {
  requestedWatts: number | null;
  allocatedWatts: number | null;
  usedWatts: number | null;
}

/** One LACP member port from lcsLACPStatusTable (4.x only). */
export interface SxLagPort {
  port: number;
  lacpLabel: string; // 'Yes' / 'No' / 'Backup'
  key: string;
  aggrId: string;
  partnerSystemId: string; // MAC of the aggregation partner, '' when unknown
  partnerPort: string;
}

/** One configured IP network (SVI on 4.x, management address on 3.x). */
export interface SxNetwork {
  name: string; // "VLAN <id>" / "Management"
  ip: string;
  prefix: number | null;
  version: 'v4' | 'v6';
  vlanId: number | null;
}

/** One neighbor-cache entry (ARP/NDP) with optional FDB port enrichment. */
export interface SxNeighbor {
  mac: string; // normalized aa:bb:cc:dd:ee:ff, '' when absent
  ip: string; // v4 dotted-quad or v6 literal
  version: 'v4' | 'v6';
  port: number | null; // learned-on port from Q-BRIDGE FDB, null when unknown
}

/** One route entry from the switch's routing tables (4.x only). */
export interface SxRoute {
  destination: string; // CIDR ("10.25.0.0/16") or bare address as reported
  gateway: string;     // '' = directly connected / unknown
  protocol: 'static' | 'connected'; // matched against the static config table
  distance: number | null; // admin distance from the config table (null for connected)
}

/** The full slow-path snapshot for one host. */
export interface SxSwitchSnapshot {
  collectedAt: number;
  variant: SxVariant;
  system: {
    name: string;
    model: string;
    firmwareVersion: string;
    serialNumber: string;
    hostMac: string; // normalized, '' when unavailable
    uptimeText: string; // DisplayString as reported
    cpuLoadPct: number | null;
    memoryTotalMb: number | null;
    memoryFreeMb: number | null;
    temperatureC: (number | null)[]; // up to 3 sensors, null when absent/unparseable
    fanSpeedText: string; // DisplayString as reported, '' when unknown
    psuAStatus: string; // DisplayString, '' when not present on this model
    psuBStatus: string;
  };
  ports: SxPort[];
  poePorts: SxPoePort[]; // empty on 3.x / non-PoE models
  poeTotals: SxPoeTotals | null;
  lags: SxLagPort[]; // empty on 3.x or when no LACP is configured
  networks: SxNetwork[];
  neighbors: SxNeighbor[];
  routes: SxRoute[]; // live routing table (4.x only — the 3.x tree has none)
}

/* ------------------------------------------------------------------ *
 * Enum label maps (from the MIBs' SYNTAX INTEGER value blocks)
 * ------------------------------------------------------------------ */

const VLAN_MODES: Record<number, string> = { 0: 'access', 1: 'trunk', 2: 'hybrid' };

function label(map: Record<number, string>, raw: string | undefined): string {
  if (raw === undefined || raw === '') return '';
  const n = Number(raw);
  return Number.isFinite(n) ? map[n] ?? String(n) : raw;
}

function toInt(value: string | undefined): number | null {
  if (value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/** Extracts a leading numeric value from DisplayStrings like "12.5", "30 W", "45 C". */
function toNumberLoose(value: string | undefined): number | null {
  if (value === undefined) return null;
  const m = value.match(/-?\d+(?:\.\d+)?/);
  return m ? Number(m[0]) : null;
}

/** Parses the CPU-load DisplayString. LCOS-SX 4.x reports multiple time
 *  windows in ONE string — live-verified on a GS-3510XP:
 *    "100ms:0%, 1s:4%, 10s:3%"
 *  A naive leading-number match grabs the WINDOW label ("100") and reports
 *  100% forever. Prefer the longest window present (10s → 1s → 100ms) as the
 *  stable gauge value; fall back to a bare percentage for other formats. */
function parseCpuLoadPct(value: string | undefined): number | null {
  if (value === undefined || value.trim() === '') return null;
  const t = value.trim();
  for (const window of ['10s', '1s', '100ms']) {
    const m = t.match(new RegExp(`${window}\\s*:\\s*(\\d+(?:\\.\\d+)?)%?`));
    if (m) return Math.max(0, Math.min(100, Number(m[1])));
  }
  // Fallback: any bare percentage in the string.
  const p = t.match(/(\d+(?:\.\d+)?)%/);
  if (p) return Math.max(0, Math.min(100, Number(p[1])));
  return toNumberLoose(t);
}

/** Parses memory DisplayStrings like "500 M" / "1.2 G" (LCOS-SX reports the
 *  total as a string, not an integer) into MB; plain integers pass through. */
function toMbLoose(value: string | undefined): number | null {
  if (value === undefined || value.trim() === '') return null;
  const m = value.match(/(\d+(?:\.\d+)?)\s*([KMG])?/i);
  if (!m) return null;
  const n = Number(m[1]);
  switch ((m[2] ?? '').toUpperCase()) {
    case 'G': return Math.round(n * 1024);
    case 'M': return Math.round(n);
    case 'K': return Math.max(1, Math.round(n / 1024)); // KB → MB (round up)
    default: return n; // bare number = already MB
  }
}

/* ------------------------------------------------------------------ *
 * OID row decoding — LANCOM addresses table rows COLUMN-FIRST:
 *   <tableBase>.1.<column>.<index…>
 * (the leading "1" is the not-accessible entry object). All SX tables are
 * indexed by plain Integer32 values, so index recovery is trivial.
 * ------------------------------------------------------------------ */

/** Splits a column-first row OID into column number + index components. */
function splitRow(oid: string, base: string): { col: number; idx: string[] } | null {
  const suffix = suffixOf(oid, base); // "<entry>.<col>.<idx…>"
  if (!suffix) return null;
  const parts = suffix.split('.');
  if (parts.length < 3 || parts[0] !== '1') return null; // entry + col + ≥1 idx part
  const col = Number(parts[1]);
  if (!Number.isInteger(col)) return null;
  return { col, idx: parts.slice(2) };
}

/** Converts a dotted-quad netmask to its CIDR prefix length (null on bad input). */
function netmaskToPrefix(netmask: string): number | null {
  const parts = (netmask ?? '').split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  let prefix = 0;
  for (const part of parts) {
    let octet = part;
    while (octet & 0x80) { prefix++; octet = (octet << 1) & 0xff; }
    if (octet !== 0) return null; // non-contiguous mask — don't guess
  }
  return prefix === 0 ? null : prefix;
}

/* ------------------------------------------------------------------ *
 * Firmware-line auto-detection
 * ------------------------------------------------------------------ */

const variantCache = new Map<string, SxVariant>();

/**
 * Determines which LCOS-SX tree the device answers on. TWO independent
 * single-OID probes — a combined multi-OID snmpget is NOT an option: older
 * agents (verified live on a GS-2310, fw 3.34) fail the WHOLE request with
 * noSuchName when the first OID is unknown — even though the second OID's
 * valid answer is printed in the same output — and exit non-zero, so the
 * wrapper throws and detection would report "SNMP query failed" for a
 * perfectly good legacy switch. The result is cached per host for the process
 * lifetime: a switch does not change MIB tree without a firmware upgrade.
 */
export async function detectVariant(
  host: string,
  creds: SnmpCredentials,
  opts: SxOptions
): Promise<{ variant: SxVariant | null; error?: string }> {
  const cached = variantCache.get(host);
  if (cached) return { variant: cached };

  /** One single-OID probe. `agentAnswered` distinguishes "the agent replied but
   *  this OID is unknown" from a transport-level failure (unreachable host or
   *  rejected credentials — the agent stays silent, net-snmp times out). */
  const probe = async (oid: string): Promise<{ value?: string; agentAnswered: boolean }> => {
    try {
      const m = await snmpGet(host, creds, [oid], opts);
      return { value: m.get(oid), agentAnswered: true };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { agentAnswered: /noSuchName|No Such Object|No Such Instance/i.test(msg) };
    }
  };

  // sx4 first — the unified tree is what every modern GS/IGS/XS switch serves.
  const p4 = await probe(DETECT.sx4Model);
  if (p4.value !== undefined) { variantCache.set(host, 'sx4'); return { variant: 'sx4' }; }

  // No agent answer at all → the host is unreachable / credentials rejected; a
  // second full-timeout probe would only double the wait for nothing.
  if (!p4.agentAnswered) {
    return { variant: null, error: 'SNMP query failed — device unreachable or credentials rejected.' };
  }

  const p3 = await probe(DETECT.sx3Model);
  if (p3.value !== undefined) { variantCache.set(host, 'sx3'); return { variant: 'sx3' }; }

  // Neither tree present. Only report a transport error when the agent never
  // answered at all — otherwise it's simply not a Lancom SX switch.
  if (!p4.agentAnswered && !p3.agentAnswered) {
    return { variant: null, error: 'SNMP query failed — device unreachable or credentials rejected.' };
  }
  return { variant: null };
}

/* ------------------------------------------------------------------ *
 * Slow path — targeted parallel walks of the runtime-status subtrees we use
 * ------------------------------------------------------------------ */

// Fresh-snapshot cache (TTL-gated) + a last-known map so a failed refresh can
// still fall back to the most recent data even after TTL expiry.
const inventoryCache = new TtlCache<SxSwitchSnapshot>();
const lastKnown = new Map<string, SxSwitchSnapshot>();
function rememberLastKnown(host: string, snapshot: SxSwitchSnapshot): void {
  lastKnown.set(host, snapshot);
  if (lastKnown.size > 512) {
    const oldest = lastKnown.keys().next().value; // Map iteration = insertion order
    if (oldest !== undefined) lastKnown.delete(oldest);
  }
}

/** The exact subtrees the slow path needs per variant — nothing else. */
function inventoryWalks(variant: SxVariant): string[] {
  if (variant === 'sx4') {
    return [
      SX4_SYS.base, // system + PSU-adjacent scalars (model, fw, serial, mem, CPU, temps)
      SX4_PSU.base, // dual-PSU status/fans/temps
      SX4_PORT_CONF.base, // per-port link/speed/description
      SX4_VLAN.base, // per-port VLAN mode/PVID/allowed list
      SX4_SVI.base, // configured IP interfaces (VLAN SVIs) → networks inventory
      SX4_IP_STATUS_ROUTES.base, // live routing table → routes inventory
      SX4_IP_ROUTES.base, // static route config (distance enrichment) → routes inventory
      SX4_NEIGHBOR.base, // ARP/NDP neighbor cache → hosts inventory
      SX4_POE_STATUS.base, // per-PoE-port power status
      SX4_POE_TOTALS.base, // switch-wide PoE totals
      SX4_LACP_STATUS.base, // LACP member state (LAG view)
    ];
  }
  return [
    SX3_SYS.base, // system scalars (model, fw, serial, mem, CPU, mgmt IP)
    SX3_PORT_CONF.base, // per-port link/speed/description/media
  ];
}

/** The FDB walk is a separate, opt-in step — see SxOptions.enrichHostPorts. */
function enrichmentWalks(): string[] {
  return [QB_FDB.base];
}

/**
 * Returns the cached SX snapshot for a host, re-walking only when the cache is
 * empty or older than `inventoryTtlMs`. Never throws — degrades to stale/empty
 * data with an explanatory error. A null snapshot means "not a recognized
 * Lancom SX switch" (the caller maps that to health 'unknown').
 */
export async function getSxInventory(
  host: string,
  creds: SnmpCredentials,
  opts: SxOptions
): Promise<{ snapshot: SxSwitchSnapshot | null; fromCache: boolean; error?: string }> {
  const cached = inventoryCache.get(host, opts.inventoryTtlMs);
  if (cached) {
    return { snapshot: cached, fromCache: true };
  }
  const stale = lastKnown.get(host); // expired-but-usable fallback

  // Probe gate first — cheap rejection of non-SX devices / bad credentials.
  const det = await detectVariant(host, creds, opts);
  if (det.error) {
    return { snapshot: stale ?? null, fromCache: stale !== undefined, error: det.error };
  }
  if (!det.variant) {
    // Agent answered but has neither SX tree — not a Lancom SX switch.
    variantCache.delete(host); // allow re-detection after a firmware upgrade
    return { snapshot: null, fromCache: false, error: 'No LCOS-SX MIB data on this device.' };
  }

  const out = new Map<string, string>();
  // Walks run STRICTLY SEQUENTIALLY. Verified on a GS-3510XP (4.30): running
  // two snmpwalk sessions concurrently makes the agent's response buffer race —
  // DisplayString values come back corrupted with fragments of OTHER rows in
  // the same table (e.g. every neighbor-cache MAC gained "…fe02:279e" from a
  // v6 address row). Sequential walks are clean; total ~5s on a 48-port switch,
  // comfortably inside the API's 10s poll budget. Do NOT parallelize this back.
  const failed: string[] = [];
  for (const oid of inventoryWalks(det.variant)) {
    try {
      const r = await snmpWalk(host, creds, [oid], opts);
      for (const [k, v] of r) out.set(k, v);
    } catch (e: unknown) {
      console.error(`[lancom-sx] inventory walk ${oid} failed:`, e instanceof Error ? e.message : e);
      failed.push(oid);
    }
  }

  // Opt-in FDB enrichment (slow on populated switches — see SxOptions).
  if (opts.enrichHostPorts) {
    for (const oid of enrichmentWalks()) {
      try {
        const r = await snmpWalk(host, creds, [oid], opts);
        for (const [k, v] of r) out.set(k, v);
      } catch (e: unknown) {
        console.error(`[lancom-sx] FDB enrichment walk failed:`, e instanceof Error ? e.message : e);
        // Best-effort — host rows simply lack port info this cycle.
      }
    }
  }

  // One retry for anything that threw (still sequential).
  let failures = 0;
  for (const oid of failed) {
    try {
      const retry = await snmpWalk(host, creds, [oid], opts);
      for (const [k, v] of retry) out.set(k, v);
    } catch {
      failures++; // still failing after the retry — subtree stays empty this cycle
    }
  }

  if (out.size === 0 && failures > 0) {
    return { snapshot: stale ?? null, fromCache: stale !== undefined, error: 'SNMP walk of the LCOS-SX status tree failed.' };
  }
  if (out.size === 0) {
    variantCache.delete(host);
    return { snapshot: null, fromCache: false, error: 'No LCOS-SX MIB data on this device.' };
  }

  const snapshot = parseSxStatus(out, det.variant);

  // Quality gate before caching: the serial number comes from a WALK (not the
  // probe scalar), and any walk failure leaves whole table groups empty — a
  // partial artifact must never be served from cache for the whole TTL. It's
  // returned once and the next poll retries fresh.
  const complete = snapshot.system.serialNumber !== '' && failures === 0;
  if (complete) {
    inventoryCache.set(host, snapshot);
    rememberLastKnown(host, snapshot);
  }

  return {
    snapshot,
    fromCache: false,
    error: complete ? undefined : 'Partial LCOS-SX data — some SNMP walks failed; retrying next cycle.',
  };
}

/** Parses the targeted SX walk output into a typed snapshot. */
function parseSxStatus(out: Map<string, string>, variant: SxVariant): SxSwitchSnapshot {
  const get = (oid: string): string => out.get(oid) ?? '';

  if (variant === 'sx4') return parseSx4(out, get);
  return parseSx3(out, get);
}

function parseSx4(out: Map<string, string>, get: (oid: string) => string): SxSwitchSnapshot {
  // --- System scalars -------------------------------------------------
  // memoryTotal is a DisplayString ("500 M"); freeMem is an Integer32 in MB.
  const memTotal = toMbLoose(get(SX4_SYS.memoryTotalMb));
  const memFree = toInt(get(SX4_SYS.memoryFreeMb));

  // --- Ports (index: panel port int) -----------------------------------
  const ports = new Map<number, Partial<SxPort>>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_PORT_CONF.base);
    if (!row || row.idx.length !== 1) continue;
    const port = Number(row.idx[0]);
    if (!Number.isInteger(port)) continue;
    let p = ports.get(port);
    if (!p) { p = {}; ports.set(port, p); }
    switch (row.col) {
      case SX4_PORT_CONF.COL_DESCRIPTION: p.label = value.trim(); break;
      case SX4_PORT_CONF.COL_LINK: p.linkUp = /^up$/i.test(value.trim()) ? true : /^down$/i.test(value.trim()) ? false : null; break;
      case SX4_PORT_CONF.COL_SPEED_STATUS: p.speedStatus = value.trim(); break;
    }
  }

  // --- VLAN view per port (index: ifIndex = panel port) ------------------
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_VLAN.base);
    if (!row || row.idx.length !== 1) continue;
    const port = Number(row.idx[0]);
    if (!Number.isInteger(port)) continue;
    let p = ports.get(port);
    if (!p) { p = {}; ports.set(port, p); }
    switch (row.col) {
      case SX4_VLAN.COL_MODE: p.vlanModeLabel = label(VLAN_MODES, value); break;
      case SX4_VLAN.COL_PVID: p.pvid = toInt(value); break;
      case SX4_VLAN.COL_ALLOWED_VLANS: p.allowedVlans = value.trim() === '-' ? '' : value.trim(); break;
    }
  }

  // --- PoE status (index: local port int) --------------------------------
  const poePorts: SxPoePort[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_POE_STATUS.base);
    if (!row || row.idx.length !== 1) continue;
    const port = Number(row.idx[0]);
    if (!Number.isInteger(port)) continue;
    let e = poePorts.find((x) => x.port === port);
    if (!e) {
      e = { port, pdClass: '', powerRequestedWatts: null, powerAllocatedWatts: null, powerUsedWatts: null, currentUsedAmps: null, priorityLabel: '', portStatusLabel: '' };
      poePorts.push(e);
    }
    switch (row.col) {
      case SX4_POE_STATUS.COL_PD_CLASS: e.pdClass = value.trim(); break;
      case SX4_POE_STATUS.COL_POWER_REQUESTED: e.powerRequestedWatts = toNumberLoose(value); break;
      case SX4_POE_STATUS.COL_POWER_ALLOCATED: e.powerAllocatedWatts = toNumberLoose(value); break;
      case SX4_POE_STATUS.COL_POWER_USED: e.powerUsedWatts = toNumberLoose(value); break;
      case SX4_POE_STATUS.COL_CURRENT_USED: e.currentUsedAmps = toNumberLoose(value); break;
      case SX4_POE_STATUS.COL_PRIORITY: e.priorityLabel = value.trim().toLowerCase(); break;
      case SX4_POE_STATUS.COL_PORT_STATUS: e.portStatusLabel = value.trim(); break;
    }
  }

  // --- PoE totals (index: switch int — take the first populated row) ------
  let poeTotals: SxPoeTotals | null = null;
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_POE_TOTALS.base);
    if (!row || row.idx.length !== 1) continue;
    poeTotals ??= { requestedWatts: null, allocatedWatts: null, usedWatts: null };
    switch (row.col) {
      case SX4_POE_TOTALS.COL_TOTAL_REQUESTED: poeTotals.requestedWatts = toNumberLoose(value); break;
      case SX4_POE_TOTALS.COL_TOTAL_ALLOCATED: poeTotals.allocatedWatts = toNumberLoose(value); break;
      case SX4_POE_TOTALS.COL_TOTAL_USED: poeTotals.usedWatts = toNumberLoose(value); break;
    }
  }

  // --- LACP status (index: port int) --------------------------------------
  const lags: SxLagPort[] = [];
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_LACP_STATUS.base);
    if (!row || row.idx.length !== 1) continue;
    const port = Number(row.idx[0]);
    if (!Number.isInteger(port)) continue;
    let e = lags.find((x) => x.port === port);
    if (!e) { e = { port, lacpLabel: '', key: '', aggrId: '', partnerSystemId: '', partnerPort: '' }; lags.push(e); }
    switch (row.col) {
      case SX4_LACP_STATUS.COL_LACP: e.lacpLabel = value.trim(); break;
      case SX4_LACP_STATUS.COL_KEY: e.key = value.trim(); break;
      case SX4_LACP_STATUS.COL_AGGR_ID: e.aggrId = value.trim(); break;
      case SX4_LACP_STATUS.COL_PARTNER_SYSTEM_ID: e.partnerSystemId = normalizeMac(value); break;
      case SX4_LACP_STATUS.COL_PARTNER_PORT: e.partnerPort = value.trim(); break;
    }
  }

  // --- Networks from SVI/IP-interface rows (index: int) --------------------
  // Collect per-index fields first, then emit one row per address family —
  // the API's networks table is keyed by ip, and v6 rows carry their own prefix.
  const sviByIndex = new Map<number, { vlanId: number | null; ip4: string; pfx4: number | null; ip6: string; pfx6: number | null }>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_SVI.base);
    if (!row || row.idx.length !== 1) continue;
    const idx = Number(row.idx[0]);
    if (!Number.isInteger(idx)) continue;
    let s = sviByIndex.get(idx);
    if (!s) { s = { vlanId: null, ip4: '', pfx4: null, ip6: '', pfx6: null }; sviByIndex.set(idx, s); }
    switch (row.col) {
      case SX4_SVI.COL_VLAN: s.vlanId = toInt(value); break;
      case SX4_SVI.COL_IPV4_ADDRESS: if (value && value !== '0.0.0.0') s.ip4 = value.trim(); break;
      case SX4_SVI.COL_IPV4_MASK_LEN: s.pfx4 = toInt(value); break;
      case SX4_SVI.COL_IPV6_ADDRESS: { const v = value.trim(); if (v && v !== '::') s.ip6 = v; } break;
      case SX4_SVI.COL_IPV6_MASK_LEN: s.pfx6 = toInt(value); break;
    }
  }
  const finalNetworks: SxNetwork[] = [];
  for (const [idx, s] of sviByIndex) {
    // The VLAN id comes from the row's own column 2 — never guess it from the index.
    const vlanLabel = s.vlanId !== null ? `VLAN ${s.vlanId}` : `IF-${idx}`;
    if (s.ip4) finalNetworks.push({ name: vlanLabel, ip: s.ip4, prefix: s.pfx4, version: 'v4', vlanId: s.vlanId });
    if (s.ip6) finalNetworks.push({ name: vlanLabel, ip: s.ip6, prefix: s.pfx6, version: 'v6', vlanId: s.vlanId });
  }

  // --- Neighbor cache (index: int) + Q-BRIDGE FDB enrichment ---------------
  const fdbPortByMac = new Map<string, number>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, QB_FDB.base);
    if (!row || row.col !== QB_FDB.COL_PORT || row.idx.length < 7) continue;
    // Index shape: mac(6 octets).fdbId — the MAC is the first six components.
    const macOctets = row.idx.slice(0, 6);
    if (!macOctets.every((p) => /^\d+$/.test(p))) continue;
    const mac = normalizeMac(macOctets.join(':'));
    if (mac && !fdbPortByMac.has(mac)) fdbPortByMac.set(mac, Number(value));
  }

  // Keyed by the STABLE table index — never by a field that gets filled in
  // later (the IP column arrives before/after the MAC column arbitrarily).
  const neighborByIndex = new Map<number, { mac: string; ip: string }>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_NEIGHBOR.base);
    if (!row || row.idx.length !== 1) continue;
    const idx = Number(row.idx[0]);
    if (!Number.isInteger(idx)) continue;
    let n = neighborByIndex.get(idx);
    if (!n) { n = { mac: '', ip: '' }; neighborByIndex.set(idx, n); }
    switch (row.col) {
      case SX4_NEIGHBOR.COL_IP_ADDRESS: n.ip = value.trim(); break;
      case SX4_NEIGHBOR.COL_LINK_ADDRESS: n.mac = normalizeMac(value); break;
    }
  }
  const finalNeighbors: SxNeighbor[] = [];
  for (const { mac, ip } of neighborByIndex.values()) {
    if (!ip) continue; // no address column seen — skip
    const version: 'v4' | 'v6' = ip.includes(':') ? 'v6' : 'v4';
    finalNeighbors.push({ mac, ip, version, port: mac ? (fdbPortByMac.get(mac) ?? null) : null });
  }

  // --- Routes from the live status table + static config table --------------
  // The status table lists ALL active routes but carries no protocol label; the
  // static config table tells us which destinations are statically configured
  // (and their admin distance). A status row matching a config entry → 'static',
  // everything else → 'connected'. Matching is on the BARE network address so it
  // works whether the agent reports "10.25.0.0" or "10.25.0.0/16".
  const bareNet = (s: string): string => s.split('/')[0].trim();

  // Static route config (index int) — network + maskLength + distance per entry.
  const cfgByIndex = new Map<number, { network: string; maskLen: number | null; distance: number | null }>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_IP_ROUTES.base);
    if (!row || row.idx.length !== 1) continue;
    const idx = Number(row.idx[0]);
    if (!Number.isInteger(idx)) continue;
    let c = cfgByIndex.get(idx);
    if (!c) { c = { network: '', maskLen: null, distance: null }; cfgByIndex.set(idx, c); }
    switch (row.col) {
      case SX4_IP_ROUTES.COL_NETWORK: c.network = value.trim(); break;
      case SX4_IP_ROUTES.COL_MASK_LENGTH: c.maskLen = toInt(value); break;
      case SX4_IP_ROUTES.COL_DISTANCE: c.distance = toInt(value); break;
    }
  }
  const staticByBareDest = new Map<string, { distance: number | null; maskLen: number | null }>();
  for (const c of cfgByIndex.values()) {
    if (!c.network) continue;
    staticByBareDest.set(bareNet(c.network), { distance: c.distance, maskLen: c.maskLen });
  }

  // Live status routes (index int) — destination + gateway per entry.
  const statusRouteByIndex = new Map<number, { network: string; gateway: string }>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX4_IP_STATUS_ROUTES.base);
    if (!row || row.idx.length !== 1) continue;
    const idx = Number(row.idx[0]);
    if (!Number.isInteger(idx)) continue;
    let r = statusRouteByIndex.get(idx);
    if (!r) { r = { network: '', gateway: '' }; statusRouteByIndex.set(idx, r); }
    switch (row.col) {
      case SX4_IP_STATUS_ROUTES.COL_NETWORK: r.network = value.trim(); break;
      case SX4_IP_STATUS_ROUTES.COL_GATEWAY: r.gateway = value.trim(); break;
    }
  }

  const finalRoutes: SxRoute[] = [];
  for (const s of statusRouteByIndex.values()) {
    if (!s.network) continue; // no destination column seen — skip
    let destination = s.network;
    let protocol: 'static' | 'connected' = 'connected';
    let distance: number | null = null;
    const match = staticByBareDest.get(bareNet(s.network));
    if (match) {
      protocol = 'static';
      distance = match.distance;
      // Enrich a bare destination with its configured prefix when we have it.
      if (!destination.includes('/') && match.maskLen !== null) destination = `${destination}/${match.maskLen}`;
    }
    finalRoutes.push({ destination, gateway: s.gateway === '0.0.0.0' ? '' : s.gateway, protocol, distance });
  }

  return {
    collectedAt: Date.now(),
    variant: 'sx4',
    system: {
      name: get(SX4_SYS.name).trim(),
      model: get(SX4_SYS.model).trim(),
      firmwareVersion: get(SX4_SYS.firmwareVersion).trim(),
      serialNumber: get(SX4_SYS.serialNumber).trim(),
      hostMac: normalizeMac(get(SX4_SYS.hostMacAddress)),
      uptimeText: get(SX4_SYS.uptime).trim(),
      cpuLoadPct: parseCpuLoadPct(get(SX4_SYS.cpuLoad)),
      memoryTotalMb: memTotal,
      memoryFreeMb: memFree,
      temperatureC: [toNumberLoose(get(SX4_SYS.temperature1)), toNumberLoose(get(SX4_SYS.temperature2)), toNumberLoose(get(SX4_SYS.temperature3))],
      fanSpeedText: get(SX4_SYS.fanSpeed).trim(),
      psuAStatus: get(SX4_PSU.psuAStatus).trim(),
      psuBStatus: get(SX4_PSU.psuBStatus).trim(),
    },
    ports: [...ports.entries()].map(([port, p]) => ({
      port,
      label: (p.label && p.label !== '') ? p.label : `Port ${port}`,
      linkUp: p.linkUp ?? null,
      speedStatus: p.speedStatus ?? '',
      media: '',
      vlanModeLabel: p.vlanModeLabel ?? '',
      pvid: p.pvid ?? null,
      allowedVlans: p.allowedVlans ?? '',
    })),
    poePorts,
    poeTotals,
    lags,
    networks: finalNetworks,
    neighbors: finalNeighbors,
    routes: finalRoutes,
  };
}

function parseSx3(out: Map<string, string>, get: (oid: string) => string): SxSwitchSnapshot {
  // --- System scalars -------------------------------------------------
  const memFreeKb = toInt(get(SX3_SYS.memFreeKb));
  const ramSizeMb = toNumberLoose(get(SX3_SYS.ramSize)) ?? null; // DisplayString KB → MB

  // --- Ports (index: panel port int) -----------------------------------
  const ports = new Map<number, Partial<SxPort>>();
  for (const [oid, value] of out) {
    const row = splitRow(oid, SX3_PORT_CONF.base);
    if (!row || row.idx.length !== 1) continue;
    const port = Number(row.idx[0]);
    if (!Number.isInteger(port)) continue;
    let p = ports.get(port);
    if (!p) { p = {}; ports.set(port, p); }
    switch (row.col) {
      case SX3_PORT_CONF.COL_DESCRIPTION: p.label = value.trim(); break;
      case SX3_PORT_CONF.COL_LINK: p.linkUp = /^up$/i.test(value.trim()) ? true : /^down$/i.test(value.trim()) ? false : null; break;
      case SX3_PORT_CONF.COL_CURRENT_SPEED: p.speedStatus = value.trim(); break;
      case SX3_PORT_CONF.COL_MEDIA: p.media = value.trim(); break;
    }
  }

  // --- Networks from the management-address scalars (no SVI table on 3.x) --
  const networks: SxNetwork[] = [];
  const v4 = get(SX3_SYS.ipv4Address).trim();
  if (v4 && v4 !== '0.0.0.0') {
    networks.push({ name: 'Management', ip: v4, prefix: netmaskToPrefix(get(SX3_SYS.ipv4SubnetMask).trim()), version: 'v4', vlanId: null });
  }
  const v6 = get(SX3_SYS.ipv6Address).trim();
  if (v6 && v6 !== '::') {
    networks.push({ name: 'Management', ip: v6, prefix: toInt(get(SX3_SYS.ipv6Prefix)), version: 'v6', vlanId: null });
  }

  return {
    collectedAt: Date.now(),
    variant: 'sx3',
    system: {
      name: get(SX3_SYS.deviceName).trim(),
      model: get(SX3_SYS.model).trim(),
      firmwareVersion: get(SX3_SYS.firmwareVersion).trim(),
      serialNumber: get(SX3_SYS.serialNumber).trim(),
      hostMac: normalizeMac(get(SX3_SYS.hostMacAddress)),
      uptimeText: get(SX3_SYS.uptime).trim(),
      cpuLoadPct: parseCpuLoadPct(get(SX3_SYS.cpuLoad)),
      memoryTotalMb: ramSizeMb,
      memoryFreeMb: memFreeKb !== null ? Math.round(memFreeKb / 1024) : null,
      temperatureC: [null, null, null], // no temperature sensors exposed on the GS-2310 MIB
      fanSpeedText: '',
      psuAStatus: '',
      psuBStatus: '',
    },
    ports: [...ports.entries()].map(([port, p]) => ({
      port,
      label: (p.label && p.label !== '') ? p.label : `Port ${port}`,
      linkUp: p.linkUp ?? null,
      speedStatus: p.speedStatus ?? '',
      media: p.media ?? '',
      vlanModeLabel: '', // no VLAN table on the 3.x tree
      pvid: null,
      allowedVlans: '',
    })),
    poePorts: [], // PoE is a 4.x-only feature in these MIBs
    poeTotals: null,
    lags: [],
    networks,
    neighbors: [], // no neighbor-cache table on the 3.x tree
    routes: [], // no route tables in the legacy GS-2310 MIB
  };
}

/* ------------------------------------------------------------------ *
 * Fast path — port byte-counter walk every poll → rx/tx rates (bits/s)
 * ------------------------------------------------------------------ */

// Shared counter-delta tracker (@unm/plugin-sdk): first sample → null,
// reset/wrap skipped, baseline always refreshed, stale hosts evicted.
const rateTracker = new CounterTracker(); // octets/s → bits/s

/** One rate sample per port: bits/s in each direction (null when unknown). */
export type SxRates = Record<string, { rx: number | null; tx: number | null }>;

/**
 * Walks the variant's port byte-counter columns and computes rates against a
 * per-host baseline. Counter resets/wraps yield null for that sample (the next
 * cycle re-baselines). Never throws — returns an empty map on failure so
 * monitoring degrades to slow-path data only.
 *
 * Only the two OCTET COLUMNS are walked, not the whole 52-column table:
 * verified live on a GS-2310 (fw 3.34) where a full-table walk takes ~50s
 * while each single column completes in <0.5s — the legacy agent is slow to
 * traverse wide tables even under v2c GetBulk. Two narrow walks are fast on
 * every model and keep the fast path well inside its budget.
 */
export async function walkSxCounters(
  host: string,
  creds: SnmpCredentials,
  opts: SxOptions,
  variant: SxVariant
): Promise<SxRates> {
  const base = variant === 'sx4' ? SX4_PORT_TRAFFIC.base : SX3_PORT_TRAFFIC.base;
  // Row addressing is <base>.1.<column>.<port> — a column subtree is the walk root.
  const colOids = [
    `${base}.1.${SX4_PORT_TRAFFIC.COL_RX_OCTETS}`,
    `${base}.1.${SX4_PORT_TRAFFIC.COL_TX_OCTETS}`,
  ];
  const out = new Map<string, string>();
  for (const oid of colOids) {
    try {
      // Sequential — the SX agents corrupt responses under concurrent sessions.
      const r = await snmpWalk(host, creds, [oid], opts);
      for (const [k, v] of r) out.set(k, v);
    } catch {
      return {}; // counters unavailable this cycle — rates stay null
    }
  }

  const now = Date.now();
  rateTracker.evictStale(now);
  const rates: SxRates = {};

  for (const [oid, value] of out) {
    const row = splitRow(oid, base);
    if (!row || row.idx.length !== 1) continue;
    if (row.col !== SX4_PORT_TRAFFIC.COL_RX_OCTETS && row.col !== SX4_PORT_TRAFFIC.COL_TX_OCTETS) continue;
    // (Both trees share the traffic-table column numbers — verified in sxOids.ts.)
    const port = Number(row.idx[0]);
    if (!Number.isInteger(port)) continue;
    const n = Number(value);
    if (!Number.isFinite(n)) continue;
    const dir = row.col === SX4_PORT_TRAFFIC.COL_RX_OCTETS ? 'rx' : 'tx';
    // Integer bits/s, as before — the tracker returns a float rate.
    const r = rateTracker.sample(`${host}:${port}:${dir}`, n, now);
    if (r === null) continue;
    const cur = rates[`P${port}`] ?? (rates[`P${port}`] = { rx: null, tx: null });
    const bitsPerSec = Math.round(r);
    if (dir === 'rx') cur.rx = bitsPerSec;
    else cur.tx = bitsPerSec;
  }

  return rates;
}
