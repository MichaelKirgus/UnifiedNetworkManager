/**
 * Firewall rule collection for the cross-device Firewall page.
 *
 * OPNsense exposes firewall rules through five separate search endpoints —
 * filter rules plus four NAT rule sets (destination/source/one-to-one/NPT) —
 * each returning an un-normalized `rows[]` array in its own field layout. This
 * module fetches all of them (with pagination, since the appliance's default
 * page size would otherwise silently truncate large rule sets), resolves alias
 * names to their real networks for display context, and maps every row onto ONE
 * unified shape so OPNsense rules can share a table with RouterOS rules on the
 * Firewall page. The API stores that shape verbatim (see api firewallRules
 * ingestion); vendor-specific leftovers go into `extra`.
 */

import type { AxiosInstance } from 'axios';
import { OpnsenseApiResult } from './client/http';
import { get } from './client/http';
import { searchFilterRules, dNat, sourceNat, oneToOne, npt, searchAliases } from './client/firewall';

/** One unified firewall rule row as emitted into `metrics['firewallRules']`. */
export interface FirewallRuleRow {
  ruleType: 'filter' | 'dnat' | 'snat' | 'one-to-one' | 'npt';
  vendorRuleId: string;
  position: number;
  protocol: string;
  sourceIp: string;
  destIp: string;
  sourcePort: string | null;
  destPort: string | null;
  action: 'allow' | 'deny' | 'other';
  enabled: boolean;
  description: string;
  scope: string;
  /** IP family the rule applies to — v4 / v6 / both. */
  ipVersion: 'v4' | 'v6' | 'both';
  /** Live pf hit counters (filter rules only; null when not reported). */
  packets?: number | null;
  bytes?: number | null;
  states?: number | null;
  extra: Record<string, unknown>;
}

/** Page size for the search endpoints — large enough to be one request on most boxes. */
const PAGE_SIZE = 500;
/** Hard safety cap so a misbehaving endpoint can't loop forever (100k rows). */
const MAX_PAGES = 200;

type SearchFn = (query?: Record<string, unknown>) => Promise<OpnsenseApiResult>;

/** Extracts the `rows[]` array from an OPNsense search response payload. */
function rowsOf(res: OpnsenseApiResult): Record<string, unknown>[] {
  if (!res.ok || !res.data || typeof res.data !== 'object') return [];
  const d = res.data as Record<string, unknown>;
  return Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
}

/**
 * Fetches ALL rows from a paginated search endpoint. OPNsense's recordset
 * endpoints honor `current`/`rowCount`; we page until a short page comes back.
 * A failing first request yields [] (best-effort — one dead NAT set must not
 * sink the whole firewall snapshot).
 */
async function fetchAllRows(search: SearchFn): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  let current = 1;
  for (;;) {
    let res: OpnsenseApiResult;
    try {
      res = await search({ current, rowCount: PAGE_SIZE });
    } catch {
      break; // transport/auth failure — stop, keep what we have
    }
    const rows = rowsOf(res);
    out.push(...rows);
    if (rows.length < PAGE_SIZE) break; // last page (or empty)
    current += 1;
    if (current > MAX_PAGES) break;
  }
  return out;
}

/** Reads a string field, trimmed; '' when absent/non-string. */
function str(row: Record<string, unknown>, key: string): string {
  const v = row[key];
  return typeof v === 'string' ? v.trim() : '';
}

/**
 * Whether a rule is enabled. OPNsense encodes booleans inconsistently across
 * models: filter/dnat rows carry `disabled` as the strings "0"/"1", while
 * source_nat rows carry an `enabled` field instead. An explicit `enabled`
 * wins; otherwise fall back to `disabled`; absent both = enabled.
 */
function isEnabled(row: Record<string, unknown>): boolean {
  const e = row['enabled'];
  if (e !== undefined) return !(e === false || e === 'false' || e === '0' || e === 0);
  const d = row['disabled'];
  if (d !== undefined) return !(d === true || d === 'true' || d === '1' || d === 1);
  return true;
}

/** Normalizes a protocol token to lowercase ('any'/'' → ''). */
function normProtocol(v: string): string {
  const p = v.trim().toLowerCase();
  return p === '' || p === 'any' ? '' : p;
}

/** Maps an OPNsense family token to the unified ipVersion.
 * Live appliances use `inet` / `inet6` / `inet46` (dual-stack) — older docs
 * say `any`, so accept both. Absent/unknown → null (caller falls back). */
function normIpVersion(raw: unknown): 'v4' | 'v6' | 'both' | null {
  const v = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (v === 'inet') return 'v4';
  if (v === 'inet6') return 'v6';
  if (v === 'any' || v === 'inet46') return 'both';
  return null; // absent/unknown → caller derives from the address text
}

/** Derives the IP family from raw rule-address text. OPNsense rows sometimes
 * carry NO `ipprotocol` at all — then only the addresses reveal the family.
 * Handles comma lists ("fe80::/10,ff02::/16"); unresolvable alias names are
 * neutral and never force a family. null = no literal addresses found. */
function deriveFamilyFromText(src: string, dst: string): 'v4' | 'v6' | 'both' | null {
  const parts = [src, dst].flatMap((s) => s.split(',')).map((p) => p.trim()).filter(Boolean);
  let v4 = false;
  let v6 = false;
  for (const p of parts) {
    if (p === 'any' || p === '*' || p.includes('.')) continue; // any/alias — neutral
    const addr = p.split('/')[0];
    if (addr.includes(':')) v6 = true;
    else v4 = true;
  }
  if (v4 && v6) return 'both';
  if (v6) return 'v6';
  if (v4) return 'v4';
  return null; // no literal addresses — family unknown
}

/** Resolves the unified ipVersion for a rule: explicit `ipprotocol` wins,
 * otherwise derive from the address text, else the given default (v4). */
function resolveIpVersion(
  row: Record<string, unknown>,
  srcKey: string,
  dstKey: string,
  fallback: 'v4' | 'v6' = 'v4'
): 'v4' | 'v6' | 'both' {
  const explicit = normIpVersion(row['ipprotocol'] ?? row['family']);
  if (explicit) return explicit;
  return deriveFamilyFromText(str(row, srcKey), str(row, dstKey)) ?? fallback;
}

/** Live per-rule pf counters from `filter_util/rule_stats` — keyed by the rule's
 * OWN uuid (live-verified on multiple appliances; NOT opaque hashes). Returns an
 * empty map when stats are disabled or the endpoint is unavailable. */
export async function fetchFilterRuleStats(client: AxiosInstance): Promise<Map<string, { packets: number | null; bytes: number | null; states: number | null }>> {
  const out = new Map<string, { packets: number | null; bytes: number | null; states: number | null }>();
  try {
    const res = await get(client, '/api/firewall/filter_util/rule_stats');
    if (!res.ok || !res.data || typeof res.data !== 'object') return out;
    const stats = (res.data as Record<string, unknown>)['stats'];
    if (!stats || typeof stats !== 'object') return out;
    for (const [uuid, s] of Object.entries(stats as Record<string, unknown>)) {
      if (!s || typeof s !== 'object') continue;
      const o = s as Record<string, unknown>;
      const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null);
      out.set(uuid, { packets: num(o['packets']), bytes: num(o['bytes']), states: num(o['states']) });
    }
  } catch {
    // best-effort — stats are display-only enrichment
  }
  return out;
}

/** Builds the alias-name → resolved-text map (comma-joined address list).
 * Paginated like the rule sets — an un-paginated search returns only OPNsense's
 * default page (~50 rows), silently dropping most aliases on busy appliances. */
async function buildAliasMap(client: AxiosInstance): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  try {
    for (const row of await fetchAllRows((q) => searchAliases(client, q))) {
      const name = str(row, 'name');
      if (!name) continue;
      // The alias body is `content` on modern appliances (older releases used
      // `address`) — a comma-separated list of hosts/networks/ports/interface names.
      const content = str(row, 'content') || str(row, 'address');
      map.set(name.toLowerCase(), content);
    }
  } catch {
    // best-effort — alias resolution is display-only context
  }
  return map;
}

/** Resolves an alias name to its address text (lowercased lookup), else undefined. */
function resolveAlias(aliases: Map<string, string>, value: string): string | undefined {
  if (!value) return undefined;
  // A rule may reference a single alias or a comma list of them — resolve each part.
  const parts = value.split(',').map((p) => p.trim()).filter(Boolean);
  const resolved = parts.map((p) => aliases.get(p.toLowerCase()) ?? p).join(', ');
  return resolved === value ? undefined : resolved; // only report when it actually changed
}

/** Maps one OPNsense filter-rule row onto the unified shape. */
function mapFilterRule(
  row: Record<string, unknown>,
  position: number,
  aliases: Map<string, string>,
  stats?: Map<string, { packets: number | null; bytes: number | null; states: number | null }>
): FirewallRuleRow | null {
  const uuid = str(row, 'uuid');
  if (!uuid) return null;
  const actionRaw = str(row, 'action').toLowerCase();
  const sourceIp = str(row, 'source_net');
  const destIp = str(row, 'destination_net');
  const extra: Record<string, unknown> = { uuid };
  for (const k of ['family', 'direction', 'log', 'tag', 'quick', 'state']) {
    if (row[k] !== undefined && row[k] !== '') extra[k] = row[k];
  }
  const rs = resolveAlias(aliases, sourceIp);
  if (rs) extra['resolvedSource'] = rs;
  const rd = resolveAlias(aliases, destIp);
  if (rd) extra['resolvedDest'] = rd;
  return {
    ruleType: 'filter',
    vendorRuleId: uuid,
    position,
    protocol: normProtocol(str(row, 'protocol')),
    sourceIp,
    destIp,
    sourcePort: str(row, 'source_port') || null,
    destPort: str(row, 'destination_port') || null,
    action: actionRaw === 'pass' ? 'allow' : actionRaw === '' ? 'other' : 'deny', // block/synproxy/… → deny
    enabled: isEnabled(row),
    description: str(row, 'description'),
    scope: str(row, 'interface'),
    ipVersion: resolveIpVersion(row, 'source_net', 'destination_net'),
    ...(stats?.get(uuid) ?? { packets: null, bytes: null, states: null }),
    extra,
  };
}

/** Maps one OPNsense DNAT (port-forward) row. This model uses FLAT dotted keys
 * (`source.network`, `destination.port`, …); the forwarded-to server is `target`
 * (+ hyphenated `local-port`). */
function mapDnatRule(row: Record<string, unknown>, position: number): FirewallRuleRow | null {
  const uuid = str(row, 'uuid');
  if (!uuid) return null;
  // Combine the network + address parts (either may be empty).
  const sourceIp = [str(row, 'source.network'), str(row, 'source.address')].filter(Boolean).join(' ');
  const destIp = [str(row, 'destination.network'), str(row, 'destination.address')].filter(Boolean).join(' ');
  const extra: Record<string, unknown> = { uuid };
  // The forwarded-to server (IP or alias) + its port — the heart of a port forward.
  const target = str(row, 'target');
  if (target) extra['forwardTo'] = target;
  const localPort = str(row, 'local-port');
  if (localPort) extra['forwardPort'] = localPort;
  return {
    ruleType: 'dnat',
    vendorRuleId: uuid,
    position,
    protocol: normProtocol(str(row, 'protocol')),
    sourceIp,
    destIp,
    sourcePort: str(row, 'source.port') || null,
    destPort: str(row, 'destination.port') || null,
    action: 'other', // NAT rules have no allow/deny verdict
    enabled: isEnabled(row),
    description: str(row, 'descr'),
    scope: str(row, 'interface'),
    ipVersion: resolveIpVersion({ ...row, source_net: sourceIp, destination_net: destIp }, 'source_net', 'destination_net'),
    extra,
  };
}

/** Maps one OPNsense source-NAT row (flat fields; uses `enabled`, not `disabled`). */
function mapSourceNatRule(row: Record<string, unknown>, position: number): FirewallRuleRow | null {
  const uuid = str(row, 'uuid');
  if (!uuid) return null;
  const extra: Record<string, unknown> = { uuid };
  const target = str(row, 'target'); // the translated source address ('wanip'/'*' = auto/masquerade)
  if (target) extra['snatAddress'] = target === '*' ? 'auto' : target;
  return {
    ruleType: 'snat',
    vendorRuleId: uuid,
    position,
    protocol: normProtocol(str(row, 'protocol')),
    sourceIp: str(row, 'source_net'),
    destIp: str(row, 'destination_net'),
    sourcePort: str(row, 'source_port') || null,
    destPort: str(row, 'destination_port') || null,
    action: 'other',
    enabled: isEnabled(row),
    description: str(row, 'description'),
    scope: str(row, 'interface'),
    ipVersion: resolveIpVersion(row, 'source_net', 'destination_net'),
    extra,
  };
}

/** Maps one OPNsense one-to-one NAT row (external IP ↔ internal host). */
function mapOneToOneRule(row: Record<string, unknown>, position: number): FirewallRuleRow | null {
  const uuid = str(row, 'uuid');
  if (!uuid) return null;
  const extra: Record<string, unknown> = { uuid };
  if (row['no_rdr'] !== undefined && row['no_rdr'] !== '') extra['noRdr'] = row['no_rdr'];
  return {
    ruleType: 'one-to-one',
    vendorRuleId: uuid,
    position,
    protocol: normProtocol(str(row, 'protocol')),
    sourceIp: str(row, 'external'),
    destIp: str(row, 'internal'),
    sourcePort: null,
    destPort: null,
    action: 'other',
    enabled: isEnabled(row),
    description: '',
    scope: str(row, 'interface'),
    ipVersion: resolveIpVersion(row, 'external', 'internal'),
    extra,
  };
}

/** Maps one OPNsense NPT (IPv6 prefix translation) row. */
function mapNptRule(row: Record<string, unknown>, position: number): FirewallRuleRow | null {
  const uuid = str(row, 'uuid');
  if (!uuid) return null;
  const extra: Record<string, unknown> = { uuid };
  return {
    ruleType: 'npt',
    vendorRuleId: uuid,
    position,
    protocol: normProtocol(str(row, 'protocol')),
    sourceIp: str(row, 'external'),
    destIp: str(row, 'internal'),
    sourcePort: null,
    destPort: null,
    action: 'other',
    enabled: isEnabled(row),
    description: '',
    scope: str(row, 'interface'),
    ipVersion: resolveIpVersion(row, 'external', 'internal', 'v6'), // NPT is inherently IPv6
    extra,
  };
}

/**
 * Collects the full firewall rule set for one appliance. Each of the five rule
 * sets is fetched independently and best-effort — a failing NAT endpoint yields
 * an empty contribution rather than sinking the whole snapshot. `stats` (live pf
 * counters keyed by uuid, see fetchFilterRuleStats) enriches filter rows when
 * provided. Throws only on unexpected internal errors (callers still wrap in
 * try/catch).
 */
export async function collectFirewallRules(
  client: AxiosInstance,
  stats?: Map<string, { packets: number | null; bytes: number | null; states: number | null }>
): Promise<FirewallRuleRow[]> {
  const aliases = await buildAliasMap(client);

  // Fetch all five rule sets in parallel; each is independent.
  const [filterRes, dnatRes, snatRes, o2oRes, nptRes] = await Promise.allSettled([
    fetchAllRows((q) => searchFilterRules(client, q)),
    fetchAllRows((q) => dNat.search(client, q)),
    fetchAllRows((q) => sourceNat.search(client, q)),
    fetchAllRows((q) => oneToOne.search(client, q)),
    fetchAllRows((q) => npt.search(client, q)),
  ]);

  const rows: FirewallRuleRow[] = [];
  const pushSet = (res: PromiseSettledResult<Record<string, unknown>[]>, map: (r: Record<string, unknown>, i: number) => FirewallRuleRow | null) => {
    if (res.status !== 'fulfilled') return; // best-effort — skip a failed set
    res.value.forEach((row, i) => {
      const mapped = map(row, i);
      if (mapped) rows.push(mapped);
    });
  };

  pushSet(filterRes, (r, i) => mapFilterRule(r, i, aliases, stats));
  pushSet(dnatRes, mapDnatRule);
  pushSet(snatRes, mapSourceNatRule);
  pushSet(o2oRes, mapOneToOneRule);
  pushSet(nptRes, mapNptRule);

  return rows;
}
