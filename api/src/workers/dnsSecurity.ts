/**
 * DNS security heuristics — background worker (leader-gated, key 9030).
 *
 * Deterministic detectors over dns_query_events (per-query rows pushed by
 * plugins via POST /plugin/dns-queries), complementing the flow-based
 * detectors in workers/flowSecurity.ts. Findings land in the SAME
 * flow_security_findings table — same auto-resolve sweep, notification
 * pipeline and securityFinding automation trigger:
 *
 *   dga        — a client queried a domain whose longest non-TLD label looks
 *                algorithmically generated (label length ≥ dnsSecurityDgaMinLabelLen
 *                AND Shannon entropy ≥ dnsSecurityDgaMinEntropyX10/10 AND vowel
 *                ratio ≤ dnsSecurityDgaMaxVowelRatioPercent) — gated by TWO
 *                noise filters learned from live operation:
 *                  · base-domain whitelist (dnsSecurityDgaBaseDomainWhitelist):
 *                    cloud/CDN services legitimately use random-looking subdomain
 *                    tokens (OneDrive, CloudFront dist ids, AWS ELB names, Alexa)
 *                    and are never scored;
 *                  · volume gate: a client must query ≥ dnsSecurityDgaMinDistinctDomainsPerClient
 *                    DISTINCT DGA-like domains inside the rolling window
 *                    (dnsSecurityDgaVolumeWindowHours) before any of them is
 *                    reported — real DGA campaigns generate dozens to hundreds of
 *                    names per host, legit services produce a handful. Confirmed
 *                    clients stay confirmed for the rest of the boot and report
 *                    every new DGA-like domain immediately.
 *                Each domain is scored once per process boot; each (client, domain)
 *                tuple raises at most one finding per boot.
 *   dns-tunnel — one client issued ≥ `dnsSecurityTunnelMinQueries` queries to
 *                the same base domain inside a rolling window (`dnsSecurityTunnelWindowHours`)
 *                whose subdomain labels average ≥ `dnsSecurityTunnelMinAvgLabelLen`
 *                characters — data encoded in DNS names (tunneling / exfiltration).
 *
 * Conventions:
 *   - Watermark = boot time; rows with tsMs ≤ watermark are never scanned (no
 *     history replay — same convention as the threat-intel firewall pass).
 *   - Only action='pass' rows count: a blocked query was already stopped by
 *     the resolver's blocklists and is not evidence of compromise.
 *   - `client` is verbatim from the appliance (IP or reverse-resolved
 *     hostname); findings need an INET source, so hostname clients are
 *     resolved via the hosts table (resolveClientHostnames) — unresolvable
 *     clients stay visible in the DNS view but raise no finding.
 */

import net from 'node:net';
import { pool } from '../db';
import { getEffectiveValues } from '../systemSettings';
import { emitNotification } from '../notifications';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { upsertFinding, type FindingInput } from './flowSecurity';
import { resolveClientHostnames } from './threatIntel';

const BEAT_MS = 60_000;
/** Max rows scanned per beat (same order as the threat-intel passes). */
const SCAN_LIMIT = 20_000;
/** Future-skew guard: rows stamped up to 5 min ahead are still scannable. */
const FUTURE_GUARD_MS = 300_000;
/** Safety cap on tracked tunnel pairs — a runaway fleet must not grow the map unbounded. */
const TUNNEL_MAX_TRACKED_PAIRS = 100_000;
/** Safety cap on clients with DGA-like domains in the volume-gate window. */
const DGA_MAX_TRACKED_CLIENTS = 100_000;

// ── State ────────────────────────────────────────────────────────────────────

let watermarkMs = Date.now(); // rows at/before boot are never scanned (no history replay)
let lastRunAt: string | null = null;
let lastError: string | null = null;
/** Per-domain DGA verdict cache — a domain is scored once per process boot. */
const dgaVerdicts = new Map<string, boolean>();
/** (client|domain) tuples already reported as DGA — avoids re-upserting on every query. */
const dgaReported = new Set<string>();
/** Volume gate: distinct DGA-like domains per client inside the rolling window (domain → first-seen ts). */
const dgaClientDomains = new Map<string, Map<string, number>>();
/** Clients that crossed the distinct-domain threshold — report every new domain for this boot. */
const dgaConfirmedClients = new Set<string>();
/** Rolling tunnel state per `${client}|${baseDomain}` — subdomain-bearing rows only. */
interface TunnelState { ts: number[]; labelLenSum: number }
const tunnelState = new Map<string, TunnelState>();

/** Snapshot for GET /v1/flows/security (dnsHeuristics status block). */
export function getDnsSecurityStats(): {
  lastRunAt: string | null;
  lastError: string | null;
  watermarkMs: number;
  dgaDomainCacheSize: number;
  dgaTrackedClients: number;
  dgaConfirmedClients: number;
  tunnelTrackedPairs: number;
} {
  return {
    lastRunAt,
    lastError,
    watermarkMs,
    dgaDomainCacheSize: dgaVerdicts.size,
    dgaTrackedClients: dgaClientDomains.size,
    dgaConfirmedClients: dgaConfirmedClients.size,
    tunnelTrackedPairs: tunnelState.size,
  };
}

// ── Pure helpers (unit-tested in dnsSecurity.test.ts) ────────────────────────

/** Shannon entropy (bits per character) of a string. Empty → 0. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Features of the label a DGA check should look at. */
export interface DgaLabelFeatures {
  /** The longest non-TLD label (the TLD is the last label). */
  label: string;
  len: number;
  entropy: number;
  /** Vowel share (a/e/i/o/u) of the label, 0–1. */
  vowelRatio: number;
}

/**
 * Longest non-TLD label of a domain — DGA strings show up as random SLDs or
 * random subdomains, so every label except the TLD is eligible. Null for
 * single-label names (nothing to evaluate).
 */
export function dgaCandidateLabel(domain: string): DgaLabelFeatures | null {
  const labels = domain.split('.');
  if (labels.length < 2) return null;
  let best = '';
  for (let i = 0; i < labels.length - 1; i++) if (labels[i].length > best.length) best = labels[i];
  if (best === '') return null;
  const vowels = (best.match(/[aeiou]/g) ?? []).length;
  return { label: best, len: best.length, entropy: shannonEntropy(best), vowelRatio: vowels / best.length };
}

/** All three gates must hold — length alone is common in human subdomains. */
export function isDgaLike(
  f: DgaLabelFeatures,
  opts: { minLabelLen: number; minEntropy: number; maxVowelRatio: number }
): boolean {
  return f.len >= opts.minLabelLen && f.entropy >= opts.minEntropy && f.vowelRatio <= opts.maxVowelRatio;
}

/** Parse a comma/whitespace-separated base-domain whitelist into a lowercase set (empty entries dropped). */
export function parseBaseDomainWhitelist(raw: string): Set<string> {
  const out = new Set<string>();
  for (const part of raw.split(/[\s,]+/)) {
    const d = part.trim().toLowerCase();
    if (d) out.add(d);
  }
  return out;
}

/**
 * True when the domain equals a whitelist entry or sits UNDER one (case-insensitive
 * suffix match) — never scored as DGA. Suffix semantics so an entry like
 * 'cloudapp.azure.com' covers every OneDrive-for-Business endpoint
 * ('…westus.cloudapp.azure.com') even though its last-two-labels base is 'azure.com'.
 */
export function isDgaBaseDomainWhitelisted(domain: string, whitelist: Set<string>): boolean {
  const d = domain.toLowerCase();
  for (const entry of whitelist) {
    if (d === entry || d.endsWith(`.${entry}`)) return true;
  }
  return false;
}

/** Naive registered domain = last two labels (co.uk-style TLDs are approximated). */
export function baseDomainOf(domain: string): string | null {
  const labels = domain.split('.');
  if (labels.length < 2) return null;
  return labels.slice(-2).join('.');
}

/**
 * Longest label LEFT of the base domain — the subdomain part where tunneling
 * tools encode data. Null when there is no subdomain (≤ 2 labels).
 */
export function tunnelLabelLen(domain: string): number | null {
  const labels = domain.split('.');
  if (labels.length < 3) return null;
  let max = 0;
  for (let i = 0; i < labels.length - 2; i++) max = Math.max(max, labels[i].length);
  return max > 0 ? max : null;
}

/** Verdict for one tunnel candidate. */
export interface TunnelVerdict {
  queries: number;
  avgLabelLen: number;
}

/** Pure decision core of the tunnel pass — extracted for unit testing. */
export function tunnelVerdict(
  state: { ts: number[]; labelLenSum: number },
  minQueries: number,
  minAvgLabelLen: number
): TunnelVerdict | null {
  if (state.ts.length < minQueries) return null;
  const avg = state.labelLenSum / state.ts.length;
  if (avg < minAvgLabelLen) return null;
  return { queries: state.ts.length, avgLabelLen: Math.round(avg * 10) / 10 };
}

/** Decision for one newly seen DGA-like domain under the per-client volume gate. */
export interface DgaVolumeDecision {
  /** The client just crossed the distinct-domain threshold — report ALL its tracked domains now. */
  confirmClient: boolean;
  /** This new domain should be reported right away (client already confirmed). */
  reportNewDomain: boolean;
}

/** Pure decision core of the DGA volume gate — extracted for unit testing. */
export function dgaVolumeDecision(
  trackedDistinctCount: number,
  alreadyConfirmed: boolean,
  minDistinctDomains: number
): DgaVolumeDecision {
  if (alreadyConfirmed) return { confirmClient: false, reportNewDomain: true };
  const crossed = trackedDistinctCount >= minDistinctDomains;
  return { confirmClient: crossed, reportNewDomain: crossed };
}

// ── Notification ─────────────────────────────────────────────────────────────

/** Emits the one-shot notification for a freshly detected DNS finding. Best-effort. */
async function notifyDnsSecurityFinding(f: FindingInput): Promise<void> {
  try {
    const title = f.kind === 'dga' ? `DGA-like domain queried by ${f.srcIp}` : `Possible DNS tunneling from ${f.srcIp}`;
    await emitNotification({
      severity: f.severity,
      source: f.deviceId ? 'device' : 'system',
      deviceId: f.deviceId ?? undefined,
      title,
      message: f.detail,
      dedupeKey: f.dedupeKey ?? `flow-security:${f.kind}:${f.srcIp}`,
      context: { ...f.context, srcIp: f.srcIp },
    });
  } catch (err) {
    // Notifications are best-effort by contract — never break the beat.
    lastError = `notification failed: ${(err as Error).message}`;
    // eslint-disable-next-line no-console
    console.error('[dns-security] notification emission failed:', err);
  }
}

// ── Beat ─────────────────────────────────────────────────────────────────────

async function beat(): Promise<void> {
  try {
    const values = await getEffectiveValues();
    if (values.dnsSecurityEnabled !== true) return; // master switch off — no new detections

    const nowMs = Date.now();
    const res = await pool.query(
      `SELECT client, domain, "deviceId", "tsMs" FROM dns_query_events
       WHERE "tsMs" > $1 AND "tsMs" <= $2 AND action = 'pass'
       ORDER BY "tsMs" ASC LIMIT ${SCAN_LIMIT}`,
      [watermarkMs, nowMs + FUTURE_GUARD_MS]
    );

    const dgaMinLabelLen = Number(values.dnsSecurityDgaMinLabelLen) || 12;
    const dgaMinEntropy = (Number(values.dnsSecurityDgaMinEntropyX10) || 36) / 10;
    const dgaMaxVowelRatio = (Number.isFinite(Number(values.dnsSecurityDgaMaxVowelRatioPercent)) ? Number(values.dnsSecurityDgaMaxVowelRatioPercent) : 25) / 100;
    const dgaMinDistinctDomains = Math.max(1, Number(values.dnsSecurityDgaMinDistinctDomainsPerClient) || 10);
    const dgaVolumeWindowHours = Number(values.dnsSecurityDgaVolumeWindowHours) || 24;
    const dgaWhitelist = parseBaseDomainWhitelist(String(values.dnsSecurityDgaBaseDomainWhitelist ?? ''));
    const tunnelWindowHours = Number(values.dnsSecurityTunnelWindowHours) || 1;
    const tunnelMinQueries = Number(values.dnsSecurityTunnelMinQueries) || 30;
    const tunnelMinAvgLabelLen = Number(values.dnsSecurityTunnelMinAvgLabelLen) || 24;

    let maxTs = watermarkMs;
    interface Row { client: string; domain: string; deviceId: string; ts: number }
    const rows: Row[] = [];
    for (const r of res.rows) {
      const ts = Number(r.tsMs);
      if (!Number.isFinite(ts)) continue;
      maxTs = Math.max(maxTs, ts);
      rows.push({ client: String(r.client), domain: String(r.domain), deviceId: r.deviceId ? String(r.deviceId) : '', ts });
    }

    // ── DGA pass — score each new domain once per boot (whitelisted base domains are never scored).
    const dgaNew = new Map<string, Row>(); // key `${client}|${domain}` → first row this beat
    for (const row of rows) {
      let verdict = dgaVerdicts.get(row.domain);
      if (verdict === undefined) {
        const f = dgaCandidateLabel(row.domain);
        verdict = f !== null && !isDgaBaseDomainWhitelisted(row.domain, dgaWhitelist)
          && isDgaLike(f, { minLabelLen: dgaMinLabelLen, minEntropy: dgaMinEntropy, maxVowelRatio: dgaMaxVowelRatio });
        dgaVerdicts.set(row.domain, verdict);
      }
      if (verdict) {
        const key = `${row.client}|${row.domain}`;
        if (!dgaReported.has(key)) dgaNew.set(key, row);
      }
    }

    // Volume gate — real DGA campaigns generate dozens of distinct names per host,
    // legit services with random-looking tokens a handful. Track distinct DGA-like
    // domains per client in a rolling window; report only once the count crosses
    // the threshold (confirmed clients stay confirmed for this boot).
    const dgaWindowStartMs = nowMs - dgaVolumeWindowHours * 3_600_000;
    for (const [clientKey, domains] of dgaClientDomains) {
      for (const [domain, firstSeenTs] of domains) if (firstSeenTs < dgaWindowStartMs) domains.delete(domain);
      if (domains.size === 0) dgaClientDomains.delete(clientKey);
    }
    if (dgaClientDomains.size > DGA_MAX_TRACKED_CLIENTS) {
      // eslint-disable-next-line no-console
      console.warn(`[dns-security] DGA client state exceeded ${DGA_MAX_TRACKED_CLIENTS} clients — resetting`);
      dgaClientDomains.clear();
    }
    const dgaToReport = new Map<string, Row>(); // key `${client}|${domain}` → row to report this beat
    for (const [key, row] of dgaNew) {
      let domains = dgaClientDomains.get(row.client);
      if (!domains) { domains = new Map(); dgaClientDomains.set(row.client, domains); }
      if (!domains.has(row.domain)) domains.set(row.domain, row.ts); // first-seen ts for window pruning
      const decision = dgaVolumeDecision(domains.size, dgaConfirmedClients.has(row.client), dgaMinDistinctDomains);
      if (decision.confirmClient) {
        dgaConfirmedClients.add(row.client);
        for (const [domain] of domains) {
          const k = `${row.client}|${domain}`;
          if (!dgaReported.has(k)) dgaToReport.set(k, { client: row.client, domain, deviceId: row.deviceId, ts: domains.get(domain)! });
        }
      } else if (decision.reportNewDomain) {
        dgaToReport.set(key, row);
      }
    }

    // ── Tunnel pass — rolling window per (client, base domain).
    const windowStartMs = nowMs - tunnelWindowHours * 3_600_000;
    for (const [key, st] of tunnelState) {
      while (st.ts.length > 0 && st.ts[0] < windowStartMs) st.ts.shift();
      if (st.ts.length === 0) tunnelState.delete(key);
    }
    if (tunnelState.size > TUNNEL_MAX_TRACKED_PAIRS) {
      // eslint-disable-next-line no-console
      console.warn(`[dns-security] tunnel state exceeded ${TUNNEL_MAX_TRACKED_PAIRS} pairs — resetting`);
      tunnelState.clear();
    }
    const touchedTunnels = new Map<string, Row>(); // key `${client}|${baseDomain}` → newest row (deviceId source)
    for (const row of rows) {
      const base = baseDomainOf(row.domain);
      const ll = tunnelLabelLen(row.domain);
      if (!base || ll === null) continue; // no subdomain — nothing to encode in
      const key = `${row.client}|${base}`;
      let st = tunnelState.get(key);
      if (!st) { st = { ts: [], labelLenSum: 0 }; tunnelState.set(key, st); }
      st.ts.push(row.ts);
      st.labelLenSum += ll;
      touchedTunnels.set(key, row); // rows arrive in tsMs order — last write is the newest
    }

    if (rows.length > 0) {
      // eslint-disable-next-line no-console
      console.log(`[dns-security] scanned ${rows.length} quer(y/ies) since ${new Date(watermarkMs).toISOString()}`);
    }

    // Resolve hostname clients to IPs for finding attribution (one batched lookup).
    const namesToResolve = new Set<string>();
    for (const row of dgaToReport.values()) if (net.isIP(row.client) === 0) namesToResolve.add(row.client.toLowerCase());
    for (const row of touchedTunnels.values()) if (net.isIP(row.client) === 0) namesToResolve.add(row.client.toLowerCase());
    const resolved = await resolveClientHostnames([...namesToResolve]);

    // DGA findings — one per (client, domain) tuple that cleared the volume gate.
    for (const [key, row] of dgaToReport) {
      const clientIp = net.isIP(row.client) !== 0 ? row.client : resolved.get(row.client.toLowerCase());
      if (!clientIp) continue; // no address to attribute — stays visible in the DNS view
      dgaReported.add(key);
      const f = dgaCandidateLabel(row.domain)!; // verdict was true → features exist
      const detail = `${row.client} queried DGA-like domain ${row.domain}` +
        ` (label "${f.label}": length ${f.len}, entropy ${f.entropy.toFixed(2)}, vowel ratio ${(f.vowelRatio * 100).toFixed(0)}%).`;
      const input: FindingInput = {
        kind: 'dga',
        srcIp: clientIp,
        dstIp: null,
        severity: 'warning',
        detail,
        context: { domain: row.domain, label: f.label, labelLen: f.len, entropy: Math.round(f.entropy * 100) / 100, vowelRatio: Math.round(f.vowelRatio * 1_000) / 1_000, client: row.client },
        deviceId: row.deviceId || null,
        dedupeKey: `flow-security:dga:${clientIp}:${row.domain}`,
      };
      const isNew = await upsertFinding(input);
      if (isNew) {
        // eslint-disable-next-line no-console
        console.log(`[dns-security] dga finding: ${row.client} → ${row.domain}`);
        await notifyDnsSecurityFinding(input);
      }
    }

    // Tunnel findings — one per (client, base domain).
    for (const [key, newestRow] of touchedTunnels) {
      const st = tunnelState.get(key);
      if (!st) continue;
      const verdict = tunnelVerdict(st, tunnelMinQueries, tunnelMinAvgLabelLen);
      if (!verdict) continue;
      const pipeIdx = key.indexOf('|');
      const client = key.slice(0, pipeIdx);
      const baseDomain = key.slice(pipeIdx + 1);
      const clientIp = net.isIP(client) !== 0 ? client : resolved.get(client.toLowerCase());
      if (!clientIp) continue; // no address to attribute — stays visible in the DNS view
      const detail = `${client} issued ${verdict.queries} DNS queries to ${baseDomain} in the last ${tunnelWindowHours} h` +
        ` with average subdomain label length ${verdict.avgLabelLen} chars — possible DNS tunneling / exfiltration.`;
      const input: FindingInput = {
        kind: 'dns-tunnel',
        srcIp: clientIp,
        dstIp: null,
        severity: 'warning',
        detail,
        context: { baseDomain, queries: verdict.queries, windowHours: tunnelWindowHours, avgLabelLen: verdict.avgLabelLen, client },
        deviceId: newestRow.deviceId || null,
        dedupeKey: `flow-security:dns-tunnel:${clientIp}:${baseDomain}`,
      };
      const isNew = await upsertFinding(input);
      if (isNew) {
        // eslint-disable-next-line no-console
        console.log(`[dns-security] dns-tunnel finding: ${client} → ${baseDomain}`);
        await notifyDnsSecurityFinding(input);
      }
    }

    watermarkMs = maxTs; // advance past everything scanned — each row is examined once
    lastRunAt = new Date().toISOString();
    lastError = null;
  } catch (err) {
    lastError = (err as Error).message;
    // eslint-disable-next-line no-console
    console.error('[dns-security] beat failed:', err);
    throw err; // trackBeat records the error; watermark stays put → next beat retries
  }
}

/**
 * Starts the DNS security worker. Must be called only after the API has bound
 * its port (same rule as every other worker — see index.ts app.listen).
 */
export function startDnsSecurityWorker(): () => void {
  initWorker('dnsSecurity', LEADER_KEYS.dnsSecurity);
  // eslint-disable-next-line no-console
  console.log('[dns-security] worker started');

  void trackBeat('dnsSecurity', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[dns-security] initial beat failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('dnsSecurity', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[dns-security] beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
