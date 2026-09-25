/**
 * LANCOM LCOS router plugin — per-device security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during monitoring. The
 * API persists only non-'ok' rows into the cross-device Security page; a clean
 * device emits no persisted findings. All data comes from the already-collected
 * slow-path snapshot (no extra SNMP walks), so this is pure derivation and can
 * never sink the poll — it's wrapped in try/catch at the call site regardless.
 *
 * Check:
 *  - vpn-crypto   Per-IPsec-connection cipher/protocol strength from
 *                 lcsStatusVpnConnectionsTable. Flags genuinely weak choices:
 *                 IKEv1 (prefer IKEv2) and DES/3DES or MD5/SHA-1 in the crypto
 *                 suite. AES-128/256 + SHA-2 are clean. The router's WLAN SSID
 *                 table exposes no cipher field, so WiFi encryption is NOT
 *                 checkable here (it IS on the LX APs).
 */

import type { SecurityCheckRow } from '@unm/plugin-sdk';
import type { LcosRouterSnapshot, LcosVpnConn } from './lcosClient';

// ---------------------------------------------------------------------------
// Re-collection throttle
// ---------------------------------------------------------------------------

/** The snapshot is TTL-cached (~15 min); re-deriving checks more often than that
 * adds no information. Matches the other plugins' security cadence. */
const RECOLLECT_TTL_MS = 15 * 60_000;
const lastRun = new Map<string, { at: number; rows: SecurityCheckRow[] }>();

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Derives every check from the snapshot (pure, never throws on its own).
 * Throttled per host so a 30 s poll cadence doesn't re-derive needlessly. */
export function deriveSecurityChecks(host: string, snapshot: LcosRouterSnapshot): SecurityCheckRow[] {
  const key = (host ?? '').trim();
  if (!key) return [];

  const cached = lastRun.get(key);
  if (cached && Date.now() - cached.at < RECOLLECT_TTL_MS) return cached.rows;

  const rows: SecurityCheckRow[] = checkVpnCrypto(snapshot.vpnConnections);

  lastRun.set(key, { at: Date.now(), rows });
  return rows;
}

/** Test hook. */
export function clearSecurityCache(): void {
  lastRun.clear();
}

// ---------------------------------------------------------------------------
// VPN crypto strength (state-based)
// ---------------------------------------------------------------------------

/** One weak-crypto finding for a single IPsec connection. */
interface VpnIssue {
  status: SecurityCheckRow['status'];
  what: string; // short human phrase, e.g. "IKEv1"
}

/** Assesses one VPN connection's reported protocol + cipher and returns its issues. */
function assessVpn(v: LcosVpnConn): VpnIssue[] {
  const issues: VpnIssue[] = [];

  // IKE version — the DisplayString is e.g. "IKEv1" / "IKEv2".
  const ike = (v.ikeType ?? '').trim();
  if (/^ike\s*v?1$/i.test(ike) || /^ikev?1\b/i.test(ike)) {
    issues.push({ status: 'warning', what: `uses ${ike} — IKEv2 is strongly preferred` });
  }

  // Cipher suite — a DisplayString like "AES-128", possibly combined. Flag only
  // genuinely weak tokens; AES (any size) and SHA-2 are acceptable.
  const alg = (v.cryptAlg ?? '').trim().toLowerCase();
  if (alg) {
    // DES / 3DES — both deprecated (Sweet32 for 3DES). Match "des" but not as a
    // substring of an unrelated word; the suite strings are short tokens.
    if (/(^|[^a-z])des([^a-z]|$)/.test(alg) || alg.includes('3des')) {
      issues.push({ status: 'critical', what: `uses ${v.cryptAlg} — DES/3DES is deprecated` });
    }
    // MD5 / SHA-1 — weak integrity algorithms (collision attacks).
    if (alg.includes('md5') || alg.includes('sha-1') || alg.includes('sha1')) {
      issues.push({ status: 'warning', what: `uses ${v.cryptAlg} — MD5/SHA-1 is a weak hash` });
    }
  }

  return issues;
}

function checkVpnCrypto(conns: LcosVpnConn[]): SecurityCheckRow[] {
  const rows: SecurityCheckRow[] = [];
  for (const v of conns) {
    const issues = assessVpn(v);
    if (issues.length === 0) continue; // clean connection → no row

    const peer = v.peer || 'unknown';
    const worst = issues.some((i) => i.status === 'critical') ? 'critical' : 'warning';
    rows.push({
      name: `vpn-${v.physConn || peer}`,
      kind: 'vpn-crypto',
      status: worst,
      detail: `IPsec "${peer}" (${v.stateLabel || 'state unknown'}): ${issues.map((i) => i.what).join('; ')}`,
      extra: { peer: v.peer || null, physConn: v.physConn || null, ikeType: v.ikeType || null, cryptAlg: v.cryptAlg || null },
    });
  }
  return rows;
}
