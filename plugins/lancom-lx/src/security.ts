/**
 * LANCOM LX-Series plugin — per-AP security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during monitoring. The
 * API persists only non-'ok' rows into the cross-device Security page; a clean
 * AP emits no persisted findings. All data comes from the already-collected
 * slow-path snapshot (no extra SNMP walks), so this is pure derivation and can
 * never sink the poll — it's wrapped in try/catch at the call site regardless.
 *
 * Checks:
 *  - wifi-encryption   Per-SSID cipher strength from lcosLXStatusWLANInterfaces.
 *                     WEP (40/104) and unencrypted ("none") SSIDs are flagged —
 *                     WEP is cryptographically broken and "none" is an open
 *                     network. WPA(-PSK)/802.1X and OWE variants are clean.
 *  - auth-failures     PSK brute-force attempts, derived as the DELTA of the
 *                     cumulative per-SSID pskFailures counter between re-checks
 *                     (the snapshot is TTL-cached, so a raw absolute value would
 *                     stay "critical" forever from old failures). A handful of
 *                     wrong-passphrase tries is scanner noise → 'info'; larger
 *                     bursts escalate to warning/critical.
 */

import type { SecurityCheckRow } from '@unm/plugin-sdk';
import type { LcosSnapshot, LcosSsid } from './snmpCollector';

// ---------------------------------------------------------------------------
// Re-collection throttle + PSK counter baselines
// ---------------------------------------------------------------------------

/** The snapshot is TTL-cached (~15 min); re-deriving checks more often than that
 * adds no information. Matches the other plugins' security cadence. */
const RECOLLECT_TTL_MS = 15 * 60_000;
const lastRun = new Map<string, { at: number; rows: SecurityCheckRow[] }>();

/** Cumulative PSK-failure baselines per (host, SSID) for delta computation. */
interface PskBaseline {
  failures: number; // cumulative pskFailures (col 5)
  wrongPw: number; // cumulative pskWrongPassphrase (col 6)
}
const pskBaselines = new Map<string, PskBaseline>();

/** PSK brute-force thresholds (failed attempts since the last re-check). */
const AUTH_WARN_AT = 5;
const AUTH_CRIT_AT = 20;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Derives every check from the snapshot (pure, never throws on its own).
 * Throttled per host so a 30 s poll cadence doesn't re-derive needlessly. */
export function deriveSecurityChecks(host: string, snapshot: LcosSnapshot): SecurityCheckRow[] {
  const key = (host ?? '').trim();
  if (!key) return [];

  const cached = lastRun.get(key);
  if (cached && Date.now() - cached.at < RECOLLECT_TTL_MS) return cached.rows;

  const rows: SecurityCheckRow[] = [
    ...checkWifiEncryption(snapshot.ssids),
    ...checkPskBruteForce(key, snapshot.ssids),
  ];

  lastRun.set(key, { at: Date.now(), rows });
  return rows;
}

/** Test hook. */
export function clearSecurityCache(): void {
  lastRun.clear();
  pskBaselines.clear();
}

// ---------------------------------------------------------------------------
// WiFi encryption (state-based)
// ---------------------------------------------------------------------------

/** Cipher labels that are genuinely insecure (from the MIB's ENCRYPTIONS map). */
const INSECURE_ENCRYPTION: Record<string, { status: SecurityCheckRow['status']; why: string }> = {
  'none': { status: 'critical', why: 'no encryption — open network' },
  'WEP-40': { status: 'critical', why: 'WEP-40 is cryptographically broken' },
  'WEP-104': { status: 'critical', why: 'WEP-104 is cryptographically broken' },
};

function checkWifiEncryption(ssids: LcosSsid[]): SecurityCheckRow[] {
  const rows: SecurityCheckRow[] = [];
  for (const s of ssids) {
    const enc = (s.encryption ?? '').trim();
    if (!enc) continue; // unknown cipher — not enough to judge, skip
    const verdict = INSECURE_ENCRYPTION[enc];
    if (!verdict) continue; // WPA-PSK / 802.1X / OWE → clean

    const label = s.ssid || s.name || 'unnamed';
    rows.push({
      name: `wifi-${s.ifc || 'wlan'}:${label}`,
      kind: 'wifi-encryption',
      status: verdict.status,
      detail: `SSID "${label}" (${s.band || 'unknown band'}) uses ${enc} — ${verdict.why}; switch to WPA2/WPA3`,
      extra: { ssid: label, ifc: s.ifc || null, band: s.band || null, encryption: enc },
    });
  }
  return rows;
}

// ---------------------------------------------------------------------------
// PSK brute-force (delta of cumulative counters)
// ---------------------------------------------------------------------------

function checkPskBruteForce(host: string, ssids: LcosSsid[]): SecurityCheckRow[] {
  const rows: SecurityCheckRow[] = [];
  for (const s of ssids) {
    if (!s.ssid && !s.name) continue;
    // Only SSIDs that actually use PSK have meaningful failure counters.
    if (!(s.encryption ?? '').includes('PSK')) continue;

    const key = `${host}|${s.ifc || 'wlan'}:${s.ssid || s.name}`;
    const prev = pskBaselines.get(key);
    const cur: PskBaseline = { failures: s.pskFailures, wrongPw: s.pskWrongPassphrase };

    if (!prev) {
      // First observation — establish the baseline, no delta yet.
      pskBaselines.set(key, cur);
      continue;
    }
    // Counter reset/wrap (AP reboot or config change) → re-baseline silently.
    if (cur.failures < prev.failures || cur.wrongPw < prev.wrongPw) {
      pskBaselines.set(key, cur);
      continue;
    }

    const dFail = cur.failures - prev.failures;
    const dWrong = cur.wrongPw - prev.wrongPw;
    pskBaselines.set(key, cur); // refresh baseline for the next cycle

    if (dFail <= 0 && dWrong <= 0) continue; // no new failures → clean

    let status: SecurityCheckRow['status'];
    if (dFail >= AUTH_CRIT_AT || dWrong >= AUTH_CRIT_AT) status = 'critical';
    else if (dFail >= AUTH_WARN_AT || dWrong >= AUTH_WARN_AT) status = 'warning';
    else status = 'info'; // a few wrong-passphrase tries is normal scanner noise

    const label = s.ssid || s.name;
    rows.push({
      name: `psk-${s.ifc || 'wlan'}:${label}`,
      kind: 'auth-failures',
      status,
      detail: `${dFail} failed PSK attempt${dFail === 1 ? '' : 's'} on SSID "${label}" since last check (${dWrong} wrong passphrase)`,
      count: dFail,
      extra: { ssid: label, ifc: s.ifc || null, failuresDelta: dFail, wrongPassphraseDelta: dWrong },
    });
  }
  return rows;
}
