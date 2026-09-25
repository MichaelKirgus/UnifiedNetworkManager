/**
 * @unm/plugin-sdk — shared security-check contract (capability 'securityChecks').
 *
 * The Security page is fed by ONE normalized metric key: plugins emit
 * `metrics['securityChecks']` = SecurityCheckRow[] during their inventory
 * collection. Each row is one CHECK on one device (e.g. "auth-failures",
 * "/etc/passwd integrity", "rate limiting active"). The plugin owns WHAT to
 * check and HOW — every appliance exposes these signals differently (syslog,
 * journal, vendor log API, file hashes) — the contract only normalizes the
 * RESULT so one cross-device page can render them.
 *
 * Contract:
 *  - `name` is the stable identity of a check within (device, kind) — e.g.
 *    "auth-failures", "/etc/passwd". The API upserts on it; rename a check and
 *    its old row disappears on the next poll (delete-on-absent).
 *  - `status` is the verdict: 'ok' | 'info' | 'warning' | 'critical'. Rows with
 *    status 'ok' are DROPPED by the API at ingest time — a clean check is the
 *    absence of a row. The other three persist: 'info' for positive/neutral
 *    states worth surfacing (e.g. "rate limiting active, 3 IPs banned"),
 *    'warning'/'critical' for problems. A plugin that finds nothing may also
 *    emit an EMPTY array; both mean "no issues".
 *  - `count` carries a numeric magnitude when one exists (e.g. number of failed
 *    logins in the window) — rendered as a chip on the Security page.
 *  - `detail` is a short human-readable line (≤ ~500 chars recommended); keep
 *    it free of secrets/credentials even though it is only visible to users
 *    with security:read.
 */

// ---------------------------------------------------------------------------
// Row contract
// ---------------------------------------------------------------------------

/** Known check kinds; plugins may emit custom strings for future kinds. */
export type SecurityCheckKind =
  | 'auth-failures' // unsuccessful login attempts (syslog/journal/vendor log)
  | 'file-integrity' // important config/identity files changed vs a known baseline
  | 'rate-limiting' // brute-force protection active (fail2ban, nftables limit, vendor lockout)
  | 'account' // account hygiene findings (passwordless root, unexpected uid-0 accounts, …)
  | 'service-exposure' // sensitive services listening on unexpected interfaces/ports
  | 'other';

/** One security check result for one device, as emitted in metrics['securityChecks']. */
export interface SecurityCheckRow {
  /** Stable identity within (device, kind): "auth-failures", "/etc/passwd", … */
  name: string;
  kind: SecurityCheckKind | (string & {});
  /** Verdict. 'ok' rows are dropped by the API — info/warning/critical persist. */
  status: 'ok' | 'info' | 'warning' | 'critical';
  /** Short human-readable finding line (what changed / how many failures). */
  detail?: string | null;
  /** Numeric magnitude when one exists (failed-login count, changed-file count…). */
  count?: number | null;
  /** Plugin-specific details (JSON object) stored verbatim — e.g. per-source
   * breakdowns of failed logins or the baseline-vs-current hash pair. */
  extra?: Record<string, unknown>;
}
