/**
 * Pure FreeRADIUS config/script renderers — no third-party imports (only the
 * node:crypto builtin), so they can be unit-tested in plain jest (CI runs
 * `cd api && npm test` with no DB/Docker) without pulling in the API's
 * db/pg/uuid dependency chain. The orchestrator that loads live data and writes
 * files lives in radiusConfig.ts; this module is only the string-building logic,
 * which is where the security-critical sanitizers are.
 */

import { createHash } from 'node:crypto';

export interface ParsedDbUrl {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

/**
 * Renders radius-auth-log.sh — the post-auth audit logger executed by the exec
 * instance `unmauthlog` (site post-auth) with POSITIONAL argv: $1 = %{reply:Packet-Type}
 * (the FINAL verdict, since this runs after unmrevoked in post-auth), $2 = User-Name,
 * $3 = Called-Station-Id, $4 = Calling-Station-Id. rlm_exec whitespace-splits the xlat'ed
 * program and strips literal [ ] from tokens (verified live); a missing attribute drops its
 * token and shifts later ones left — safe because every value passes the strict sanitizer
 * below before touching SQL. Writes ONE radpostauth row per completed auth attempt via psql
 * as the least-privilege unm_radius role (INSERT on radpostauth only). This is the
 * unsuccessful-login audit trail: rlm_sql cannot do it on FreeRADIUS 3.2.x (no post-auth
 * method binding — verified live), so a small shell script does.
 *
 * SECURITY: every value parsed from the pair list is DEVICE-supplied (the NAS/supplicant
 * sets User-Name, station ids…). They are interpolated into an SQL string, so each is
 * sanitized to [A-Za-z0-9._:@/-] and length-capped — anything else (quotes, spaces, `;`,
 * backticks…) cannot appear in a real RADIUS username/station id, so it is dropped rather
 * than fed to psql. This makes SQL injection via the auth channel impossible by construction.
 * Any failure (psql missing, DB down, timeout) is fail-OPEN: exit 0 — logging must never
 * affect authentication.
 */
export function renderAuthLogScript(db: ParsedDbUrl, creds: { user: string; password: string }): string {
  const bsh = (s: string) => `'${String(s).replace(/'/g, "'\\''")}'`;
  return [
    '#!/bin/bash',
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    '# Post-auth audit logging: one radpostauth row per completed auth attempt.',
    '# argv: $1=reply Packet-Type  $2=User-Name  $3=Called-Station-Id  $4=Calling-Station-Id',
    'set -u',
    `PGHOST=${bsh(db.host)}`,
    `PGPORT="${db.port}"`,
    `PGUSER=${bsh(creds.user)}`,
    `PGPASSWORD=${bsh(creds.password)}`,
    `PGDATABASE=${bsh(db.database)}`,
    'export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE',
    '# argv = xlat of RADIUS attributes (shell_escape=no → direct execvp, one token',
    '# per attribute). A missing attribute drops its token and shifts later ones left;',
    '# the strict sanitizer below turns anything malformed into "unknown"/empty,',
    '# so a shifted value can at worst be mislabeled — never injected.',
    'verdict="${1:-Access-Reject}"',
    'user="${2:-}"; called="${3:-}"; calling="${4:-}"',
    '[ -n "$user" ] || user="unknown"',
    '# --- sanitize device-supplied values (SQL-injection guard) -----------------',
    'case "$user" in *[!A-Za-z0-9._:@/-]*|"") user="unknown" ;; esac',
    '[ ${#user} -le 128 ] || user=${user:0:128}',
    'case "$called" in *[!A-Za-z0-9._:@/-]*) called="" ;; esac',
    '[ ${#called} -le 75 ] || called=${called:0:75}',
    'case "$calling" in *[!A-Za-z0-9._:@/-]*) calling="" ;; esac',
    '[ ${#calling} -le 75 ] || calling=${calling:0:75}',
    'case "$verdict" in Access-Accept|Access-Reject) ;; *) verdict="unknown" ;; esac',
    '# --- insert (fail-open) -----------------------------------------------------',
    '# Sanitized values contain no quotes, so single-quoting them is safe.',
    `timeout 5 psql -qc "INSERT INTO radpostauth (username, pass, reply, calledstationid, callingstationid, authdate) VALUES ('$user', '', '$verdict', NULLIF('$called', ''), NULLIF('$calling', ''), now())" 2>/dev/null || {`,
    '  echo "[unm-radius] auth-log insert failed (fail-open)" >&2',
    '}',
    'exit 0',
    '',
  ].join('\n');
}

/** Extracts every `-----BEGIN CERTIFICATE … END CERTIFICATE` block from a PEM document (original text preserved). */
function pemCertificates(pem: string): string[] {
  const out: string[] = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) out.push(m[0].trim());
  return out;
}

/**
 * Builds the CA trust bundle for EAP-TLS client-cert validation (FreeRADIUS
 * `ca_file`). Concatenates the local UNM CA root (when bootstrapped) with the
 * replicated/extra trusted roots from the `radiusTrustedCaPem` setting,
 * de-duplicated by SHA-256 of the normalized PEM block — so a slave that also
 * happens to run its own step-ca never carries the same cert twice, and order
 * is stable (local root first). Returns '' when nothing is trustable.
 * NOTE: the rendered eap.conf still points ca_file at the bundle unconditionally
 * and FreeRADIUS 3.x is strict about it — a MISSING file breaks config parse AND
 * fresh loads, and an EMPTY file fails rlm_eap_tls SSL-context instantiation
 * ("no certificate or crl found"); both verified live. The entrypoint therefore
 * ALWAYS leaves a non-empty bundle in place: real roots when this function would
 * return something, else the self-signed RADIUS server cert as a placeholder that
 * trusts no real client until a root lands (see radius/entrypoint.sh).
 */
export function buildCaBundle(localRootPem: string | null, trustedCaPem: string): string {
  const seen = new Set<string>();
  const blocks: string[] = [];
  for (const pem of [localRootPem ?? '', trustedCaPem ?? '']) {
    for (const block of pemCertificates(pem)) {
      // Fingerprint the NORMALIZED form so line-wrapping differences don't defeat dedup.
      const fp = createHash('sha256').update(block.replace(/\s+/g, ' ')).digest('hex');
      if (seen.has(fp)) continue;
      seen.add(fp);
      blocks.push(block);
    }
  }
  return blocks.join('\n') + (blocks.length > 0 ? '\n' : '');
}
