import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { asc } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { getSecretFresh } from '../secretsProvider';
import { getEffectiveValues } from '../systemSettings';
// Pure renderers (no db/pg/uuid imports) — kept in radiusRender.ts so the
// security-critical sanitizers are unit-testable without a live database.
import { buildCaBundle, renderAuthLogScript, type ParsedDbUrl } from './radiusRender';

/**
 * Renders the FreeRADIUS config for the unm-radius sidecar (WiFi EAP-TLS) and
 * writes it to the shared config volume. The RADIUS service watches these files'
 * mtimes and SIGHUPs radiusd on change (see radius/entrypoint.sh), so a write
 * here hot-applies new NAS clients / accounting toggles without restarting the
 * container — same pattern as the CA's ca.json (api/src/ca/stepCaConfig.ts).
 *
 * Layout contract (two volumes — see radius/Dockerfile):
 *   /data/radius  shared with the API. The API renders:
 *                   clients.conf       NAS list (shared secrets)
 *                   eap.conf           EAP-TLS module instance (mods-enabled/eap,
 *                                      REPLACES the stock one — rlm_eap requires
 *                                      an Auth-Type dict value named after the
 *                                      INSTANCE, and only "EAP" exists by default,
 *                                      so a custom-named instance cannot instantiate)
 *                   exec-unm.conf      revocation-check program instance (mods-enabled/)
 *                   sql-unm.conf       rlm_sql accounting instance (mods-enabled/)
 *                   site-eaptls.conf   the auth+acct site (REPLACES `default`)
 *                   radius-user-profile.sh  per-auth exec: revocation check +
 *                                           RADIUS reply attributes (VLAN, static
 *                                           IP, session limits) from Postgres
 *                 The entrypoint copies each to its exact raddb destination —
 *                 FreeRADIUS 3.x loads module instances ONLY from mods-enabled/
 *                 and sites ONLY from sites-enabled/.
 *   /data/ca      the CA shared volume, mounted READ-ONLY. The entrypoint keeps
 *                 root_ca.crt in sync into the local raddb so EAP-TLS validates
 *                 client certs against UNM's own CA. step-ca 0.30.x has no CRL
 *                 endpoint, so revocation is enforced per-auth: revoked serials
 *                 live in Postgres (revoked_serials) and the exec check below
 *                 rejects them (exit 1 = RLM_MODULE_REJECT — verified against
 *                 rlm_exec's status2rcode mapping).
 *
 * The RADIUS server cert/key are NOT rendered here: they're self-signed by the
 * entrypoint on first boot and persisted in /var/lib/unm-radius inside the
 * container (container recreation keeps the same identity; no API involvement).
 */

export const RADIUS_CONFIG_PATH = process.env.UNM_RADIUS_CONFIG_PATH ?? '/data/radius';

/** The raddb path the eap instance validates client certs against (entrypoint-synced).
 *  A BUNDLE: local UNM CA root + replicated trusted roots (RADIUS failover slaves
 *  trust their replication source's CA — see buildCaBundle in radiusRender.ts).
 *  ALWAYS exists on disk NON-EMPTY (the entrypoint seeds it with the self-signed
 *  RADIUS server cert as a placeholder before any real CA has bootstrapped)
 *  because FR3 fails parse on a missing ca_file and rlm_eap_tls refuses to
 *  instantiate an empty one. */
const CA_BUNDLE_IN_RADD = '/etc/freeradius/3.0/ca/bundle.pem';
/** Rendered file carrying the extra/trusted CA roots from the `radiusTrustedCaPem`
 *  setting; the entrypoint merges it with the local root into CA_BUNDLE_IN_RADD. */
const TRUSTED_CA_FILE = 'trusted-ca.pem';
/** Where the entrypoint persists the self-signed RADIUS server cert/key. */
const SERVER_CERT = '/var/lib/unm-radius/server.crt';
const SERVER_KEY = '/var/lib/unm-radius/server.key';

// ParsedDbUrl is imported from ./radiusRender (the pure renderers module).

/** Parses DATABASE_URL into the pieces rlm_sql's radius_db connection string needs. */
export function parseDatabaseUrl(url: string): ParsedDbUrl {
  const u = new URL(url);
  if (!u.hostname) throw new Error('DATABASE_URL has no host');
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 5432,
    user: decodeURIComponent(u.username || 'unm'),
    password: decodeURIComponent(u.password || ''),
    database: (u.pathname ?? '/').replace(/^\//, '') || 'unm',
  };
}

/**
 * Escapes a string for use inside a FreeRADIUS double-quoted config value
 * (NAS client IP / shared secret in clients.conf). SECURITY: the rendered file
 * is parsed line-by-line by radiusd, so a value containing CR/LF or other control
 * characters could break out of its `key = "…"` line and inject arbitrary raddb
 * directives. Strip all C0 controls + DEL (never valid in an IP literal or a RADIUS
 * shared secret) BEFORE escaping backslashes/quotes, so the result is always a
 * single safe line.
 */
function frQuote(s: string): string {
  return s.replace(/[\x00-\x1f\x7f]/g, '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Extracts the RADIUS shared secret from a decrypted secret's fields. The
 * secrets-provider types that make sense for a NAS client are single-value —
 * apiKeyNoSecret (apiKey), tunnelPsk (psk), scpRefreshToken (refreshToken) …;
 * multi-field types map to their secret half (usernamePassword → password,
 * apiKey → apiSecret). Anything else is not usable as a shared secret.
 */
function pickRadiusSharedSecret(type: string, fields: Record<string, string>): string | undefined {
  switch (type) {
    case 'apiKey':
      return fields.apiSecret || fields.apiKey || undefined;
    case 'usernamePassword':
      return fields.password || undefined;
    default: {
      // Single-field types: the one non-empty value IS the secret.
      const values = Object.values(fields).filter((v) => typeof v === 'string' && v.length > 0);
      if (values.length === 1) return values[0];
      return undefined;
    }
  }
}

/**
 * Loads NAS clients from the radius_nas_clients table and resolves each row's
 * shared secret via its owning provider — getSecretFresh, never cached: the
 * rendered file must reflect the CURRENT value (a rotated secret applies on
 * the next render). Rows without a secret, or whose secret can no longer be
 * resolved / mapped to a usable field, are skipped with a warning: one broken
 * credential must not take down the whole RADIUS service.
 */
async function loadNasClients(): Promise<Array<{ ip: string; secret: string }>> {
  const rows = await db.query.radiusNasClients.findMany({ orderBy: [asc(schema.radiusNasClients.ip)] });
  const out: Array<{ ip: string; secret: string }> = [];
  for (const row of rows) {
    if (!row.secretId) continue; // not configured yet — the webapp shows a warning chip
    let s;
    try {
      s = await getSecretFresh(row.secretId);
    } catch (err) {
      console.warn(`[radius] NAS client ${row.ip} references an unresolvable secret (${row.secretId}):`, (err as Error).message);
      continue;
    }
    const value = pickRadiusSharedSecret(s.type, s.fields);
    if (!value) {
      console.warn(`[radius] NAS client ${row.ip}: secret type "${s.type}" has no usable shared-secret field — skipped`);
      continue;
    }
    out.push({ ip: row.ip, secret: value });
  }
  return out;
}

/**
 * Detects the API container's own IP on its primary non-internal interface.
 * FreeRADIUS matches a request's SOURCE address against clients.conf, so the
 * internal probe entry must use exactly the address the probe socket binds to —
 * which is this one (the worker sends from the default route's source). The
 * value is re-detected on every render and persisted back into radius_probe_client
 * so a container recreation with a new IP self-heals without manual work.
 */
export function detectOwnIp(): string | null {
  const ifaces = os.networkInterfaces();
  for (const list of Object.values(ifaces)) {
    for (const a of list ?? []) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return null;
}

/**
 * Loads UNM's internal probe client (self-monitoring). The row is bootstrapped
 * by initDb with a machine-generated secret; this resolves the CURRENT value so
 * a manual DB edit of the secret applies on the next render. Returns null when
 * the row is missing or no own-IP could be detected — self-monitoring then
 * simply stays off (the probe worker reports "not configured"), never breaking
 * the rest of the render.
 */
async function loadProbeClient(): Promise<{ ip: string; secret: string } | null> {
  try {
    const rows = await db.query.radiusProbeClient.findMany();
    if (rows.length === 0) return null;
    const row = rows[0];
    const ownIp = detectOwnIp();
    if (!ownIp) {
      console.warn('[radius] could not detect the API container IP — internal probe client skipped');
      return null;
    }
    // Persist the freshly detected IP (no-op when unchanged).
    if (row.ip !== ownIp) {
      await pool.query(`UPDATE radius_probe_client SET ip = $1 WHERE id = $2`, [ownIp, row.id]);
    }
    return { ip: ownIp, secret: row.secret };
  } catch (err) {
    console.warn('[radius] could not load the internal probe client:', (err as Error).message);
    return null;
  }
}

function renderClientsConf(clients: Array<{ ip: string; secret: string; options?: Record<string, string> }>): string {
  const lines = [
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    '# NAS clients allowed to authenticate against this RADIUS server.',
    '',
  ];
  for (const c of clients) {
    lines.push(
      `client ${c.ip} {`,
      '    ipaddr = ' + frQuote(c.ip),
      '    secret = "' + frQuote(c.secret) + '"'
    );
    if (c.options) {
      for (const [k, val] of Object.entries(c.options)) lines.push(`    ${k} = ${val}`);
    }
    lines.push('}', '');
  }
  return lines.join('\n');
}

function renderEapConf(): string {
  // Uses the STANDARD instance name `eap` (replacing the stock mods-enabled/eap),
  // NOT a custom one. rlm_eap sets xlat_name = the INSTANCE name and requires an
  // Auth-Type dictionary value with that exact name; only "EAP" exists by default,
  // so any custom-named instance fails to instantiate ("Failed to find 'Auth-Type
  // <name>' section"). The stock `default` site relies on exactly this — a plain
  // `eap { ... }` instance referenced as bare `eap`. Verified against rlm_eap.c.
  return [
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    'eap {',
    '    default_eap_type = tls',
    '    timer_expire = 60',
    '    tls {',
    `        certificate_file = ${SERVER_CERT}`,
    `        private_key_file = ${SERVER_KEY}`,
    // Bundle (local root + replicated trusted roots) — the entrypoint assembles
    // it from /data/ca/root_ca.crt + rendered trusted-ca.pem and ALWAYS leaves a
    // NON-EMPTY file in place: FR3 fails config parse on a MISSING ca_file and
    // rlm_eap_tls refuses to instantiate an EMPTY one ("no certificate or crl
    // found") — both verified live. Before any CA exists the entrypoint seeds it
    // with the self-signed RADIUS server cert as a placeholder that trusts no real
    // client; see sync_config in radius/entrypoint.sh.
    `        ca_file = ${CA_BUNDLE_IN_RADD}`,
    '        verify_depth = 2',
    '        check_crl = no',
    '    }',
    '}',
    '',
  ].join('\n');
}

/**
 * The least-privilege Postgres role the radius sidecar connects with (created
 * by initDb — see db.ts). It can only INSERT/UPDATE radacct and SELECT
 * revoked_serials; the API's own superuser credentials are NEVER rendered into
 * the raddb, so a compromised radius container cannot read/write other tables.
 */
export async function getRadiusDbCredentials(): Promise<{ user: string; password: string }> {
  const rows = await db.select().from(schema.radiusDbCredentials).limit(1);
  if (rows.length > 0) return { user: rows[0].username, password: rows[0].password };
  // initDb always creates the row before the first render — reaching here means
  // bootstrap is mid-flight. Fall back to DATABASE_URL so the service still
  // comes up; the next re-render (15s retry loop) picks up the limited role.
  console.error('[radius] radius_db_credentials row missing at render time — falling back to API DB credentials');
  const dbUrl = process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm';
  const p = parseDatabaseUrl(dbUrl);
  return { user: p.user, password: p.password };
}

function renderSqlConf(db: ParsedDbUrl, creds: { user: string; password: string }): string {
  // rlm_sql, postgresql dialect. The queries.conf include is HARDCODED to the
  // stock path (the package's own mods-available/sql uses ${.:name}, which for a
  // named instance (section `sql unm`) would resolve to sql/unm/main/... — wrong).
  // libpq conn strings escape values with SINGLE quotes ('' doubling) — double
  // quotes are passed through as literal characters and break authentication
  // (verified: password=\"…\" → FATAL, password='…' → connected).
  const sq = (s: string) => s.replace(/'/g, "''");
  const conn = [
    'host=' + db.host,
    'port=' + db.port,
    'dbname=' + db.database,
    'user=' + creds.user,
    "password='" + sq(creds.password) + "'",
  ].join(' ');
  // queries.conf references ${client_table}, ${authcheck_table}, ... AND
  // ${group_attribute} — the stock mods-available/sql defines all of them before
  // its include; a custom instance must too. We use accounting (radacct) and
  // post-auth logging (radpostauth); the auth/group tables point at radacct as
  // well: they're never queried by our site, but every variable must resolve or
  // queries.conf fails to parse ("Reference ... not found"). group_attribute is
  // xlat'ed as %{${group_attribute}} in the two (unused) group check/reply
  // queries — it MUST be a real dictionary attribute or config parsing fails
  // (the stock value "SQL-Group" is NOT one, which only works because stock sql
  // is disabled by default). "User-Name" parses cleanly and those queries are
  // dead code in our site anyway.
  return [
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    'sql unm {',
    '    driver = "rlm_sql_postgresql"',
    `    radius_db = "${frQuote(conn)}"`,
    '    acct_table1 = "radacct"',
    '    acct_table2 = "radacct"',
    // postauth_table must be defined because the stock queries.conf (included
    // below) references ${..postauth_table} — but rlm_sql on FreeRADIUS 3.2.x
    // does NOT execute a post-auth query: its method bindings are only
    // accounting/authorize/recv/send, so calling it from a site `post-auth`
    // section is a silent no-op (verified live on 3.2.7: Access-Rejects were
    // processed with zero radpostauth rows and no SQL errors). The actual
    // post-auth audit logging is done by the exec instance `unmauthlog` +
    // radius-auth-log.sh (see renderExecConf / renderAuthLogScript).
    '    postauth_table = "radpostauth"',
    '    authcheck_table = "radacct"',
    '    groupcheck_table = "radacct"',
    '    authreply_table = "radacct"',
    '    groupreply_table = "radacct"',
    '    usergroup_table = "radacct"',
    '    client_table = "radacct"',
    '    group_attribute = "User-Name"',
    '    $INCLUDE /etc/freeradius/3.0/mods-config/sql/main/postgresql/queries.conf',
    '}',
    '',
  ].join('\n');
}

function renderSiteConf(accountingEnabled: boolean): string {
  // The EAP-TLS site REPLACES the stock `default` (which would also accept
  // PAP/CHAP/EAP-MD5). Accounting is native via rlm_sql → Postgres radacct.
  const lines = [
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    'server eap-tls {',
    '    listen {',
    '        type = auth',
    '        ipaddr = *',
    '        port = 0',
    '    }',
  ];
  if (accountingEnabled) {
    lines.push(
      '    listen {',
      '        type = acct',
      '        ipaddr = *',
      '        port = 0',
      '    }'
    );
  }
  // No `realm` in authorize: FR3 does not allow calling the bare realm module
  // ("Failed to find \"realm\" as a module or policy" — it's a container of the
  // IPASS/suffix/… submodules), and EAP-TLS users are always local anyway.
  lines.push(
    '    authorize {',
    '        filter_username',
    '        preprocess',
    '        eap { ok = return }',
    '    }',
    '    authenticate {',
    '        eap',
    '    }'
  );
  if (accountingEnabled) {
    // NOTE: no `preacct` section — rlm_sql has no preacct method binding
    // ("sql modules aren't allowed in 'preacct' sections", verified against
    // FreeRADIUS 3.2.7). Accounting is the only sql hook we need.
    lines.push(
      '    accounting {',
      '        unm',
      '    }'
    );
  }
  // Revocation check + per-user reply attributes: the exec program receives the
  // client cert serial (lowercase hex, as FreeRADIUS sets TLS-Client-Cert-Serial)
  // and exits 1 when it is in revoked_serials — exit 1 maps to RLM_MODULE_REJECT,
  // which flips the Access-Accept into an Access-Reject. remove_reply_message_if_eap
  // runs FIRST: it strips the EAP-tunnel Reply-Message (e.g. "Access denied"), and
  // must not run after unmrevoked or it would also delete the per-user
  // Reply-Message the script just added to the reply list.
  //
  // FR3 unlang references module instances by their BARE instance name (the
  // section's second word: `sql unm {…}` → `unm`, `exec unmrevoked {…}` →
  // `unmrevoked`). The dotted form (`sql.unm`) is NOT resolvable — the compiler
  // looks up "sql.unm" as an instance name, then chops to base module "sql",
  // and never tries the bare instance (verified: "Failed to find sql.unm as a
  // module or policy").
  // unmauthlog (exec) in post-auth: writes one radpostauth row per completed
  // auth attempt, ACCEPT and REJECT alike — the unsuccessful-login audit trail
  // that the radiusMonitor worker turns into notifications. It runs AFTER
  // unmrevoked so a revocation flip to REJECT is logged as a reject (final
  // verdict). rlm_sql has NO post-auth binding on FreeRADIUS 3.2.x (verified
  // live: calling `unm` here is a silent no-op), hence the exec-based logger.
  // CRITICAL: in FR3 the plain `post-auth` block runs ONLY for ACCEPTED
  // requests — rejects flow through `Post-Auth-Type REJECT`. So unmauthlog is
  // listed LAST in BOTH blocks (verified live: a reject produced no row while
  // it was only in the plain post-auth block). %{reply:Packet-Type} at that
  // point is always the final verdict.
  lines.push(
    '    post-auth {',
    '        remove_reply_message_if_eap',
    '        unmrevoked',
    '        unmauthlog',
    '        Post-Auth-Type REJECT {',
    '            attr_filter.access_reject',
    '            eap',
    '            remove_reply_message_if_eap',
    '            unmauthlog',
    '        }',
    '    }'
  );
  lines.push('}', '');
  return lines.join('\n');
}

function renderExecConf(): string {
  // Two per-auth exec program instances.
  //
  // unmrevoked (post-auth): `program` is xlat'ed per request —
  // %{TLS-Client-Cert-Serial} expands to the client cert serial (lowercase hex,
  // set by FreeRADIUS during EAP-TLS cert verification). shell_escape = no so
  // the value arrives as a single argv element. output_pairs = reply copies
  // whatever the script prints on stdout into the REPLY list — in post-auth
  // that is exactly what gets encoded into the Access-Accept packet, so this
  // is how per-user VLAN / static IP / session limits reach the NAS without
  // any rlm_sql authorize wiring (same pattern as the stock exec-program-wait
  // sample). output_pairs only accepts pair-LIST names: request/reply/
  // control/session-state — "request-pair" is NOT one of them and fails
  // instantiation.
  //
  // unmauthlog (post-auth): writes ONE radpostauth row per completed auth
  // attempt (ACCEPT and REJECT alike) via psql as the least-privilege
  // unm_radius role — the unsuccessful-login audit trail. All values are xlat'd
  // into `program` and arrive as POSITIONAL argv (the same proven pattern as
  // radius-user-profile.sh): $1 = %{reply:Packet-Type} (the FINAL verdict in
  // post-auth, so a revocation flip to REJECT is logged as a reject),
  // $2..$4 = User-Name / Called-Station-Id / Calling-Station-Id. Verified live:
  // rlm_exec whitespace-splits the xlat'ed program AND strips literal [ ] from
  // tokens, and does NOT feed input_pairs to the child's stdin — positional
  // argv is the only reliable channel. A missing attribute drops its token,
  // shifting later ones left; that is SAFE because every value passes through
  // the strict sanitizer below (anything malformed → "unknown"/empty), so a
  // shifted station id can at worst be mislabeled, never injected.
  // shell_escape = no → direct execvp, so no shell metacharacter can be
  // interpreted. A DB failure must never affect auth: the script always exits 0.
  return [
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    'exec unmrevoked {',
    '    input_pairs = request',
    '    output_pairs = reply',
    '    shell_escape = no',
    '    timeout = 5',
    '    program = "/etc/freeradius/3.0/radius-user-profile.sh %{TLS-Client-Cert-Serial}"',
    '}',
    '',
    'exec unmauthlog {',
    // No output_pairs line: rlm_exec's default is "none" (stdout discarded),
    // and `output_pairs = none` is REJECTED by FreeRADIUS 3.2.x ("Invalid
    // output list") — verified live, it crash-looped the sidecar.
    '    shell_escape = no',
    '    timeout = 5',
    // Single bracketed token: rlm_exec whitespace-splits the xlat'ed program,
    // so separate tokens with empty expansions would vanish and shift argv.
    // Positional argv — rlm_exec whitespace-splits the xlat'ed program and
    // strips literal [ ] from tokens (verified live), so no delimiters survive.
    '    program = "/etc/freeradius/3.0/radius-auth-log.sh %{reply:Packet-Type} %{User-Name} %{Called-Station-Id} %{Calling-Station-Id}"',
    '}',
    '',
  ].join('\n');
}

function renderUserProfileScript(db: ParsedDbUrl, creds: { user: string; password: string }): string {
  // Executed by the exec.unmrevoked instance with argv[1] = client cert serial.
  // Two jobs in one Postgres round-trip:
  //   1. Revocation — exit 1 when $1 is in revoked_serials (FreeRADIUS maps
  //      exit N to module result N-1, so exit 1 = RLM_MODULE_REJECT →
  //      Access-Reject). step-ca has no CRL endpoint; this IS the enforcement.
  //   2. Per-user profile — prints the set fields of radius_user_profiles as
  //      "Attr = value" lines on stdout; rlm_exec (output_pairs = reply,
  //      run in post-auth) adds them to the Access-Accept packet, so the NAS
  //      applies VLAN / static IP / session limits for THIS session only.
  // Any Postgres failure is fail-OPEN (exit 0) — a DB outage must not lock
  // every client out. Bash single-quote escaping (close, literal ', reopen)
  // keeps arbitrary values shell-safe.
  const bsh = (s: string) => `'${String(s).replace(/'/g, "'\\''")}'`;
  return [
    '#!/bin/bash',
    '# Rendered by the UNM API — do not edit (re-rendered on every change).',
    '# Per-auth check + per-user RADIUS reply attributes. $1 = client cert serial',
    '# (lowercase hex, as FreeRADIUS sets TLS-Client-Cert-Serial).',
    'set -u',
    `PGHOST=${bsh(db.host)}`,
    `PGPORT="${db.port}"`,
    `PGUSER=${bsh(creds.user)}`,
    `PGPASSWORD=${bsh(creds.password)}`,
    `PGDATABASE=${bsh(db.database)}`,
    'export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE',
    'serial="${1:-}"',
    '[ -n "$serial" ] || exit 0',
    // SECURITY: $1 is DEVICE-supplied (the client presents the cert; FreeRADIUS
    // xlat's TLS-Client-Cert-Serial into argv). It is interpolated into two SQL
    // strings below, so it MUST be validated before any query runs. A real X.509
    // serial rendered by FreeRADIUS is lowercase hex only — anything else (quotes,
    // spaces, `;`, backticks…) is not a cert we can map to a profile or revocation
    // row, so fail OPEN with no attributes rather than feed it to psql. This makes
    // SQL injection via the auth channel impossible by construction.
    'case "$serial" in',
    '  *[!0-9a-f]*|"") exit 0 ;;',
    'esac',
    '[ ${#serial} -le 64 ] || exit 0',
    '# --- 1. Revocation (checked first — a revoked cert must not get attributes) ---',
    'count=$(timeout 5 psql -Atc "SELECT count(*) FROM revoked_serials WHERE lower(serial) = lower(\'$serial\')" 2>/dev/null) || {',
    '  echo "[unm-radius] revocation check failed (fail-open)" >&2',
    '  exit 0',
    '}',
    '[ -n "$count" ] && [ "$count" != "0" ] && exit 1',
    '# --- 2. Per-user profile → RADIUS reply attributes on stdout ---------------',
    '# Columns: vlanId, framedIp, framedIpv6, sessionTimeoutSec, idleTimeoutSec,',
    '#          replyMessage — all nullable; only set values are printed.',
    // NOTE: the SQL identifiers must reach psql QUOTED (camelCase columns). The
    // file therefore carries literal \" sequences — bash strips one level of
    // backslash inside the double-quoted -c argument, leaving "vlanId" for
    // Postgres. Bare "vlanId" here would be consumed by bash → unquoted
    // identifier → "column vlanid does not exist".
    'row=$(timeout 5 psql -AtF \\| -c "SELECT \\"vlanId\\", \\"framedIp\\", \\"framedIpv6\\", \\"sessionTimeoutSec\\", \\"idleTimeoutSec\\", \\"replyMessage\\" FROM radius_user_profiles WHERE lower(serial) = lower(\'$serial\') LIMIT 1" 2>/dev/null) || {',
    '  echo "[unm-radius] profile lookup failed (fail-open)" >&2',
    '  exit 0',
    '}',
    '[ -n "$row" ] || exit 0',
    'IFS=\\| read -r vlan ip6v4 ip6v6 sess idle msg <<< "$row"',
    '# VLAN assignment: the IEEE-802 tunnel pair is what NASes key on; the ID goes',
    '# in Tunnel-Private-Group-ID (the 802.1X-standard attribute for VLANs).',
    'if [ -n "$vlan" ]; then',
    '  echo "Tunnel-Type = IEEE-802"',
    '  echo "Tunnel-Medium-Type = IEEE-802"',
    '  echo "Tunnel-Private-Group-ID = $vlan"',
    'fi',
    '[ -n "$ip6v4" ] && echo "Framed-IP-Address = $ip6v4"',
    '[ -n "$ip6v6" ] && echo "Framed-IPv6-Address = $ip6v6"',
    'if [ -n "$sess" ]; then',
    '  echo "Session-Timeout = $sess"',
    '  echo "Termination-Action = RESTART"',
    'fi',
    '[ -n "$idle" ] && echo "Idle-Timeout = $idle"',
    '[ -n "$msg" ] && echo "Reply-Message = $msg"',
    'exit 0',
    '',
  ].join('\n');
}

// renderAuthLogScript now lives in radiusRender.ts (pure, no db imports) so it is
// unit-testable without a live database — see authLogScript.test.ts.

/** Builds all rendered files from effective settings + the NAS client table. */
export async function renderRadiusConfig(): Promise<Record<string, string>> {
  const v = await getEffectiveValues();
  if (String(v.radiusEnabled ?? 'true') === 'false') return {}; // service off — nothing to render

  const dbUrl = process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm';
  const db = parseDatabaseUrl(dbUrl);
  // The sidecar connects with its own least-privilege role (radacct +
  // revoked_serials only) — never the API's superuser credentials.
  const creds = await getRadiusDbCredentials();
  const accountingEnabled = String(v.radiusAccountingEnabled ?? 'true') !== 'false';

  // localhost is ALWAYS a client (radclient/wpa_supplicant testing from the host
  // or sibling containers) with a stable dev secret; NAS clients from the
  // radius_nas_clients table are appended on top. Duplicates by IP keep the
  // first occurrence (the localhost entry wins).
  const clients: Array<{ ip: string; secret: string; options?: Record<string, string> }> = [
    { ip: '127.0.0.1', secret: 'unm-radius-local' },
  ];
  for (const c of await loadNasClients()) {
    if (!clients.some((x) => x.ip === c.ip)) clients.push(c);
  }
  // UNM's own internal probe client — the self-monitoring entry. FreeRADIUS
  // drops requests from any source IP not listed here (no reply at all), so
  // this is what makes a functional liveness check possible: the radiusMonitor
  // worker sends a test Access-Request from this address and treats ANY
  // well-formed response as "the server is alive, loaded its config, and
  // recognizes UNM". The secret is machine-generated (radius_probe_client),
  // never user-supplied; the entry is always rendered while RADIUS is on.
  //
  // limit_proxy_state / require_message_authenticator are pinned to `no`
  // because FR3's default `auto` LEARNS a client's traits from its FIRST
  // packet ("Setting \"limit_proxy_state = true\" for client …") and then
  // SILENTLY DROPS every later request that violates the learned state — no
  // reply, no log line. That made the probe flaky: any change to the probe's
  // attribute set (e.g. adding/removing Proxy-State) could poison the client.
  // Explicit `no` disables learning for this entry entirely → deterministic.
  const probe = await loadProbeClient();
  if (probe && !clients.some((x) => x.ip === probe.ip)) {
    clients.push({ ...probe, options: { limit_proxy_state: 'no', require_message_authenticator: 'no' } });
  }

  const files: Record<string, string> = {
    'clients.conf': renderClientsConf(clients),
    // `eap.conf` — the entrypoint copies it to mods-enabled/eap, REPLACING the
    // stock instance (see renderEapConf for why a custom name is impossible).
    'eap.conf': renderEapConf(),
    'exec-unm.conf': renderExecConf(),
    'sql-unm.conf': renderSqlConf(db, creds),
    'site-eaptls.conf': renderSiteConf(accountingEnabled),
    'radius-user-profile.sh': renderUserProfileScript(db, creds),
    'radius-auth-log.sh': renderAuthLogScript(db, creds),
  };
  // Extra/trusted CA roots (RADIUS failover: a slave gets its replication
  // source's root via the radius section). Public cert only — no keys ever.
  const trustedPem = String(v.radiusTrustedCaPem ?? '').trim();
  if (trustedPem.includes('BEGIN CERTIFICATE')) {
    files[TRUSTED_CA_FILE] =
      '# Rendered by the UNM API from the radiusTrustedCaPem setting — do not edit.\n' + trustedPem + '\n';
  }
  return files;
}

/**
 * Renders + atomically writes every file (tmp + rename per file, so radiusd's
 * mtime watch never sees a half-written config). Returns true when the content
 * actually changed. An empty render (radiusEnabled=false) is a no-op — the last
 * rendered files stay in place and the service simply isn't started by compose.
 */
export async function writeRadiusConfig(): Promise<{ changed: boolean }> {
  const files = await renderRadiusConfig();
  if (Object.keys(files).length === 0) return { changed: false };

  fs.mkdirSync(RADIUS_CONFIG_PATH, { recursive: true });
  let changed = false;
  for (const [name, content] of Object.entries(files)) {
    const dest = path.join(RADIUS_CONFIG_PATH, name);
    if (fs.existsSync(dest) && fs.readFileSync(dest, 'utf8') === content) continue;
    const tmp = `${dest}.tmp`;
    fs.writeFileSync(tmp, content);
    fs.renameSync(tmp, dest);
    // The entrypoint re-chowns everything on sync, but keep the script readable
    // by freerad even before the first reload.
    if (name === 'radius-user-profile.sh') fs.chmodSync(dest, 0o750);
    changed = true;
  }
  // A cleared radiusTrustedCaPem must remove the rendered file so the entrypoint
  // rebuilds the bundle from what remains (only while a render is active — an
  // empty render above returns early and leaves everything in place).
  const trustedDest = path.join(RADIUS_CONFIG_PATH, TRUSTED_CA_FILE);
  if (!files[TRUSTED_CA_FILE] && fs.existsSync(trustedDest)) {
    fs.rmSync(trustedDest);
    changed = true;
  }
  return { changed };
}
