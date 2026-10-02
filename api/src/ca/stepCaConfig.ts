import * as fs from 'fs';
import * as path from 'path';
import { getEffectiveValues } from '../systemSettings';
import { loadAdminJwk } from './adminKey';

/**
 * Renders step-ca's `ca.json` from UNM global settings and writes it to the
 * shared config volume. The CA service watches this file's mtime and SIGHUPs
 * itself on change (see ca/entrypoint.sh), so a write here hot-applies new
 * claims/policy/challenges/tls values without restarting the CA container.
 *
 * Layout contract (two volumes — see ca/Dockerfile):
 *   /pki      CA-only: root_ca.crt, intermediate_ca.crt, intermediate_ca_key
 *             (bootstrapped by the entrypoint; NEVER mounted on the API)
 *   /data/ca  shared with the API: this file + step-ca's Badger state DB.
 *             The API also persists its own admin JWK private key here
 *             (admin-jwk.pem, 0600).
 */

export const CA_CONFIG_PATH = process.env.UNM_CA_CONFIG_PATH ?? '/data/ca/ca.json';
const PKI_DIR = '/pki';
/** ACME provisioner name — the directory URL is https://unm-ca:9000/acme/<name>. */
export const ACME_PROVISIONER_NAME = 'acme';
/** UNM's own management provisioner (public JWK embedded below). */
export const ADMIN_PROVISIONER_NAME = 'unm-admin';

interface StepCaConfig {
  root: string;
  crt: string;
  key: string;
  address: string;
  dnsNames: string[];
  logger: { format: string };
  db: { type: string; dataSource: string };
  authority: {
    claims: Record<string, unknown>;
    /** Omitted entirely in "any"/"deny" enrollment-policy modes (no x509 name policy). */
    policy?: Record<string, unknown>;
    provisioners: Array<Record<string, unknown>>;
  };
  tls: Record<string, unknown>;
}

function daysToDuration(days: number): string {
  // Go time.Duration format — step-ca parses these.
  return `${Math.round(days * 24)}h`;
}

/** Splits a comma-separated setting value into a trimmed list (empty → []). */
export function splitList(value: unknown): string[] {
  if (typeof value !== 'string') return [];
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

/** Builds the ca.json document from effective settings + UNM's admin JWK. */
export async function renderStepCaConfig(): Promise<StepCaConfig> {
  const v = await getEffectiveValues();
  const minDays = Number(v.caLeafMinDays ?? 7);
  const maxDays = Number(v.caLeafMaxDays ?? 365);
  const defaultDays = Number(v.caLeafDefaultDays ?? 90);

  // SAN allow-list: the CA must be able to issue for every compose service name
  // (plugins + api + mcp) plus localhost/127.0.0.1 for host-dev mode. The admin
  // extends this list when adding remote instances.
  const allowedDns = splitList(v.caAllowedDnsNames);

  // ACME enrollment policy (three modes — see the caAcmeEnrollmentPolicy setting):
  //   any       → no x509 name policy at all; step-ca's engine treats "no policy"
  //               as allow-all, so new plugins enroll without touching this list.
  //   allowlist → permit only the names in caAllowedDnsNames (wildcards off).
  //   deny      → omit the ACME provisioner entirely (below); enrollment then fails
  //               at the directory while the unm-admin JWK provisioner keeps UNM's
  //               management plane working. There is no step-ca DNS constraint that
  //               matches "everything", so this is the cleanest deny-all encoding.
  const policy = String(v.caAcmeEnrollmentPolicy ?? 'any');
  const acmeEnabled = policy !== 'deny';
  const x509Policy: Record<string, unknown> | null =
    policy === 'allowlist' ? { allow: { dns: allowedDns }, allowWildcardNames: false } : null;

  const challenges = splitList(v.caAcmeChallenges).length > 0 ? splitList(v.caAcmeChallenges) : ['http-01'];

  const adminJwk = loadAdminJwk();
  // The ACME provisioner is present only when enrollment isn't denied. The
  // unm-admin JWK provisioner (UNM's management credential — public half only, the
  // private key lives in admin-jwk.pem on this same volume and never leaves it) is
  // ALWAYS present so the CA stays manageable even when ACME enrollment is off.
  const provisioners: Array<Record<string, unknown>> = [
    { type: 'JWK', name: ADMIN_PROVISIONER_NAME, key: adminJwk.public },
  ];
  if (acmeEnabled) provisioners.unshift({ type: 'ACME', name: ACME_PROVISIONER_NAME, challenges });

  return {
    root: `${PKI_DIR}/root_ca.crt`,
    crt: `${PKI_DIR}/intermediate_ca.crt`,
    key: `${PKI_DIR}/intermediate_ca_key`,
    address: ':9000',
    dnsNames: ['unm-ca', 'localhost'],
    logger: { format: 'text' },
    db: { type: 'badgerv2', dataSource: '/data/ca/db' },
    authority: {
      claims: {
        minTLSCertDuration: daysToDuration(minDays),
        maxTLSCertDuration: daysToDuration(maxDays),
        defaultTLSCertDuration: daysToDuration(defaultDays),
      },
      // Omitted in "any" (allow-all) and "deny" modes — only allowlist renders one.
      ...(x509Policy ? { policy: { x509: x509Policy } } : {}),
      provisioners,
    },
    tls: { minVersion: 1.2, maxVersion: 1.3 },
  };
}

/**
 * Renders + atomically writes ca.json (tmp file in the same dir, then rename —
 * so step-ca never reads a half-written config). Returns true when the content
 * actually changed (callers can skip redundant SIGHUPs; the CA's own mtime watch
 * is the source of truth for reloads anyway).
 */
export async function writeStepCaConfig(): Promise<{ changed: boolean }> {
  const cfg = await renderStepCaConfig();
  const json = JSON.stringify(cfg, null, 2) + '\n';

  if (fs.existsSync(CA_CONFIG_PATH)) {
    const existing = fs.readFileSync(CA_CONFIG_PATH, 'utf8');
    if (existing === json) return { changed: false };
  }

  fs.mkdirSync(path.dirname(CA_CONFIG_PATH), { recursive: true });
  const tmp = `${CA_CONFIG_PATH}.tmp`;
  fs.writeFileSync(tmp, json);
  fs.renameSync(tmp, CA_CONFIG_PATH);
  return { changed: true };
}
