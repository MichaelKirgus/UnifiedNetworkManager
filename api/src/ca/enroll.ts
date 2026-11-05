/**
 * enroll — EAP-TLS WiFi client certificate enrollment against UNM's CA.
 *
 * Flow: validate → keygen (selectable type) → hand-rolled PKCS#10 CSR with
 * SAN/keyUsage/EKU extensions → mint an OTT for the unm-admin JWK provisioner
 * carrying sub=CN + sans (step-ca requires the token sans set to EQUAL the
 * CSR dNSNames exactly) → POST /1.0/sign → parse the leaf. The private key is
 * returned in-process only — the route stores it encrypted (keyVault.ts) and
 * never sends it over HTTP.
 *
 * CHAIN GUARD: a client cert must never outlive its issuer, so the requested
 * validity is clamped to min(rootNotAfter, intermediateNotAfter) − 7 days.
 */

import * as crypto from 'crypto';
import { loadAdminJwk, mintAdminToken } from './adminKey';
import { buildEapTlsCsr } from './eapCsr';
import { CA_BASE, getCaStatus, signCsr } from './stepCaAdmin';
import { ADMIN_PROVISIONER_NAME } from './stepCaConfig';
import { getEffectiveValues } from '../systemSettings';

export type EapKeyType = 'ec-p256' | 'ec-p384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096';

const NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** Safety margin so a leaf never expires in the same window as its issuer. */
const CHAIN_MARGIN_MS = 7 * 86_400_000;

export interface EnrollEapTlsOptions {
  /** Stable identity label (unique per enrollment) — also the default CN. */
  name: string;
  /** Subject CN override (defaults to `name`). */
  cn?: string;
  /** Subject organization RDN (optional). */
  organization?: string;
  /** Subject organizational unit RDN (optional). */
  organizationalUnit?: string;
  /** Extra SAN dNSNames beyond the CN. */
  sans?: string[];
  keyType?: EapKeyType;
  /** Requested validity in days (default: caWifiCertDefaultDays, clamped to caWifiCertMaxDays + chain). */
  days?: number;
}

export interface EnrolledCert {
  serial: string;
  subject: string;
  notBefore: string;
  notAfter: string;
  /** Leaf PEM only. */
  certPem: string;
  /** PKCS#8 private key PEM — in-process only, never over HTTP. */
  keyPem: string;
  /** Full bundle (leaf + intermediates) for client installation. */
  chainPem: string;
  /** True when the chain guard shortened the requested validity. */
  clamped?: boolean;
  clampReason?: string;
}

/** Validation failure → HTTP 400 at the route (CA failures are 502). */
export class EnrollValidationError extends Error {}

function validateName(value: unknown, field: string): string {
  if (typeof value !== 'string' || !NAME_RE.test(value)) {
    throw new EnrollValidationError(`"${field}" must be 1–64 chars of [A-Za-z0-9._-]`);
  }
  return value;
}

function validateRdn(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const v = value.trim();
  if (v.length > 64) throw new EnrollValidationError(`"${field}" must be at most 64 characters`);
  return v;
}

function generateKey(keyType: EapKeyType): crypto.KeyObject {
  switch (keyType) {
    case 'ec-p256':
      return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    case 'ec-p384':
      return crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    case 'rsa-2048':
      return crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 }).privateKey;
    case 'rsa-3072':
      return crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 }).privateKey;
    case 'rsa-4096':
      return crypto.generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 0x10001 }).privateKey;
    default:
      throw new EnrollValidationError(`unknown keyType "${String(keyType)}"`);
  }
}

/**
 * Enrolls one EAP-TLS client certificate. See module header for the flow.
 */
export async function enrollEapTlsClient(opts: EnrollEapTlsOptions): Promise<EnrolledCert> {
  const name = validateName(opts.name, 'name');
  const cn = opts.cn !== undefined ? validateName(opts.cn, 'cn') : name;
  const organization = validateRdn(opts.organization, 'organization');
  const organizationalUnit = validateRdn(opts.organizationalUnit, 'organizationalUnit');

  // Extra SANs: deduped, each validated with the same pattern. The CN is
  // ALWAYS part of the SAN set (supplicants match on dNSNames).
  const extraSans = Array.isArray(opts.sans) ? opts.sans : [];
  for (const s of extraSans) validateName(s, 'sans entry');
  const sans = [...new Set([cn, ...extraSans])];

  const keyType: EapKeyType = opts.keyType ?? 'ec-p256';
  if (!['ec-p256', 'ec-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'].includes(keyType)) {
    throw new EnrollValidationError(`unknown keyType "${String(keyType)}"`);
  }

  // Validity: setting defaults + hard cap, then the chain guard.
  const v = await getEffectiveValues();
  const defaultDays = Number(v.caWifiCertDefaultDays ?? 1095);
  const maxDays = Number(v.caWifiCertMaxDays ?? 3650);
  let days = opts.days !== undefined ? Math.floor(Number(opts.days)) : defaultDays;
  if (!Number.isFinite(days) || days < 1) throw new EnrollValidationError('"days" must be a positive integer');
  if (days > maxDays) days = maxDays;

  // CHAIN GUARD — the leaf must never outlive its issuer. The intermediate is
  // what signs client certs, so min(root, intermediate) − margin is the real
  // ceiling. getCaStatus() reads both from public CA endpoints + local PEMs.
  const status = await getCaStatus();
  let clamped: boolean | undefined;
  let clampReason: string | undefined;
  try {
    const rootEnd = Date.parse(status.rootNotAfter);
    const interEnd = status.intermediateNotAfter ? Date.parse(status.intermediateNotAfter) : Number.POSITIVE_INFINITY;
    if (Number.isFinite(rootEnd)) {
      const chainLimitMs = Math.min(rootEnd, interEnd) - Date.now() - CHAIN_MARGIN_MS;
      const maxChainDays = Math.floor(chainLimitMs / 86_400_000);
      if (days > maxChainDays) {
        days = maxChainDays;
        clamped = true;
        clampReason = `Validity was shortened to ${days}d — the CA chain expires sooner than requested (root/intermediate expiry minus a 7-day safety margin). Renew or rekey the CA for longer-lived certificates.`;
      }
    }
  } catch {
    /* status already fetched above — parse failure is non-fatal, skip clamping */
  }
  if (days < 1) {
    throw new EnrollValidationError(
      `Requested validity exceeds the CA chain expiry — the root/intermediate expires on ${status.intermediateNotAfter ?? status.rootNotAfter}; renew or rekey the CA before enrolling long-lived certificates`
    );
  }

  // Keygen + CSR (the token sans and CSR dNSNames MUST be identical sets).
  const privateKey = generateKey(keyType);
  const keyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  const { csrPem } = buildEapTlsCsr(privateKey, { cn, organization, organizationalUnit, sanDns: sans });

  // OTT for the unm-admin JWK provisioner — sub=CN + sans (step-ca's
  // commonNameSliceValidator accepts CN ∈ {sub} ∪ {sans}).
  const adminJwk = loadAdminJwk();
  const { token } = mintAdminToken(adminJwk.privateKeyPem, {
    aud: `${CA_BASE}/1.0/sign`,
    provisionerName: ADMIN_PROVISIONER_NAME,
    sub: cn,
    sans,
  });

  const nowIso = new Date().toISOString();
  const notAfterIso = new Date(Date.now() + days * 86_400_000).toISOString();
  const res = await signCsr(csrPem, token, nowIso, notAfterIso);

  // Parse the issued leaf (step-ca returns PEM strings; certChain is
  // [leaf, ...intermediates] when present).
  const leaf = new crypto.X509Certificate(res.crt);
  const chainParts: string[] = [];
  for (const pem of res.certChain ?? [res.crt, res.ca]) {
    if (pem && !chainParts.includes(pem)) chainParts.push(pem.trimEnd());
  }

  return {
    serial: leaf.serialNumber,
    subject: cn,
    notBefore: new Date(leaf.validFrom).toISOString(),
    notAfter: new Date(leaf.validTo).toISOString(),
    certPem: res.crt,
    keyPem,
    chainPem: `${chainParts.join('\n')}\n`,
    ...(clamped !== undefined ? { clamped } : {}),
    ...(clampReason !== undefined ? { clampReason } : {}),
  };
}
