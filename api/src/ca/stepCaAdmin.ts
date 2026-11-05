import * as https from 'https';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { loadAdminJwk, mintAdminToken } from './adminKey';
import { ADMIN_PROVISIONER_NAME } from './stepCaConfig';

/**
 * UNM's client for step-ca's management API (`/1.0/*` + public endpoints).
 *
 * The CA serves TLS on :9000 with its own intermediate cert; we validate that
 * chain against the root PEM in the shared config volume (no self-signed
 * exceptions — full chain validation, same standard as every other mTLS path in
 * UNM). Management calls are authenticated with a short-lived ES256 JWT signed
 * by UNM's own admin JWK provisioner key (adminKey.ts) — step-ca never sees the
 * CA signing keys and UNM never needs step-ca's internal password.
 */

export const CA_BASE = process.env.UNM_CA_URL ?? 'https://unm-ca:9000';
const ROOT_PEM_PATH = '/data/ca/root_ca.crt';

let cachedAgent: https.Agent | null = null;
let cachedRootPem: string | null = null;

/** https agent that trusts the UNM root (re-read on each call — cheap, and it
 *  picks up a re-keyed CA without an API restart). */
function caAgent(): https.Agent {
  const rootPem = fs.readFileSync(ROOT_PEM_PATH, 'utf8');
  if (!cachedAgent || cachedRootPem !== rootPem) {
    cachedAgent = new https.Agent({ ca: [rootPem] });
    cachedRootPem = rootPem;
  }
  return cachedAgent;
}

function request(
  method: string,
  urlPath: string,
  opts: { body?: unknown; authed?: boolean; token?: string } = {}
): Promise<{ status: number; json: () => Promise<unknown> }> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  // `token` carries a PRE-MINTED JWT verbatim (e.g. the /1.0/sign OTT with
  // sub/sans from enroll.ts); otherwise mint a fresh management token.
  if (opts.token !== undefined) {
    headers.Authorization = `Bearer ${opts.token}`;
  } else if (opts.authed) {
    const adminJwk = loadAdminJwk();
    const aud = `${CA_BASE}${urlPath}`;
    const { token } = mintAdminToken(adminJwk.privateKeyPem, {
      aud,
      provisionerName: ADMIN_PROVISIONER_NAME,
    });
    headers.Authorization = `Bearer ${token}`;
  }

  return new Promise((resolve, reject) => {
    const req = https.request(
      `${CA_BASE}${urlPath}`,
      { method, agent: caAgent(), headers },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, json: async () => JSON.parse(data || 'null') })
        );
      }
    );
    req.on('error', reject);
    if (opts.body !== undefined) req.write(JSON.stringify(opts.body));
    req.end();
  });
}

/** GETs a CA endpoint and returns the raw response body as text (PEM endpoints). */
async function rawText(urlPath: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      `${CA_BASE}${urlPath}`,
      { method: 'GET', agent: caAgent() },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve(res.statusCode === 200 ? data : null));
      }
    );
    req.on('error', reject);
    req.end();
  });
}

export interface CaStatus {
  /** step-ca version string, e.g. "0.30.2". */
  version: string;
  /** SHA-256 fingerprint of the root cert (hex). */
  rootFingerprint: string;
  /** Root subject CN. */
  rootSubject: string;
  /** ISO expiry of the root certificate. */
  rootNotAfter: string;
  /** ISO expiry of the intermediate (signing) certificate, when readable. */
  intermediateNotAfter?: string;
}

/** CA health + identity, read from public endpoints + the local PEMs. */
export async function getCaStatus(): Promise<CaStatus> {
  const versionRes = await request('GET', '/1.0/version');
  if (versionRes.status !== 200) throw new Error(`CA /1.0/version returned ${versionRes.status}`);
  const versionBody = (await versionRes.json()) as { version?: string };

  const rootPem = fs.readFileSync(ROOT_PEM_PATH, 'utf8');
  const rootCert = new crypto.X509Certificate(rootPem);
  // The intermediate lives in the CA-only volume (not readable from the API).
  // Its expiry is surfaced via /1.0/intermediates.pem — a public endpoint that
  // returns RAW PEM (not JSON), so fetch it as text and parse directly.
  let intermediateNotAfter: string | undefined;
  try {
    const interPem = await rawText('/1.0/intermediates.pem');
    if (interPem) {
      const interCert = new crypto.X509Certificate(interPem);
      intermediateNotAfter = interCert.validTo;
    }
  } catch {
    /* non-fatal — surfaced as undefined */
  }

  return {
    version: versionBody.version ?? 'unknown',
    rootFingerprint: rootCert.fingerprint256,
    rootSubject: rootCert.subject,
    rootNotAfter: rootCert.validTo,
    intermediateNotAfter,
  };
}

/**
 * The CA trust bundle as PEM: the ROOT (from the shared config volume) followed
 * by the INTERMEDIATE(S) from step-ca's public /1.0/intermediates.pem endpoint.
 * This is what non-CA services use as their `ca` trust anchor — plugins never
 * mount the PKI volume, so the API brokers it (GET /plugin/ca/bundle).
 */
export async function getCaBundlePem(): Promise<string> {
  const rootPem = fs.readFileSync(ROOT_PEM_PATH, 'utf8');
  let intermediates = '';
  try {
    const interPem = await rawText('/1.0/intermediates.pem');
    if (interPem) intermediates = interPem.endsWith('\n') ? interPem : `${interPem}\n`;
  } catch {
    /* CA not ready — root alone still lets clients verify the ACME endpoint's chain */
  }
  return `${rootPem.trimEnd()}\n${intermediates}`;
}

/**
 * Passively revokes a certificate by serial (hex). step-ca marks it revoked in
 * its DB; existing connections keep working until the leaf expires or is
 * renewed — this matches UNM's short-leaf-lifetime threat model.
 */
export async function revokeCertificate(
  serial: string,
  reason?: number
): Promise<{ status: number; body: unknown }> {
  // step-ca's /1.0/revoke wants base-10 or base-16 WITH a '0x' prefix — bare
  // hex (our storage format) is rejected with "not a valid serial number".
  const caSerial = /^[0-9]+$/.test(serial) ? serial : `0x${serial}`;
  // passive: true = mark revoked in the CA's DB only. Non-passive revocation
  // (pushing CRL/OCSP updates to live connections) is unimplemented in step-ca
  // v0.30.x and answers 501 — fine for UNM, whose leaves are short-lived and
  // re-enrolled on renewal anyway.
  // Like /1.0/sign, the JWK token must ride in the BODY as `ott` (the
  // Authorization header alone is rejected with "missing ott or client
  // certificate"). The JWK provisioner's AuthorizeRevoke enforces a
  // self-service model: the token's `sub` MUST equal the revoked cert's serial
  // in DECIMAL form ("request serial number X and token subject Y do not
  // match" otherwise). UNM holds every private key it issues, so minting such
  // tokens is always possible.
  const decimalSerial = /^[0-9]+$/.test(serial) ? serial : BigInt(`0x${serial}`).toString();
  const adminJwk = loadAdminJwk();
  const { token } = mintAdminToken(adminJwk.privateKeyPem, {
    aud: `${CA_BASE}/1.0/revoke`,
    provisionerName: ADMIN_PROVISIONER_NAME,
    sub: decimalSerial,
  });
  const res = await request('POST', '/1.0/revoke', {
    token,
    body: { serial: caSerial, passive: true, ott: token, ...(reason !== undefined ? { reason } : {}) },
  });
  return { status: res.status, body: await res.json() };
}

/**
 * Signs a PKCS#10 CSR via step-ca's /1.0/sign (one-time-token flow). The OTT
 * is the pre-minted unm-admin JWT carrying sub/sans — it goes in the BODY as
 * `ott` (step-ca reads it from there, not the Authorization header) and also
 * rides along as Bearer for API-key-style clients. Returns 201 with PEMs.
 */
export async function signCsr(
  csrPem: string,
  ott: string,
  notBeforeIso?: string,
  notAfterIso?: string
): Promise<{ crt: string; ca: string; certChain?: string[] }> {
  const res = await request('POST', '/1.0/sign', {
    token: ott,
    body: {
      csr: csrPem,
      ott,
      ...(notBeforeIso ? { notBefore: notBeforeIso } : {}),
      ...(notAfterIso ? { notAfter: notAfterIso } : {}),
    },
  });
  if (res.status !== 201) {
    const body = await res.json().catch(() => null);
    throw new Error(`CA /1.0/sign returned ${res.status}: ${JSON.stringify(body ?? 'no body')}`);
  }
  const out = (await res.json()) as { crt?: string; ca?: string; certChain?: string[] };
  if (!out.crt) throw new Error('CA /1.0/sign response missing certificate');
  return { crt: out.crt, ca: out.ca ?? '', certChain: out.certChain };
}
