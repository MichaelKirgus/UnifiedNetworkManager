/**
 * tlsIdentity — mTLS enrollment + certificate lifecycle for UNM plugins (and
 * any other service that talks to step-ca over ACME).
 *
 * Flow (all verified live against smallstep/step-ca 0.30.2):
 *   1. Load-or-create a long-lived EC P-256 ACCOUNT key in the TLS dir — this
 *      is the ACME account identity and survives re-enrollments/renewals.
 *   2. Fetch the CA trust bundle (root + intermediate PEMs) from the UNM API's
 *      internal `GET /plugin/ca/bundle` route (x-plugin-api-key gated). The PKI
 *      volume is deliberately NOT mounted into plugins — the API brokers it.
 *   3. If a previously enrolled leaf still covers the desired identifiers and
 *      has >1/3 of its lifetime left, reuse it (no ACME traffic at all).
 *   4. Otherwise: generate a fresh LEAF key, serve http-01 challenges on :80
 *      for the duration of enrollment only, run AcmeClient.enroll(), and write
 *      tls.key / tls.crt / ca-bundle.pem atomically (tmp + rename, 0600).
 *
 * Identifiers are DNS names that must resolve FROM THE CA CONTAINER to this
 * service — in compose that is the service name from ADVERTISED_ENDPOINT.
 * localhost/127.0.0.1 can never validate via http-01 (the CA fetches them on
 * its own loopback).
 */

import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import path from 'path';
import axios from 'axios';
import { AcmeClient } from './acmeClient';

export interface TlsIdentityOptions {
  /** Directory for keys/certs. Default '/data/tls' (writable in plugin containers). */
  dir?: string;
  /** ACME directory URL. Default https://unm-ca:9000/acme/acme/directory */
  acmeDirectoryUrl?: string;
  /** Identity label for logs + the account file name, e.g. 'opnsense-plugin'. */
  identity: string;
  /** DNS names to cover in the leaf. Default: host of ADVERTISED_ENDPOINT. */
  identifiers?: string[];
  /** Skip the reuse check and enroll a FRESH leaf (same ACME account). Used by
   *  manual re-enrollment triggers — the old leaf simply dies at its expiry. */
  forceRenewal?: boolean;
  /**
   * Fetches the CA trust bundle (root + intermediate PEMs). Defaults to the
   * UNM API's internal route `${UNM_API_URL}/plugin/ca/bundle` with the shared
   * x-plugin-api-key header. Injectable for tests against a scratch CA.
   */
  fetchCaBundle?: () => Promise<string>;
  /** Port for the transient http-01 challenge listener. Default 80. */
  challengePort?: number;
  log?: (msg: string) => void;
}

export interface TlsIdentity {
  /** Leaf private key PEM — the TLS server's `key`. */
  keyPem: string;
  /** Leaf + intermediate(s) PEM chain — the TLS server's `cert`. */
  certChainPem: string;
  /** Root + intermediate PEMs — what clients use as their trust anchor (`ca`). */
  caBundlePem: string;
  /** Leaf issue time (UTC). */
  notBefore: Date;
  /** Leaf expiry (UTC). */
  notAfter: Date;
  /** True when an existing valid leaf was reused instead of enrolling. */
  reused: boolean;
}

const DEFAULT_DIR = '/data/tls';
const DEFAULT_ACME_URL = 'https://unm-ca:9000/acme/acme/directory';
/** Renew once we've burned through this fraction of the leaf's lifetime. */
const RENEW_FRACTION = 2 / 3;

function defaultIdentifiers(): string[] {
  const endpoint = process.env.ADVERTISED_ENDPOINT ?? '';
  try {
    const host = new URL(endpoint).hostname;
    return host ? [host] : [];
  } catch {
    return [];
  }
}

/**
 * Public resolver for the identifiers a service should enroll (the host of
 * ADVERTISED_ENDPOINT). Exposed so the server's enrollment loop can detect an
 * endpoint rename at runtime and re-enroll without waiting for renewal.
 */
export function resolveTlsIdentifiers(): string[] {
  return defaultIdentifiers();
}

/** Default bundle fetcher: the API brokers root+intermediate (PKI volume is CA-only). */
async function defaultFetchCaBundle(): Promise<string> {
  const baseUrl = process.env.UNM_API_URL ?? 'http://api:3000/v1';
  const apiKey = process.env.PLUGIN_API_KEY;
  if (!apiKey) throw new Error('tlsIdentity: PLUGIN_API_KEY is not set — cannot fetch the CA bundle');
  const res = await axios.get(`${baseUrl}/plugin/ca/bundle`, { headers: { 'x-plugin-api-key': apiKey }, timeout: 15000 });
  const pem = (res.data?.pem ?? '') as string;
  if (!/-----BEGIN CERTIFICATE-----/.test(pem)) throw new Error('tlsIdentity: CA bundle response contained no certificates');
  return pem;
}

function loadOrCreateAccountKey(file: string): crypto.KeyObject {
  try {
    const pem = fs.readFileSync(file, 'utf8');
    return crypto.createPrivateKey(pem);
  } catch {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    fs.writeFileSync(file, pem, { mode: 0o600 });
    return privateKey;
  }
}

/** Atomic write: tmp file in the same dir + rename, with explicit mode. */
function atomicWrite(file: string, content: string, mode = 0o644): void {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, content, { mode });
  fs.renameSync(tmp, file);
}

/** Parses SAN dns names + CN out of a PEM chain's FIRST certificate. */
function leafNames(chainPem: string): { cn?: string; sans: string[] } {
  const first = chainPem.split(/(?=-----BEGIN CERTIFICATE-----)/).find((b) => b.includes('CERTIFICATE'));
  if (!first) return { sans: [] };
  const cert = new crypto.X509Certificate(first);
  // subjectAltName is a comma-joined "DNS:name" list.
  const sans = (cert.subjectAltName ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.startsWith('DNS:'))
    .map((s) => s.slice(4));
  return { cn: cert.subject, sans };
}

/** Descriptive metadata of one CA-issued leaf (what UNM's registry stores). */
export interface TlsCertInfo {
  /** Hex serial number (no 0x prefix) — the revocation address. */
  serial: string;
  /** SAN DNS names on the leaf. */
  sans: string[];
  /** Issuer DN as reported by Node (e.g. "CN = UNM Intermediate, O = Unified Network Manager"). */
  issuer: string;
  notBefore: string;
  notAfter: string;
}

/**
 * Describes the FIRST certificate of a PEM chain (serial, SANs, issuer,
 * validity window). Lets a service REPORT its own CA-issued leaf to UNM
 * without re-parsing step-ca internals. Null when no parseable cert is found.
 */
export function describeTlsCert(chainPem: string): TlsCertInfo | null {
  try {
    const firstBlock = chainPem.split(/(?=-----BEGIN CERTIFICATE-----)/).find((b) => b.includes('CERTIFICATE'));
    if (!firstBlock) return null;
    const cert = new crypto.X509Certificate(firstBlock);
    const { sans } = leafNames(chainPem);
    return {
      serial: cert.serialNumber,
      sans,
      issuer: cert.issuer,
      notBefore: new Date(cert.validFrom).toISOString(),
      notAfter: new Date(cert.validTo).toISOString(),
    };
  } catch {
    return null;
  }
}

/**
 * Describes the leaf stored in `dir` (reads tls.crt). Null when no readable
 * leaf exists yet.
 */
export function describeLeaf(dir: string): TlsCertInfo | null {
  try {
    const chainPem = fs.readFileSync(path.join(dir, 'tls.crt'), 'utf8');
    return describeTlsCert(chainPem);
  } catch {
    return null;
  }
}

/** The transient http-01 challenge server — serves ONLY /.well-known/acme-challenge/<token>. */
function createChallengeServer(port: number): Promise<{ set(token: string, keyAuth: string): void; clear(): void; close(): Promise<void> }> {
  let current: { token: string; keyAuth: string } | null = null;
  const server = http.createServer((req, res) => {
    const m = /^\/\.well-known\/acme-challenge\/([^/]+)$/.exec(req.url ?? '');
    if (m && current && decodeURIComponent(m[1]) === current.token) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(current.keyAuth);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, () => {
      resolve({
        set: (token, keyAuth) => (current = { token, keyAuth }),
        clear: () => (current = null),
        close: () => new Promise<void>((res2) => server.close(() => res2())),
      });
    });
  });
}

/**
 * Ensures a valid mTLS identity for this service. Idempotent: reuses the
 * existing leaf while it covers the identifiers and has >1/3 lifetime left;
 * otherwise (re-)enrolls via ACME http-01. Safe to call at boot AND from the
 * renewal timer.
 */
export async function ensureTlsIdentity(opts: TlsIdentityOptions): Promise<TlsIdentity> {
  const dir = opts.dir ?? DEFAULT_DIR;
  const log = opts.log ?? ((m: string) => console.log(`[tls:${opts.identity}] ${m}`));
  const identifiers = (opts.identifiers ?? defaultIdentifiers()).filter(Boolean);
  if (identifiers.length === 0) throw new Error('tlsIdentity: no identifiers — set ADVERTISED_ENDPOINT or pass identifiers[]');

  fs.mkdirSync(dir, { recursive: true });
  const accountKeyFile = path.join(dir, `account-${opts.identity}.key.pem`);
  const keyFile = path.join(dir, 'tls.key');
  const certFile = path.join(dir, 'tls.crt');
  const bundleFile = path.join(dir, 'ca-bundle.pem');

  // --- reuse check (no network at all when the leaf is still good) ---------
  if (!opts.forceRenewal) {
    try {
      const chainPem = fs.readFileSync(certFile, 'utf8');
      const keyPem = fs.readFileSync(keyFile, 'utf8');
      const bundlePem = fs.readFileSync(bundleFile, 'utf8');
      const firstBlock = chainPem.split(/(?=-----BEGIN CERTIFICATE-----)/).find((b) => b.includes('CERTIFICATE'));
      if (firstBlock && /-----BEGIN PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----/.test(keyPem)) {
        const cert = new crypto.X509Certificate(firstBlock);
        const notBefore = new Date(cert.validFrom);
        const notAfter = new Date(cert.validTo);
        const now = new Date();
        const renewAt = new Date(notBefore.getTime() + (notAfter.getTime() - notBefore.getTime()) * RENEW_FRACTION);
        const { sans } = leafNames(chainPem);
        const coversAll = identifiers.every((id) => sans.includes(id));
        if (coversAll && now < renewAt && now < notAfter) {
          log(`reusing existing leaf (SANs=[${sans.join(',')}], valid to ${notAfter.toISOString()})`);
          return { keyPem, certChainPem: chainPem, caBundlePem: bundlePem, notBefore, notAfter, reused: true };
        }
        log('existing leaf needs renewal/re-enrollment');
      }
    } catch {
      /* no usable existing identity — enroll below */
    }
  } else {
    log('forceRenewal requested — skipping reuse check, enrolling a fresh leaf');
  }

  // --- fresh enrollment ------------------------------------------------------
  const accountKey = loadOrCreateAccountKey(accountKeyFile);
  const bundlePem = await (opts.fetchCaBundle ?? defaultFetchCaBundle)();
  fs.mkdirSync(dir, { recursive: true });
  atomicWrite(bundleFile, bundlePem, 0o644);

  // The ACME client trusts the ROOT only; the bundle may also carry the
  // intermediate — that's fine (extra CAs in `ca` are ignored unless needed).
  const rootBlock = bundlePem.split(/(?=-----BEGIN CERTIFICATE-----)/).find((b) => b.includes('CERTIFICATE')) ?? bundlePem;

  const leafKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  const client = new AcmeClient({ directoryUrl: opts.acmeDirectoryUrl ?? DEFAULT_ACME_URL, rootPem: rootBlock, log });

  const challengePort = opts.challengePort ?? 80;
  const challenges = await createChallengeServer(challengePort);
  log(`enrolling via ACME http-01 for identifiers [${identifiers.join(', ')}] (challenge listener on :${challengePort})`);
  let chainPem: string;
  try {
    chainPem = await client.enroll(
      accountKey,
      leafKey,
      identifiers,
      (token, keyAuth) => challenges.set(token, keyAuth),
      () => challenges.clear(),
    );
  } finally {
    await challenges.close();
  }

  const firstBlock = chainPem.split(/(?=-----BEGIN CERTIFICATE-----)/).find((b) => b.includes('CERTIFICATE')) ?? '';
  const leafCert = new crypto.X509Certificate(firstBlock);
  const notBefore = new Date(leafCert.validFrom);
  const notAfter = new Date(leafCert.validTo);
  const keyPem = leafKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  atomicWrite(keyFile, keyPem, 0o600);
  atomicWrite(certFile, chainPem.endsWith('\n') ? chainPem : `${chainPem}\n`, 0o644);
  log(`enrolled — leaf valid to ${notAfter.toISOString()}; wrote ${keyFile}, ${certFile}`);

  return { keyPem, certChainPem: chainPem, caBundlePem: bundlePem, notBefore, notAfter, reused: false };
}

/**
 * Schedules a renewal re-check at ~2/3 of the leaf's lifetime. Returns a stop
 * function. The callback should re-run ensureTlsIdentity() and swap the live
 * TLS server (see createPluginServer's tls option).
 */
export function scheduleTlsRenewal(identity: TlsIdentity, onDue: () => void | Promise<void>, log?: (msg: string) => void): () => void {
  const lifetimeMs = identity.notAfter.getTime() - identity.notBefore.getTime();
  const renewAt = identity.notBefore.getTime() + lifetimeMs * RENEW_FRACTION;
  // setTimeout overflows past 2^31-1 ms (~24.8 days) and silently clamps to 1ms —
  // an unclamped delay would re-fire the renewal check in a tight loop for any
  // leaf longer than ~37 days (UNM's default is 90). Clamping is safe: early
  // checks are harmless because ensureTlsIdentity() reuses the leaf until it is
  // actually due, and consumers only swap material when it changed.
  const MAX_TIMEOUT_MS = 0x7fffffff;
  let delayMs = Math.max(60_000, renewAt - Date.now());
  if (delayMs > MAX_TIMEOUT_MS) delayMs = MAX_TIMEOUT_MS;
  log?.(`next renewal check in ${Math.round(delayMs / 3_600_000)}h`);
  const t = setTimeout(() => {
    void Promise.resolve(onDue()).catch((err) => console.error('[tls] renewal failed:', err));
  }, delayMs);
  (t as unknown as { unref?: () => void }).unref?.();
  return () => clearTimeout(t);
}
