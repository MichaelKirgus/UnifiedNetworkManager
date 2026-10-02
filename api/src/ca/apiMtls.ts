/**
 * apiMtls — the API's OWN mTLS identity (Stage 1).
 *
 * The API enrolls against UNM's step-ca exactly like a plugin does (SDK
 * ensureTlsIdentity, ACME http-01), with two differences:
 *   - It fetches its trust bundle LOCALLY from the shared config volume
 *     (/data/ca/root_ca.crt — mirrored there by the CA entrypoint) plus the
 *     intermediate from step-ca's public endpoint. No HTTP round-trip to itself.
 *   - Its identifier is 'api' (the compose service name, in the default
 *     caAllowedDnsNames allow-list). The CA fetches http://api/.well-known/… on
 *     port 80 — this module's transient challenge listener answers it.
 *
 * On success: setApiMtlsIdentity() arms the pluginHttp factory (all outbound
 * calls to mTLS-live plugins then use https + client cert) and a TLS listener
 * is opened on :8443 serving the SAME express app (webapp/mcp can talk to the
 * API over mTLS; plain :3000 stays up for backward compatibility).
 */

import https from 'https';
import type { Express } from 'express';
import { describeTlsCert, ensureTlsIdentity, scheduleTlsRenewal, TlsIdentity } from '@unm/plugin-sdk';
import { getCaBundlePem } from './stepCaAdmin';
import { registerApiLeaf } from './registry';
import { setApiMtlsIdentity } from '../utils/pluginHttp';

const API_TLS_PORT = Number(process.env.UNM_API_TLS_PORT ?? 8443);
const IDENTIFIER = 'api';
const TLS_DIR = process.env.UNM_API_TLS_DIR ?? '/data/tls';

let stopRenewal: (() => void) | null = null;
// Set by startApiMtls() — lets POST /ca/renew/api force a fresh leaf without
// reaching into the enrollment closure. Null until mTLS is enabled + started.
let renewFn: (() => Promise<{ ok: boolean; error?: string }>) | null = null;

/** Force a fresh ACME enrollment for the API's own identity (new leaf, same
 *  account) and swap the :8443 listener to it. No-op with an error when mTLS
 *  is not enabled. */
export async function renewApiMtls(): Promise<{ ok: boolean; error?: string }> {
  if (!renewFn) return { ok: false, error: 'mTLS is not enabled (UNM_TLS != 1)' };
  return renewFn();
}

/**
 * Runs the API's enrollment loop. Resolves once the first identity is live
 * (or rejects if `failFast`); keeps retrying every 30s while it fails so a
 * late-bootstrapping CA never blocks startup. `onLive` fires when the TLS
 * listener comes up (and again on renewal swaps).
 */
export async function startApiMtls(
  app: Express,
  opts: { failFast?: boolean; onLive?: (identity: TlsIdentity) => void; onServer?: (server: https.Server) => void } = {},
): Promise<TlsIdentity> {
  let currentServer: https.Server | null = null;
  // Material the live listener was opened with — renewal checks that come back
  // with an UNCHANGED leaf must NOT close+reopen :8443 (that would drop every
  // in-flight mTLS connection on a no-op swap).
  let loadedKeyPem: string | null = null;
  let loadedCertPem: string | null = null;

  const openTlsListener = async (identity: TlsIdentity): Promise<void> => {
    if (currentServer) {
      await new Promise<void>((resolve) => {
        currentServer!.close(() => resolve());
        (currentServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      });
    }
    // https.createServer — NOT tls.createServer. The latter completes the TLS
    // handshake but never parses HTTP: no 'request' events are ever emitted,
    // so a listener built that way accepts connections and then goes silent.
    const server = https.createServer(
      {
        key: identity.keyPem,
        cert: identity.certChainPem,
        ca: [identity.caBundlePem],
        requestCert: true,
        rejectUnauthorized: true,
      },
      app,
    );
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(API_TLS_PORT, () => resolve());
    });
    currentServer = server;
    loadedKeyPem = identity.keyPem;
    loadedCertPem = identity.certChainPem;
    opts.onServer?.(server);
    console.log(`[api] mTLS listener live on :${API_TLS_PORT} (identity "${IDENTIFIER}", leaf valid to ${identity.notAfter.toISOString()})`);
  };

  const enrollOnce = async (forceRenewal = false): Promise<TlsIdentity> => {
    // Local bundle: root from the shared volume + intermediate from step-ca's
    // public endpoint. Throws until the CA has bootstrapped its PKI.
    const identity = await ensureTlsIdentity({
      dir: TLS_DIR,
      identity: IDENTIFIER,
      identifiers: [IDENTIFIER],
      fetchCaBundle: async () => getCaBundlePem(),
      forceRenewal,
      log: (m) => console.log(`[api][tls] ${m}`),
    });
    setApiMtlsIdentity({ keyPem: identity.keyPem, certChainPem: identity.certChainPem, caBundlePem: identity.caBundlePem });
    // Mirror our own leaf into the CA registry — the "mtls" row for subject
    // 'api' on the Certificates page. Best-effort; a DB hiccup must never
    // break enrollment itself.
    const info = describeTlsCert(identity.certChainPem);
    if (info) {
      void registerApiLeaf(info).catch((e: Error) => console.warn('[api][tls] CA registry update failed:', e.message));
    }
    // Swap the listener only when it isn't up yet OR the material actually
    // changed. Early renewal checks (the SDK clamps long delays to ~24.8d) come
    // back with the SAME reused leaf — re-binding would drop every in-flight
    // mTLS connection for no reason.
    if (!currentServer || identity.keyPem !== loadedKeyPem || identity.certChainPem !== loadedCertPem) {
      await openTlsListener(identity);
    } else {
      console.log(`[api][tls] leaf unchanged — keeping :${API_TLS_PORT} listener (valid to ${identity.notAfter.toISOString()})`);
    }
    stopRenewal?.();
    stopRenewal = scheduleTlsRenewal(
      identity,
      async () => {
        const renewed = await enrollOnce();
        opts.onLive?.(renewed);
      },
      (m) => console.log(`[api][tls] ${m}`),
    );
    return identity;
  };

  // Manual re-enrollment (POST /ca/renew with subject 'api'): force a fresh
  // leaf + swap the :8443 listener. Guards against concurrent calls.
  let renewing = false;
  renewFn = async () => {
    if (renewing) return { ok: false, error: 'a renewal is already in progress' };
    renewing = true;
    try {
      const identity = await enrollOnce(true);
      opts.onLive?.(identity);
      return { ok: true };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn('[api][tls] manual re-enrollment failed:', msg);
      return { ok: false, error: msg };
    } finally {
      renewing = false;
    }
  };

  try {
    const identity = await enrollOnce();
    opts.onLive?.(identity);
    return identity;
  } catch (err) {
    if (opts.failFast) throw err;
    // CA not ready yet — retry every 30s in the background. The API keeps
    // serving plain HTTP on :3000 and talking to plugins over http meanwhile.
    console.warn(`[api] mTLS enrollment deferred (CA not ready?): ${(err as Error).message} — retrying every 30s`);
    const timer = setInterval(() => {
      void enrollOnce()
        .then((identity) => opts.onLive?.(identity))
        .catch((e: Error) => console.warn(`[api] mTLS enrollment still failing: ${e.message}`));
    }, 30_000);
    (timer as unknown as { unref?: () => void }).unref?.();
    throw new Error('mTLS enrollment deferred — CA not ready');
  }
}
