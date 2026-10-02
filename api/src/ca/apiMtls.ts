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
import { ensureTlsIdentity, scheduleTlsRenewal, TlsIdentity } from '@unm/plugin-sdk';
import { getCaBundlePem } from './stepCaAdmin';
import { setApiMtlsIdentity } from '../utils/pluginHttp';

const API_TLS_PORT = Number(process.env.UNM_API_TLS_PORT ?? 8443);
const IDENTIFIER = 'api';
const TLS_DIR = process.env.UNM_API_TLS_DIR ?? '/data/tls';

let stopRenewal: (() => void) | null = null;

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

  const enrollOnce = async (): Promise<TlsIdentity> => {
    // Local bundle: root from the shared volume + intermediate from step-ca's
    // public endpoint. Throws until the CA has bootstrapped its PKI.
    const identity = await ensureTlsIdentity({
      dir: TLS_DIR,
      identity: IDENTIFIER,
      identifiers: [IDENTIFIER],
      fetchCaBundle: async () => getCaBundlePem(),
      log: (m) => console.log(`[api][tls] ${m}`),
    });
    setApiMtlsIdentity({ keyPem: identity.keyPem, certChainPem: identity.certChainPem, caBundlePem: identity.caBundlePem });
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
