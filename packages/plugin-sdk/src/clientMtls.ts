/**
 * clientMtls — background mTLS enrollment for CLIENT-only services.
 *
 * Plugins (server.ts) and the API (apiMtls.ts) enroll to SERVE TLS; a service
 * like the MCP server only ever PRESENTS its leaf as an outbound client cert.
 * This helper wraps ensureTlsIdentity() + scheduleTlsRenewal() in the same
 * non-blocking retry loop, so every UNM service shares one enrollment path:
 *   - resolves immediately (never blocks startup);
 *   - retries every 30s while the CA is not ready;
 *   - reports liveness via live()/material(); onLive fires on first success
 *     AND after each renewal swap, so consumers can rebuild their TLS material.
 */

import { ensureTlsIdentity, scheduleTlsRenewal } from './tlsIdentity';
import type { TlsIdentity } from './tlsIdentity';

export interface ClientMtlsOptions {
  /** Identity label for logs + the account file name (e.g. 'mcp'). */
  identity: string;
  /** DNS names to cover in the leaf. Default: host of ADVERTISED_ENDPOINT. */
  identifiers?: string[];
  /** Directory for keys/certs. Default '/data/tls'. */
  dir?: string;
  /** ACME directory URL. Default https://unm-ca:9000/acme/acme/directory */
  acmeDirectoryUrl?: string;
  /** Fetches the CA trust bundle (root + intermediate PEMs). */
  fetchCaBundle?: () => Promise<string>;
  /** Retry interval while enrollment fails. Default 30_000 ms. */
  retryMs?: number;
  log?: (msg: string) => void;
}

export interface ClientMtlsHandle {
  /** True once a leaf is live (callers may then prefer https). */
  live(): boolean;
  /** Current identity material — null until the first enrollment succeeds. */
  material(): TlsIdentity | null;
}

/** Starts the background client-enrollment loop. Non-blocking, non-fatal. */
export function startClientMtls(opts: ClientMtlsOptions & { onLive?: (identity: TlsIdentity) => void }): ClientMtlsHandle {
  let current: TlsIdentity | null = null;
  let stopRenewal: (() => void) | null = null;
  const log = opts.log ?? ((m: string) => console.error(`[mtls:${opts.identity}] ${m}`));

  const enrollOnce = async (): Promise<void> => {
    const id = await ensureTlsIdentity({
      dir: opts.dir,
      acmeDirectoryUrl: opts.acmeDirectoryUrl,
      identity: opts.identity,
      identifiers: opts.identifiers,
      fetchCaBundle: opts.fetchCaBundle,
      log,
    });
    current = id;
    stopRenewal?.();
    stopRenewal = scheduleTlsRenewal(id, () => void enrollOnce(), (m) => log(m));
    log(`client mTLS identity live ("${opts.identity}", leaf valid to ${id.notAfter.toISOString()})`);
    opts.onLive?.(id);
  };

  const retryMs = opts.retryMs ?? 30_000;
  void enrollOnce().catch((err: Error) => {
    log(`enrollment deferred (CA not ready?): ${err.message} — retrying every ${Math.round(retryMs / 1000)}s`);
    const timer = setInterval(() => {
      void enrollOnce().catch((e: Error) => log(`enrollment still failing: ${e.message}`));
    }, retryMs);
    (timer as unknown as { unref?: () => void }).unref?.();
  });

  return {
    live: () => current !== null,
    material: () => current,
  };
}
