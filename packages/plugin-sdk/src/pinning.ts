/**
 * @unm/plugin-sdk — certificate/host-key PINNING for device connections.
 *
 * Security feature: before a plugin transmits CREDENTIALS to a device (HTTPS
 * management API, SSH), it must verify that the endpoint presents the SAME
 * certificate / host key UNM has in its certificate inventory. A changed
 * fingerprint means either a legitimate re-key OR an active MITM — by default
 * ("strict") the connection is refused and no credentials are sent; the failure
 * surfaces as a clear error message (and shows up in device health/logs).
 *
 * Modes (global system setting `certPinningMode`, delivered via the
 * x-unm-global-settings header):
 *   - 'strict' (default): known fingerprint must match → mismatch REFUSES the
 *     connection. Unknown endpoint (no inventory row yet) → TOFU: the observed
 *     fingerprint is recorded and the connection proceeds; it lands in UNM's
 *     certificate inventory via the next `certificates` metric emission, so from
 *     then on it IS pinned.
 *   - 'ignore': no verification at all (legacy behavior — self-signed certs
 *     accepted, host keys not checked).
 *
 * The KNOWN fingerprints are delivered by the API in the SAME header as the
 * mode (`knownCertificates`), keyed by "host:port" for both endpoint kinds:
 *   - https:<host>:<port>  → SHA-256 fingerprint of the served leaf certificate
 *   - ssh:<host>:<port>    → OpenSSH-style SHA-256 fingerprint of the host key
 * (exactly the `name`/`fingerprint` columns of UNM's certificates table).
 *
 * WHY A PREFLIGHT (and not an https.Agent hook): Node only invokes
 * checkServerIdentity when rejectUnauthorized is TRUE — and with it true, the
 * self-signed management certs every appliance ships fail chain validation
 * BEFORE any identity hook runs. So strict mode enforces the pin in a separate
 * CREDENTIAL-FREE TLS handshake (verifyTlsFingerprint) that happens before the
 * real client is used; the data connection itself keeps the legacy permissive
 * agent (the preflight already proved the key identity). SSH works natively:
 * ssh2's hostVerifier runs during the handshake, BEFORE any auth message — so
 * makeSshHostVerifier() pins there directly.
 *
 * TOFU memory: a plugin process keeps an in-memory record of fingerprints it
 * has observed itself (module-level, survives across polls until restart) so a
 * brand-new endpoint is not re-accepted as "unknown" on every poll. The API's
 * inventory remains the persistent source of truth; this cache only bridges the
 * gap between first observation and the next inventory ingestion.
 */

import tls from 'tls';
import crypto from 'crypto';
import type { SshFingerprint } from './ssh';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** How the app reacts to a certificate/host-key mismatch (global setting). */
export type PinningMode = 'strict' | 'ignore';

/** One known endpoint fingerprint as delivered by the API. */
export interface KnownCertificate {
  /** SHA-256 fingerprint ("SHA256:<base64>") — leaf cert or SSH host key. */
  fingerprint: string;
  /** Subject CN / label of the recorded certificate (informational). */
  commonName?: string | null;
}

/** The pinning context for one API→plugin call (mode + known fingerprints). */
export interface PinningContext {
  mode: PinningMode;
  /** "host:port" → known fingerprint. Empty when the API sent none yet. */
  known: Map<string, KnownCertificate>;
}

/** Raised in strict mode when an endpoint presents a DIFFERENT key than pinned. */
export class CertificatePinningError extends Error {
  readonly observedFingerprint: string;
  readonly expectedFingerprint: string;
  constructor(message: string, expectedFingerprint: string, observedFingerprint: string) {
    super(message);
    this.name = 'CertificatePinningError';
    this.expectedFingerprint = expectedFingerprint;
    this.observedFingerprint = observedFingerprint;
  }
}

// ---------------------------------------------------------------------------
// Context construction (from the x-unm-global-settings header)
// ---------------------------------------------------------------------------

/** Normalizes a fingerprint to canonical "SHA256:<base64>" form (null if unusable). */
export function normalizeCertFingerprint(input?: string | null): SshFingerprint | null {
  if (!input) return null;
  let s = String(input).trim();
  if (!s) return null;
  const m = s.match(/^(?:SHA256|sha256)\s*[:=]?\s*(.+)$/);
  if (m) s = m[1].trim();
  if (!/^[A-Za-z0-9+\/]+={0,2}$/.test(s)) return null;
  return `SHA256:${s.replace(/=+$/, '')}`;
}

/** True when two fingerprints denote the same key (case-insensitive base64). */
export function certFingerprintMatches(a?: string | null, b?: string | null): boolean {
  const na = normalizeCertFingerprint(a);
  const nb = normalizeCertFingerprint(b);
  return !!na && !!nb && na === nb;
}

/** Canonical endpoint key "host:port" (lowercase host — IPv6 literals kept as-is). */
export function endpointKey(host: string, port: number): string {
  return `${String(host ?? '').trim().toLowerCase()}:${Number(port)}`;
}

/**
 * The API-style pin key for one endpoint kind: "https:<host>:<port>" or
 * "ssh:<host>:<port>". This EXACTLY matches the keys the API builds in its
 * `knownCertificates` header (the certificates table's type/host/port columns),
 * so a lookup only hits when UNM actually has a recorded key for that endpoint.
 */
export function apiPinKey(type: 'https' | 'ssh', host: string, port: number): string {
  return `${type}:${endpointKey(host, port)}`;
}

/**
 * Builds the pinning context for one API call from its headers. Reads the
 * `x-unm-global-settings` JSON header (the same one readGlobalSettings uses);
 * a missing/malformed header yields 'strict' with an EMPTY known map — which is
 * safe: strict + unknown endpoint = TOFU accept-and-record, never a lockout of
 * devices UNM has not inventoried yet.
 */
export function pinningContextFromRequest(req: { headers?: Record<string, unknown> }): PinningContext {
  const raw = req.headers?.['x-unm-global-settings'];
  let parsed: Record<string, unknown> | null = null;
  if (typeof raw === 'string' && raw.trim() !== '') {
    try {
      const p = JSON.parse(raw);
      if (p && typeof p === 'object') parsed = p as Record<string, unknown>;
    } catch {
      parsed = null; // malformed header — fall back to defaults below
    }
  }
  const mode: PinningMode = parsed?.['certPinningMode'] === 'ignore' ? 'ignore' : 'strict';

  const known = new Map<string, KnownCertificate>();
  const rawKnown = parsed?.['knownCertificates'];
  if (rawKnown && typeof rawKnown === 'object') {
    for (const [key, val] of Object.entries(rawKnown as Record<string, unknown>)) {
      let fingerprint: string | null = null;
      let commonName: string | null = null;
      if (typeof val === 'string') {
        fingerprint = normalizeCertFingerprint(val);
      } else if (val && typeof val === 'object') {
        const v = val as Record<string, unknown>;
        fingerprint = normalizeCertFingerprint(typeof v['fingerprint'] === 'string' ? v['fingerprint'] : null);
        commonName = typeof v['commonName'] === 'string' ? v['commonName'] : null;
      }
      if (fingerprint) known.set(key, { fingerprint, commonName });
    }
  }
  return { mode, known };
}

/** The known fingerprint for one endpoint kind, or null when UNM has none recorded. */
export function knownFingerprint(
  ctx: PinningContext | null | undefined,
  type: 'https' | 'ssh',
  host: string,
  port: number
): KnownCertificate | null {
  if (!ctx || ctx.mode !== 'strict') return null;
  return ctx.known.get(apiPinKey(type, host, port)) ?? null;
}

// ---------------------------------------------------------------------------
// TOFU memory (per plugin process)
// ---------------------------------------------------------------------------

/**
 * Process-wide record of fingerprints this plugin has OBSERVED itself. Bridges
 * the gap between first observation and UNM's next inventory ingestion: without
 * it, a brand-new endpoint would be re-accepted as "unknown" on every poll even
 * after its certificate was seen (and implicitly approved) once. Keyed by
 * "host:port"; bounded — one entry per endpoint this plugin talks to.
 */
const observedFingerprints = new Map<string, string>();

/** Records a fingerprint observed on an endpoint (TOFU accept / refresh). */
export function recordObservedFingerprint(host: string, port: number, fingerprint: string): void {
  const norm = normalizeCertFingerprint(fingerprint);
  if (!norm) return;
  observedFingerprints.set(endpointKey(host, port), norm);
}

/** The locally-observed fingerprint for an endpoint (null when never seen). */
export function observedFingerprintFor(host: string, port: number): string | null {
  return observedFingerprints.get(endpointKey(host, port)) ?? null;
}

// ---------------------------------------------------------------------------
// TLS preflight — verify BEFORE credentials are transmitted
// ---------------------------------------------------------------------------

/** Options for the credential-free TLS preflight probe. */
export interface TlsPreflightOptions {
  host: string;
  port?: number;
  /** SNI servername (defaults to host). */
  servername?: string;
  timeoutMs?: number;
}

/** Result of a successful preflight (the observed leaf fingerprint). */
export interface TlsPreflightResult {
  fingerprint: string;
  /** True when the endpoint had no known pin and was just recorded (TOFU). */
  firstSeen: boolean;
}

/**
 * Opens a CREDENTIAL-FREE TLS connection to the management endpoint, reads the
 * served leaf certificate and checks it against UNM's inventory:
 *   - strict + known fingerprint MISMATCH → throws CertificatePinningError
 *     (the caller must NOT transmit credentials to this host);
 *   - strict + unknown endpoint → records the observed fingerprint (TOFU) and
 *     resolves; the plugin's next `certificates` emission makes it persistent;
 *   - ignore mode / no known pin → just records + resolves.
 * A plain TCP/TLS connect — no HTTP request, no auth material on the wire.
 */
export function verifyTlsFingerprint(
  ctx: PinningContext | null | undefined,
  opts: TlsPreflightOptions
): Promise<TlsPreflightResult> {
  const port = opts.port ?? 443;
  return new Promise<TlsPreflightResult>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void): void => {
      if (!settled) {
        settled = true;
        fn();
      }
    };

    let socket: tls.TLSSocket | null = null;
    const timer = setTimeout(() => {
      finish(() => {
        try { socket?.destroy(); } catch { /* noop */ }
        reject(new Error(`TLS preflight to ${opts.host}:${port} timed out after ${opts.timeoutMs ?? 5000} ms`));
      });
    }, opts.timeoutMs ?? 5_000);

    try {
      socket = tls.connect(
        { host: opts.host, port, servername: opts.servername ?? opts.host, rejectUnauthorized: false },
        () => {
          const cert = socket?.getPeerCertificate();
          if (!cert || !Array.isArray(cert.raw) || (cert.raw as Buffer[]).length === 0) {
            finish(() => {
              clearTimeout(timer);
              try { socket?.destroy(); } catch { /* noop */ }
              reject(new Error(`TLS preflight to ${opts.host}:${port}: no certificate presented`));
            });
            return;
          }
          const leafRaw = (cert.raw as Buffer[])[0];
          const fingerprint = `SHA256:${crypto.createHash('sha256').update(leafRaw).digest('base64').replace(/=+$/, '')}`;

          const known = knownFingerprint(ctx, 'https', opts.host, port);
          if (known && !certFingerprintMatches(known.fingerprint, fingerprint)) {
            finish(() => {
              clearTimeout(timer);
              try { socket?.destroy(); } catch { /* noop */ }
              reject(
                new CertificatePinningError(
                  `Certificate mismatch for ${opts.host}:${port} — UNM has a different certificate on record. ` +
                    `Connection refused (no credentials transmitted). Expected ${known.fingerprint}, observed ${fingerprint}.`,
                  known.fingerprint,
                  fingerprint
                )
              );
            });
            return;
          }

          const firstSeen = !known && !observedFingerprints.has(endpointKey(opts.host, port));
          recordObservedFingerprint(opts.host, port, fingerprint);
          finish(() => {
            clearTimeout(timer);
            try { socket?.destroy(); } catch { /* noop */ }
            resolve({ fingerprint, firstSeen });
          });
        }
      );
    } catch (err) {
      finish(() => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
      return;
    }

    socket.on('error', (err: Error) => {
      finish(() => {
        clearTimeout(timer);
        // A preflight that cannot even complete the handshake is a transport
        // problem, not a pinning verdict — surface it as-is.
        reject(new Error(`TLS preflight to ${opts.host}:${port} failed: ${err.message}`));
      });
    });
  });
}

/**
 * True when the given management address + transport mode will actually speak
 * TLS: an explicit scheme in the address wins; 'http' never; 'auto'/'https' do.
 */
export function endpointUsesTls(address: string, transport?: 'auto' | 'http' | 'https'): boolean {
  const t = transport ?? 'auto';
  if (t === 'http') return false;
  const m = String(address ?? '').match(/^(https?):\/\//i);
  if (m) return m[1].toLowerCase() === 'https';
  return true; // auto/https → TLS expected
}

/** Options for verifyEndpointForRequest. */
export interface EndpointCheckOptions {
  /** Management address as stored (may carry an explicit scheme). */
  address: string;
  /** Transport mode the client will use ('auto' | 'http' | 'https'). */
  transport?: 'auto' | 'http' | 'https';
  timeoutMs?: number;
}

/**
 * One-line guard for a plugin's request entry points (/monitoring, /config, …):
 * resolves the host:port from the management address and runs the credential-
 * free TLS preflight when the endpoint speaks TLS. Semantics:
 *   - strict + known pin MISMATCH → throws CertificatePinningError — the caller
 *     MUST stop here; no credentials may be transmitted to this host;
 *   - transport failure (plain-HTTP box, refused, timeout) → resolves null and
 *     lets the client's own scheme-fallback logic handle it (a non-TLS endpoint
 *     has nothing to pin);
 *   - ignore mode / unknown endpoint → records + resolves (TOFU).
 */
export async function verifyEndpointForRequest(
  ctx: PinningContext | null | undefined,
  opts: EndpointCheckOptions
): Promise<TlsPreflightResult | null> {
  // Ignore mode = no verification at all (legacy behavior) — skip the extra
  // handshake entirely; the certificates metric still records fingerprints.
  if (!ctx || ctx.mode !== 'strict') return null;
  if (!endpointUsesTls(opts.address, opts.transport)) return null;
  let u: URL;
  try {
    u = new URL(String(opts.address).includes('://') ? String(opts.address) : `https://${opts.address}`);
  } catch {
    return null; // unparseable address — the client will fail on its own terms
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) return null;
  try {
    return await verifyTlsFingerprint(ctx, { host, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80), timeoutMs: opts.timeoutMs });
  } catch (e) {
    if (e instanceof CertificatePinningError) throw e; // real security verdict — propagate
    return null; // transport problem — not a pinning decision
  }
}

// ---------------------------------------------------------------------------
// Per-plugin guard — one line per request entry point
// ---------------------------------------------------------------------------

/** Options for createPinningGuard. */
export interface PinningGuardOptions {
  /** Preflight timeout (default 5 s). */
  timeoutMs?: number;
}

/** The guard returned by createPinningGuard. */
export type PinningGuard = (
  req: { headers?: Record<string, unknown> },
  address: string,
  transport?: 'auto' | 'http' | 'https'
) => Promise<void>;

/**
 * Builds a process-wide pinning guard for one plugin. Call it at the TOP of
 * every credential-bearing request handler (/monitoring, /config, /state, …):
 *
 *   const assertPinned = createPinningGuard();          // module scope, once
 *   app.post('/monitoring', async (req, res) => {
 *     await assertPinned(req, managementAddress, transport);  // throws on mismatch
 *     ...
 *   });
 *
 * Semantics: strict mode + known pin MISMATCH → throws CertificatePinningError
 * (the handler must stop — no credentials may be transmitted). The check runs
 * on EVERY call — deliberately NOT cached: a passed handshake says nothing about
 * the NEXT one, and caching would open a window in which a swapped certificate
 * is accepted without verification. The cost is one credential-free TLS
 * handshake per request entry point (far cheaper than the API calls that follow).
 * Transport failures and ignore mode resolve silently (the client's own scheme
 * fallback logic applies — a non-TLS endpoint has nothing to pin).
 */
export function createPinningGuard(opts: PinningGuardOptions = {}): PinningGuard {
  const timeoutMs = opts.timeoutMs ?? 5_000;

  return async function assertPinned(req, address, transport): Promise<void> {
    const ctx = pinningContextFromRequest(req);
    // Remember the freshest context for this endpoint — SSH verifiers (which may
    // run later on a pooled session) read it via currentPinningContextFor().
    rememberPinningContext(ctx, address);
    if (ctx.mode !== 'strict') return; // ignore mode — legacy behavior
    if (!endpointUsesTls(address, transport)) return; // plain HTTP — nothing to pin

    let u: URL;
    try {
      u = new URL(String(address).includes('://') ? String(address) : `https://${address}`);
    } catch {
      return; // unparseable address — the client fails on its own terms
    }
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host) return;
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);

    // A known pin for this endpoint is what makes the check meaningful.
    const known = knownFingerprint(ctx, 'https', host, port);
    if (!known) return; // unknown endpoint — TOFU happens via the certificates metric

    try {
      await verifyTlsFingerprint(ctx, { host, port, timeoutMs });
    } catch (e) {
      if (e instanceof CertificatePinningError) throw e; // security verdict — propagate
      // Transport problem (refused/timeout): NOT a pinning decision — the client's
      // own fallback logic handles it. Never cache or swallow a real mismatch.
    }
  };
}

// ---------------------------------------------------------------------------
// Latest-context tracking (for SSH verifiers on pooled sessions)
// ---------------------------------------------------------------------------

/** Bare hostname (lowercase) → most recent PinningContext seen for that device. */
const latestContexts = new Map<string, { ctx: PinningContext; at: number }>();

/** Resolves host+port from a management address (null when unparseable). */
function parseEndpoint(address: string): { host: string; port: number } | null {
  try {
    const u = new URL(String(address).includes('://') ? String(address) : `https://${address}`);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host) return null;
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    return { host, port };
  } catch {
    return null;
  }
}

/** Bare hostname of an address (lowercase, no scheme/port/brackets). */
function bareHost(address: string): string | null {
  const ep = parseEndpoint(address);
  if (ep) return ep.host.toLowerCase();
  const t = String(address ?? '').trim().toLowerCase();
  return t && !t.includes('://') ? t.split('/')[0].split(':')[0] : null;
}

/** Stores the freshest pinning context for a device (called by the guard). */
export function rememberPinningContext(ctx: PinningContext, address: string): void {
  const host = bareHost(address);
  if (!host) return;
  latestContexts.set(host, { ctx, at: Date.now() });
}

/** The most recent pinning context for a device (null when never seen). */
export function currentPinningContextFor(address: string): PinningContext | null {
  const host = bareHost(address);
  if (!host) return null;
  return latestContexts.get(host)?.ctx ?? null;
}

/**
 * A host-key verifier that resolves the pin DYNAMICALLY at handshake time from
 * the freshest context remembered for this device. Pass as `hostKeyVerifier`
 * to SshClient / SftpSession / terminal pools: pooled sessions outlive single
 * requests, and a re-keyed device must be verified against the CURRENT trusted
 * fingerprint (e.g. right after the user accepted it), not one baked in when
 * the pool entry was created. `address` may be the bare host or a full address —
 * both resolve to the same context store key.
 */
export function dynamicSshHostVerifier(
  address: string,
  port = 22,
  onObserved?: (fingerprint: SshFingerprint) => void
): (key: unknown, cb: (ok: boolean) => void) => void {
  return (key: unknown, cb: (ok: boolean) => void): void => {
    const host = bareHost(address) ?? String(address ?? '').trim();
    makeSshHostVerifier(currentPinningContextFor(address), host, port, null, onObserved)(key, cb);
  };
}

// ---------------------------------------------------------------------------
// SSH host-key pinning (used by SshClient / SftpSession / terminal pools)
// ---------------------------------------------------------------------------

/**
 * Resolves the effective pinned host-key fingerprint for an SSH connection:
 * the explicit `hostKeyFingerprint` option wins; otherwise strict mode consults
 * UNM's inventory (`ssh:<host>:<port>`). Returns null in ignore mode or when no
 * pin is known (TOFU — the observed key is recorded via onHostKey instead).
 */
export function resolveSshPinnedFingerprint(
  ctx: PinningContext | null | undefined,
  host: string,
  port: number,
  explicit?: string | null
): SshFingerprint | null {
  if (explicit) return normalizeCertFingerprint(explicit);
  const known = knownFingerprint(ctx, 'ssh', host, port);
  return known ? known.fingerprint : null;
}

/**
 * The ssh2 `hostVerifier` callback implementing pinning + TOFU recording.
 * Pass as the `hostKeyVerifier` option of SshClient / SftpSession / terminal
 * pools (it overrides their built-in hostKeyFingerprint logic). ssh2 invokes it
 * during the handshake — BEFORE any authentication message is sent — so a
 * mismatch rejects the connection and no credentials ever reach the host.
 */
export function makeSshHostVerifier(
  ctx: PinningContext | null | undefined,
  host: string,
  port: number,
  explicitPin?: string | null,
  onObserved?: (fingerprint: SshFingerprint) => void
): (key: unknown, cb: (ok: boolean) => void) => void {
  const pinned = resolveSshPinnedFingerprint(ctx, host, port, explicitPin);
  return (key: unknown, cb: (ok: boolean) => void): void => {
    try {
      if (!Buffer.isBuffer(key)) {
        cb(true); // unexpected shape — accept (nothing to compare against)
        return;
      }
      const fp = `SHA256:${crypto.createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
      if (pinned && !certFingerprintMatches(pinned, fp)) {
        cb(false); // reject the handshake — credentials are never transmitted
        return;
      }
      recordObservedFingerprint(host, port, fp);
      onObserved?.(fp);
      cb(true);
    } catch {
      cb(true); // verifier must never throw into ssh2's internals
    }
  };
}

/**
 * Convenience: the SSH pinning error message a plugin should surface when its
 * SshClient rejects a handshake in strict mode (ssh2 reports it as a generic
 * "handshake failed" — this gives users the actionable detail).
 */
export function sshPinningErrorMessage(host: string, port: number, expected: string, observed: string): string {
  return `SSH host key mismatch for ${host}:${port} — UNM has a different host key on record. ` +
    `Connection refused (no credentials transmitted). Expected ${expected}, observed ${observed}.`;
}
