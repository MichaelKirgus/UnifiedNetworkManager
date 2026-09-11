/**
 * @unm/plugin-sdk — shared certificate collection + validation for plugins.
 *
 * Powers the cross-device "Certificates" page: every plugin can report, per
 * device, (a) the TLS certificate served by its HTTPS management endpoint and
 * (b) the SSH host key presented on port 22 — with issuer, expiry, key length/
 * algorithm and a real chain-validation verdict.
 *
 * Why this lives in the SDK:
 *   - The TLS handshake + X.509 parsing + chain validation is identical for
 *     every vendor; re-implementing it per plugin would be error-prone.
 *   - Both probes are CREDENTIAL-FREE (a plain TCP/TLS connect), so any plugin
 *     that knows the device's management address can use them — no secret needed.
 *   - Validation is done with Node's built-in `crypto`/`tls` only (no deps).
 *
 * Chain validation semantics (what "valid" means here):
 *   1. Every certificate in the served chain must be inside its validity window
 *      at `now` — this catches an EXPIRED ISSUER even when the leaf is still
 *      nominally valid (the classic silent-break case).
 *   2. Each certificate's signature must verify against its issuer's public key
 *      (real crypto verification, not just DN string matching). A self-signed
 *      cert verifies against its own key and is treated as the trust anchor.
 *   3. The leaf's SAN/hostname must match the probed host (a management cert
 *      issued for a different name is flagged).
 *   Trust-ANCHOR verification ("is the root in my CA store") is intentionally NOT
 *     part of `valid` — device management endpoints overwhelmingly use self-signed
 *     certs, so a self-signed-but-well-formed chain reports valid:true with
 *     `selfSigned:true` rather than failing. Callers surface that distinction.
 */

import tls from 'tls';
import crypto from 'crypto';
import { Client as Ssh2Client } from 'ssh2';
import { computeFingerprint } from './ssh';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One X.509 certificate (leaf or chain element) in normalized form. */
export interface CertificateInfo {
  /** Subject Common Name, or the full subject DN when no CN is present. */
  commonName: string;
  /** Full subject distinguished name (e.g. "CN=foo,O=bar"). */
  subject: string;
  /** Issuer distinguished name. */
  issuer: string;
  /** True when issuer === subject (self-signed). */
  selfSigned: boolean;
  /** Validity start as ISO timestamp. */
  notBefore: string;
  /** Expiry as ISO timestamp. */
  notAfter: string;
  /** Public key algorithm, e.g. "RSA", "ECDSA", "ED25519". */
  keyAlgorithm: string;
  /** Key size in bits (RSA modulus); null for EC/Ed keys (see curveName). */
  keySizeBits: number | null;
  /** Elliptic curve name for EC keys (e.g. "prime256v1"); null otherwise. */
  curveName: string | null;
  /** Signature algorithm, friendly name when known else the raw OID. */
  signatureAlgorithm: string;
  /** SAN DNS names + IPs as reported by the certificate. */
  sanNames: string[];
  /** Serial number (hex). */
  serialNumber: string;
}

/** One certificate endpoint row emitted into `metrics['certificates']`. */
export interface CertificateRow {
  /** Stable identity of this endpoint on the device, e.g. "https:443", "ssh:22". */
  name: string;
  /** https | ssh — what kind of credential material is presented. */
  type: 'https' | 'ssh';
  /** Hostname/IP probed (the management address). */
  host: string;
  /** Port probed. */
  port: number;
  /** SHA-256 fingerprint of the leaf cert / SSH host key (OpenSSH-style). */
  fingerprint?: string;
  /** The leaf certificate actually served, or null when the endpoint was unreachable. */
  cert: CertificateInfo | null;
  /** Full chain as served (leaf first) for issuer validation. Empty when unavailable. */
  chain: CertificateInfo[];
  /** Chain-validation verdict (see validateChain). Null when no cert could be read. */
  valid: boolean | null;
  /** Human-readable reason when valid === false, else null. */
  invalidReason: string | null;
  /** Days until the LEAF expires (negative = already expired). Null when unknown. */
  daysToExpiry: number | null;
  /** Days until the EARLIEST chain element expires — an issuer expiring before its
   *  leaf is a real break even though the leaf itself is still valid. Null when unknown. */
  chainDaysToExpiry: number | null;
}

/** Options for probing one TLS endpoint. */
export interface TlsProbeOptions {
  host: string;
  port?: number;
  /** SNI servername (defaults to host). */
  servername?: string;
  timeoutMs?: number;
}

/** A parsed certificate that still carries its DER bytes (for signature verification). */
export type RawCertificate = CertificateInfo & { _raw?: Buffer };

/** Result of a successful TLS probe. */
export interface TlsProbeResult {
  cert: RawCertificate;
  chain: RawCertificate[];
  /** SHA-256 fingerprint of the leaf (OpenSSH-style), for display/pinning. */
  fingerprint: string;
}

/** Options for probing an SSH endpoint's host key (no authentication). */
export interface SshProbeOptions {
  host: string;
  port?: number;
  timeoutMs?: number;
}

/** Result of a successful SSH host-key probe. */
export interface SshProbeResult {
  /** OpenSSH-style "SHA256:<base64>" fingerprint of the presented host key. */
  fingerprint: string;
  /** Key type as advertised by sshd (e.g. "ssh-ed25519", "rsa-sha2-512"). */
  keyType: string;
  /** Effective key size in bits, derived from the wire blob (null when unknown). */
  keyBits: number | null;
}

/** Options for collectDeviceCertificates(). */
export interface DeviceCertOptions {
  host: string;
  /** Probe this TLS port for the management HTTPS cert (default 443). Omit/0 to skip. */
  httpsPort?: number | null;
  /** SNI override for the TLS probe. Defaults to host. */
  servername?: string;
  /** Probe SSH port 22 for the host key (default true). Set false to skip. */
  sshEnabled?: boolean;
  /** SSH port to probe (default 22). */
  sshPort?: number;
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// X.509 parsing
// ---------------------------------------------------------------------------

/** Signature-algorithm OID → friendly name + hash used by crypto.verify(). */
const SIG_ALG_OIDS: Record<string, { name: string; hash: string | null }> = {
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', hash: 'md5' },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', hash: 'sha1' },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', hash: 'sha256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', hash: 'sha384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', hash: 'sha512' },
  '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', hash: 'sha1' },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', hash: 'sha256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', hash: 'sha384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', hash: 'sha512' },
  '1.3.101.112': { name: 'Ed25519', hash: null },
};

/** Normalizes a DN's separator characters (Node emits newlines) to ", " for display. */
function normalizeDnSeparators(dn: string): string {
  return dn.replace(/[\r\n;]+/g, ', ').replace(/\s*,\s*/g, ', ').trim();
}

/** Extracts the CN from a DN string, or returns the whole DN when there is none. */
function commonNameFromDn(dn: string): string {
  const m = dn.match(/CN\s*=\s*([^,;\r\n]+)/);
  return m ? m[1].trim() : normalizeDnSeparators(dn);
}

/**
 * Splits a base URL (or bare host) into `{ host, port }` for probing. Handles an
 * explicit scheme + port ("https://host:8443"), IPv6 literals with or without
 * brackets ("[::1]:443" / "::1"), and bare hosts (port = default). Returns null
 * when the input is empty/unusable. The host never carries a scheme, brackets or
 * port — ready to pass straight into tls.connect()/ssh2.
 */
export function parseProbeTarget(base: string, defaultPort: number): { host: string; port: number } | null {
  let s = (base ?? '').trim();
  if (!s) return null;
  // Strip a scheme ("https://", "wss://", …).
  const schemeIdx = s.indexOf('://');
  if (schemeIdx !== -1) s = s.slice(schemeIdx + 3);
  // Drop any path/query.
  const slash = s.search(/[/?#]/);
  if (slash !== -1) s = s.slice(0, slash);
  let host: string;
  let port = defaultPort;
  if (s.startsWith('[')) {
    // Bracketed IPv6 — the port follows "]:".
    const close = s.indexOf(']');
    if (close === -1) return null;
    host = s.slice(1, close);
    const rest = s.slice(close + 1);
    if (rest.startsWith(':')) {
      const p = Number(rest.slice(1));
      if (Number.isFinite(p) && p > 0) port = Math.trunc(p);
    }
  } else if (s.split(':').length > 2) {
    // Unbracketed IPv6 literal — no explicit port possible.
    host = s;
  } else {
    const lastColon = s.lastIndexOf(':');
    if (lastColon !== -1) {
      const p = Number(s.slice(lastColon + 1));
      if (Number.isFinite(p) && p > 0) {
        port = Math.trunc(p);
        host = s.slice(0, lastColon);
      } else {
        host = s;
      }
    } else {
      host = s;
    }
  }
  if (!host) return null;
  return { host, port };
}

/** Parses a SAN value (Node returns "DNS:a,IP:1.2.3" or an array) into plain names. */
function parseSanNames(raw: unknown): string[] {
  if (!raw) return [];
  const out: string[] = [];
  const push = (s: string) => {
    const t = s.trim().replace(/^(DNS|IP)\s*:\s*/i, '');
    if (t !== '') out.push(t);
  };
  if (Array.isArray(raw)) {
    for (const item of raw) if (typeof item === 'string') push(item);
  } else if (typeof raw === 'string') {
    for (const part of raw.split(',')) push(part);
  }
  return out;
}

/** Reads one DER TLV at `offset`; returns the tag, value span and end offset. */
function readTlv(buf: Buffer, offset: number): { tag: number; valueStart: number; valueLen: number; end: number } | null {
  if (offset >= buf.length) return null;
  const tag = buf[offset];
  let len = buf[offset + 1];
  let pos = offset + 2;
  if (len & 0x80) {
    // Long-form length: low 7 bits = number of following length bytes.
    const numBytes = len & 0x7f;
    if (numBytes === 0 || pos + numBytes > buf.length) return null;
    len = 0;
    for (let i = 0; i < numBytes; i++) len = len * 256 + buf[pos + i];
    pos += numBytes;
  }
  if (pos + len > buf.length) return null;
  return { tag, valueStart: pos, valueLen: len, end: pos + len };
}

/**
 * Splits a full X.509 DER certificate into the signed data and the signature
 * BIT STRING payload — the two pieces crypto.verify() needs. Also returns the
 * signature-algorithm OID (dotted) read from the envelope.
 *
 * IMPORTANT: the signed data is the ENTIRE TBSCertificate INCLUDING its own
 * SEQUENCE header (RFC 5280 §4.1 signs "the TBSCertificate" as a whole DER
 * value). Slicing only the content (after the TBS header) makes every valid
 * signature fail verification.
 */
function splitTbsAndSignature(der: Buffer): { tbs: Buffer; signature: Buffer; sigAlgOid: string } | null {
  try {
    const outer = readTlv(der, 0); // SEQUENCE
    if (!outer || outer.tag !== 0x30) return null;
    const tbsStart = outer.valueStart; // TBS header begins here (signed data start)
    const tbs = readTlv(der, tbsStart); // TBSCertificate SEQUENCE
    if (!tbs || tbs.tag !== 0x30) return null;
    const sigAlgSeq = readTlv(der, tbs.end); // signatureAlgorithm SEQUENCE
    if (!sigAlgSeq || sigAlgSeq.tag !== 0x30) return null;
    const bitStr = readTlv(der, sigAlgSeq.end); // signatureValue BIT STRING
    if (!bitStr || bitStr.tag !== 0x03 || bitStr.valueLen < 1) return null;

    // The first OID inside the signatureAlgorithm SEQUENCE is the algorithm.
    const oidTlv = readTlv(der, sigAlgSeq.valueStart);
    let sigAlgOid = '';
    if (oidTlv && oidTlv.tag === 0x06) {
      // Base-128 decode of the OID body: first byte packs arcs 0 and 1
      // (arc0 = b/40, arc1 = b%40); each following base-128 group is one arc.
      const bytes = der.slice(oidTlv.valueStart, oidTlv.end);
      if (bytes.length > 0) {
        const arcs: number[] = [Math.floor(bytes[0] / 40), bytes[0] % 40];
        let cur = 0;
        for (let i = 1; i < bytes.length; i++) {
          cur = cur * 128 + (bytes[i] & 0x7f);
          if (!(bytes[i] & 0x80)) {
            arcs.push(cur);
            cur = 0;
          }
        }
        sigAlgOid = arcs.join('.');
      }
    }

    return {
      // Signed data = the whole TBSCertificate value (header + content).
      tbs: der.slice(tbsStart, tbs.end),
      signature: der.slice(bitStr.valueStart + 1, bitStr.end), // skip unused-bits byte
      sigAlgOid,
    };
  } catch {
    return null;
  }
}

/** Parses a DER/PEM certificate into the normalized CertificateInfo shape. Throws on garbage. */
export function parseCertificate(input: Buffer | string): CertificateInfo {
  const x509 = new crypto.X509Certificate(input);
  const subject = normalizeDnSeparators(typeof x509.subject === 'string' ? x509.subject : dnToString(x509.subject as Record<string, unknown>));
  const issuer = normalizeDnSeparators(typeof x509.issuer === 'string' ? x509.issuer : dnToString(x509.issuer as Record<string, unknown>));

  let keyAlgorithm = '';
  let keySizeBits: number | null = null;
  let curveName: string | null = null;
  try {
    const keyObj = x509.publicKey as crypto.KeyObject;
    const details = (keyObj.asymmetricKeyDetails ?? {}) as Record<string, unknown>;
    const type = String(keyObj.asymmetricKeyType ?? '').toUpperCase();
    keyAlgorithm = type === 'EC' ? 'ECDSA' : type === 'RSA' ? 'RSA' : type || 'UNKNOWN';
    if (typeof details['modulusLength'] === 'number') keySizeBits = details['modulusLength'] as number;
    if (typeof details['namedCurve'] === 'string') curveName = details['namedCurve'] as string;
  } catch {
    // publicKey unavailable — leave algorithm fields empty.
  }

  let signatureAlgorithm = '';
  try {
    const split = splitTbsAndSignature(x509.raw);
    if (split) {
      const known = SIG_ALG_OIDS[split.sigAlgOid];
      signatureAlgorithm = known ? known.name : split.sigAlgOid || 'unknown';
    }
  } catch {
    // best-effort — signature algorithm is display-only.
  }

  return {
    commonName: commonNameFromDn(subject),
    subject,
    issuer,
    selfSigned: normalizeDn(issuer) === normalizeDn(subject),
    notBefore: x509.validFrom,
    notAfter: x509.validTo,
    keyAlgorithm,
    keySizeBits,
    curveName,
    signatureAlgorithm,
    sanNames: parseSanNames((x509 as unknown as { subjectAltName?: unknown }).subjectAltName),
    serialNumber: x509.serialNumber ?? '',
  };
}

/** Node <17 returned DN objects; normalize to a string defensively. */
function dnToString(dn: Record<string, unknown>): string {
  const parts = Object.entries(dn)
    .filter(([, v]) => typeof v === 'string' && (v as string).length > 0)
    .map(([k, v]) => `${k}=${v}`);
  return parts.join(',');
}

/** Case/whitespace-insensitive DN comparison for self-signed detection. */
function normalizeDn(dn: string): string {
  return dn.replace(/\s+/g, '').toLowerCase();
}

// ---------------------------------------------------------------------------
// Chain validation
// ---------------------------------------------------------------------------

export interface ChainValidation {
  valid: boolean;
  reason: string | null;
}

/** Days (fractional) from `now` until an ISO timestamp; negative = in the past. */
function daysUntil(iso: string, now: Date): number | null {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  return (t - now.getTime()) / 86_400_000;
}

/**
* Validates a served chain (leaf first) at `now`. Performs real signature
 * verification against each issuer's public key and checks EVERY certificate's
 * validity window — so an EXPIRED ISSUER is flagged even when the leaf itself
 * is still inside its own window. Trust-anchor membership in a CA store is NOT
 * checked (device management endpoints are overwhelmingly self-signed); a
 * well-formed self-signed chain validates as true.
 */
export function validateChain(leaf: RawCertificate, chain: RawCertificate[], probedHost: string, now: Date = new Date()): ChainValidation {
  const reasons: string[] = [];

  // 1. Validity windows — EVERY cert in the chain must be live at `now`.
  for (const c of chain) {
    const d = daysUntil(c.notAfter, now);
    if (d !== null && d < 0) {
      reasons.push(`${c.commonName || 'certificate'} expired ${Math.abs(Math.round(d))} day(s) ago`);
    } else {
      const nb = daysUntil(c.notBefore, now);
      if (nb !== null && nb > 0) reasons.push(`${c.commonName || 'certificate'} not yet valid (${Math.round(nb)} day(s) early)`);
    }
  }

  // 2. Signature verification up the chain.
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    if (!cert._raw) continue; // no DER → can't verify signature; validity still checked above
    const split = splitTbsAndSignature(cert._raw);
    if (!split) continue;

    let issuerCert: RawCertificate | null = null;
    if (cert.selfSigned) {
      issuerCert = cert; // self-signed → verify against own key (trust anchor)
    } else {
      // Find the chain member whose subject matches this cert's issuer DN.
      issuerCert = chain.find((c) => c !== cert && normalizeDn(c.subject) === normalizeDn(cert.issuer)) ?? null;
      if (!issuerCert) {
        reasons.push(`issuer of "${cert.commonName}" not present in the served chain (incomplete/untrusted)`);
        continue;
      }
    }

    const known = SIG_ALG_OIDS[split.sigAlgOid];
    const hash = known?.hash ?? null;
    if (!hash) {
      // Ed25519 / unknown scheme — no separate hash to verify with. DN linkage +
      // validity windows still apply; don't fail the chain on an unverifiable sig.
      continue;
    }
    try {
      const issuerKey = new crypto.X509Certificate(issuerCert._raw as Buffer).publicKey;
      const ok = crypto.verify(hash, split.tbs, issuerKey, split.signature);
      if (!ok) reasons.push(`signature verification failed for "${cert.commonName}"`);
    } catch {
      // Issuer key unparseable — treat as unverifiable rather than invalid.
    }
  }

  // NOTE: hostname/SAN matching is deliberately NOT part of this verdict —
  // device management endpoints are routinely self-signed with a CN that does
  // not match the probed IP (e.g. CN="OPNsense" on an appliance reached by LAN
  // address). SANs are still surfaced in CertificateInfo for display.

  return { valid: reasons.length === 0, reason: reasons.length > 0 ? reasons.join('; ') : null };
}

// ---------------------------------------------------------------------------
// TLS probe
// ---------------------------------------------------------------------------

/**
 * Opens a single TLS connection to `host:port` (self-signed accepted) and reads
 * the served leaf + immediate issuer. Resolves with TlsProbeResult on success or
 * `{ error }` on any failure — never throws, so callers can treat it best-effort.
 */
export function probeTlsEndpoint(opts: TlsProbeOptions): Promise<TlsProbeResult | { error: string }> {
  const host = opts.host;
  const port = opts.port ?? 443;
  const timeoutMs = opts.timeoutMs ?? 5_000;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (r: TlsProbeResult | { error: string }) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };

    let socket: tls.TLSSocket;
    try {
      socket = tls.connect(
        { host, port, servername: opts.servername ?? host, rejectUnauthorized: false },
        () => {
          try {
            const peer = socket.getPeerCertificate(true) as unknown as Record<string, unknown>;
            if (!peer || !peer['raw']) {
              finish({ error: 'no certificate presented' });
              return;
            }
            const leafRaw = Buffer.from(peer['raw'] as Buffer);
            const chain: Array<CertificateInfo & { _raw?: Buffer }> = [
              Object.assign(parseCertificate(leafRaw), { _raw: leafRaw }),
            ];
            // Immediate issuer (one hop — Node exposes only the direct issuer DER).
            const issuerDer = peer['issuerCertificate'] as Buffer | undefined;
            if (issuerDer && issuerDer.length > 0) {
              try {
                chain.push(Object.assign(parseCertificate(Buffer.from(issuerDer)), { _raw: Buffer.from(issuerDer) }));
              } catch {
                // unparseable issuer — keep the leaf only.
              }
            }
            const fingerprint = crypto.createHash('sha256').update(leafRaw).digest('base64').replace(/=+$/, '');
            finish({ cert: chain[0], chain, fingerprint: `SHA256:${fingerprint}` });
          } catch (err) {
            finish({ error: err instanceof Error ? err.message : String(err) });
          } finally {
            socket.end();
          }
        }
      );
    } catch (err) {
      finish({ error: err instanceof Error ? err.message : String(err) });
      return;
    }

    const timer = setTimeout(() => {
      try {
        socket.destroy(new Error(`TLS probe timed out after ${timeoutMs} ms`));
      } catch {
        // already closed.
      }
    }, timeoutMs);
    socket.on('error', (err) => {
      clearTimeout(timer);
      finish({ error: err.message });
    });
  });
}

// ---------------------------------------------------------------------------
// SSH host-key probe
// ---------------------------------------------------------------------------

/**
 * Connects to `host:port` over SSH and captures the presented host key WITHOUT
 * authenticating (sshd sends its host key during key exchange, before auth).
 * Resolves with SshProbeResult on success or `{ error }` — never throws.
 */
export function probeSshHostKey(opts: SshProbeOptions): Promise<SshProbeResult | { error: string }> {
  const host = opts.host;
  const port = opts.port ?? 22;
  const timeoutMs = opts.timeoutMs ?? 5_000;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (r: SshProbeResult | { error: string }) => {
      if (!settled) {
        settled = true;
        try {
          conn.end();
        } catch {
          // already closed.
        }
        resolve(r);
      }
    };

    const conn = new Ssh2Client();
    const timer = setTimeout(() => finish({ error: `SSH probe timed out after ${timeoutMs} ms` }), timeoutMs);

    conn.on('error', (err) => {
      clearTimeout(timer);
      finish({ error: err.message });
    });
    // We never authenticate — reaching 'ready' would be unexpected; abort.
    conn.on('ready', () => {
      clearTimeout(timer);
      finish({ error: 'unexpected ready without host key capture' });
    });

    try {
      conn.connect({
        host,
        port,
        username: 'unm-probe',
        password: '',
        readyTimeout: timeoutMs,
        // SyncHostVerifier receives only the wire blob — parse the key type from
        // its first string. Capture fingerprint + size, then reject (no auth).
        hostVerifier: (blob: Buffer): boolean => {
          clearTimeout(timer);
          const keyType = sshKeyTypeFromBlob(blob) ?? 'unknown';
          finish({ fingerprint: computeFingerprint(blob), keyType, keyBits: sshKeyBits(keyType, blob) });
          return false;
        },
      });
    } catch (err) {
      clearTimeout(timer);
      finish({ error: err instanceof Error ? err.message : String(err) });
    }
  });
}

// ---------------------------------------------------------------------------
// High-level collector
// ---------------------------------------------------------------------------

/** Builds an https CertificateRow from a successful TLS probe + validation. */
function buildHttpsRow(host: string, port: number, r: TlsProbeResult): CertificateRow {
  const now = new Date();
  const verdict = validateChain(r.cert, r.chain, host, now);
  const leafDays = daysUntil(r.cert.notAfter, now);
  let chainDays: number | null = null;
  for (const c of r.chain) {
    const d = daysUntil(c.notAfter, now);
    if (d !== null && (chainDays === null || d < chainDays)) chainDays = d;
  }
  return {
    name: `https:${port}`,
    type: 'https',
    host,
    port,
    fingerprint: r.fingerprint,
    cert: r.cert,
    chain: r.chain.map(({ _raw, ...rest }) => rest),
    valid: verdict.valid,
    invalidReason: verdict.reason,
    daysToExpiry: leafDays !== null ? Math.floor(leafDays) : null,
    chainDaysToExpiry: chainDays !== null ? Math.floor(chainDays) : null,
  };
}

/** Reads the first length-prefixed string (the key type) from an SSH wire blob. */
function sshKeyTypeFromBlob(blob: Buffer): string | null {
  if (blob.length < 5) return null;
  const len = blob.readUInt32BE(0);
  if (len <= 0 || 4 + len > blob.length) return null;
  return blob.subarray(4, 4 + len).toString('utf8');
}

/**
 * Derives the effective key size (bits) from an SSH wire-format public-key blob:
 *   ssh-ed25519 → 256; rsa-sha2-* / ssh-rsa → modulus byte length × 8 (leading
 *   zero byte excluded); ecdsa-* → curve name → bits. Returns null when unknown.
 */
function sshKeyBits(keyType: string, blob: Buffer): number | null {
  if (keyType.includes('ed25519')) return 256;
  const readStr = (off: number): { data: Buffer; next: number } | null => {
    if (off + 4 > blob.length) return null;
    const len = blob.readUInt32BE(off);
    if (len < 0 || off + 4 + len > blob.length) return null;
    return { data: blob.subarray(off + 4, off + 4 + len), next: off + 4 + len };
  };
  try {
    let off = readStr(0)?.next ?? 4; // skip the key-type string
    if (keyType.startsWith('rsa')) {
      const m = readStr(off);
      if (!m) return null;
      // A leading 0x00 byte marks a positive integer, not part of the modulus.
      const modBytes = m.data.length > 1 && m.data[0] === 0 ? m.data.length - 1 : m.data.length;
      return modBytes * 8;
    }
    if (keyType.startsWith('ecdsa')) {
      off += 4; // skip curve-name string length
      const curve = blob.subarray(off, off + Math.min(32, blob.length - off)).toString('utf8').replace(/\0.*$/, '');
      return { 'prime256v1': 256, 'secp384r1': 384, 'secp521r1': 521 }[curve] ?? null;
    }
  } catch {
    // malformed blob — size unknown.
  }
  return null;
}

/** Builds an ssh CertificateRow from a successful host-key probe. */
function buildSshRow(host: string, port: number, r: SshProbeResult): CertificateRow {
  // SSH host keys have no expiry/issuer — they're long-lived public keys.
  // The "valid" verdict is that we successfully read one; key type + size are
  // surfaced through the (synthetic) cert fields so the page renders uniformly.
  const alg = r.keyType.includes('ed25519')
    ? 'ED25519'
    : r.keyType.startsWith('rsa')
      ? 'RSA'
      : r.keyType.startsWith('ecdsa')
        ? 'ECDSA'
        : r.keyType;
  return {
    name: `ssh:${port}`,
    type: 'ssh',
    host,
    port,
    fingerprint: r.fingerprint,
    cert: {
      commonName: 'SSH Host Key',
      subject: '',
      issuer: '',
      selfSigned: false,
      notBefore: '',
      notAfter: '',
      keyAlgorithm: alg,
      keySizeBits: r.keyBits,
      curveName: null,
      signatureAlgorithm: '',
      sanNames: [],
      serialNumber: '',
    },
    chain: [],
    valid: true,
    invalidReason: null,
    daysToExpiry: null,
    chainDaysToExpiry: null,
  };
}

/**
 * Collects certificate rows for one device: the management HTTPS endpoint and
 * (optionally) the SSH host key. Both probes run in parallel and are fully
 * best-effort — a failed probe simply contributes no row. Returns [] when nothing
 * could be read, so callers can safely spread it into `metrics['certificates']`.
 */
export async function collectDeviceCertificates(opts: DeviceCertOptions): Promise<CertificateRow[]> {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const rows: CertificateRow[] = [];

  const jobs: Array<Promise<void>> = [];

  if (opts.httpsPort) {
    jobs.push(
      probeTlsEndpoint({ host: opts.host, port: opts.httpsPort, servername: opts.servername ?? opts.host, timeoutMs }).then((r) => {
        if ('cert' in r && r.cert) rows.push(buildHttpsRow(opts.host, opts.httpsPort as number, r));
      })
    );
  }

  const sshPort = opts.sshPort ?? 22;
  if (opts.sshEnabled !== false) {
    jobs.push(
      probeSshHostKey({ host: opts.host, port: sshPort, timeoutMs }).then((r) => {
        if ('fingerprint' in r && r.fingerprint) rows.push(buildSshRow(opts.host, sshPort, r));
      })
    );
  }

  await Promise.all(jobs);
  return rows;
}

/**
 * Convenience wrapper for plugins that already resolve a base URL (scheme + host
 * [+ explicit port]) for their management endpoint. Parses the target and probes
 * the HTTPS cert on that port plus the SSH host key on `sshPort` (default 22).
 * Fully best-effort — returns [] when nothing could be read.
 */
export async function collectCertificatesForBaseUrl(
  baseUrl: string,
  opts?: { sshEnabled?: boolean; sshPort?: number; timeoutMs?: number }
): Promise<CertificateRow[]> {
  const target = parseProbeTarget(baseUrl, 443);
  if (!target) return [];
  // Only probe TLS when the endpoint actually speaks https (a plain-http
  // management address has no certificate to read).
  const isHttps = /^https:|wss:/i.test((baseUrl ?? '').trim());
  return collectDeviceCertificates({
    host: target.host,
    httpsPort: isHttps ? target.port : null,
    servername: target.host,
    sshEnabled: opts?.sshEnabled,
    sshPort: opts?.sshPort,
    timeoutMs: opts?.timeoutMs,
  });
}
