import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

/**
 * UNM's own CA-administration credential.
 *
 * step-ca authenticates /1.0/* management calls (sign/renew/revoke) with a JWT
 * signed by a provisioner key. Rather than depend on step-ca's internal
 * password-encrypted admin key, UNM generates its OWN EC P-256 keypair once and
 * embeds the PUBLIC half into ca.json as a JWK provisioner named `unm-admin`
 * (see stepCaConfig.ts). The PRIVATE half is persisted here so it survives API
 * restarts/rebuilds; every token UNM mints is signed with it. This keeps the CA
 * signing keys in the CA-only volume while UNM holds a separate, lower-privilege
 * management credential — and means swapping step-ca for any other RFC 8555 /
 * JWK-provisioner CA requires no change to this module.
 */

const DEFAULT_KEY_PATH = process.env.UNM_CA_ADMIN_KEY ?? '/data/ca/admin-jwk.pem';

export interface AdminJwk {
  /** The public JWK embedded into ca.json as the `unm-admin` provisioner key. */
  public: Record<string, unknown>;
  /** PEM (PKCS#8) private key used to sign management tokens. */
  privateKeyPem: string;
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

/** RFC 7638 JWK Thumbprint = base64url(SHA-256 of the canonical public-key JSON). */
export function jwkThumbprint(jwk: Record<string, unknown>): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return b64url(crypto.createHash('sha256').update(canonical).digest());
}

/** Loads the persisted admin keypair, generating + persisting it on first use. */
export function loadAdminJwk(keyPath: string = DEFAULT_KEY_PATH): AdminJwk {
  if (fs.existsSync(keyPath)) {
    const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
    const publicKey = crypto.createPublicKey(privateKeyPem);
    return { public: toPublicJwk(publicKey), privateKeyPem };
  }

  // First boot: generate EC P-256 and persist the private key (0600).
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  fs.writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });
  return { public: toPublicJwk(publicKey), privateKeyPem };
}

function toPublicJwk(publicKey: crypto.KeyObject): Record<string, unknown> {
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  // Node omits `use`/`alg`; step-ca's JWK provisioner expects them for token validation.
  return { use: 'sig', kty: 'EC', crv: 'P-256', alg: 'ES256', kid: jwkThumbprint(jwk), x: jwk.x, y: jwk.y };
}

export interface MintedToken {
  token: string;
  /** Epoch seconds the token expires at. */
  exp: number;
}

/**
 * Mints a short-lived ES256 JWT for one step-ca /1.0/* call, signed with UNM's
 * admin key. `aud` must be the full URL of the target endpoint (step-ca binds
 * tokens to their audience). Kept deliberately minimal — no external deps.
 */
export function mintAdminToken(
  privateKeyPem: string,
  opts: { aud: string; provisionerName?: string; ttlSeconds?: number; sub?: string; sans?: string[] }
): MintedToken {
  const priv = crypto.createPrivateKey(privateKeyPem);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (opts.ttlSeconds ?? 300);
  // step-ca's JWK provisioner selects the verification key via the token's `kid`
  // (RFC 7638 thumbprint of the public key) — a header without it is rejected
  // with "provisioner not found or invalid audience".
  const kid = toPublicJwk(crypto.createPublicKey(priv)).kid;
  const header = b64url(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid }));
  // `sub`/`sans` are for /1.0/sign OTTs — step-ca's JWK provisioner validates
  // the CSR CN against {sub} ∪ {sans} and requires the token sans set to equal
  // the CSR dNSNames exactly (see enroll.ts). Absent = plain management call.
  const payload = b64url(
    JSON.stringify({
      aud: opts.aud,
      exp,
      iat: now - 5, // small skew tolerance for clock drift between containers
      iss: opts.provisionerName ?? 'unm-admin',
      sub: opts.sub ?? (opts.provisionerName ?? 'unm-admin'),
      ...(opts.sans ? { sans: opts.sans } : {}),
      jti: crypto.randomUUID(),
    })
  );
  const signingInput = `${header}.${payload}`;
  // Node's crypto.sign returns a DER-encoded ECDSA signature for EC keys, but
  // JWS ES256 (RFC 7518 §3.4) requires the raw r‖s concatenation (exactly 64
  // bytes for P-256). step-ca's JWT verifier rejects anything else — convert.
  const derSig = crypto.sign('sha256', Buffer.from(signingInput), priv);
  const signature = b64url(priv.asymmetricKeyType === 'ec' ? derToRawEcdsa(derSig) : derSig);
  return { token: `${signingInput}.${signature}`, exp };
}

/** Converts a DER-encoded ECDSA signature (SEQ{INTEGER r, INTEGER s}) to raw r‖s. */
function derToRawEcdsa(der: Buffer): Buffer {
  const ints: Buffer[] = [];
  let i = 2; // skip SEQUENCE tag + length (short form — always true for P-256)
  while (i < der.length && der[i] === 0x02) {
    const len = der[i + 1];
    ints.push(der.subarray(i + 2, i + 2 + len));
    i += 2 + len;
  }
  if (ints.length !== 2) throw new Error('malformed DER ECDSA signature');
  // Right-align into 32 bytes. A 33-byte integer is a leading-0x00 sign pad —
  // drop the FIRST byte, never the last (a naive copy at offset 0 truncates
  // the low byte and silently corrupts ~75% of signatures).
  const pad = (b: Buffer): Buffer => {
    const out = Buffer.alloc(32);
    if (b.length <= 32) b.copy(out, 32 - b.length);
    else b.copy(out, 0, b.length - 32);
    return out;
  };
  return Buffer.concat([pad(ints[0]), pad(ints[1])]);
}
