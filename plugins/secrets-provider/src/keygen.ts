import * as crypto from 'crypto';
import forge from 'node-forge';

/**
 * Key-material generation for the generatable secret types.
 *
 * This module is the ONLY place in UNM that creates cryptographic key material.
 * The OPNsense plugin (and any other consumer) never generates keys — it asks
 * this provider to, via `POST /generate` or a plan's provisionRequests. That
 * keeps all crypto in one audited backend and lets secrets be persisted,
 * rotated and shared across devices/plugins.
 *
 * Each generator returns the PLAIN field values (the same shape the secret
 * type's schema declares); the caller encrypts + stores them like any other
 * secret. Regeneration re-runs a generator for the generatable fields only and
 * preserves non-generatable context (labels, CN/SANs) under the SAME id.
 */

/**
 * Generates a WireGuard key pair (X25519). Returns the raw 32-byte keys as
 * standard base64 — exactly the format OPNsense's wireguard API expects for
 * `publicKey` / `privateKey`.
 */
export function generateWireguardKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');

  // Node exports x25519 keys as JWK with base64url-encoded raw material.
  // WireGuard wants standard base64 of the 32-byte value.
  const pubJwk = publicKey.export({ format: 'jwk' }) as { x?: string };
  const privJwk = privateKey.export({ format: 'jwk' }) as { d?: string };

  if (!pubJwk.x || !privJwk.d) throw new Error('Failed to export X25519 key material');

  const pubRaw = Buffer.from(pubJwk.x, 'base64url');
  const privRaw = Buffer.from(privJwk.d, 'base64url');
  if (pubRaw.length !== 32 || privRaw.length !== 32) {
    throw new Error('Unexpected X25519 key length');
  }

  return { publicKey: pubRaw.toString('base64'), privateKey: privRaw.toString('base64') };
}

/**
 * Generates a shared pre-shared key for IPsec (swanctl) tunnels. Returns a
 * 32-byte random value as hex (64 chars) — an unambiguous, copy-safe string.
 */
export function generateTunnelPsk(): { psk: string } {
  return { psk: crypto.randomBytes(32).toString('hex') };
}

/**
 * Generates a self-signed CA + one leaf certificate/key signed by it — the
 * bundle an OpenVPN site-to-site instance needs (`ca`, `cert`, `key` PEMs).
 *
 * For a true two-endpoint link each side would ideally hold its own leaf; this
 * generator produces ONE leaf (the follow-up can extend to per-endpoint leaves
 * sharing the same CA). The CA is what both endpoints must trust, so it is the
 * shared secret of the link.
 */
/** Creates an ASN.1 SEQUENCE and returns it with a typed `value` array for pushing children. */
function asn1Seq(): { value: unknown[] } {
  const seq = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []);
  return seq as unknown as { value: unknown[] };
}

/** Builds a basicConstraints extension value (SEQUENCE [cA BOOLEAN]). */
function basicConstraintsValue(cA: boolean): unknown {
  const seq = asn1Seq();
  if (cA) seq.value.push(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.BOOLEAN, false, String.fromCharCode(0xff)));
  return seq;
}

/** Builds a keyUsage extension value (BIT STRING of the given flag bytes). */
function keyUsageValue(flags: number): unknown {
  // First byte = count of unused high bits in the first flag byte.
  const unused = flags & 0x80 ? 7 : flags & 0x40 ? 6 : flags & 0x20 ? 5 : 8;
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.BITSTRING, false, String.fromCharCode(unused) + String.fromCharCode(flags));
}

/** Builds an extendedKeyUsage extension value (SEQUENCE of OIDs). */
function extKeyUsageValue(oidNames: string[]): unknown {
  const seq = asn1Seq();
  for (const name of oidNames) {
    seq.value.push(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(name).getBytes()));
  }
  return seq;
}

/** Builds a subjectAltName extension value (SEQUENCE of dNSName entries). */
function subjectAltNameValue(dnsNames: string[]): unknown {
  const seq = asn1Seq();
  for (const name of dnsNames) {
    // CONTEXT_SPECIFIC tag 2 = dNSName; value is the raw string.
    seq.value.push(forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 2, false, name));
  }
  return seq;
}

/** Builds a subjectKeyIdentifier extension value (OCTET STRING of SHA-1 SPKI hash). */
function subjectKeyIdValue(cert: { generateSubjectKeyIdentifier: () => { getBytes: () => string } }): unknown {
  const ski = cert.generateSubjectKeyIdentifier();
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, ski.getBytes());
}

/**
 * Generates an ed25519 SSH key pair. The private key is stored in the secret
 * (PKCS#8 PEM — accepted by both ssh2 and modern OpenSSH clients); the public
 * key is a PASTE-READY `authorized_keys` line (`ssh-ed25519 <base64>`) so the
 * user never needs any keygen toolchain. UNM never touches the device.
 */
export function generateSshKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  // Raw 32-byte ed25519 public key = tail of the SPKI DER (fixed 44-byte layout:
  // AlgorithmIdentifier + BIT STRING wrapper around exactly 32 bytes).
  const spkiDer = publicKey.export({ format: 'der', type: 'spki' });
  if (spkiDer.length !== 44) throw new Error(`unexpected ed25519 SPKI DER length ${spkiDer.length}`);
  const rawPub = spkiDer.subarray(spkiDer.length - 32);
  // OpenSSH wire format: string "ssh-ed25519" + string <raw public key>.
  const wire = Buffer.concat([
    Buffer.from([0, 0, 0, 11]),
    Buffer.from('ssh-ed25519', 'ascii'),
    Buffer.from([0, 0, 0, 32]),
    rawPub,
  ]);
  return {
    publicKey: `ssh-ed25519 ${wire.toString('base64')}`,
    privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}

export function generateOpenvpnProfile(fields?: Record<string, unknown>): { ca: string; cert: string; key: string } {
  const cn = typeof fields?.commonName === 'string' && fields.commonName ? (fields.commonName as string) : 'unm-openvpn';

  // node-forge does NOT auto-fill extension OIDs or values when signing a
  // freshly-built cert (it only does so while parsing), so each extension below
  // carries an explicit `id` (OID) and pre-built ASN.1 `value`.

  // --- CA ------------------------------------------------------------------
  const caKeys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const caCert = forge.pki.createCertificate();
  caCert.publicKey = caKeys.publicKey;
  caCert.serialNumber = crypto.randomBytes(16).toString('hex');
  caCert.validity.notBefore = new Date();
  caCert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000); // 10 years

  const caName = caCert.subject;
  caName.addField({ name: 'commonName', value: `${cn}-ca` });
  caName.addField({ name: 'organizationName', value: 'UnifiedNetworkManager' });
  caCert.extensions = [
    { name: 'basicConstraints', id: '2.5.29.19', critical: true, value: basicConstraintsValue(true) },
    // keyCertSign (0x04) + digitalSignature (0x80). cRLSign omitted — node-forge can't map it.
    { name: 'keyUsage', id: '2.5.29.15', critical: true, value: keyUsageValue(0x84) },
    { name: 'subjectKeyIdentifier', id: '2.5.29.14', value: subjectKeyIdValue(caCert as never) },
  ];
  caCert.sign(caKeys.privateKey, forge.md.sha256.create());

  // --- Leaf (server) ---------------------------------------------------------
  const leafKeys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const leafCert = forge.pki.createCertificate();
  leafCert.publicKey = leafKeys.publicKey;
  leafCert.serialNumber = crypto.randomBytes(16).toString('hex');
  leafCert.validity.notBefore = new Date();
  leafCert.validity.notAfter = new Date(Date.now() + 5 * 365 * 24 * 3600 * 1000); // 5 years

  const leafName = leafCert.subject;
  leafName.addField({ name: 'commonName', value: cn });
  leafName.addField({ name: 'organizationName', value: 'UnifiedNetworkManager' });
  leafCert.extensions = [
    { name: 'basicConstraints', id: '2.5.29.19', critical: true, value: basicConstraintsValue(false) },
    // digitalSignature (0x80) + keyEncipherment (0x20).
    { name: 'keyUsage', id: '2.5.29.15', critical: true, value: keyUsageValue(0xa0) },
    { name: 'extendedKeyUsage', id: '2.5.29.37', value: extKeyUsageValue(['serverAuth', 'clientAuth']) },
    { name: 'subjectAltName', id: '2.5.29.17', value: subjectAltNameValue([cn]) }, // DNS SAN
  ];
  // The issuer DN must match the CA's subject; node-forge does not copy it for us.
  leafCert.issuer = caCert.subject;
  leafCert.sign(caKeys.privateKey, forge.md.sha256.create());

  return {
    ca: forge.pki.certificateToPem(caCert),
    cert: forge.pki.certificateToPem(leafCert),
    key: forge.pki.privateKeyToPem(leafKeys.privateKey),
  };
}

/**
 * The generatable secret types and how to (re)generate their fields. A type is
 * "generatable" when every field it stores can be produced by this provider —
 * that's what makes `POST /regenerate` safe: it re-rolls the material in place
 * without needing any external input, while preserving non-material context.
 */
export interface GeneratableType {
  type: string;
  /** Generates fresh field values (merged over any provided context fields). */
  generate: (fields?: Record<string, unknown>) => Record<string, string>;
}

export const GENERATABLE_TYPES: Record<string, GeneratableType> = {
  wireguardKeyPair: { type: 'wireguardKeyPair', generate: () => generateWireguardKeyPair() },
  tunnelPsk: { type: 'tunnelPsk', generate: () => generateTunnelPsk() },
  openvpnProfile: { type: 'openvpnProfile', generate: (fields) => generateOpenvpnProfile(fields) },
  // Context fields (username, passphrase) are preserved across regeneration —
  // only the key material itself is re-rolled.
  sshKeyPair: { type: 'sshKeyPair', generate: () => generateSshKeyPair() },
};
