/**
 * eapCsr — hand-rolled PKCS#10 CSR builder for EAP-TLS client certificates.
 *
 * Node has no X509CertificateRequest API, so the DER is built by hand using
 * the same minimal helpers as packages/plugin-sdk/src/acmeClient.ts (copied
 * verbatim to keep this module dependency-free — the plugin SDK is not an
 * api/ dependency). The layout was verified byte-for-byte against
 * openssl-generated references in acmeClient.buildCsr.
 *
 * EAP-TLS specifics:
 *   - Subject RDNs O → OU → CN (O/OU optional, CN always last) — the RADIUS
 *     server / supplicant match on these; RFC 5280 order is not normative for
 *     client certs but O→OU→CN is what every vendor tooling emits.
 *   - keyUsage digitalSignature ONLY (byte 0x80 — RFC 5280 MSB-first bit
 *     numbering; 0x01 would be encipherOnly).
 *   - EKU clientAuth + EAP-TLS (1.3.6.1.5.5.7.3.13) so the cert is accepted
 *     for WiFi supplicant auth and nothing else.
 */

import * as crypto from 'crypto';

// ---------- minimal DER builders (PKCS#10 only, copied from acmeClient.ts) ---
function derLen(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const b: number[] = [];
  let v = n;
  while (v > 0) { b.unshift(v & 0xff); v >>= 8; }
  return Buffer.concat([Buffer.from([0x80 | b.length]), Buffer.from(b)]);
}
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
const concat = (arr: Buffer[]): Buffer => Buffer.concat(arr);
function derOid(oidStr: string): Buffer {
  const p = oidStr.split('.').map(Number);
  const bytes = [p[0] * 40 + p[1]];
  for (let i = 2; i < p.length; i++) {
    let v = p[i];
    const enc = [v & 0x7f];
    v >>= 7;
    while (v > 0) { enc.unshift((v & 0x7f) | 0x80); v >>= 7; }
    bytes.push(...enc);
  }
  return tlv(0x06, Buffer.from(bytes));
}
function derInt(n: number): Buffer {
  const b: number[] = [];
  let v = n;
  do { b.unshift(v & 0xff); v >>= 8; } while (v > 0);
  if (b[0] & 0x80) b.unshift(0);
  return tlv(0x02, Buffer.from(b.length ? b : [0]));
}
function derUtf8(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, 'utf8'));
}

/** One RDN = SET{ SEQ{ OID, UTF8String } }. */
function rdn(oid: string, value: string): Buffer {
  return tlv(0x31, tlv(0x30, concat([derOid(oid), derUtf8(value)])));
}

/** Subject Name = SEQUENCE OF RDN SETs (O → OU → CN; O/OU only when given). */
function buildName(opts: { cn: string; organization?: string; organizationalUnit?: string }): Buffer {
  const rdns: Buffer[] = [];
  if (opts.organization) rdns.push(rdn('2.5.4.10', opts.organization)); // organizationName
  if (opts.organizationalUnit) rdns.push(rdn('2.5.4.11', opts.organizationalUnit)); // organizationalUnitName
  rdns.push(rdn('2.5.4.3', opts.cn)); // commonName — always last
  return tlv(0x30, concat(rdns));
}

/**
 * Builds a PKCS#10 CSR (PEM) for an EAP-TLS client certificate.
 *
 *   CertificationRequestInfo = SEQ { INTEGER 0, Name, SPKI BIT STRING,
 *     attributes [0] { extensionRequest Attribute } }
 *   extensions: SAN (dNSName per entry), keyUsage digitalSignature,
 *               EKU {clientAuth, EAP-TLS} — all non-critical.
 *
 * NOTE on the ISSUED certificate: step-ca v0.30.2's JWK provisioner ignores
 * the CSR's extensionRequest for keyUsage/EKU and applies its own defaults
 * (critical digitalSignature + EKU serverAuth,clientAuth). That is fine for
 * EAP-TLS — RADIUS requires clientAuth, which is present; SAN still comes from
 * the token/CSR sans. The requested extensions are kept anyway: they document
 * intent and take effect if step-ca ever honors them (or we switch CAs).
 */
export function buildEapTlsCsr(
  privateKey: crypto.KeyObject,
  opts: { cn: string; organization?: string; organizationalUnit?: string; sanDns: string[] }
): { csrPem: string } {
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });

  // SAN — GeneralNames of dNSName [2] IA5String entries.
  const generalNames = tlv(0x30, concat(opts.sanDns.map((n) => tlv(0x82, Buffer.from(n, 'utf8')))));
  const sanExtension = tlv(0x30, concat([derOid('2.5.29.17'), tlv(0x04, generalNames)]));

  // keyUsage — digitalSignature only: OCTET STRING { BIT STRING { unused=0x00, usage=[0x80] } }.
  // Every X.509 extension value is an OCTET STRING wrapping the DER payload (RFC 5280 §4.2);
  // Go's strict asn1 decoder rejects a bare BIT STRING here.
  const keyUsageValue = tlv(0x04, tlv(0x03, concat([Buffer.from([0x00]), Buffer.from([0x80])])));
  const keyUsageExtension = tlv(0x30, concat([derOid('2.5.29.15'), keyUsageValue]));

  // EKU — clientAuth (…7.3.2) + EAP-TLS (…7.3.13): OCTET STRING { SEQ OF OID }.
  const ekuInner = tlv(0x30, concat([derOid('1.3.6.1.5.5.7.3.2'), derOid('1.3.6.1.5.5.7.3.13')]));
  const ekuExtension = tlv(0x30, concat([derOid('2.5.29.37'), tlv(0x04, ekuInner)]));

  // extensionRequest attribute: SEQ{ OID 1.2.840.113549.1.9.14, SET { Extensions } }.
  // The SET directly contains the Extensions SEQUENCE — identical to Go's own
  // CreateCertificateRequest (Value [][]pkix.Extension `asn1:"set"`) and openssl output;
  // an extra OCTET STRING wrapper here is rejected by Go's strict asn1 decoder.
  const extensionsSeq = tlv(0x30, concat([sanExtension, keyUsageExtension, ekuExtension]));
  const extReqAttr = tlv(0x30, concat([derOid('1.2.840.113549.1.9.14'), tlv(0x31, extensionsSeq)]));
  const attrs = tlv(0xa0, extReqAttr); // [0] directly contains the Attribute (openssl/Go style)

  const name = buildName(opts);
  const cri = tlv(0x30, concat([derInt(0), name, spki, attrs]));

  // Signature algorithm by key type; crypto.sign returns DER for both — correct
  // for PKCS#10 (unlike JWS ES256 which needs raw r‖s).
  const isEc = privateKey.asymmetricKeyType === 'ec';
  const sigAlgOid = isEc ? '1.2.840.10045.4.3.2' : '1.2.840.113549.1.1.11'; // ecdsa-SHA256 / rsa-SHA256
  const sigAlgId = tlv(0x30, concat([derOid(sigAlgOid), tlv(0x05, Buffer.alloc(0))]));
  const sig = crypto.sign('sha256', cri, privateKey);

  const csrDer = tlv(0x30, concat([cri, sigAlgId, tlv(0x03, concat([Buffer.from([0]), sig]))]));
  const b64 = Buffer.from(csrDer).toString('base64');
  const lines: string[] = ['-----BEGIN CERTIFICATE REQUEST-----'];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  lines.push('-----END CERTIFICATE REQUEST-----');
  return { csrPem: `${lines.join('\n')}\n` };
}
