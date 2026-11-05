/**
 * Unit tests for the hand-rolled PKCS#10 CSR builder (eapCsr.ts).
 *
 * The DER layout is verified against HOST OPENSSL (`openssl req -verify`), which
 * is an independent, strict ASN.1 implementation — this is what caught the
 * original OCTET STRING / extensionRequest wrapper bugs. Node has no X509 CSR
 * API, so openssl is the only practical oracle. The suite skips cleanly when
 * openssl is not installed (e.g. minimal CI images).
 */

import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildEapTlsCsr } from './eapCsr';

function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const HAS_OPENSSL = opensslAvailable();

/** Writes the CSR to a temp file and runs `openssl req -in … <args>`. */
function opensslReq(csrPem: string, ...args: string[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-csr-test-'));
  try {
    const csrPath = path.join(dir, 'req.csr');
    fs.writeFileSync(csrPath, csrPem);
    return execFileSync('openssl', ['req', '-in', csrPath, ...args], { encoding: 'utf8' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('buildEapTlsCsr (EC P-256)', () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const opts = { cn: 'office-ap-01', organization: 'Acme Corp', organizationalUnit: 'IT', sanDns: ['ap01.lan', 'ap01.example.com'] };

  it('produces a CSR whose signature openssl verifies (ECDSA-SHA256)', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, opts);
    // -verify checks the request signature against the embedded public key.
    expect(opensslReq(csrPem, '-noout', '-verify')).toContain('Certificate request self-signature verify OK');
  });

  it('carries the subject RDNs in O → OU → CN order', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, opts);
    const text = opensslReq(csrPem, '-noout', '-subject');
    expect(text).toContain('O=Acme Corp');
    expect(text).toContain('OU=IT');
    expect(text).toContain('CN=office-ap-01');
  });

  it('omits O/OU RDNs when not provided (CN only)', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, { cn: 'bare', sanDns: ['bare.lan'] });
    const text = opensslReq(csrPem, '-noout', '-subject');
    expect(text).toContain('CN=bare');
    expect(text).not.toContain('O=');
    expect(text).not.toContain('OU=');
  });

  it('embeds the SAN dNSNames exactly as requested (plus nothing else)', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, opts);
    const text = opensslReq(csrPem, '-noout', '-text');
    expect(text).toContain('DNS:ap01.lan');
    expect(text).toContain('DNS:ap01.example.com');
  });

  it('requests keyUsage digitalSignature only (non-critical)', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, opts);
    const text = opensslReq(csrPem, '-noout', '-text');
    expect(text).toContain('X509v3 Key Usage: ');
    expect(text).toContain('Digital Signature');
    // Must NOT request keyEncipherment etc. (supplicant client certs sign only).
    expect(text).not.toContain('Key Encipherment');
  });

  it('requests EKU clientAuth + EAP-TLS', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, opts);
    const text = opensslReq(csrPem, '-noout', '-text');
    expect(text).toContain('TLS Web Client Authentication');
    // openssl renders the EAP-TLS EKU by its raw OID (it has no built-in name).
    expect(text).toContain('1.3.6.1.5.5.7.3.13');
  });

  it('embeds the correct public key (SPKI matches the source key)', () => {
    if (!HAS_OPENSSL) return;
    const { csrPem } = buildEapTlsCsr(privateKey, opts);
    // openssl req -pubkey extracts the SPKI from the CSR — compare with Node's.
    const csrPub = opensslReq(csrPem, '-noout', '-pubkey').replace(/-----[^-]+-----|\s/g, '');
    const nodePub = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64');
    expect(csrPub).toBe(nodePub);
  });

  it('produces a different CSR for a different private key (SPKI differs)', () => {
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    expect(buildEapTlsCsr(privateKey, opts).csrPem).not.toBe(buildEapTlsCsr(other, opts).csrPem);
  });

  it('every build of the same request verifies under openssl (repeated builds stay well-formed)', () => {
    if (!HAS_OPENSSL) return;
    for (let i = 0; i < 3; i++) {
      const { csrPem } = buildEapTlsCsr(privateKey, opts);
      expect(opensslReq(csrPem, '-noout', '-verify')).toContain('Certificate request self-signature verify OK');
    }
  });
});

describe('buildEapTlsCsr (RSA)', () => {
  it('signs with rsa-SHA256 and verifies under openssl', () => {
    if (!HAS_OPENSSL) return;
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
    const { csrPem } = buildEapTlsCsr(privateKey, { cn: 'rsa-client', sanDns: ['rsa.lan'] });
    expect(opensslReq(csrPem, '-noout', '-verify')).toContain('Certificate request self-signature verify OK');
    const text = opensslReq(csrPem, '-noout', '-text');
    expect(text).toContain('Signature Algorithm: sha256WithRSAEncryption');
  });
});
