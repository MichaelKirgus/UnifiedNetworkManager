/**
 * Unit tests for PKCS#12 bundle building (pkcs12.ts).
 *
 * Builds a REAL two-level chain with host openssl (root → intermediate → leaf)
 * and verifies the produced .p12 with an independent openssl invocation:
 * correct bags, working password, private key round-trip. Skips cleanly when
 * openssl is not installed on the test host.
 */

import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildPkcs12, generateP12Password } from './pkcs12';

function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const HAS_OPENSSL = opensslAvailable();

/** A self-signed root + intermediate CA + leaf, all in one temp dir. */
interface ChainFixture {
  dir: string;
  leafPem: string;
  interPem: string;
  keyPem: string; // PKCS#8 leaf private key
}

function makeChainFixture(): ChainFixture {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-p12-fixture-'));
  const run = (...args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });

  // Root CA (OpenSSL ≥3.0 -x509 adds basicConstraints=critical,CA:true + SKID/AKID).
  run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-keyout', 'root.key', '-out', 'root.crt', '-days', '3650', '-nodes',
    '-subj', '/O=UNM Test/CN=Test Root CA');

  // Intermediate CA signed by the root.
  run('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-keyout', 'inter.key', '-out', 'inter.csr', '-nodes', '-subj', '/O=UNM Test/CN=Test Intermediate CA');
  fs.writeFileSync(path.join(dir, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  run('x509', '-req', '-in', 'inter.csr', '-CA', 'root.crt', '-CAkey', 'root.key',
    '-CAcreateserial', '-days', '1825', '-extfile', 'ca.ext', '-out', 'inter.crt');

  // Leaf client cert signed by the intermediate.
  run('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-keyout', 'leaf.key', '-out', 'leaf.csr', '-nodes', '-subj', '/O=Acme/CN=p12-test-client');
  fs.writeFileSync(path.join(dir, 'leaf.ext'),
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:p12test.lan\n');
  run('x509', '-req', '-in', 'leaf.csr', '-CA', 'inter.crt', '-CAkey', 'inter.key',
    '-CAcreateserial', '-days', '365', '-extfile', 'leaf.ext', '-out', 'leaf.crt');

  const leafPem = fs.readFileSync(path.join(dir, 'leaf.crt'), 'utf8');
  const interPem = fs.readFileSync(path.join(dir, 'inter.crt'), 'utf8');
  // Convert the leaf key to PKCS#8 (what enroll.ts stores).
  const keyDer = execFileSync('openssl', ['ec', '-in', 'leaf.key', '-outform', 'DER'], { cwd: dir, stdio: P12_STDIO });
  const keyPem = crypto.createPrivateKey({ key: keyDer, format: 'der', type: 'sec1' })
    .export({ format: 'pem', type: 'pkcs8' }) as string;

  return { dir, leafPem, interPem, keyPem };
}

// openssl pkcs12 writes its summary lines ("Certificate bag", MAC info) to
// STDERR — discard them and keep only the stdout dump.
const P12_STDIO: ('ignore' | 'pipe')[] = ['ignore', 'pipe', 'ignore'];
function p12Info(p12Path: string, password: string): string {
  return execFileSync('openssl', ['pkcs12', '-info', '-in', p12Path, '-passin', `pass:${password}`, '-nokeys'], { encoding: 'utf8', stdio: P12_STDIO });
}

describe('generateP12Password', () => {
  it('is 16 chars from the unambiguous alphabet (no I/L/O/0/1)', () => {
    for (let i = 0; i < 50; i++) {
      const pw = generateP12Password();
      expect(pw).toHaveLength(16);
      // Alphabet: A-Z minus I/O, a-z minus l, 2-9 (no ambiguous chars).
      expect(pw).toMatch(/^[A-HJ-NP-Za-km-z2-9]{16}$/);
    }
  });

  it('is unique across calls (random, not constant)', () => {
    const set = new Set(Array.from({ length: 100 }, () => generateP12Password()));
    expect(set.size).toBe(100);
  });
});

describe('buildPkcs12', () => {
  let fixture: ChainFixture;

  beforeAll(() => {
    if (HAS_OPENSSL) fixture = makeChainFixture();
  });

  afterAll(() => {
    if (fixture) fs.rmSync(fixture.dir, { recursive: true, force: true });
  });

  it('builds a P12 with leaf + intermediate bags and the private key', async () => {
    if (!HAS_OPENSSL) return;
    const chainPem = `${fixture.leafPem.trimEnd()}\n${fixture.interPem.trimEnd()}\n`;
    const bundle = await buildPkcs12(chainPem, fixture.keyPem);

    expect(bundle.p12Base64).toMatch(/^[A-Za-z0-9+/=]+$/);
    const p12Path = path.join(fixture.dir, 'out.p12');
    fs.writeFileSync(p12Path, Buffer.from(bundle.p12Base64, 'base64'));

    // openssl verifies the MAC with the returned password and lists both bags.
    // NOTE: `openssl pkcs12 -info` writes the "Certificate bag" summary lines to
    // STDERR — stdout carries Bag Attributes, subject=/issuer= (with ALL RDNs,
    // e.g. `subject=O=Acme, CN=p12-test-client`) and one PEM block per cert bag.
    const info = p12Info(p12Path, bundle.password);
    expect(info).toContain('CN=p12-test-client');
    expect(info).toContain('issuer=O=UNM Test, CN=Test Intermediate CA');
    // Two certificate bags (leaf + intermediate), no root — count the PEM blocks.
    const bagCount = (info.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
    expect(bagCount).toBe(2);

    // The private key inside matches the source key (compare public halves).
    const spkiOf = (privPemText: string): string =>
      crypto.createPublicKey(crypto.createPrivateKey(privPemText)).export({ type: 'spki', format: 'der' }).toString('base64');
    const extractedKey = execFileSync('openssl', ['pkcs12', '-in', p12Path, '-passin', `pass:${bundle.password}`, '-nocerts', '-nodes'], { encoding: 'utf8', stdio: P12_STDIO });
    expect(extractedKey).toContain('PRIVATE KEY');
    expect(spkiOf(extractedKey)).toBe(spkiOf(fixture.keyPem));

    // The leaf inside the P12 verifies against the fixture chain.
    const extractedLeaf = execFileSync('openssl', ['pkcs12', '-in', p12Path, '-passin', `pass:${bundle.password}`, '-nokeys'], { encoding: 'utf8', stdio: P12_STDIO });
    const leafCert = new crypto.X509Certificate(extractedLeaf);
    expect(leafCert.subject).toContain('p12-test-client');
  }, 30_000);

  it('rejects the P12 with a WRONG password (MAC check)', async () => {
    if (!HAS_OPENSSL) return;
    const chainPem = `${fixture.leafPem.trimEnd()}\n${fixture.interPem.trimEnd()}\n`;
    const bundle = await buildPkcs12(chainPem, fixture.keyPem);
    const p12Path = path.join(fixture.dir, 'out-wrong.p12');
    fs.writeFileSync(p12Path, Buffer.from(bundle.p12Base64, 'base64'));

    expect(() => execFileSync('openssl', ['pkcs12', '-info', '-in', p12Path, '-passin', 'pass:definitely-wrong'], { stdio: 'pipe' })).toThrow();
  }, 30_000);

  it('handles a leaf-only chain (no intermediates)', async () => {
    if (!HAS_OPENSSL) return;
    // A self-signed cert + its key — single-block chain, no -certfile needed.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-p12-self-'));
    try {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-keyout', path.join(dir, 'k.key'), '-out', path.join(dir, 'c.crt'), '-days', '365', '-nodes',
        '-subj', '/CN=self-signed-client'], { cwd: dir, stdio: 'ignore' });
      const keyDer = execFileSync('openssl', ['ec', '-in', 'k.key', '-outform', 'DER'], { cwd: dir, stdio: P12_STDIO });
      const keyPem = crypto.createPrivateKey({ key: keyDer, format: 'der', type: 'sec1' }).export({ format: 'pem', type: 'pkcs8' }) as string;
      const certPem = fs.readFileSync(path.join(dir, 'c.crt'), 'utf8');

      const single = await buildPkcs12(certPem, keyPem);
      const p12Path = path.join(dir, 'single.p12');
      fs.writeFileSync(p12Path, Buffer.from(single.p12Base64, 'base64'));
      const info = p12Info(p12Path, single.password);
      // One certificate bag — count the PEM blocks in stdout (see note above).
      expect((info.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length).toBe(1);
      expect(info).toContain('CN=self-signed-client');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('rejects an empty chain', async () => {
    await expect(buildPkcs12('', fixture.keyPem)).rejects.toThrow(/no certificates/i);
  });

  it('leaves no temp files behind (key material cleanup)', async () => {
    if (!HAS_OPENSSL) return;
    const before = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith('unm-p12-'));
    await buildPkcs12(`${fixture.leafPem.trimEnd()}\n${fixture.interPem.trimEnd()}\n`, fixture.keyPem);
    const after = fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith('unm-p12-') && !before.includes(f));
    expect(after).toEqual([]);
  }, 30_000);
});
