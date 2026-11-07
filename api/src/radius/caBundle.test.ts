/**
 * Unit tests for buildCaBundle (radiusRender.ts) — the CA trust bundle that a
 * RADIUS failover slave uses to validate client certs issued by its replication
 * source's CA. Pure string logic: no DB, no fs.
 */
import { buildCaBundle } from './radiusRender';

const cert = (label: string): string =>
  `-----BEGIN CERTIFICATE-----\n${Buffer.from(`fake-cert-${label}`).toString('base64')}\n-----END CERTIFICATE-----`;

describe('buildCaBundle', () => {
  it('returns empty when neither source has a certificate', () => {
    expect(buildCaBundle(null, '')).toBe('');
    expect(buildCaBundle('', 'no pem here')).toBe('');
  });

  it('passes through the local root alone', () => {
    const out = buildCaBundle(cert('local'), '');
    expect(out).toContain(cert('local'));
    expect(out.trim().split('\n').filter((l) => l.includes('BEGIN CERTIFICATE')).length).toBe(1);
  });

  it('passes through trusted roots alone (slave without a local CA)', () => {
    const out = buildCaBundle(null, cert('primary-root'));
    expect(out).toContain(cert('primary-root'));
  });

  it('concatenates local root first, then trusted roots', () => {
    const out = buildCaBundle(cert('local'), `${cert('trusted-a')}\n${cert('trusted-b')}`);
    const ia = out.indexOf(cert('local'));
    const ib = out.indexOf(cert('trusted-a'));
    const ic = out.indexOf(cert('trusted-b'));
    expect(ia).toBeGreaterThanOrEqual(0);
    expect(ib).toBeGreaterThan(ia);
    expect(ic).toBeGreaterThan(ib);
  });

  it('de-duplicates the same certificate appearing in both sources', () => {
    const root = cert('shared-root');
    const out = buildCaBundle(root, `${root}\n${cert('extra')}`);
    const count = out.split('BEGIN CERTIFICATE').length - 1;
    expect(count).toBe(2); // shared once + extra
  });

  it('ignores non-certificate PEM blocks (keys, CRLs) and surrounding text', () => {
    const keyPem = '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----';
    const out = buildCaBundle(null, `# comment\n${keyPem}\n${cert('root')}`);
    expect(out).not.toContain('PRIVATE KEY');
    expect(out).toContain(cert('root'));
  });

  it('normalizes whitespace inside a block for de-duplication', () => {
    const compact = cert('x').replace(/\n/g, ' ');
    const out = buildCaBundle(cert('x'), compact);
    const count = out.split('BEGIN CERTIFICATE').length - 1;
    expect(count).toBe(1);
  });
});
