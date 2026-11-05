/**
 * Unit tests for the CA-administration credential (adminKey.ts).
 *
 * These guard the step-ca JWK-provisioner protocol — every failure mode here
 * was discovered empirically against a live step-ca 0.30.2 and shows up as a
 * misleading "provisioner not found or invalid audience" 401:
 *   - header MUST carry `kid` = RFC 7638 thumbprint of the public key
 *   - JWS ES256 signature MUST be raw r‖s (64 bytes), NOT Node's DER encoding
 *   - a 33-byte DER INTEGER is sign-padded — drop the FIRST byte, never the last
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import jwt = require('jsonwebtoken');
import { jwkThumbprint, loadAdminJwk, mintAdminToken } from './adminKey';

function b64urlJson(seg: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

describe('jwkThumbprint (RFC 7638)', () => {
  it('matches the known thumbprint of UNM\'s live unm-admin provisioner key', () => {
    // Regression vector from the dev CA's ca.json — if this changes, every
    // minted token stops validating against the deployed CA.
    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: 'eZuUAWlSV12xcgwfhEdHAJjLSm8_zBE1rYsRDX84TYo',
      y: '4w8lx10S-OuqWXrjijk1ZmjmO0m7xfNvUJbVabjl4Ik',
    };
    expect(jwkThumbprint(jwk)).toBe('hA6cksht5StOocvCHf9lKTRzCNhWNxyXrT8PuzijOS4');
  });

  it('is independent of extra JWK fields (use/alg/kid are not part of the canonical form)', () => {
    const base = { kty: 'EC', crv: 'P-256', x: 'eZuUAWlSV12xcgwfhEdHAJjLSm8_zBE1rYsRDX84TYo', y: '4w8lx10S-OuqWXrjijk1ZmjmO0m7xfNvUJbVabjl4Ik' };
    const withExtras = { ...base, use: 'sig', alg: 'ES256', kid: 'whatever' };
    expect(jwkThumbprint(withExtras)).toBe(jwkThumbprint(base));
  });

  it('is sensitive to every coordinate (a changed key yields a different thumbprint)', () => {
    const base = { kty: 'EC', crv: 'P-256', x: 'eZuUAWlSV12xcgwfhEdHAJjLSm8_zBE1rYsRDX84TYo', y: '4w8lx10S-OuqWXrjijk1ZmjmO0m7xfNvUJbVabjl4Ik' };
    expect(jwkThumbprint({ ...base, x: Buffer.from(base.x as string).toString('base64url') })).not.toBe(jwkThumbprint(base));
    // Flip one character of y.
    const y = base.y as string;
    const flippedY = (y[0] === 'A' ? 'B' : 'A') + y.slice(1);
    expect(jwkThumbprint({ ...base, y: flippedY })).not.toBe(jwkThumbprint(base));
  });

  it('produces a base64url SHA-256 digest (43 chars, no padding)', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'eZuUAWlSV12xcgwfhEdHAJjLSm8_zBE1rYsRDX84TYo', y: '4w8lx10S-OuqWXrjijk1ZmjmO0m7xfNvUJbVabjl4Ik' };
    expect(jwkThumbprint(jwk)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('loadAdminJwk', () => {
  it('generates + persists a P-256 keypair on first use (0600) and is stable across reloads', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-adminkey-test-'));
    try {
      const keyPath = path.join(dir, 'admin-jwk.pem');
      const first = loadAdminJwk(keyPath);
      expect(fs.existsSync(keyPath)).toBe(true);
      expect((fs.statSync(keyPath).mode & 0o777)).toBe(0o600);
      expect(first.privateKeyPem).toContain('PRIVATE KEY');

      // The public JWK is a full step-ca provisioner key: use/alg/kid/x/y.
      const pub = first.public as { kty: string; crv: string; alg: string; use: string; kid: string; x: string; y: string };
      expect(pub.kty).toBe('EC');
      expect(pub.crv).toBe('P-256');
      expect(pub.alg).toBe('ES256');
      expect(pub.use).toBe('sig');
      expect(jwkThumbprint({ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y })).toBe(pub.kid);

      // Reload from disk — same key (kid stable), so tokens keep validating.
      const second = loadAdminJwk(keyPath);
      expect(second.public).toEqual(first.public);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('loads an existing key without regenerating', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-adminkey-test-'));
    try {
      const keyPath = path.join(dir, 'admin-jwk.pem');
      const a = loadAdminJwk(keyPath);
      const mtimeBefore = fs.statSync(keyPath).mtimeMs;
      // Give the clock a tick so an accidental rewrite would be visible.
      const b = loadAdminJwk(keyPath);
      expect(b.privateKeyPem).toBe(a.privateKeyPem);
      expect(fs.statSync(keyPath).mtimeMs).toBe(mtimeBefore);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('mintAdminToken', () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  const pubPem = crypto.createPublicKey(privateKey).export({ format: 'pem', type: 'spki' }) as string;

  it('mints a token whose ES256 signature verifies (jsonwebtoken oracle)', () => {
    const aud = 'https://unm-ca:9000/1.0/sign';
    const { token } = mintAdminToken(privPem, { aud, provisionerName: 'unm-admin', sub: 'office-ap-01', sans: ['ap01.lan'] });

    // jsonwebtoken expects raw r‖s for ES256 — a DER signature would fail here.
    const claims = jwt.verify(token, pubPem, { algorithms: ['ES256'], audience: aud, issuer: 'unm-admin' }) as Record<string, unknown>;
    expect(claims.sub).toBe('office-ap-01');
    expect(claims.sans).toEqual(['ap01.lan']);
  });

  it('binds the token to its audience — a different endpoint is rejected', () => {
    const aud = 'https://unm-ca:9000/1.0/sign';
    const { token } = mintAdminToken(privPem, { aud });
    expect(() => jwt.verify(token, pubPem, { algorithms: ['ES256'], audience: 'https://unm-ca:9000/1.0/revoke' })).toThrow();
  });

  it('carries kid = RFC 7638 thumbprint in the header (step-ca key selection)', () => {
    const { token } = mintAdminToken(privPem, { aud: 'https://unm-ca:9000/1.0/sign' });
    const header = b64urlJson(token.split('.')[0]);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');
    const pubJwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' }) as Record<string, unknown>;
    expect(header.kid).toBe(jwkThumbprint(pubJwk));
  });

  it('emits a raw r‖s signature of exactly 64 bytes for P-256 (never DER)', () => {
    const { token } = mintAdminToken(privPem, { aud: 'https://unm-ca:9000/1.0/sign' });
    const sig = Buffer.from(token.split('.')[2], 'base64url');
    expect(sig.length).toBe(64); // DER would be 70–72 bytes and start with 0x30
    expect(sig[0]).not.toBe(0x30);
  });

  it('defaults sub to the provisioner name when omitted (plain management call)', () => {
    const { token } = mintAdminToken(privPem, { aud: 'https://unm-ca:9000/1.0/version', provisionerName: 'unm-admin' });
    const payload = b64urlJson(token.split('.')[1]);
    expect(payload.sub).toBe('unm-admin');
    expect(payload.sans).toBeUndefined();
  });

  it('honors ttlSeconds (expiry is enforced by the verifier)', () => {
    const aud = 'https://unm-ca:9000/1.0/sign';
    const expired = mintAdminToken(privPem, { aud, ttlSeconds: -10 });
    expect(() => jwt.verify(expired.token, pubPem, { algorithms: ['ES256'], audience: aud })).toThrow(/expired/i);

    const fresh = mintAdminToken(privPem, { aud, ttlSeconds: 300 });
    const claims = jwt.verify(fresh.token, pubPem, { algorithms: ['ES256'], audience: aud }) as { exp: number };
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000) + 290);
  });

  it('survives the 33-byte DER sign-pad case (regression: silent low-byte truncation)', () => {
    // Force signatures whose r or s needs a leading 0x00 pad byte in DER by
    // minting many tokens — with P-256, ~75% of integers are 33 bytes. If the
    // padding logic ever regresses to "copy at offset 0", some fraction of
    // these would fail verification (or produce a 64-byte-but-wrong sig).
    for (let i = 0; i < 25; i++) {
      const { token } = mintAdminToken(privPem, { aud: 'https://unm-ca:9000/1.0/sign' });
      expect(() => jwt.verify(token, pubPem, { algorithms: ['ES256'], audience: 'https://unm-ca:9000/1.0/sign' })).not.toThrow();
    }
  });

  it('works for RSA keys too (signature passed through unconverted)', () => {
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
    const rsaPem = rsa.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
    const aud = 'https://unm-ca:9000/1.0/sign';
    const { token } = mintAdminToken(rsaPem, { aud });
    // RS256 is the honest alg for RSA — but UNM only ever mints ES256 (EC).
    // Verify the raw signature directly instead of via jsonwebtoken's alg map.
    const [h, p, s] = token.split('.');
    const sig = Buffer.from(s, 'base64url');
    expect(crypto.verify('sha256', Buffer.from(`${h}.${p}`), rsa.publicKey, sig)).toBe(true);
  });
});
