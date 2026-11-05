/**
 * Unit tests for the EAP-TLS enrollment flow (enroll.ts) — focused on the
 * CHAIN GUARD, which is business-critical: an issued client cert must never
 * outlive its issuer, or every enrolled device loses WiFi auth at once.
 *
 * The CA boundary is mocked (signCsr/getCaStatus/adminKey); signCsr returns a
 * REAL openssl-generated certificate so the leaf parsing path runs for real.
 */

import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { enrollEapTlsClient, EnrollValidationError } from './enroll';

// --- mocks (declared before importing the module under test) -----------------
jest.mock('./stepCaAdmin', () => ({
  CA_BASE: 'https://unm-ca:9000',
  getCaStatus: jest.fn(),
  signCsr: jest.fn(),
}));
jest.mock('./adminKey', () => ({
  loadAdminJwk: jest.fn(() => ({ public: {}, privateKeyPem: 'FAKE-PEM' })),
  mintAdminToken: jest.fn(() => ({ token: 'fake-ott', exp: 9_999_999_999 })),
}));
jest.mock('../systemSettings', () => ({ getEffectiveValues: jest.fn() }));

import { signCsr, getCaStatus } from './stepCaAdmin';
import { mintAdminToken } from './adminKey';
import { getEffectiveValues } from '../systemSettings';

const mockSign = signCsr as jest.MockedFunction<typeof signCsr>;
const mockStatus = getCaStatus as jest.MockedFunction<typeof getCaStatus>;
const mockMint = mintAdminToken as jest.MockedFunction<typeof mintAdminToken>;
const mockSettings = getEffectiveValues as jest.MockedFunction<typeof getEffectiveValues>;

function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
const HAS_OPENSSL = opensslAvailable();

/** A real self-signed cert (PEM) standing in for the CA-issued leaf. */
let fixtureLeafPem = '';
beforeAll(() => {
  if (!HAS_OPENSSL) return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-enroll-fixture-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-keyout', path.join(dir, 'k.key'), '-out', path.join(dir, 'c.crt'), '-days', '365', '-nodes',
      '-subj', '/CN=fixture-leaf'], { cwd: dir, stdio: 'ignore' });
    fixtureLeafPem = fs.readFileSync(path.join(dir, 'c.crt'), 'utf8');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Default settings: 3-year default, 10-year cap. */
function settings(defaultDays = 1095, maxDays = 3650): void {
  mockSettings.mockResolvedValue({ caWifiCertDefaultDays: String(defaultDays), caWifiCertMaxDays: String(maxDays) });
}

/** CA chain expiring in `rootDays` / `interDays` from now. */
function chain(rootDays: number, interDays?: number): void {
  const iso = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
  mockStatus.mockResolvedValue({
    version: '0.30.2',
    rootFingerprint: 'aa',
    rootSubject: 'CN=Root',
    rootNotAfter: iso(rootDays),
    intermediateNotAfter: interDays !== undefined ? iso(interDays) : undefined,
  });
}

/** The notAfter (ISO) that enroll asked the CA for in its last signCsr call. */
function requestedNotAfter(): Date {
  const arg = mockSign.mock.calls[mockSign.mock.calls.length - 1][3];
  return new Date(arg as string);
}

/** signCsr returns the fixture leaf (the CA boundary is mocked). */
function mockSignOk(): void {
  mockSign.mockResolvedValue({ crt: fixtureLeafPem, ca: '', certChain: [fixtureLeafPem] });
}

const DAY_MS = 86_400_000;
/** Asserts a date is within `tolMs` of now + days. */
function expectDaysFromNow(d: Date, days: number, tolMs = 5_000): void {
  const expected = Date.now() + days * DAY_MS;
  expect(Math.abs(d.getTime() - expected)).toBeLessThan(tolMs);
}

beforeEach(() => {
  jest.clearAllMocks();
  // Safe defaults for every test — individual tests override as needed.
  settings(1095, 3650);
  chain(3650, 3650);
});

describe('enrollEapTlsClient — validity handling', () => {
  it('uses the configured default (3 years) when no days are given', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    chain(3650, 3650); // far-future chain — no clamping
    mockSignOk();

    const res = await enrollEapTlsClient({ name: 'default-days' });
    expectDaysFromNow(requestedNotAfter(), 1095);
    expect(res.clamped).toBeUndefined();
  });

  it('honors an explicit days override (short-lived cert)', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    chain(3650, 3650);
    mockSignOk();

    await enrollEapTlsClient({ name: 'short', days: 30 });
    expectDaysFromNow(requestedNotAfter(), 30);
  });

  it('caps the requested validity at caWifiCertMaxDays (silent cap)', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    chain(7300, 7300); // chain outlives the cap — only the setting binds
    mockSignOk();

    const res = await enrollEapTlsClient({ name: 'long', days: 4000 });
    expectDaysFromNow(requestedNotAfter(), 3650);
    expect(res.clamped).toBeUndefined(); // cap is a policy limit, not the chain guard
  });

  it('CLAMPS to root expiry − 7d when the ROOT expires first (chain guard)', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    chain(100, 2000); // root in 100 days, intermediate far away
    mockSignOk();

    const res = await enrollEapTlsClient({ name: 'clamp-root', days: 365 });
    // 100 − 7 margin; Math.floor() can land on either side of the exact day
    // boundary depending on ms elapsed between mock setup and the call.
    const gotDays = Math.round((requestedNotAfter().getTime() - Date.now()) / DAY_MS);
    expect(gotDays).toBeGreaterThanOrEqual(92);
    expect(gotDays).toBeLessThanOrEqual(93);
    expect(res.clamped).toBe(true);
    expect(res.clampReason).toMatch(/CA chain expires sooner/i);
  }, 20_000);

  it('CLAMPS to intermediate expiry − 7d when the INTERMEDIATE binds (chain guard)', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    chain(3650, 30); // root fine, intermediate in 30 days
    mockSignOk();

    const res = await enrollEapTlsClient({ name: 'clamp-inter', days: 365 });
    // 30 − 7 margin; see the root-clamp test for why this is a range, not exact.
    const gotDays = Math.round((requestedNotAfter().getTime() - Date.now()) / DAY_MS);
    expect(gotDays).toBeGreaterThanOrEqual(22);
    expect(gotDays).toBeLessThanOrEqual(23);
    expect(res.clamped).toBe(true);
  }, 20_000);

  it('REFUSES enrollment when the chain expires within the safety margin', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    chain(5, 5); // root + intermediate expire in 5 days (< 7d margin)
    mockSignOk();

    await expect(enrollEapTlsClient({ name: 'too-late', days: 365 })).rejects.toThrow(EnrollValidationError);
    await expect(enrollEapTlsClient({ name: 'too-late' })).rejects.toThrow(/renew or rekey the CA/i);
    expect(mockSign).not.toHaveBeenCalled(); // nothing may be signed against a dying chain
  });

  it('skips clamping gracefully when the intermediate expiry is unknown', async () => {
    if (!HAS_OPENSSL) return;
    settings(1095, 3650);
    mockStatus.mockResolvedValue({
      version: '0.30.2', rootFingerprint: 'aa', rootSubject: 'CN=Root',
      rootNotAfter: new Date(Date.now() + 3650 * DAY_MS).toISOString(),
      // intermediateNotAfter absent — only the root binds
    });
    mockSignOk();

    const res = await enrollEapTlsClient({ name: 'no-inter', days: 1095 });
    expectDaysFromNow(requestedNotAfter(), 1095);
    expect(res.clamped).toBeUndefined();
  }, 20_000);

  it('never lets the requested window exceed min(root, intermediate) − margin (property)', async () => {
    if (!HAS_OPENSSL) return;
    // Sweep a range of chain expiries and request lengths — the invariant that
    // matters in production: issued notAfter ≤ issuer expiry − 7d.
    for (const [rootD, interD, req] of [[100, 500, 365], [500, 100, 365], [200, 200, 4000], [90, 90, 30]] as const) {
      jest.clearAllMocks();
      settings(1095, 3650);
      chain(rootD, interD);
      mockSignOk();
      try {
        await enrollEapTlsClient({ name: `prop-${rootD}-${interD}`, days: req });
      } catch (e) {
        if (!(e instanceof EnrollValidationError)) throw e; // refusal is also acceptable
        continue;
      }
      const granted = requestedNotAfter().getTime() - Date.now();
      const limit = Math.min(rootD, interD) * DAY_MS - 7 * DAY_MS;
      expect(granted).toBeLessThanOrEqual(limit + 5_000); // within tolerance of the margin
    }
  }, 30_000);
});

describe('enrollEapTlsClient — input validation', () => {
  it('rejects invalid names (charset/length)', async () => {
    for (const bad of ['', 'has space', 'semi;colon', 'x'.repeat(65)]) {
      await expect(enrollEapTlsClient({ name: bad })).rejects.toThrow(EnrollValidationError);
    }
  });

  it('rejects CN overrides that violate the name rules', async () => {
    await expect(enrollEapTlsClient({ name: 'ok-name', cn: 'bad cn!' })).rejects.toThrow(/"cn"/i);
  });

  it('rejects RDN values over 64 chars', async () => {
    await expect(enrollEapTlsClient({ name: 'ok', organization: 'x'.repeat(65) })).rejects.toThrow(/at most 64/i);
  });

  it('rejects unknown key types', async () => {
    await expect(enrollEapTlsClient({ name: 'ok', keyType: 'ml-dsa-65' as never })).rejects.toThrow(/unknown keyType/i);
  });

  it('rejects non-positive or non-finite day counts', async () => {
    for (const bad of [0, -5, NaN]) {
      await expect(enrollEapTlsClient({ name: 'ok', days: bad })).rejects.toThrow(/"days"/i);
    }
  });

  it('rejects invalid SAN entries', async () => {
    await expect(enrollEapTlsClient({ name: 'ok', sans: ['not a hostname!'] })).rejects.toThrow(EnrollValidationError);
  });
});

describe('enrollEapTlsClient — token/CSR contract with the CA', () => {
  it('mints an OTT whose sub is the CN and whose sans set includes the CN exactly once (deduped)', async () => {
    if (!HAS_OPENSSL) return;
    settings(); chain(3650, 3650); mockSignOk();

    await enrollEapTlsClient({ name: 'ap-01', sans: ['extra.lan', 'ap-01'] }); // CN duplicated in sans
    expect(mockMint).toHaveBeenCalledWith('FAKE-PEM', expect.objectContaining({
      aud: 'https://unm-ca:9000/1.0/sign',
      sub: 'ap-01',
      sans: ['ap-01', 'extra.lan'], // CN first, deduped — MUST equal the CSR dNSNames set
    }));
  });

  it('defaults the CN to the enrollment name and keeps the SAN set = {cn}', async () => {
    if (!HAS_OPENSSL) return;
    settings(); chain(3650, 3650); mockSignOk();

    await enrollEapTlsClient({ name: 'bare-ap' });
    expect(mockMint).toHaveBeenCalledWith('FAKE-PEM', expect.objectContaining({ sub: 'bare-ap', sans: ['bare-ap'] }));
  });

  it('returns the parsed leaf metadata + PKCS#8 key + chain bundle', async () => {
    if (!HAS_OPENSSL) return;
    settings(); chain(3650, 3650); mockSignOk();

    const res = await enrollEapTlsClient({ name: 'shape-check' });
    expect(res.serial).toMatch(/^[0-9A-F]+$/i);
    expect(res.subject).toBe('shape-check');
    expect(new Date(res.notAfter).getTime()).toBeGreaterThan(Date.now());
    expect(res.certPem).toContain('BEGIN CERTIFICATE');
    expect(res.keyPem).toContain('-----BEGIN PRIVATE KEY-----'); // PKCS#8
    expect(res.chainPem).toContain('BEGIN CERTIFICATE');

    // The key is a real, usable P-256 key (default type).
    const key = crypto.createPrivateKey(res.keyPem);
    expect(key.asymmetricKeyType).toBe('ec');
  });

  it('generates the requested RSA key size', async () => {
    if (!HAS_OPENSSL) return;
    settings(); chain(3650, 3650); mockSignOk();

    const res = await enrollEapTlsClient({ name: 'rsa-check', keyType: 'rsa-2048' });
    const key = crypto.createPrivateKey(res.keyPem);
    expect(key.asymmetricKeyType).toBe('rsa');
    // Node's KeyObject exposes no modulusLength at runtime — ask openssl.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-rsa-check-'));
    try {
      const keyPath = path.join(dir, 'k.pem');
      fs.writeFileSync(keyPath, res.keyPem);
      const text = execFileSync('openssl', ['rsa', '-in', keyPath, '-noout', '-text'], { encoding: 'utf8' });
      expect(text).toContain('2048 bit');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('surfaces CA sign failures as a readable error', async () => {
    if (!HAS_OPENSSL) return;
    settings(); chain(3650, 3650);
    mockSign.mockRejectedValue(new Error('CA /1.0/sign returned 403: {"message":"sans mismatch"}'));

    await expect(enrollEapTlsClient({ name: 'ca-fail' })).rejects.toThrow(/sans mismatch/);
  });
});
