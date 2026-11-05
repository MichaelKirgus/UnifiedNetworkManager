/**
 * End-to-end verification for the CA + WiFi (EAP-TLS) client certificates.
 *
 * Validates against the deployed stack (API on :3000, unm-ca running):
 *   1. CA status sanity — version, root fingerprint, root/intermediate expiry
 *      in the future; root bundle is a parseable PEM certificate.
 *   2. Enrollment defaults — no `days` → configured default (3y), response
 *      shape (serial hex, notBefore/notAfter sane).
 *   3. Enrollment overrides — custom name/cn/org/ou/sans + RSA-2048 key type;
 *      the issued PEM really contains an RSA private key of that size.
 *   4. Validation errors — bad names / unknown keyType / days < 1 → 400;
 *      duplicate enrollment name → 409.
 *   5. Downloads — PEM bundle (chain + PKCS#8 key), P12 bundle (base64 +
 *      password) verified with an INDEPENDENT openssl invocation: MAC check,
 *      leaf+intermediate bags, extracted key SPKI == stored key SPKI, and the
 *      full chain verifies against the root bundle.
 *   6. Revocation — idempotent (second call still 200), both download formats
 *      then answer 409, DB rows mirrored (wifi_client_certs + ca_certificates).
 *   7. Cleanup — test rows are deleted again (revoked leaves stay in the CA's
 *      own DB; that is expected and harmless).
 *
 * Usage (from the repo root, with the stack up):
 *   ./node_modules/.bin/tsx scripts/e2e-ca-wifi.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
// pg lives in the API package's node_modules — resolve it from there.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown) {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
const HAS_OPENSSL = opensslAvailable();

/** SPKI (DER, base64) of a PEM private key — the public half, for comparison. */
function spkiOf(privPem: string): string {
  return crypto.createPublicKey(crypto.createPrivateKey(privPem)).export({ type: 'spki', format: 'der' }).toString('base64');
}

const DAY_MS = 86_400_000;

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Auth -------------------------------------------------------------------
  // Preferred: a long-lived API token (UNM_API_TOKEN env or .env) — no 2FA.
  let token = process.env.UNM_API_TOKEN ?? null;
  if (!token) {
    try {
      const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
      const m = envFile.match(/^UNM_API_TOKEN=(.+)$/m);
      if (m?.[1]?.trim()) token = m[1].trim();
    } catch { /* no .env */ }
  }
  if (!token) {
    const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
    if (!adminRow?.totpSecret) {
      const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: process.env.UNM_ADMIN_PW ?? 'admin' }) });
      token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
    } else {
      // otplib@13 dropped the `authenticator` instance — use the functional API.
      const { generate: otpGenerate } = apiRequire('otplib');
      const code = await otpGenerate({ strategy: 'totp', secret: adminRow.totpSecret });
      const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: process.env.UNM_ADMIN_PW ?? 'admin' }) });
      const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
      const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
      token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
    }
  }
  check('authenticated (API token / login)', Boolean(token));
  if (!token) throw new Error('no API token available');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; text: () => Promise<string>; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, text: async () => (await res.text()), json: async () => (await res.json().catch(() => null)) as never };
  };

  const run = (...args: string[]) => execFileSync('openssl', args);
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-e2e-ca-wifi-'));
  const serials: string[] = []; // collected for cleanup

  try {
    // ---------------------------------------------------------------------------
    // 1. CA status sanity
    // ---------------------------------------------------------------------------
    console.log('\n— CA status —');
    const st = await authed('GET', '/ca/status');
    check('GET /ca/status returns 200', st.status === 200, { status: st.status });
    const status = ((await st.json()) as { status?: Record<string, unknown> }).status ?? {};
    check('CA version reported', typeof status.version === 'string' && (status.version as string).length > 0, status.version);
    check('root fingerprint present', typeof status.rootFingerprint === 'string' && (status.rootFingerprint as string).length >= 16, status.rootFingerprint);
    const rootEnd = Date.parse(String(status.rootNotAfter ?? ''));
    const interEnd = status.intermediateNotAfter ? Date.parse(String(status.intermediateNotAfter)) : NaN;
    check('root expiry in the future', Number.isFinite(rootEnd) && rootEnd > Date.now() + DAY_MS, status.rootNotAfter);
    // The bootstrap signs the intermediate ~1s AFTER the root (both 10y), so a
    // tiny skew is expected — allow up to 60s. What must never happen: the
    // intermediate outliving the root by more than that.
    check('intermediate expiry in the future (and ≈ root, ≤ +60s)', Number.isFinite(interEnd) && interEnd > Date.now() + DAY_MS && (!Number.isFinite(rootEnd) || interEnd - rootEnd <= 60_000), { intermediate: status.intermediateNotAfter, root: status.rootNotAfter });

    const rb = await authed('GET', '/ca/root-bundle');
    const rootBundlePem = await rb.text(); // single read — the body stream is consumed once
    check('GET /ca/root-bundle returns 200 PEM', rb.status === 200 && rootBundlePem.includes('-----BEGIN CERTIFICATE-----'), { status: rb.status });
    fs.writeFileSync(path.join(workdir, 'root.pem'), rootBundlePem);

    // ---------------------------------------------------------------------------
    // 2. Enrollment with defaults
    // ---------------------------------------------------------------------------
    console.log('\n— Enrollment (defaults) —');
    const suffix = Date.now().toString(36);
    const nameDefault = `e2e-ca-wifi-${suffix}`;
    const en1 = await authed('POST', '/ca/enroll', { name: nameDefault });
    const en1Body = await en1.text(); // read once — the body stream is consumed
    check('enroll (defaults) returns 201', en1.status === 201, { status: en1.status, body: en1Body.slice(0, 300) });
    const r1 = ((JSON.parse(en1Body || 'null')) as Record<string, unknown>) ?? {};
    const serial1 = String(r1.serial ?? '');
    check('serial is hex', /^[0-9A-Fa-f]{1,64}$/.test(serial1), serial1);
    if (serial1) serials.push(serial1);
    check('cn defaults to the enrollment name', r1.cn === nameDefault, { cn: r1.cn });
    const na1 = Date.parse(String(r1.notAfter ?? ''));
    const nb1 = Date.parse(String(r1.notBefore ?? ''));
    check('notBefore ≈ now, notAfter in the future', Number.isFinite(nb1) && Math.abs(nb1 - Date.now()) < 5 * 60_000 && na1 > Date.now() + DAY_MS, { notBefore: r1.notBefore, notAfter: r1.notAfter });
    // Default validity = caWifiCertDefaultDays (3y), clamped to the chain if that binds.
    const defaultDays = Number((await pool.query(`SELECT value FROM system_settings WHERE "key" = 'caWifiCertDefaultDays'`)).rows[0]?.value ?? 1095);
    const grantedDays = Math.round((na1 - nb1) / DAY_MS);
    const chainCeilingDays = Math.floor(Math.min(rootEnd, Number.isFinite(interEnd) ? interEnd : rootEnd) - Date.now() - 7 * DAY_MS) / DAY_MS;
    check(`granted validity ≈ min(default ${defaultDays}d, chain ceiling ~${Math.round(chainCeilingDays)}d)`, Math.abs(grantedDays - Math.min(defaultDays, Math.floor(chainCeilingDays))) <= 1, { grantedDays });

    // ---------------------------------------------------------------------------
    // 3. Enrollment with overrides (RSA-2048 + custom RDNs/SANs)
    // ---------------------------------------------------------------------------
    console.log('\n— Enrollment (overrides: RSA-2048, org/ou/sans) —');
    const nameRsa = `e2e-ca-wifi-rsa-${suffix}`;
    const en2 = await authed('POST', '/ca/enroll', {
      name: nameRsa, cn: 'e2e-rsa-client', organization: 'E2E Org', organizationalUnit: 'NetOps',
      sans: ['e2e-rsa-1.lan', 'e2e-rsa-2.lan'], keyType: 'rsa-2048', days: 365,
    });
    const en2Body = await en2.text(); // read once — the body stream is consumed
    check('enroll (RSA overrides) returns 201', en2.status === 201, { status: en2.status, body: en2Body.slice(0, 300) });
    const r2 = ((JSON.parse(en2Body || 'null')) as Record<string, unknown>) ?? {};
    const serial2 = String(r2.serial ?? '');
    check('serial is hex (rsa)', /^[0-9A-Fa-f]{1,64}$/.test(serial2), serial2);
    if (serial2) serials.push(serial2);
    check('cn override honored', r2.cn === 'e2e-rsa-client', { cn: r2.cn });

    // PEM download of the RSA cert — verify key type/size + chain with openssl.
    const dl2 = await authed('GET', `/ca/wifi-certs/${serial2}/download`);
    check('PEM download returns 200', dl2.status === 200, { status: dl2.status });
    const pem2 = await dl2.text();
    if (HAS_OPENSSL && serial2) {
      const certCount = (pem2.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
      check('PEM bundle has leaf + intermediate', certCount === 2, { certCount });
      check('PEM bundle contains a PKCS#8 private key', pem2.includes('-----BEGIN PRIVATE KEY-----'));
      const pemPath = path.join(workdir, 'rsa.pem');
      fs.writeFileSync(pemPath, pem2);
      // Split: first PEM block(s) are certs, the last is the key.
      const blocks = pem2.split(/(?=-----BEGIN)/).map((b) => b.trim()).filter(Boolean);
      const keyBlock = blocks.find((b) => b.includes('PRIVATE KEY')) ?? '';
      const certBlocks = blocks.filter((b) => b.includes('CERTIFICATE'));
      fs.writeFileSync(path.join(workdir, 'rsa-key.pem'), keyBlock + '\n');
      fs.writeFileSync(path.join(workdir, 'rsa-chain.pem'), certBlocks.map((b) => b + '\n').join(''));
      const rsaText = execFileSync('openssl', ['pkey', '-in', path.join(workdir, 'rsa-key.pem'), '-noout', '-text'], { encoding: 'utf8' });
      check('private key is RSA 2048 bit', rsaText.includes('2048 bit'), rsaText.split('\n')[1]);
      const leafText = execFileSync('openssl', ['x509', '-in', path.join(workdir, 'rsa-chain.pem'), '-noout', '-subject', '-issuer'], { encoding: 'utf8' });
      check('leaf subject carries the CN override', leafText.includes('e2e-rsa-client'), leafText);
      const verify = execFileSync('openssl', ['verify', '-CAfile', path.join(workdir, 'root.pem'), '-untrusted', path.join(workdir, 'rsa-chain.pem'), path.join(workdir, 'rsa-chain.pem')], { encoding: 'utf8' });
      check('RSA chain verifies against the root bundle', verify.includes(': OK'), verify);
    } else if (!HAS_OPENSSL) {
      console.log('  SKIP openssl-based PEM verification (openssl not installed on this host)');
    }

    // ---------------------------------------------------------------------------
    // 4. Validation errors + duplicate name
    // ---------------------------------------------------------------------------
    console.log('\n— Validation —');
    const bad1 = await authed('POST', '/ca/enroll', { name: 'bad name with spaces' });
    check('enroll rejects a bad name (400)', bad1.status === 400, { status: bad1.status });
    const bad2 = await authed('POST', '/ca/enroll', { name: `e2e-bad-${suffix}`, keyType: 'ml-dsa-65' });
    check('enroll rejects an unknown keyType (400)', bad2.status === 400, { status: bad2.status });
    const bad3 = await authed('POST', '/ca/enroll', { name: `e2e-bad-${suffix}`, days: 0 });
    check('enroll rejects days=0 (400)', bad3.status === 400, { status: bad3.status });
    const dup = await authed('POST', '/ca/enroll', { name: nameDefault });
    check('duplicate enrollment name → 409', dup.status === 409, { status: dup.status });

    // ---------------------------------------------------------------------------
    // 5. Downloads (PEM + P12) of the default cert — verified with openssl
    // ---------------------------------------------------------------------------
    console.log('\n— Downloads —');
    const dl = await authed('GET', `/ca/wifi-certs/${serial1}/download`);
    check('PEM download returns 200', dl.status === 200, { status: dl.status });
    const pemText = await dl.text();
    const certCount = (pemText.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
    check('PEM bundle has leaf + intermediate', certCount === 2, { certCount });
    check('PEM bundle contains a PKCS#8 private key', pemText.includes('-----BEGIN PRIVATE KEY-----'));

    const dlP12 = await authed('GET', `/ca/wifi-certs/${serial1}/download?format=p12`);
    check('P12 download returns 200 JSON', dlP12.status === 200, { status: dlP12.status });
    const p12 = ((await dlP12.json()) as Record<string, unknown>) ?? {};
    check('P12 response shape (format/p12Base64/password)', p12.format === 'p12' && typeof p12.p12Base64 === 'string' && typeof p12.password === 'string' && (p12.password as string).length >= 8, { format: p12.format, pwLen: String(p12.password ?? '').length });

    if (HAS_OPENSSL && serial1) {
      fs.writeFileSync(path.join(workdir, 'root.pem'), rootBundlePem);
      const blocks = pemText.split(/(?=-----BEGIN)/).map((b) => b.trim()).filter(Boolean);
      const keyBlock = blocks.find((b) => b.includes('PRIVATE KEY')) ?? '';
      const certBlocks = blocks.filter((b) => b.includes('CERTIFICATE'));
      fs.writeFileSync(path.join(workdir, 'key.pem'), keyBlock + '\n');
      fs.writeFileSync(path.join(workdir, 'chain.pem'), certBlocks.map((b) => b + '\n').join(''));

      const p12Path = path.join(workdir, 'client.p12');
      fs.writeFileSync(p12Path, Buffer.from(String(p12.p12Base64), 'base64'));
      const pw = String(p12.password);

      // MAC check + bag listing. NOTE: openssl writes the "Certificate bag"
      // summary lines to STDERR — count the PEM blocks in stdout instead.
      const info = execFileSync('openssl', ['pkcs12', '-info', '-in', p12Path, '-passin', `pass:${pw}`, '-nokeys'], { encoding: 'utf8' });
      check('P12 opens with the returned password (MAC ok)', true);
      const bags = (info.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
      check('P12 contains leaf + intermediate bags', bags === 2, { bags });
      check('P12 leaf subject matches enrollment name', info.includes(`CN=${nameDefault}`), info.split('\n').filter((l) => l.startsWith('subject=')).join(' '));

      // The key inside the P12 is the SAME key as in the PEM bundle.
      const extractedKey = execFileSync('openssl', ['pkcs12', '-in', p12Path, '-passin', `pass:${pw}`, '-nocerts', '-nodes'], { encoding: 'utf8' });
      check('P12 contains a private key', extractedKey.includes('PRIVATE KEY'));
      check('P12 key SPKI == PEM bundle key SPKI', spkiOf(extractedKey) === spkiOf(keyBlock));

      // The full chain verifies against the root bundle.
      const verify = execFileSync('openssl', ['verify', '-CAfile', path.join(workdir, 'root.pem'), '-untrusted', path.join(workdir, 'chain.pem'), path.join(workdir, 'chain.pem')], { encoding: 'utf8' });
      check('PEM chain verifies against the root bundle', verify.includes(': OK'), verify);

      // A wrong password must be rejected (MAC).
      let wrongPwRejected = false;
      try {
        execFileSync('openssl', ['pkcs12', '-info', '-in', p12Path, '-passin', 'pass:definitely-wrong'], { stdio: 'ignore' });
      } catch {
        wrongPwRejected = true;
      }
      check('P12 rejects a wrong password (MAC)', wrongPwRejected);
    } else if (!HAS_OPENSSL) {
      console.log('  SKIP openssl-based P12 verification (openssl not installed on this host)');
    }

    // Bad format value → 400.
    const badFmt = await authed('GET', `/ca/wifi-certs/${serial1}/download?format=der`);
    check('unknown download format → 400', badFmt.status === 400, { status: badFmt.status });

    // ---------------------------------------------------------------------------
    // 6. Revocation (idempotent) + post-revoke behavior + DB mirror
    // ---------------------------------------------------------------------------
    console.log('\n— Revocation —');
    const rev1 = await authed('POST', `/ca/wifi-certs/${serial1}/revoke`);
    check('revoke returns 200 (CA accepted)', rev1.status === 200, { status: rev1.status, body: await rev1.text() });
    const rev2 = await authed('POST', `/ca/wifi-certs/${serial1}/revoke`);
    check('second revoke is idempotent (still 200)', rev2.status === 200, { status: rev2.status });

    const dlAfterPem = await authed('GET', `/ca/wifi-certs/${serial1}/download`);
    check('PEM download after revoke → 409', dlAfterPem.status === 409, { status: dlAfterPem.status });
    const dlAfterP12 = await authed('GET', `/ca/wifi-certs/${serial1}/download?format=p12`);
    check('P12 download after revoke → 409', dlAfterP12.status === 409, { status: dlAfterP12.status });

    const wifiRow = (await pool.query(`SELECT status, "revokedAt" FROM wifi_client_certs WHERE serial = $1`, [serial1])).rows[0] as { status: string; revokedAt: string | null } | undefined;
    check('DB: wifi_client_certs row is revoked', wifiRow?.status === 'revoked' && Boolean(wifiRow.revokedAt), wifiRow);
    const regRows = (await pool.query(`SELECT status, kind FROM ca_certificates WHERE serial = $1`, [serial1])).rows as Array<{ status: string; kind: string }>;
    check('DB: ca_certificates mirror row exists (kind=wifi) and is revoked', regRows.length > 0 && regRows.every((r) => r.kind === 'wifi' && r.status === 'revoked'), regRows);

    // The listing reflects the revocation.
    const list = await authed('GET', '/ca/wifi-certs');
    check('GET /ca/wifi-certs returns 200', list.status === 200, { status: list.status });
    const rows = (((await list.json()) as { certificates?: Array<Record<string, unknown>> }).certificates ?? []) as Array<Record<string, unknown>>;
    const listed = rows.find((r) => r.serial === serial1);
    check('listing shows the revoked cert with status=revoked', listed?.status === 'revoked' && Boolean(listed.revokedAt), listed);

    // ---------------------------------------------------------------------------
    // 7. Cleanup — remove this run's test rows (the CA keeps its own revocation)
    // ---------------------------------------------------------------------------
    console.log('\n— Cleanup —');
    if (serials.length > 0) {
      const delWifi = await pool.query(`DELETE FROM wifi_client_certs WHERE serial = ANY($1::text[])`, [serials]);
      const delReg = await pool.query(`DELETE FROM ca_certificates WHERE serial = ANY($1::text[]) AND kind = 'wifi'`, [serials]);
      check('test rows removed from both tables', (delWifi.rowCount ?? 0) >= 1 && (delReg.rowCount ?? 0) >= 1, { wifi: delWifi.rowCount, registry: delReg.rowCount });
    }
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
    await pool.end();
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error('E2E run crashed:', e);
  process.exit(1);
});
