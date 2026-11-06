/**
 * End-to-end verification for the CA + WiFi (EAP-TLS) client certificates.
 *
 * Validates against the deployed stack (API on :3000, unm-ca running):
 *   1. CA status sanity — version, root fingerprint, root/intermediate expiry
 *      in the future; root bundle is a parseable PEM certificate.
 *   2. Enrollment defaults — no `days` → configured default (3y), response
 *      shape (serial hex, notBefore/notAfter sane). Enrolled through a SYSTEM
 *      plan (ca.client-cert.enroll) executed via the 2FA-gated workflow; the new
 *      serial is read from the step result.
 *   3. Enrollment overrides — custom name/cn/org/ou/sans + RSA-2048 key type;
 *      the issued PEM really contains an RSA private key of that size.
 *   4. Validation errors — bad names / unknown keyType / days < 1 → the plan
 *      FAILS with a validation error in the step result; duplicate enrollment
 *      name → the plan fails with "already exists". (There is no direct enroll
 *      route anymore — every mutation is plan-gated.)
 *   5. Downloads — PEM bundle (chain + PKCS#8 key), P12 bundle (base64 +
 *      password) verified with an INDEPENDENT openssl invocation: MAC check,
 *      leaf+intermediate bags, extracted key SPKI == stored key SPKI, and the
 *      full chain verifies against the root bundle.
 *   6. Revocation — idempotent (second plan reports alreadyRevoked), both
 *      download formats then answer 409, DB rows mirrored (wifi_client_certs +
 *      ca_certificates). Revoked through a SYSTEM plan (ca.client-cert.revoke).
 *   6b. Templates — CRUD of the reusable enrollment presets (plain routes, NOT
 *      plan-gated: create/list/duplicate-409/bad-keyType-400/patch/delete) plus
 *      enrolling with a template's values through the plan workflow.
 *   7. Cleanup — test cert rows AND the system plans created by this run are
 *      removed again (revoked leaves stay in the CA's own DB; that is expected
 *      and harmless).
 *
 * AUTH: enrollment/revocation are 2FA-gated, so a long-lived API token (amr
 * ['token']) can never pass. This script mints a short-lived JWT for admin with
 * amr:['totp'] + the needed permissions, signed with the stack's JWT_SECRET —
 * exactly what /auth/2fa/verify would mint after a real TOTP challenge. It does
 * NOT verify an actual code; require2FA only checks that the session's `amr`
 * intersects the user's gateAmrs (default ['totp']).
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
// pg + jsonwebtoken live in the API package's node_modules — resolve them there.
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

/** Read a value from the repo .env (falls back to process.env). */
function envValue(key: string): string | null {
  if (process.env[key]) return process.env[key];
  try {
    const m = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8').match(new RegExp(`^${key}=(.+)$`, 'm'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

/** Mint a short-lived admin JWT with amr:['totp'] so it passes require2FA. */
async function mintAdminJwt(pool: import('pg').Pool): Promise<string> {
  const jwt = apiRequire('jsonwebtoken');
  const secret = envValue('JWT_SECRET') ?? 'dev-secret';
  const row = (await pool.query(`SELECT id FROM users WHERE username = 'admin'`)).rows[0] as { id: string } | undefined;
  if (!row) throw new Error('no admin user found — cannot mint a 2FA session');
  return jwt.sign(
    {
      sub: row.id,
      username: 'admin',
      roles: [],
      // The plan workflow needs configs:apply + plans:read; CA reads need ca:read,
      // the CA mutations need ca:manage.
      permissions: ['configs:apply', 'plans:read', 'ca:read', 'ca:manage', 'radius:write'],
      amr: ['totp'],
    },
    secret,
    { expiresIn: '1h' } as jwt.SignOptions,
  );
}

interface PlanStepView {
  status: string;
  /** Stored as { success, result: { verified, ...details } | { error } }. */
  result?: Record<string, unknown> | null;
}

/** Unwraps the executor's nested step-result envelope to the inner details. */
function stepResultOf(step: PlanStepView): Record<string, unknown> {
  const r = (step.result ?? {}) as Record<string, unknown>;
  return (r.result && typeof r.result === 'object' ? (r.result as Record<string, unknown>) : r) as Record<string, unknown>;
}
interface PlanView {
  id: string;
  status: string;
  error?: string | null;
  steps: PlanStepView[];
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Auth -------------------------------------------------------------------
  // Enrollment/revocation are 2FA-gated → mint a TOTP-AMR admin JWT (see header).
  const token = await mintAdminJwt(pool);
  check('minted a 2FA-capable admin session', Boolean(token));

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; text: () => Promise<string>; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, text: async () => (await res.text()), json: async () => (await res.json().catch(() => null)) as never };
  };

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-e2e-ca-wifi-'));
  const serials: string[] = []; // collected for cleanup
  const planIds: string[] = []; // system plans created by this run — deleted in cleanup

  /** Create a SYSTEM plan, execute it (2FA-gated), and poll to a terminal status. */
  async function runSystemPlan(intentActionId: string, input: Record<string, unknown>): Promise<PlanView> {
    const create = await authed('POST', '/plans/system', { intentActionId, inputs: input });
    if (create.status !== 201) throw new Error(`plan creation failed (${create.status}): ${await create.text()}`);
    const created = ((await create.json()) as PlanView);
    planIds.push(created.id);

    const exec = await authed('POST', `/plans/${created.id}/execute`);
    if (exec.status !== 202) throw new Error(`plan execution rejected (${exec.status}): ${await exec.text()}`);

    // The executor runs on a ~5s tick — poll until the plan reaches a terminal state.
    const startedAt = Date.now();
    for (;;) {
      const g = await authed('GET', `/plans/${created.id}`);
      const plan = ((await g.json()) as PlanView);
      if (['succeeded', 'unverified', 'failed', 'cancelled', 'skipped'].includes(plan.status)) return plan;
      if (Date.now() - startedAt > 120_000) throw new Error(`plan ${created.id} did not finish in time (status=${plan.status})`);
      await new Promise((r) => setTimeout(r, 750));
    }
  }

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
    // 2. Enrollment with defaults (via a system plan)
    // ---------------------------------------------------------------------------
    console.log('\n— Enrollment (defaults, via system plan) —');
    const suffix = Date.now().toString(36);
    const nameDefault = `e2e-ca-wifi-${suffix}`;
    const p1 = await runSystemPlan('ca.client-cert.enroll', { name: nameDefault });
    check('enroll (defaults) plan succeeded', p1.status === 'succeeded' || p1.status === 'unverified', { status: p1.status, error: p1.error });
    const r1 = stepResultOf(p1.steps[0] ?? { status: '', result: null });
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
    // 3. Enrollment with overrides (RSA-2048 + custom RDNs/SANs), via a system plan
    // ---------------------------------------------------------------------------
    console.log('\n— Enrollment (overrides: RSA-2048, org/ou/sans) —');
    const nameRsa = `e2e-ca-wifi-rsa-${suffix}`;
    const p2 = await runSystemPlan('ca.client-cert.enroll', {
      name: nameRsa, cn: 'e2e-rsa-client', organization: 'E2E Org', organizationalUnit: 'NetOps',
      sans: ['e2e-rsa-1.lan', 'e2e-rsa-2.lan'], keyType: 'rsa-2048', days: 365,
    });
    check('enroll (RSA overrides) plan succeeded', p2.status === 'succeeded' || p2.status === 'unverified', { status: p2.status, error: p2.error });
    const r2 = stepResultOf(p2.steps[0] ?? { status: '', result: null });
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
    // 4. Validation errors + duplicate name — now surfaced as FAILED plans
    // ---------------------------------------------------------------------------
    console.log('\n— Validation (plan failures) —');
    const bad1 = await runSystemPlan('ca.client-cert.enroll', { name: 'bad name with spaces' });
    check('enroll rejects a bad name (plan failed)', bad1.status === 'failed', { status: bad1.status, error: String(stepResultOf(bad1.steps[0] ?? { status: '', result: null }).error ?? '') });
    const bad2 = await runSystemPlan('ca.client-cert.enroll', { name: `e2e-bad-${suffix}`, keyType: 'ml-dsa-65' });
    check('enroll rejects an unknown keyType (plan failed)', bad2.status === 'failed' && /keyType/.test(String(stepResultOf(bad2.steps[0] ?? { status: '', result: null }).error ?? '')), { status: bad2.status, error: String(stepResultOf(bad2.steps[0] ?? { status: '', result: null }).error ?? '') });
    const bad3 = await runSystemPlan('ca.client-cert.enroll', { name: `e2e-bad-${suffix}`, days: 0 });
    check('enroll rejects days=0 (plan failed)', bad3.status === 'failed' && /days/.test(String(stepResultOf(bad3.steps[0] ?? { status: '', result: null }).error ?? '')), { status: bad3.status, error: String(stepResultOf(bad3.steps[0] ?? { status: '', result: null }).error ?? '') });
    const dup = await runSystemPlan('ca.client-cert.enroll', { name: nameDefault });
    check('duplicate enrollment name → plan failed (already exists)', dup.status === 'failed' && /already exists/.test(String(stepResultOf(dup.steps[0] ?? { status: '', result: null }).error ?? '')), { status: dup.status, error: String(stepResultOf(dup.steps[0] ?? { status: '', result: null }).error ?? '') });

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
    // 6. Revocation (idempotent) via a system plan + post-revoke behavior + DB mirror
    // ---------------------------------------------------------------------------
    console.log('\n— Revocation (via system plan) —');
    const rev1 = await runSystemPlan('ca.client-cert.revoke', { serial: serial1 });
    check('revoke plan succeeded', rev1.status === 'succeeded' || rev1.status === 'unverified', { status: rev1.status, error: rev1.error });
    const rr1 = stepResultOf(rev1.steps[0] ?? { status: '', result: null });
    check('first revoke reports alreadyRevoked=false + CA 2xx', rr1.alreadyRevoked === false && typeof rr1.caStatus === 'number' && Number(rr1.caStatus) < 300, rr1);

    const rev2 = await runSystemPlan('ca.client-cert.revoke', { serial: serial1 });
    check('second revoke is idempotent (plan succeeded)', rev2.status === 'succeeded' || rev2.status === 'unverified', { status: rev2.status, error: rev2.error });
    const rr2 = stepResultOf(rev2.steps[0] ?? { status: '', result: null });
    check('idempotent revoke reports alreadyRevoked=true', rr2.alreadyRevoked === true, rr2);

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
    // 6b. Client-cert templates (pure metadata CRUD, NOT plan-gated) + using one
    // ---------------------------------------------------------------------------
    console.log('\n— Templates (CRUD + enroll with template values) —');
    const tplName = `e2e-tpl-${suffix}`;
    const tplCreate = await authed('POST', '/ca/client-cert-templates', {
      name: tplName, organization: 'Tpl Org', organizationalUnit: 'Tpl OU',
      sans: ['tpl-a.lan'], keyType: 'ec-p384', days: 120,
    });
    const tpl = ((await tplCreate.json()) as Record<string, unknown>) ?? {}; // single read — the body stream is consumed once
    check('template create → 201 with full shape', tplCreate.status === 201 && typeof tpl.id === 'string' && Array.isArray(tpl.sans), { status: tplCreate.status });
    const tplId = String(tpl.id ?? '');

    const tplList = await authed('GET', '/ca/client-cert-templates');
    const tplListBody = ((await tplList.json()) as { templates?: unknown[] }) ?? {}; // single read
    check('template list → 200 {templates:[…]} incl. the new one', tplList.status === 200 && (tplListBody.templates ?? []).some((t) => (t as Record<string, unknown>).id === tplId), { status: tplList.status });

    const tplDup = await authed('POST', '/ca/client-cert-templates', { name: tplName });
    check('duplicate template name → 409', tplDup.status === 409, { status: tplDup.status });

    const tplBad = await authed('POST', '/ca/client-cert-templates', { name: `e2e-tpl-bad-${suffix}`, keyType: 'ml-dsa' });
    check('bad template keyType → 400', tplBad.status === 400, { status: tplBad.status });

    const tplPatch = await authed('PATCH', `/ca/client-cert-templates/${tplId}`, { days: null, organizationalUnit: 'Tpl OU v2' });
    const patched = ((await tplPatch.json()) as Record<string, unknown>) ?? {};
    check('template patch (partial) → 200 with updated fields', tplPatch.status === 200 && patched.organizationalUnit === 'Tpl OU v2' && patched.days === null, { status: tplPatch.status });

    // USING a template = enrolling with its values through the plan-gated workflow.
    const nameTpl = `e2e-ca-wifi-tpl-${suffix}`;
    const pTpl = await runSystemPlan('ca.client-cert.enroll', {
      name: nameTpl, organization: 'Tpl Org', organizationalUnit: 'Tpl OU v2',
      sans: ['tpl-a.lan'], keyType: 'ec-p384', days: 120,
    });
    check('enroll with template values (via plan) succeeded', pTpl.status === 'succeeded' || pTpl.status === 'unverified', { status: pTpl.status, error: pTpl.error });
    const rTpl = stepResultOf(pTpl.steps[0] ?? { status: '', result: null });
    if (rTpl.serial) serials.push(String(rTpl.serial));

    // Template delete → 204; deleting again → 404.
    const tplDel = await authed('DELETE', `/ca/client-cert-templates/${tplId}`);
    check('template delete → 204', tplDel.status === 204, { status: tplDel.status });
    const tplDelAgain = await authed('DELETE', `/ca/client-cert-templates/${tplId}`);
    check('second template delete → 404', tplDelAgain.status === 404, { status: tplDelAgain.status });

    // ---------------------------------------------------------------------------
    // 7. Cleanup — remove this run's test cert rows AND system plans
    // ---------------------------------------------------------------------------
    console.log('\n— Cleanup —');
    if (serials.length > 0) {
      const delWifi = await pool.query(`DELETE FROM wifi_client_certs WHERE serial = ANY($1::text[])`, [serials]);
      const delReg = await pool.query(`DELETE FROM ca_certificates WHERE serial = ANY($1::text[]) AND kind = 'wifi'`, [serials]);
      check('test cert rows removed from both tables', (delWifi.rowCount ?? 0) >= 1 && (delReg.rowCount ?? 0) >= 1, { wifi: delWifi.rowCount, registry: delReg.rowCount });
    }
    let plansDeleted = 0;
    for (const pid of planIds) {
      const d = await authed('DELETE', `/plans/${pid}`);
      if (d.status === 204 || d.status === 404) plansDeleted++; // 404 = already gone
    }
    check(`system plans removed (${planIds.length} created)`, planIds.length === 0 || plansDeleted === planIds.length, { deleted: plansDeleted, total: planIds.length });
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
