/* Temporary E2E for the reworked first-run onboarding flow. Simulates a FRESH
 * initial admin (no TOTP secret + requiredMethods [] override) using a throwaway
 * user, then walks: password-only login -> completeLogin -> enroll TOTP ->
 * confirm code -> verify 2FA is now enforced. Cleans up after itself. */
const path = require('node:path');
const { createRequire } = require('node:module');

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg');
const { authenticator } = apiRequire('otplib');
const bcrypt = apiRequire('bcryptjs');

const BASE = 'http://localhost:3000/v1';
const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log('  PASS', name); }
  else { fail++; console.log('  FAIL', name); }
}

async function j(method, urlPath, body, token) {
  const res = await fetch(BASE + urlPath, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data; try { data = await res.json(); } catch { data = null; }
  return { status: res.status, data };
}

// Generate a TOTP code that is CURRENTLY valid (avoids the ±1-step boundary
// flake when a test runs right on a 30s window edge).
async function freshValidCode(secret) {
  for (let i = 0; i < 8; i++) {
    const c = authenticator.generate(secret);
    if (authenticator.verify({ token: c, secret })) return c;
    await new Promise((r) => setTimeout(r, 750));
  }
  throw new Error('could not produce a valid TOTP code');
}

(async () => {
  const username = 'onb' + Date.now().toString(36);
  const otherUsername = 'onbother' + Date.now().toString(36);
  const uid = crypto.randomUUID ? crypto.randomUUID() : require('crypto').randomUUID();
  const otherUid = crypto.randomUUID ? crypto.randomUUID() : require('crypto').randomUUID();
  const now = new Date().toISOString();

  // Simulate a FRESH initial admin: no TOTP secret, requiredMethods [] override.
  await pool.query(
    `INSERT INTO users (id, username, "passwordHash", roles, permissions, "createdAt")
     VALUES ($1,$2,$3,'["admin"]','[]',$4)`,
    [uid, username, bcrypt.hashSync('admin', 10), now]
  );
  await pool.query(
    `INSERT INTO credential_policies (id,"userId","requiredMethods","gateAmrs","updatedAt")
     VALUES ($1,$2,'[]','[]',$3)`,
    [crypto.randomUUID(), uid, now]
  );

  try {
    // 1. Login -> password-only (twoFactorRequired false).
    const login = await j('POST', '/auth/login', { username, password: 'admin' });
    check('login 200', login.status === 200);
    check('twoFactorRequired=false (no 2FA enrolled)', login.data?.twoFactorRequired === false);

    // 2. Password-only completion -> session minted (amr pwd).
    const complete = await j('POST', '/auth/login/complete', { challengeToken: login.data.challengeToken });
    check('login/complete 200', complete.status === 200);
    check('got accessToken', typeof complete.data?.accessToken === 'string');
    const token = complete.data.accessToken;

    // 3. Enroll TOTP (self) -> fresh secret + otpauth URI.
    const enroll = await j('POST', `/users/${uid}/totp/enroll`, {}, token);
    check('enrollTotp 200', enroll.status === 200);
    const secret = enroll.data?.enrollment?.secret;
    check('got TOTP secret', typeof secret === 'string' && secret.length > 8);

    // 4. Confirm a VALID code -> valid true.
    const goodCode = await freshValidCode(secret);
    const confirmOk = await j('POST', `/users/${uid}/totp/confirm`, { code: goodCode }, token);
    check('confirm valid code -> valid:true', confirmOk.status === 200 && confirmOk.data?.valid === true);

    // 5. Confirm a WRONG code -> valid false (not an error).
    const badCode = '000000' === goodCode ? '111111' : '000000';
    const confirmBad = await j('POST', `/users/${uid}/totp/confirm`, { code: badCode }, token);
    check('confirm wrong code -> valid:false', confirmBad.status === 200 && confirmBad.data?.valid === false);

    // 6. Now that a TOTP secret exists, login must demand 2FA again.
    const login2 = await j('POST', '/auth/login', { username, password: 'admin' });
    check('re-login twoFactorRequired=true (TOTP now enrolled)', login2.status === 200 && login2.data?.twoFactorRequired === true);

    // 7. Password-only completion must be REFUSED once a factor is enrolled.
    const completeRefused = await j('POST', '/auth/login/complete', { challengeToken: login2.data.challengeToken });
    check('login/complete refused (403 two_factor_required)', completeRefused.status === 403 && completeRefused.data?.code === 'two_factor_required');

    // 8. Normal TOTP step still works with the enrolled secret (fresh challenge —
    //    the previous one was consumed by the refusal above).
    const login3 = await j('POST', '/auth/login', { username, password: 'admin' });
    const verify = await j('POST', '/auth/2fa/verify', { challengeToken: login3.data.challengeToken, totpCode: await freshValidCode(secret) });
    check('2fa/verify with valid code -> 200', verify.status === 200 && typeof verify.data?.accessToken === 'string');

    // 9. Self-only guard: a DIFFERENT user cannot confirm this one's TOTP.
    await pool.query(`INSERT INTO users (id, username, "passwordHash", roles, permissions, "createdAt") VALUES ($1,$2,$3,'["admin"]','[]',$4)`, [otherUid, otherUsername, bcrypt.hashSync('x', 10), now]);
    // Mint a token for the "other" user directly to test the self-only guard.
    const jwt = apiRequire('jsonwebtoken');
    const otherToken = jwt.sign({ sub: otherUid, username: 'onbother', roles: ['admin'], permissions: ['users:self-credentials'], amr: ['pwd'] }, 'dev-secret', { expiresIn: 5 * 60 });
    const crossConfirm = await j('POST', `/users/${uid}/totp/confirm`, { code: goodCode }, otherToken);
    check('cross-user confirm -> 403 (self-only)', crossConfirm.status === 403);

    console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
    process.exitCode = fail > 0 ? 1 : 0;
  } finally {
    await pool.query('DELETE FROM credential_policies WHERE "userId" IN ($1,$2)', [uid, otherUid]);
    await pool.query('DELETE FROM users WHERE id IN ($1,$2)', [uid, otherUid]);
    console.log('cleanup done');
  }
})().catch((e) => { console.error(e); process.exit(2); });
