/* E2E check for the session-credential feature (run from repo root). */
const BASE = 'http://localhost:3000/v1';
const TOKEN = process.env.TOKEN;
const DEV = process.argv[2];

async function call(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* no body */ }
  return { status: res.status, data };
}

(async () => {
  // Find the two E2E secrets created by the earlier step.
  const list = (await call('GET', '/secrets')).data;
  const e2e = list.filter((s) => s.label && String(s.label).startsWith('E2E-'));
  console.log('--- flagged E2E secrets in list:');
  for (const s of e2e) console.log(`  ${s.label} [${s.type}] login=${!!s.interactiveLoginAllowed} file=${!!s.fileAccessAllowed}`);

  const S1 = e2e.find((s) => s.label === 'E2E-SSH-A')?.id;
  const S2 = e2e.find((s) => s.label === 'E2E-SSH-B')?.id;
  if (!S1 || !S2) { console.log('missing test secrets — abort'); process.exit(1); }

  // Options with exactly one eligible (B is login-only, A is both): purpose=console has BOTH.
  const opts = await call('GET', `/devices/${DEV}/session-credentials?purpose=console`);
  console.log('--- options(console):', JSON.stringify(opts.data));

  // Auto-use: no stored pref + >1 candidate => should be 409 selection_required.
  let r = await call('POST', `/devices/${DEV}/console`, {});
  console.log(`--- mint auto (expect 409 prompt): HTTP ${r.status} code=${r.data?.code}`);

  // Store a preference (S1 first) => auto-use should now succeed.
  r = await call('PUT', `/devices/${DEV}/session-credentials`, { purpose: 'console', secretIds: [S1, S2] });
  console.log(`--- store pref: HTTP ${r.status} ids=${JSON.stringify(r.data?.secretIds)}`);

  r = await call('POST', `/devices/${DEV}/console`, {});
  console.log(`--- mint auto with default (expect 201): HTTP ${r.status}`);

  // Explicit pick of S2.
  r = await call('POST', `/devices/${DEV}/console`, { secretId: S2 });
  console.log(`--- mint explicit S2 (expect 201): HTTP ${r.status}`);

  // Bad pick.
  r = await call('POST', `/devices/${DEV}/console`, { secretId: 'nope' });
  console.log(`--- mint bad id (expect 403): HTTP ${r.status}`);

  // Filesystem purpose: only A is file-eligible => single candidate auto-use.
  r = await call('GET', `/devices/${DEV}/session-credentials?purpose=filesystem`);
  console.log('--- options(filesystem):', JSON.stringify(r.data));

  // Cleanup test secrets + preference row.
  for (const id of [S1, S2]) {
    const d = await call('DELETE', `/secrets/${id}`);
    console.log(`--- delete ${id.slice(0, 8)}: HTTP ${d.status}`);
  }
  // Clear the stored preference by storing an empty list.
  r = await call('PUT', `/devices/${DEV}/session-credentials`, { purpose: 'console', secretIds: [] });
  console.log(`--- clear pref: HTTP ${r.status} ids=${JSON.stringify(r.data?.secretIds)}`);
})().catch((e) => { console.error(e); process.exit(1); });
