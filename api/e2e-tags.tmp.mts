/**
 * E2E — documented hosts: tags + device placement inheritance + bulk site/layer.
 * Run from api/: npx tsx e2e-tags.tmp.mts   (against the live fleet on :3000)
 */
import jwt from 'jsonwebtoken';

const BASE = 'http://localhost:3000/v1';
const token = jwt.sign(
  { sub: 'admin', username: 'admin', roles: ['admin'], permissions: ['documented-hosts:read', 'documented-hosts:write', 'devices:read', 'devices:write'], amr: ['pwd', 'totp'] },
  'dev-secret'
);

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, detail?: unknown) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failed++; console.error(`  FAIL ${name}`, detail ?? ''); }
}

async function req(method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(BASE + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json: any = null;
  try { json = await res.json(); } catch { /* 204 etc. */ }
  return { status: res.status, json };
}

// --- fixtures (real fleet) ---------------------------------------------------
const KIRGUS_DEVICE_ID = 'd124978b-2c22-40b5-a17c-b35e7de9d937'; // registered device "KIRGUSBANDE"
const SITE_KIRGUS = '38f9cb89-e148-4ceb-a9f6-fcde1deaff16';      // HQ Kirgusbande
const SITE_RALF = '3cbae7f3-b4bd-4d0a-9183-da5a09fa388c';        // HQ Ralf

console.log('== 1. tags field present on documented hosts ==');
{
  const { status, json } = await req('GET', '/documented-hosts');
  check('list returns 200', status === 200);
  check('every row has a tags array', Array.isArray(json) && json.every((h: any) => Array.isArray(h.tags)), json?.[0]);
}

console.log('== 2. inventory import inherits device site/layer/tags (KIRGUSBANDE) ==');
{
  // Give the real KIRGUSBANDE device a temporary tag so inheritance is observable.
  const dev = await req('PATCH', `/devices/${KIRGUS_DEVICE_ID}`, { tags: ['e2etags'] });
  check('device tagged (setup)', dev.status === 200, dev.json);

  // Scope the import to ONLY KIRGUSBANDE's address (range filter) so the test
  // never touches any other documented host.
  const IMPORT_OPTS = { rangeMode: 'include-only', ranges: ['fdf8:f53b:85e4::60-fdf8:f53b:85e4::60'], maxAgeHours: 0 };

  // Dry-run first — the kirgusbande group must be planned as an update.
  const dry = await req('POST', '/documented-hosts/import-from-inventory', { ...IMPORT_OPTS, dryRun: true });
  check('dry-run 200', dry.status === 200, dry.json);
  const entry = (dry.json?.planned ?? []).find((p: any) => p.hostname?.toLowerCase() === 'kirgusbande');
  check('plan has kirgusbande entry', !!entry, dry.json?.planned?.slice(0, 5));
  check('kirgusbande planned as update (placement gap)', entry?.action === 'update', entry);

  // Apply.
  const apply = await req('POST', '/documented-hosts/import-from-inventory', { ...IMPORT_OPTS, dryRun: false });
  check('apply 200', apply.status === 200, apply.json);

  const list = (await req('GET', '/documented-hosts')).json;
  const row = list.find((h: any) => h.dnsNames?.includes('kirgusbande'));
  check('row exists after import', !!row);
  check('site inherited from device (HQ Kirgusbande)', row?.siteId === SITE_KIRGUS, row && { siteId: row.siteId, siteName: row.siteName });
  check('layer inherited from device (core override)', row?.layerId === 'core', row && { layerId: row.layerId, layerName: row.layerName });
  check('tags inherited from device (e2etags)', Array.isArray(row?.tags) && row.tags.includes('e2etags'), row?.tags);

  // Idempotency — a second apply must NOT lose the inherited placement.
  const apply2 = await req('POST', '/documented-hosts/import-from-inventory', { ...IMPORT_OPTS, dryRun: false });
  check('second apply 200', apply2.status === 200, apply2.json);
  const listAfter2 = (await req('GET', '/documented-hosts')).json;
  const row2 = listAfter2.find((h: any) => h.dnsNames?.includes('kirgusbande'));
  check('placement survives a second import', row2?.id === row.id && row2.siteId === SITE_KIRGUS && row2.layerId === 'core' && (row2.tags ?? []).includes('e2etags'), row2 && { id: row2.id, siteId: row2.siteId, layerId: row2.layerId, tags: row2.tags });

  // Remove the temporary tag from the device again.
  const untag = await req('PATCH', `/devices/${KIRGUS_DEVICE_ID}`, { tags: [] });
  check('device untagged (cleanup)', untag.status === 200, untag.json);
}

console.log('== 3. bulk site/layer placement ==');
{
  const mk = async (name: string, ip: string, tags: string[]) => {
    const r = await req('POST', '/documented-hosts', { dnsNames: [name], ips: [{ address: ip }], tags });
    check(`created ${name}`, r.status === 201, r.json);
    return r.json;
  };
  const a = await mk('e2e-bulk-a', '10.200.64.11', ['tagA']);
  const b = await mk('e2e-bulk-b', '10.200.64.12', []);

  const setRes = await req('POST', '/documented-hosts/bulk', { ids: [a.id, b.id], siteId: SITE_RALF, layerId: 'access' });
  check('bulk set 200', setRes.status === 200, setRes.json);
  check('bulk updated both', setRes.json?.updated === 2 && (setRes.json?.missing ?? []).length === 0, setRes.json);

  const list = (await req('GET', '/documented-hosts')).json;
  for (const id of [a.id, b.id]) {
    const row = list.find((h: any) => h.id === id);
    check(`${id.slice(0, 8)} got site HQ Ralf`, row?.siteId === SITE_RALF, row && { siteId: row.siteId });
    check(`${id.slice(0, 8)} got layer access`, row?.layerId === 'access', row && { layerId: row.layerId });
  }

  // Clear again.
  const clearRes = await req('POST', '/documented-hosts/bulk', { ids: [a.id, b.id], siteId: null, layerId: null });
  check('bulk clear 200', clearRes.status === 200, clearRes.json);
  const list2 = (await req('GET', '/documented-hosts')).json;
  for (const id of [a.id, b.id]) {
    const row = list2.find((h: any) => h.id === id);
    check(`${id.slice(0, 8)} placement cleared`, row?.siteId == null && row?.layerId == null, row && { siteId: row.siteId, layerId: row.layerId });
  }

  // Error cases.
  const badSite = await req('POST', '/documented-hosts/bulk', { ids: [a.id], siteId: 'no-such-site' });
  check('unknown siteId → 400', badSite.status === 400, badSite.json);
  const emptyIds = await req('POST', '/documented-hosts/bulk', { ids: [] });
  check('empty ids → 400', emptyIds.status === 400, emptyIds.json);

  // --- merge unions tags -----------------------------------------------------
  console.log('== 4. manual merge unions tags ==');
  const m = await req('POST', '/documented-hosts/merge', { ids: [a.id, b.id] });
  check('merge 200', m.status === 200, m.json);
  const mergedTags = m.json?.merged?.tags ?? [];
  check('merged tags are the union (tagA)', mergedTags.includes('tagA'), mergedTags);

  // Cleanup throwaway rows.
  for (const id of [m.json?.merged?.id]) {
    if (!id) continue;
    const del = await req('DELETE', `/documented-hosts/${id}`);
    check(`deleted ${String(id).slice(0, 8)} (cleanup)`, del.status === 204, del.status);
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
