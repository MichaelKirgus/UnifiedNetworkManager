/**
 * End-to-end verification for the Documented Networks feature (API + data model).
 *
 * Runs against the LIVE dev stack (setup.sh / docker compose up):
 *   1. logs in via the real auth flow (admin/admin, TOTP when enabled)
 *   2. CRUD: create → duplicate-name 409 → subnet-overlap 409 → patch → bulk
 *   3. CSV import endpoint: fresh rows + matched update + per-row error isolation
 *   4. Import from inventory: dry-run plan vs live /networks, apply is additive,
 *      second dry-run shows "already fully documented" skips (idempotency)
 *   5. Merge duplicates → oldest survives, unions deduped
 *   6. cleans up everything it created
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-documented-networks.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

interface DocNet {
  id: string; name: string; subnets: string[]; vlanId: number | null;
  gateways: string[]; dnsServers: string[]; ntpServers: string[]; friendlyName: string | null;
  description: string | null; siteId: string | null; layerId: string | null;
  tags: string[]; discovered: boolean; lastSeenAt: string | null;
  observedSubnets: string[]; observedVlanId: number | null; isActive: boolean;
  createdAt: string; updatedAt: string;
}

async function main(): Promise<void> {
  // 0. API up?
  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  // 1. Login (admin/admin; TOTP minted from the seeded secret when enabled).
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated (login flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  const createdIds: string[] = [];
  const cleanup = async (): Promise<void> => {
    for (const id of [...createdIds].reverse()) {
      await authed('DELETE', `/documented-networks/${id}`);
    }
  };

  // ---------------------------------------------------------------------------
  // 2. CRUD
  // ---------------------------------------------------------------------------
  console.log('\n— CRUD —');

  const createA = await authed('POST', '/documented-networks', {
    name: 'E2E Test LAN A',
    subnets: ['10.99.1.5/24'], // host bits must be canonicalized to 10.99.1.0/24
    vlanId: 99,
    gateways: ['10.99.1.1', 'fd00:e2e::1'],
    dnsServers: ['10.99.1.53'],
    ntpServers: ['10.99.1.54'],
    friendlyName: 'E2E A',
    description: 'created by e2e-documented-networks.ts',
    tags: ['e2e'],
  });
  const netA = (await createA.json()) as DocNet;
  check('create returns 201 + view', createA.status === 201 && Boolean(netA.id), { status: createA.status, body: await createA.json() });
  if (netA.id) createdIds.push(netA.id);
  check('subnet canonicalized (host bits cleared)', netA.subnets.includes('10.99.1.0/24'), netA.subnets);
  check('gateways/dnsServers/ntpServers round-trip', netA.gateways.length === 2 && netA.dnsServers[0] === '10.99.1.53' && netA.ntpServers[0] === '10.99.1.54');

  // Duplicate name (case-insensitive) → 409.
  const dupName = await authed('POST', '/documented-networks', { name: 'e2e test lan a' });
  check('duplicate name (different case) rejected with 409', dupName.status === 409, await dupName.json());

  // Subnet overlap under a different name → 409.
  const dupSub = await authed('POST', '/documented-networks', { name: 'E2E Overlap B', subnets: ['10.99.1.0/25'] });
  check('overlapping subnet range rejected with 409', dupSub.status === 409, await dupSub.json());

  // Invalid CIDR → 400.
  const badCidr = await authed('POST', '/documented-networks', { name: 'E2E Bad Cidr', subnets: ['10.99.2.0/33'] });
  check('invalid prefix rejected with 400', badCidr.status === 400, await badCidr.json());

  // Name-only row is valid (mirrors live VLAN-only groups).
  const createB = await authed('POST', '/documented-networks', { name: 'E2E Test LAN B' });
  const netB = (await createB.json()) as DocNet;
  check('name-only row accepted (empty subnets)', createB.status === 201 && netB.subnets.length === 0, await createB.json());
  if (netB.id) createdIds.push(netB.id);

  // PATCH — partial update + subnet replacement.
  const patchA = await authed('PATCH', `/documented-networks/${netA.id}`, { subnets: ['10.99.1.0/24', 'fd00:e2e::/64'], vlanId: null });
  const netAPatched = (await patchA.json()) as DocNet;
  check('patch replaces subnet list + clears VLAN', patchA.status === 200 && netAPatched.subnets.length === 2 && netAPatched.vlanId === null, await patchA.json());

  // PATCH — name clash with another row → 409.
  const patchClash = await authed('PATCH', `/documented-networks/${netB.id}`, { name: 'E2E Test LAN A' });
  check('patch to an existing name rejected with 409', patchClash.status === 409, await patchClash.json());

  // Bulk — mark stale + set site (null = clear).
  const sites = ((await authed('GET', '/sites').then((r) => r.json())) as Array<{ id: string; name: string }>) ?? [];
  const bulk1 = await authed('POST', '/documented-networks/bulk', { ids: [netA.id, netB.id], isActive: false });
  check('bulk mark stale updates both rows', (await bulk1.json() as { updated?: number }).updated === 2, await bulk1.json());
  const bulk2 = await authed('POST', '/documented-networks/bulk', { ids: [netA.id], isActive: true, siteId: sites[0]?.id ?? null });
  check('bulk mark active + set site', (await bulk2.json() as { updated?: number }).updated === 1, await bulk2.json());

  // ---------------------------------------------------------------------------
  // 3. CSV import endpoint
  // ---------------------------------------------------------------------------
  console.log('\n— CSV import —');

  const csvImport = await authed('POST', '/documented-networks/import', {
    networks: [
      { name: 'E2E Csv New', subnets: ['10.99.3.0/24'], gateways: ['10.99.3.1'] }, // create
      { name: 'e2e test lan a', subnets: ['10.99.1.0/24', 'fd00:e2e::/64'], tags: ['csv-tag'] }, // update (case-insensitive match)
      { name: 'E2E Csv Bad', subnets: ['not-a-cidr'] }, // invalid subnet — must not abort the batch (name-only rows ARE valid by design)
    ],
    matchBy: 'name',
    updateExisting: true,
  });
  const csvRes = (await csvImport.json()) as { created?: number; updated?: number; skipped?: number; errors?: { index: number; error: string }[] };
  check('csv import: 1 created + 1 updated + 1 row error', csvImport.status === 200 && csvRes.created === 1 && csvRes.updated === 1 && (csvRes.errors?.length ?? 0) === 1, csvRes);

  // The matched update must have merged tags additively and kept the id.
  const listAfterCsv = ((await authed('GET', '/documented-networks').then((r) => r.json())) as DocNet[]).filter((n) => n.name.toLowerCase() === 'e2e test lan a');
  check('csv update merged tags additively (kept id)', listAfterCsv.length === 1 && listAfterCsv[0].id === netA.id && listAfterCsv[0].tags.includes('e2e') && listAfterCsv[0].tags.includes('csv-tag'), listAfterCsv[0]?.tags);

  // updateExisting=false → matched rows skipped.
  const csvSkip = await authed('POST', '/documented-networks/import', {
    networks: [{ name: 'E2E Csv New' }],
    matchBy: 'name',
    updateExisting: false,
  });
  check('csv import with updateExisting=false skips matched rows', (await csvSkip.json() as { skipped?: number }).skipped === 1, await csvSkip.json());

  // ---------------------------------------------------------------------------
  // 4. Import from inventory (dry-run + apply + idempotency)
  // ---------------------------------------------------------------------------
  console.log('\n— Import from inventory —');

  const liveNetworks = ((await authed('GET', '/networks').then((r) => r.json())) as Array<{ name: string; subnets?: string[]; vlanId?: number | null }>) ?? [];
  check('live /networks has data to import from', liveNetworks.length > 0, `count=${liveNetworks.length}`);

  const dry1 = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: true });
  const plan1 = (await dry1.json()) as { totalLiveNetworks?: number; planned?: Array<{ name: string; action: string }>; created?: number; updated?: number; skipped?: number };
  check('dry-run returns a per-network plan', dry1.status === 200 && (plan1.planned?.length ?? 0) > 0, { status: dry1.status, total: plan1.totalLiveNetworks });

  // --- Filter checks on a CLEAN SLATE (before anything is documented) --------
  // The live fleet carries public WAN subnets + private LANs, so every filter below is observable.
  const isPublicV4Cidr = (cidr: string): boolean => {
    const net = cidr.split('/')[0];
    if (!net || net.includes(':')) return false;
    const o = net.split('.').map(Number);
    if (o.length !== 4) return false;
    if (o[0] >= 224) return false; // multicast + reserved space count as internal (SDK parity)
    if (o[0] === 10) return false;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
    if (o[0] === 192 && o[1] === 168) return false;
    if (o[0] === 127 || o[0] === 169) return false; // loopback / link-local
    return true;
  };

  // Public-IP policies (same scheme as the hosts import).
  const dryPub = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: true, publicIpv4Policy: 'skip-network' });
  const planPub = (await dryPub.json()) as { planned?: Array<{ name: string; action: string; reason?: string; subnets: string[] }> };
  const pubLeak = (planPub.planned ?? []).filter((p) => p.action !== 'skip').some((p) => p.subnets.some(isPublicV4Cidr));
  const pubAffected = (planPub.planned ?? []).some((p) => p.action === 'skip' && p.reason === 'public IPv4 subnet');
  check('public v4 skip-network policy skips the public WAN networks', !pubLeak && pubAffected, planPub);

  const dryStrip = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: true, publicIpv4Policy: 'strip' });
  const planStrip = (await dryStrip.json()) as { planned?: Array<{ name: string; action: string; subnets: string[]; stripped?: number }> };
  const stripLeaksPublic = (planStrip.planned ?? []).filter((p) => p.action !== 'skip').some((p) => p.subnets.some(isPublicV4Cidr));
  check('public v4 strip policy removes public subnets from every planned row', !stripLeaksPublic, planStrip);

  // Family filter — a v4-only run must never plan a network without any v4 subnet.
  const dryV4 = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: true, version: 'v4' });
  const planV4 = (await dryV4.json()) as { planned?: Array<{ action: string; subnets: string[] }> };
  const v4Leak = (planV4.planned ?? []).filter((p) => p.action !== 'skip').some((p) => !p.subnets.some((s) => s.includes('/') && !s.split('/')[0].includes(':')));
  check('family filter: no planned row without a v4 subnet', !v4Leak, planV4);

  // Range filter — exclude mode must skip the matching networks (CIDR-aware).
  const dryRange = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: true, rangeMode: 'exclude', ranges: ['10.25.0.0/16'] });
  const planRange = (await dryRange.json()) as { planned?: Array<{ action: string; reason?: string; subnets: string[] }> };
  const inExcluded = (cidr: string): boolean => {
    const sc = cidr.split('/');
    if (sc.length !== 2) return false;
    const a = sc[0].split('.').map(Number);
    return a.length === 4 && a[0] === 10 && a[1] === 25;
  };
  const rangeExcludedSeen = (planRange.planned ?? []).some((p) => p.action === 'skip' && p.reason === 'excluded range');
  const rangeLeak = (planRange.planned ?? []).filter((p) => p.action !== 'skip').some((p) => p.subnets.some(inExcluded));
  check('range filter: excluded networks skipped, none planned', rangeExcludedSeen && !rangeLeak, planRange);

  // Pre-document ONE live network with user data — the apply must merge additively.
  const target = (plan1.planned ?? []).find((p) => p.action === 'create' && p.name);
  let preDocId: string | null = null;
  if (target) {
    const pre = await authed('POST', '/documented-networks', { name: target.name, description: 'pre-existing user data — must survive the merge' });
    preDocId = ((await pre.json()) as DocNet).id ?? null;
    if (preDocId) createdIds.push(preDocId);
  }

  const apply1 = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: false });
  const applied = (await apply1.json()) as { created?: number; updated?: number; skipped?: number; affectedIds?: string[] };
  check('apply wrote rows (created+updated > 0)', apply1.status === 200 && ((applied.created ?? 0) + (applied.updated ?? 0)) > 0, applied);
  // Track every row the import touched so cleanup can delete them precisely.
  for (const id of applied.affectedIds ?? []) if (!createdIds.includes(id)) createdIds.push(id);

  // The pre-documented row kept its user data and gained the live subnets.
  if (preDocId && target) {
    const after = ((await authed('GET', '/documented-networks').then((r) => r.json())) as DocNet[]).find((n) => n.id === preDocId);
    check('additive merge kept user description + added live subnets', Boolean(after?.description?.includes('pre-existing')) && (after?.subnets.length ?? 0) > 0, after ? { desc: after.description, subnets: after.subnets } : 'row missing');
  }

  // Idempotency — a second dry-run must plan no changes for the imported rows.
  const dry2 = await authed('POST', '/documented-networks/import-from-inventory', { skipWithoutSubnet: true, maxAgeHours: 24, dryRun: true });
  const plan2 = (await dry2.json()) as { planned?: Array<{ name: string; action: string; reason?: string }>; created?: number; updated?: number };
  const pendingAfter = (plan2.planned ?? []).filter((p) => p.action !== 'skip');
  check('second dry-run is a no-op (all "already fully documented")', (plan2.created ?? 0) === 0 && (plan2.updated ?? 0) === 0, { created: plan2.created, updated: plan2.updated, pendingAfter });

  // ---------------------------------------------------------------------------
  // 5. Merge duplicates
  // ---------------------------------------------------------------------------
  console.log('\n— Merge —');

  // Create rejects overlapping subnets, so the fixtures start disjoint — then a
  // CSV import re-points Y into X's range (the update path CAN produce overlap).
  const m1 = await authed('POST', '/documented-networks', { name: 'E2E Merge X', subnets: ['10.99.7.0/24'], gateways: ['10.99.7.1'] });
  const mergeX = (await m1.json()) as DocNet;
  check('merge fixture X created', m1.status === 201, await m1.json());
  if (mergeX.id) createdIds.push(mergeX.id);
  await new Promise((r) => setTimeout(r, 5)); // distinct createdAt for "oldest survives"
  const m2 = await authed('POST', '/documented-networks', { name: 'E2E Merge Y', subnets: ['10.99.8.0/24'], dnsServers: ['10.99.7.53'], ntpServers: ['10.99.7.54'] });
  const mergeY = (await m2.json()) as DocNet;
  check('merge fixture Y created', m2.status === 201, await m2.json());
  if (mergeY.id) createdIds.push(mergeY.id);

  // CSV import replaces fields wholesale on update (hosts semantics) — carry the
  // DNS + NTP servers forward so they survive and are exercised by the merge union below.
  const repoint = await authed('POST', '/documented-networks/import', { networks: [{ name: 'E2E Merge Y', subnets: ['10.99.7.128/25'], dnsServers: ['10.99.7.53'], ntpServers: ['10.99.7.54'] }], matchBy: 'name' });
  check("csv import re-pointed Y into X's range (overlap now exists)", (await repoint.json() as { updated?: number }).updated === 1, await repoint.json());

  const mergeRes = await authed('POST', '/documented-networks/merge', { ids: [mergeX.id, mergeY.id] });
  const merged = (await mergeRes.json()) as { merged?: DocNet; removed?: string[]; count?: number };
  check('merge returns the surviving row + removed ids', mergeRes.status === 200 && merged.count === 2 && merged.removed?.length === 1, await mergeRes.json());
  check('merged row unions subnets/gateways/dns/ntp deduped', Boolean(merged.merged) && merged.merged.subnets.length === 2 && merged.merged.gateways.length === 1 && merged.merged.dnsServers.length === 1 && merged.merged.ntpServers.length === 1, merged.merged ? { s: merged.merged.subnets, g: merged.merged.gateways, d: merged.merged.dnsServers, n: merged.merged.ntpServers } : 'missing');
  if (merged.merged?.id) createdIds.push(merged.merged.id);

  // ---------------------------------------------------------------------------
  // 6. Cleanup — delete every row this script created (imported rows included).
  // ---------------------------------------------------------------------------
  console.log('\n— Cleanup —');
  const all = ((await authed('GET', '/documented-networks').then((r) => r.json())) as DocNet[]);
  const e2eRows = all.filter((n) => n.name.startsWith('E2E ') || n.description?.includes('created by e2e-documented-networks.ts'));
  // Also delete the inventory-imported rows (they carry no E2E marker — match by
  // name against the live network names imported above).
  const importedNames = new Set((plan1.planned ?? []).map((p) => p.name));
  for (const n of all) {
    // E2E-prefixed rows + inventory-imported rows are deleted too — the CSV
    // import created some without tracking their ids.
    if (!createdIds.includes(n.id) && (e2eRows.some((x) => x.id === n.id) || importedNames.has(n.name))) createdIds.push(n.id);
  }
  let deleted = 0;
  for (const id of [...new Set(createdIds)].reverse()) {
    const r = await authed('DELETE', `/documented-networks/${id}`);
    if (r.status === 204) deleted++;
  }
  check(`cleanup deleted ${deleted} row(s)`, deleted > 0, `deleted=${deleted}, total=${new Set(createdIds).size}`);

  const remaining = ((await authed('GET', '/documented-networks').then((r) => r.json())) as DocNet[]).filter((n) => n.name.startsWith('E2E '));
  check('no E2E rows remain', remaining.length === 0, remaining.map((n) => n.name));

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
