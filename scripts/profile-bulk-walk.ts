/**
 * Bulk-walk profiler (Round 2 — read-only, GETs only).
 *
 * Measures the REAL cost of the inventory walk patterns used by lancom-lcos /
 * lancom-sx on live devices: per-subtree wall time, PDU counts (via a
 * session.send wrapper), and total pattern wall time for candidate strategies:
 *   A) current LCOS pattern — fresh session per walk, batches of 4 + 750ms settle
 *   B) single shared session, sequential walks
 *   C) shared session with higher maxRepetitions (100 / 200)
 *   D) multi-subtree combined GetBulk loop (N cursors in one PDU stream)
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/profile-bulk-walk.ts [lcos|sx]
 */
import { createRequire } from 'node:module';

const lcosRequire = createRequire(__dirname + '/../plugins/lancom-lcos/package.json');
const snmpClient = lcosRequire('@unm/snmp-client') as typeof import('../packages/snmp-client/src/index');
// net-snmp resolves through the plugin's node_modules (same copy the plugin runs).
const snmp: any = lcosRequire('net-snmp');

const SECRETS_API = process.env.SECRETS_API ?? 'http://localhost:4003';
const PLUGIN_KEY = process.env.PLUGIN_API_KEY ?? 'dev-plugin-key';

// --- targets (from the live DB) ---------------------------------------------
const LCOS_TARGET = { host: '10.28.0.1', name: 'GW_Ralf', secretId: '11cfb7c0-2183-4468-a804-1ce1d616bd08' };
const SX_TARGET = { host: '10.28.10.1', name: 'Switch01', secretId: '11cfb7c0-2183-4468-a804-1ce1d616bd08' };

const OIDS = lcosRequire('./dist/src/lcosOids.js');
const sxRequire = createRequire(__dirname + '/../plugins/lancom-sx/package.json');
const SX_OIDS = sxRequire('./dist/src/sxOids.js');

// LCOS inventory walks — same list as plugins/lancom-lcos/src/lcosClient.ts INVENTORY_WALKS.
const LCOS_WALKS: string[] = [
  `${OIDS.LCOS_BASE}.2.1`,
  OIDS.HW.base,
  OIDS.FIRMWARE.versionTableBase,
  OIDS.LAN_IF.base,
  OIDS.WAN_IP.base,
  OIDS.NET_LIST.base,
  OIDS.ARP.base,
  OIDS.DHCP.base,
  OIDS.IP_ROUTES.base,
  OIDS.IP_CIDR_ROUTES.base,
  OIDS.VPN_CONN.base,
  OIDS.WLAN_NET.base,
  OIDS.WLAN_RADIO.base,
  OIDS.WLAN_STATION.base,
  OIDS.TEMP_EXTREMES.base,
];

// Set during main()'s detection step; consumed by patternMultiSx.
let variant: 'sx4' | 'sx3' = 'sx4';

// Inventory walks per variant — same lists as sxClient.ts inventoryWalks().
const SX_WALKS_SX4: string[] = [
  SX_OIDS.SX4_SYS.base,
  SX_OIDS.SX4_PSU.base,
  SX_OIDS.SX4_PORT_CONF.base,
  SX_OIDS.SX4_VLAN.base,
  SX_OIDS.SX4_SVI.base,
  SX_OIDS.SX4_IP_STATUS_ROUTES.base,
  SX_OIDS.SX4_IP_ROUTES.base,
  SX_OIDS.SX4_NEIGHBOR.base,
  SX_OIDS.SX4_POE_STATUS.base,
  SX_OIDS.SX4_POE_TOTALS.base,
  SX_OIDS.SX4_LACP_STATUS.base,
];
const SX_WALKS_SX3: string[] = [
  SX_OIDS.SX3_SYS.base,
  SX_OIDS.SX3_PORT_CONF.base,
];

const OPTS = { timeoutMs: 5_000, retries: 2 }; // plugin defaults

// --- helpers ------------------------------------------------------------------
async function fetchCreds(secretId: string): Promise<any> {
  const r = await fetch(`${SECRETS_API}/secrets/${secretId}`, { headers: { 'x-plugin-api-key': PLUGIN_KEY } });
  if (!r.ok) throw new Error(`secrets API ${r.status}`);
  const body = (await r.json()) as { type: string; fields: Record<string, unknown> };
  const built = snmpClient.buildSnmpCredentials(body.fields);
  if (!built.creds) throw new Error(built.error ?? 'credential build failed');
  return built.creds;
}

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

interface WalkStats {
  oid: string;
  varbinds: number;
  pdus: number;
  ms: number;
  error?: string;
}

/** Instrumented single-subtree walk on a given session (mirrors snmp-client's walkSubtree). */
function instrumentedWalk(
  session: any,
  baseOid: string,
  maxRepetitions: number,
  budgetMs = 9_500
): Promise<{ varbinds: Map<string, unknown>; pdus: number; ms: number }> {
  return new Promise((resolve, reject) => {
    const out = new Map<string, unknown>();
    let pdus = 0;
    const t0 = Date.now();
    const timer = setTimeout(() => reject(new Error(`timed out after ${budgetMs}ms`)), budgetMs);
    session.subtree(
      baseOid.replace(/^\./, ''),
      maxRepetitions,
      (varbinds: any[]) => {
        pdus++;
        for (const vb of varbinds) if (!snmp.isVarbindError(vb)) out.set(`.${vb.oid}`, vb.value);
        return false;
      },
      (err: Error | null) => {
        clearTimeout(timer);
        const ms = Date.now() - t0;
        if (err) reject(err);
        else resolve({ varbinds: out, pdus, ms });
      }
    );
  });
}

function makeSession(host: string, creds: any): any {
  // Mirror snmp-client's createSession for v1/v2c + v3.
  const sessionOpts = { timeout: OPTS.timeoutMs, retries: OPTS.retries, port: 161 };
  if (creds.version === 'v3') {
    const level =
      creds.securityLevel === 'authNoPriv' ? snmp.SecurityLevel.authNoPriv
      : creds.securityLevel === 'authPriv' ? snmp.SecurityLevel.authPriv
      : snmp.SecurityLevel.noAuthNoPriv;
    const user: any = { name: creds.username ?? '', level };
    if (level !== snmp.SecurityLevel.noAuthNoPriv && creds.authProtocol) {
      user.authProtocol = creds.authProtocol === 'MD5' ? snmp.AuthProtocols.md5 : snmp.AuthProtocols.sha;
      user.authKey = creds.authPassword ?? '';
    }
    if (level === snmp.SecurityLevel.authPriv) {
      user.privProtocol = snmp.PrivProtocols.aes;
      user.privKey = creds.privPassword ?? '';
    }
    return snmp.createV3Session(host, user, sessionOpts);
  }
  const version = creds.version === 'v1' ? snmp.Version1 : snmp.Version2c;
  return snmp.createSession(host, creds.community ?? '', { ...sessionOpts, version });
}

function summarize(label: string, stats: WalkStats[]): void {
  console.log(`\n--- ${label} ---`);
  let totalMs = 0, totalPdu = 0, totalVb = 0;
  for (const s of stats) {
    if (s.error) { console.log(`  ${s.oid.slice(0, 40).padEnd(42)} ERROR ${s.error}`); continue; }
    totalMs += s.ms; totalPdu += s.pdus; totalVb += s.varbinds;
    console.log(`  ${s.oid.slice(0, 40).padEnd(42)} ${String(s.varbinds).padStart(5)} vb  ${String(s.pdus).padStart(3)} pdu  ${String(s.ms).padStart(6)} ms`);
  }
  console.log(`  TOTAL: ${totalVb} varbinds, ${totalPdu} PDUs, ${totalMs}ms (sum of walks)`);
}

// --- pattern A: current LCOS behavior (fresh session per walk, batch 4 + settle) --
async function patternA(creds: any): Promise<WalkStats[]> {
  const stats: WalkStats[] = [];
  for (let i = 0; i < LCOS_WALKS.length; i += 4) {
    if (i > 0) await sleep(750);
    const chunk = LCOS_WALKS.slice(i, i + 4);
    const results = await Promise.allSettled(
      chunk.map(async (oid) => {
        const session = makeSession(LCOS_TARGET.host, creds);
        try {
          const r = await instrumentedWalk(session, oid, 50);
          return { oid, ...r };
        } finally {
          session.close();
        }
      })
    );
    results.forEach((r, j) => {
      if (r.status === 'fulfilled') stats.push({ oid: chunk[j], varbinds: r.value.varbinds.size, pdus: r.value.pdus, ms: r.value.ms });
      else stats.push({ oid: chunk[j], varbinds: 0, pdus: 0, ms: 0, error: (r.reason as Error).message });
    });
  }
  return stats;
}

// --- pattern B/C: shared session, sequential walks ------------------------------
async function patternShared(creds: any, maxRepetitions: number): Promise<{ stats: WalkStats[]; wallMs: number }> {
  const session = makeSession(LCOS_TARGET.host, creds);
  const stats: WalkStats[] = [];
  try {
    const t0 = Date.now();
    for (const oid of LCOS_WALKS) {
      try {
        const r = await instrumentedWalk(session, oid, maxRepetitions);
        stats.push({ oid, varbinds: r.varbinds.size, pdus: r.pdus, ms: r.ms });
      } catch (e) {
        stats.push({ oid, varbinds: 0, pdus: 0, ms: 0, error: (e as Error).message });
      }
    }
    return { stats, wallMs: Date.now() - t0 };
  } finally {
    session.close();
  }
}

// --- pattern D: multi-subtree combined loop ------------------------------------
/**
 * Walks N subtrees in ONE PDU stream. Request = one varbind per cursor, ALL in
 * the repeat section (nonRepeaters=0), maxRepetitions=R → each cursor advances
 * up to R OIDs per PDU. net-snmp's getBulk feedCb returns a flat array where
 * positions [c*R .. c*R+R-1] belong to cursor c — this is only unambiguous if
 * the agent pads finished cursors with EndOfMibView (RFC 3416 behavior). The
 * per-value subtree validation below DETECTS misattribution on non-padding
 * agents so we know whether the approach is safe for LANCOM hardware.
 */
async function patternMulti(creds: any, bases: string[], maxRepetitions: number): Promise<{ stats: WalkStats[]; wallMs: number }> {
  const session = makeSession(LCOS_TARGET.host, creds);
  try {
    const t0 = Date.now();
    const perOid = new Map<string, { vb: number }>();
    for (const b of bases) perOid.set(b, { vb: 0 });
    let cursors = bases.map((b) => ({ base: b.replace(/^\./, ''), next: b.replace(/^\./, '') }));
    let pdus = 0;
    let misattributed = 0;
    const deadline = Date.now() + 9_500;

    while (cursors.length > 0 && Date.now() < deadline) {
      const oids = cursors.map((c) => c.next);
      // net-snmp getBulk callback shape: flat array — first N entries are the
      // per-cursor "first value" singletons, then N arrays of up to R repeats.
      const resp: any[] = await new Promise((resolve, reject) => {
        session.getBulk(oids, 0, maxRepetitions, (err: Error | null, vbs?: any[]) => (err ? reject(err) : resolve(vbs ?? [])));
      });
      pdus++;
      const n = cursors.length;
      // net-snmp getBulk callback layout (nonRepeaters=0): an array of N
      // ARRAYS — resp[c] holds up to R varbinds for cursor c. (With
      // nonRepeaters>0 the first entries are single objects instead.)
      const perCursor: any[][] = [];
      for (let c = 0; c < n; c++) {
        const vbs = resp[c];
        perCursor.push(Array.isArray(vbs) ? vbs : vbs ? [vbs] : []);
      }
      const nextCursors: typeof cursors = [];
      for (let c = 0; c < n; c++) {
        const vbs = perCursor[c];
        if (!vbs.length) continue; // agent returned nothing — treat as done (defensive)
        let finished = false;
        for (const vb of vbs) {
          if (snmp.isVarbindError(vb)) { finished = true; break; }
          const parts = cursors[c].base.split('.');
          const vbParts = String(vb.oid).split('.');
          const inSubtree = vbParts.length >= parts.length && parts.every((p, i) => p === vbParts[i]);
          if (!inSubtree) { misattributed++; finished = true; break; } // value from ANOTHER subtree → padding assumption violated
          perOid.get(`.${cursors[c].base}`)!.vb++;
        }
        const last = vbs[vbs.length - 1];
        if (!finished && !snmp.isVarbindError(last)) nextCursors.push({ base: cursors[c].base, next: String(last.oid) });
      }
      cursors = nextCursors;
    }
    const wallMs = Date.now() - t0;
    const stats: WalkStats[] = bases.map((b) => ({ oid: b, varbinds: perOid.get(b)?.vb ?? 0, pdus: 0, ms: 0 }));
    console.log(`  [multi] ${bases.length} subtrees in ${pdus} PDUs, ${wallMs}ms wall, misattributed=${misattributed}`);
    return { stats, wallMs };
  } finally {
    session.close();
  }
}

// --- main -----------------------------------------------------------------------
async function main(): Promise<void> {
  const which = process.argv[2] ?? 'lcos';
  console.log(`SNMP version check + bulk-walk profile: ${which}`);

  if (which === 'lcos') {
    const creds = await fetchCreds(LCOS_TARGET.secretId);
    console.log(`creds: v${creds.version} ${creds.community ? '(community)' : `(v3 user=${creds.username} level=${creds.securityLevel})`}`);

    // Probe first (like the plugin does) to confirm reachability.
    const probeSession = makeSession(LCOS_TARGET.host, creds);
    try {
      const t0 = Date.now();
      await new Promise<void>((resolve, reject) =>
        probeSession.get([OIDS.HW.swVersion.replace(/^\./, '')], (err: Error | null, vbs?: any[]) => {
          if (err) return reject(err);
          console.log(`probe ${OIDS.HW.swVersion}: ${(vbs ?? []).length} vb in ${Date.now() - t0}ms`);
          resolve();
        })
      );
    } catch (e) {
      console.error('probe failed:', (e as Error).message);
      return;
    } finally {
      probeSession.close();
    }

    const a = await patternA(creds);
    summarize(`A: current LCOS pattern (fresh session/walk, batch 4 + 750ms settle)`, a);

    await sleep(2_000); // let the agent drain between strategy runs
    const b = await patternShared(creds, 50);
    summarize(`B: shared session, sequential, maxRepetitions=50 (wall ${b.wallMs}ms)`, b.stats);

    await sleep(2_000);
    const c100 = await patternShared(creds, 100);
    summarize(`C100: shared session, sequential, maxRepetitions=100 (wall ${c100.wallMs}ms)`, c100.stats);

    await sleep(2_000);
    const c200 = await patternShared(creds, 200);
    summarize(`C200: shared session, sequential, maxRepetitions=200 (wall ${c200.wallMs}ms)`, c200.stats);

    // Multi-subtree over ALL inventory subtrees (the production scenario).
    await sleep(2_000);
    console.log(`\n--- D: multi-subtree combined loop, all ${LCOS_WALKS.length} subtrees ---`);
    const d = await patternMulti(creds, LCOS_WALKS, 50); // R=50 → same per-cursor rate as today's per-walk PDUs
    for (const s of d.stats) console.log(`  ${s.oid.slice(0, 42).padEnd(44)} ${String(s.varbinds).padStart(5)} vb`);

    // Sanity: compare varbind counts A vs B vs D for the same subtrees.
    const aMap = new Map(a.map((s) => [s.oid, s.varbinds]));
    let mismatch = 0;
    for (const s of b.stats) if ((aMap.get(s.oid) ?? -1) !== s.varbinds && !s.error) { mismatch++; console.log(`MISMATCH ${s.oid}: A=${aMap.get(s.oid)} B=${s.varbinds}`); }
    const dMap = new Map(d.stats.map((s) => [s.oid, s.varbinds]));
    for (const s of b.stats) if ((dMap.get(s.oid) ?? -1) !== s.varbinds && !s.error) { mismatch++; console.log(`MISMATCH ${s.oid}: B=${s.varbinds} D=${dMap.get(s.oid)}`); }
    console.log(mismatch === 0 ? '\nvarbind counts identical across strategies ✓' : `\n${mismatch} varbind-count mismatches ✗`);
  } else {
    const creds = await fetchCreds(SX_TARGET.secretId);
    console.log(`creds: v${creds.version}`);

    // Detect the variant first (same probes as sxClient.detectVariant).
    {
      const s = makeSession(SX_TARGET.host, creds);
      try {
      const p4: any[] = await new Promise((res, rej) => s.get([SX_OIDS.DETECT.sx4Model.replace(/^\./, '')], (e: Error | null, v?: any[]) => e ? rej(e) : res(v ?? [])));
      if ((p4[0] && !snmp.isVarbindError(p4[0]))) variant = 'sx4';
      else {
        const p3: any[] = await new Promise((res, rej) => s.get([SX_OIDS.DETECT.sx3Model.replace(/^\./, '')], (e: Error | null, v?: any[]) => e ? rej(e) : res(v ?? [])));
        variant = (p3[0] && !snmp.isVarbindError(p3[0])) ? 'sx3' : 'sx4';
      }
    } finally { s.close(); }
    }
    const SX_WALKS = variant === 'sx4' ? SX_WALKS_SX4 : SX_WALKS_SX3;
    console.log(`detected variant: ${variant} (${SX_WALKS.length} walks)`);

    // Current SX pattern: strictly sequential, fresh session per walk.
    const stats: WalkStats[] = [];
    let wallMs = 0;
    {
      const t0 = Date.now();
      for (const oid of SX_WALKS) {
        const session = makeSession(SX_TARGET.host, creds);
        try {
          const r = await instrumentedWalk(session, oid, 50);
          stats.push({ oid, varbinds: r.varbinds.size, pdus: r.pdus, ms: r.ms });
        } catch (e) {
          stats.push({ oid, varbinds: 0, pdus: 0, ms: 0, error: (e as Error).message });
        } finally {
          session.close();
        }
      }
      wallMs = Date.now() - t0;
    }
    summarize(`SX current pattern (sequential, fresh session/walk) — wall ${wallMs}ms`, stats);

    await sleep(2_000);
    const b = await patternSharedSx(creds, 50);
    summarize(`SX shared session, sequential, R=50 (wall ${b.wallMs}ms)`, b.stats);

    await sleep(2_000);
    const c100 = await patternSharedSx(creds, 100);
    summarize(`SX shared session, sequential, R=100 (wall ${c100.wallMs}ms)`, c100.stats);

    // Multi-subtree combined loop — validates the padding assumption on this agent.
    await sleep(2_000);
    console.log(`\n--- SX D: multi-subtree combined loop, all ${SX_WALKS.length} subtrees ---`);
    const d = await patternMultiSx(creds, 50);
    for (const s of d.stats) console.log(`  ${s.oid.slice(0, 42).padEnd(44)} ${String(s.varbinds).padStart(5)} vb`);
  }
}

async function patternMultiSx(creds: any, maxRepetitions: number): Promise<{ stats: WalkStats[]; wallMs: number }> {
  const SX_WALKS = variant === 'sx4' ? SX_WALKS_SX4 : SX_WALKS_SX3;
  const session = makeSession(SX_TARGET.host, creds);
  try {
    const t0 = Date.now();
    const perOid = new Map<string, { vb: number }>();
    for (const b of SX_WALKS) perOid.set(b, { vb: 0 });
    let cursors = SX_WALKS.map((b) => ({ base: b.replace(/^\./, ''), next: b.replace(/^\./, '') }));
    let pdus = 0;
    let misattributed = 0;
    const deadline = Date.now() + 9_500;

    while (cursors.length > 0 && Date.now() < deadline) {
      const oids = cursors.map((c) => c.next);
      const resp: any[] = await new Promise((resolve, reject) => {
        session.getBulk(oids, 0, maxRepetitions, (err: Error | null, vbs?: any[]) => (err ? reject(err) : resolve(vbs ?? [])));
      });
      pdus++;
      const n = cursors.length;
      const perCursor: any[][] = [];
      for (let c = 0; c < n; c++) {
        const vbs = resp[c];
        perCursor.push(Array.isArray(vbs) ? vbs : vbs ? [vbs] : []);
      }
      const nextCursors: typeof cursors = [];
      for (let c = 0; c < n; c++) {
        const vbs = perCursor[c];
        if (!vbs.length) continue;
        let finished = false;
        for (const vb of vbs) {
          if (snmp.isVarbindError(vb)) { finished = true; break; }
          const parts = cursors[c].base.split('.');
          const vbParts = String(vb.oid).split('.');
          const inSubtree = vbParts.length >= parts.length && parts.every((p, i) => p === vbParts[i]);
          if (!inSubtree) { misattributed++; finished = true; break; }
          perOid.get(`.${cursors[c].base}`)!.vb++;
        }
        const last = vbs[vbs.length - 1];
        if (!finished && !snmp.isVarbindError(last)) nextCursors.push({ base: cursors[c].base, next: String(last.oid) });
      }
      cursors = nextCursors;
    }
    const wallMs = Date.now() - t0;
    console.log(`  [multi] ${SX_WALKS.length} subtrees in ${pdus} PDUs, ${wallMs}ms wall, misattributed=${misattributed}`);
    return { stats: SX_WALKS.map((b) => ({ oid: b, varbinds: perOid.get(b)?.vb ?? 0, pdus: 0, ms: 0 })), wallMs };
  } finally {
    session.close();
  }
}

async function patternSharedSx(creds: any, maxRepetitions: number): Promise<{ stats: WalkStats[]; wallMs: number }> {
  const SX_WALKS = variant === 'sx4' ? SX_WALKS_SX4 : SX_WALKS_SX3;
  const session = makeSession(SX_TARGET.host, creds);
  const stats: WalkStats[] = [];
  try {
    const t0 = Date.now();
    for (const oid of SX_WALKS) {
      try {
        const r = await instrumentedWalk(session, oid, maxRepetitions);
        stats.push({ oid, varbinds: r.varbinds.size, pdus: r.pdus, ms: r.ms });
      } catch (e) {
        stats.push({ oid, varbinds: 0, pdus: 0, ms: 0, error: (e as Error).message });
      }
    }
    return { stats, wallMs: Date.now() - t0 };
  } finally {
    session.close();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
