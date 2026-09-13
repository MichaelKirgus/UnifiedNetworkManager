/**
 * READ-ONLY verification of the EXACT RPC calls the TrueNAS Web UI uses for its
 * SMB + NFS session pages. Confirms method names, params and result shapes on a
 * live appliance before wiring them into shares.ts (replacing SSH scraping).
 *
 *   smb.status(['SESSIONS'])          -> SmbSession[]  (per-share share_connections)
 *   nfs.get_nfs3_clients([])          -> Nfs3Session[] {ip, export}
 *   nfs.get_nfs4_clients([])          -> [{info: Nfs4Session['info']}]
 *
 * Usage: TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<id>-<material> npx tsx probe-sessions.ts verify
 */
import { TruenasClient, TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';
const timeoutMs = Number(process.env['TRUENAS_TIMEOUT_MS'] ?? 20000);

let creds: TruenasCredentials;
if (process.env['TRUENAS_API_KEY']) {
  const owner = process.env['TRUENAS_API_KEY_USERNAME'] || 'root';
  creds = { kind: 'apiKey', username: owner, apiKey: process.env['TRUENAS_API_KEY'] };
} else if (process.env['TRUENAS_USER'] && process.env['TRUENAS_PASSWORD']) {
  creds = { kind: 'password', username: process.env['TRUENAS_USER'], password: process.env['TRUENAS_PASSWORD'] };
} else {
  console.error('Set TRUENAS_HOST + (TRUENAS_API_KEY or TRUENAS_USER+TRUENAS_PASSWORD).');
  process.exit(1);
}

async function main(): Promise<void> {
  const client = new TruenasClient(host, transport, timeoutMs);
  console.log(`\n=== session RPC verify (READ-ONLY): ${host} ===\n`);
  await client.login(creds);
  console.log('✅ login OK\n');

  // 1. SMB sessions — exactly what the Web UI calls.
  try {
    const r = await client.call<Record<string, unknown>[]>('smb.status', ['SESSIONS'], creds);
    console.log(`--- smb.status(['SESSIONS']): ${r.length} session(s) ---`);
    for (const s of r.slice(0, 3)) {
      const conns = Array.isArray(s['share_connections']) ? (s['share_connections'] as Record<string, unknown>[]) : [];
      console.log(`  session_id=${String(s['session_id']).padEnd(12)} user=${String(s['username']).padEnd(10)} remote=${String(s['remote_machine']).padEnd(18)} dialect=${String(s['session_dialect'])} shares=[${conns.map((c) => String(c['service'])).join(', ')}]`);
    }
    if (r[0]) console.log('\n  full first session JSON:\n' + JSON.stringify(r[0], null, 2).slice(0, 3500));
  } catch (e) {
    console.error(`smb.status failed: ${(e as Error).message}`);
  }

  // 2. NFSv3 clients.
  try {
    const r = await client.call<Record<string, unknown>[]>('nfs.get_nfs3_clients', [], creds);
    console.log(`\n--- nfs.get_nfs3_clients([]): ${r.length} row(s) ---`);
    for (const c of r.slice(0, 5)) {
      console.log(`  ip=${String(c['ip']).padEnd(18)} export=${String(c['export'])}`);
    }
    if (r[0]) console.log('  full first row JSON:\n' + JSON.stringify(r[0], null, 2).slice(0, 1500));
  } catch (e) {
    console.error(`nfs.get_nfs3_clients failed: ${(e as Error).message}`);
  }

  // 3. NFSv4 clients — result is an array of {info:{...}} wrappers.
  try {
    const r = await client.call<Record<string, unknown>[]>('nfs.get_nfs4_clients', [], creds);
    console.log(`\n--- nfs.get_nfs4_clients([]): ${r.length} row(s) ---`);
    for (const w of r.slice(0, 5)) {
      const info = (w['info'] ?? {}) as Record<string, unknown>;
      console.log(`  clientid=${String(info['clientid']).padEnd(12)} address=${String(info['address']).padEnd(18)} status=${String(info['status'])}`);
    }
    if (r[0]) console.log('  full first wrapper JSON:\n' + JSON.stringify(r[0], null, 2).slice(0, 2500));
  } catch (e) {
    console.error(`nfs.get_nfs4_clients failed: ${(e as Error).message}`);
  }

  client.close();
  console.log('\n=== done ===');
  process.exit(0);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
