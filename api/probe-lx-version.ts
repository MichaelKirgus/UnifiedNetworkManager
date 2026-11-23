/** One-off: read AP_Wohnzimmer's live firmware version via ubus (status OID 13.1.59.1.1.10). */
import https from 'node:https';
import { getSecretFresh } from './src/secretsProvider';
import { setApiMtlsIdentity, setPluginTransports } from './src/utils/pluginHttp';
import fs from 'node:fs';

const TLS_DIR = '/data/tls';
setApiMtlsIdentity({ keyPem: fs.readFileSync(`${TLS_DIR}/tls.key`, 'utf8'), certChainPem: fs.readFileSync(`${TLS_DIR}/tls.crt`, 'utf8'), caBundlePem: fs.readFileSync(`${TLS_DIR}/ca-bundle.pem`, 'utf8') });
setPluginTransports([{ endpoint: 'http://secrets-provider-plugin:4080', tlsLive: true }]);

const AP = process.env.LX_AP ?? '10.25.1.2';
const SECRET_ID = process.env.LX_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

function ubusPost(params: unknown[], id = 1): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id, method: 'call', params });
    const req = https.request(
      { host: AP, port: 443, path: '/ubus', method: 'POST', rejectUnauthorized: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => { let data = ''; res.on('data', (c) => (data += c)); res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(new Error(`non-JSON: ${data.slice(0, 200)}`)); } }); },
    );
    req.on('error', reject); req.write(body); req.end();
  });
}

async function main(): Promise<void> {
  const secret = await getSecretFresh(SECRET_ID);
  const f = (secret.fields ?? {}) as Record<string, string>;
  const login = await ubusPost(['0'.repeat(32), 'session', 'login', { username: f.username, password: f.password, timeout: 900 }]);
  const sid = String(login.result?.[1]?.ubus_rpc_session);
  if (!sid) throw new Error(`login failed: ${JSON.stringify(login).slice(0, 200)}`);
  // Status scalars: firmware version + hardware model (best-effort OIDs from the MIB mirror).
  const tx = await ubusPost([sid, 'lxcd', 'handleTransactionStream', { transaction: { id: `probe-${Date.now()}`, inp: false, ignoreerr: true, cmd: [
    { func: 'getScalar', param: ['13.1.47.9'] },  // lcosLXStatusHardwareInfo swVersion (HW.swVersion)
    { func: 'getScalar', param: ['13.1.47.8'] },  // boardRevision
    { func: 'getScalar', param: ['13.2.1'] },     // system name (sanity — config scalar)
  ] } }]);
  console.log(JSON.stringify(tx, null, 1).slice(0, 1200));
  await ubusPost([sid, 'session', 'destroy', {}], 2).catch(() => undefined);
}

main().then(() => process.exit(0)).catch((e) => { console.error('FAILED:', e instanceof Error ? e.message : e); process.exit(1); });
