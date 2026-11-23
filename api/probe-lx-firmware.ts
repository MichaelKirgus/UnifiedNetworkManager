/**
 * One-off probe: verify the LANCOM-LX firmware upload protocol on a live AP.
 * Reverse-engineered from the vendor WEBconfig SPA bundle (main.*.js):
 *   1. POST /cgi-bin/cgi-upload — multipart form with fields
 *        sessionid = <ubus session token>, filetype = "firmware", filedata = <file>
 *      → result[1] = { filename } (staged on the AP, NOT installed)
 *   2. ubus params:[SID,"lxupdate","firmwareUpgrade",{path:<filename>}] — installs + reboots.
 * THIS PROBE ONLY STAGES (step 1). It NEVER calls firmwareUpgrade — pass a real
 * .upx via UPX_PATH to test staging of the actual image; DUMMY=1 sends 1 KB of
 * junk instead to observe validation behaviour without writing anything useful.
 *
 * Run inside the API container (needs the secrets provider + LAN reachability):
 *   docker cp api/probe-lx-firmware.ts <api-c>:/app/api/ && \
 *   [docker cp ~/Downloads/LC-LX-6500-7.20.0192-RU1.upx <api-c>:/tmp/fw.upx] && \
 *   docker exec -e UPX_PATH=/tmp/fw.upx [-e DUMMY=1] <api-c> sh -c "cd /app/api && npx ts-node --transpile-only probe-lx-firmware.ts"
 */
import fs from 'node:fs';
import https from 'node:https';
import { getSecretFresh } from './src/secretsProvider';
import { setApiMtlsIdentity, setPluginTransports } from './src/utils/pluginHttp';

// A standalone process has an EMPTY plugin-transport registry (defaults to
// plain HTTP) and no mTLS identity — seed both exactly like boot does, or the
// secrets-provider call hangs on a dead plain-HTTP listener.
const TLS_DIR = '/data/tls';
setApiMtlsIdentity({
  keyPem: fs.readFileSync(`${TLS_DIR}/tls.key`, 'utf8'), // leaf private key (account-*.key.pem is the ACME account key)
  certChainPem: fs.readFileSync(`${TLS_DIR}/tls.crt`, 'utf8'),
  caBundlePem: fs.readFileSync(`${TLS_DIR}/ca-bundle.pem`, 'utf8'),
});
setPluginTransports([{ endpoint: 'http://secrets-provider-plugin:4080', tlsLive: true }]);

const AP = process.env.LX_AP ?? '10.25.1.2'; // AP_Wohnzimmer (LX-6500)
const SECRET_ID = process.env.LX_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';
const UPX_PATH = process.env.UPX_PATH ?? ''; // e.g. /tmp/fw.upx (docker cp'd in)
const DUMMY = process.env.DUMMY === '1';

function log(...args: unknown[]): void { console.log(new Date().toISOString(), ...args); }

/** Raw JSON-RPC POST to the AP's /ubus endpoint (self-signed TLS). */
function ubusPost(params: unknown[], id = 1): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id, method: 'call', params });
    const req = https.request(
      { host: AP, port: 443, path: '/ubus', method: 'POST', rejectUnauthorized: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => { let data = ''; res.on('data', (c) => (data += c)); res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(new Error(`non-JSON response: ${data.slice(0, 300)}`)); } }); },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/** Multipart POST to /cgi-bin/cgi-upload with sessionid + filetype + filedata. */
function uploadFile(sid: string, filename: string, data: Buffer): Promise<any> {
  return new Promise((resolve, reject) => {
    const boundary = `----unmprobe${Date.now().toString(16)}`;
    const parts: Buffer[] = [];
    const field = (name: string, value: string): void => {
      parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
    };
    field('sessionid', sid);
    field('filetype', 'firmware');
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="filedata"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`));
    parts.push(data, Buffer.from('\r\n'));
    parts.push(Buffer.from(`--${boundary}--\r\n`));
    const body = Buffer.concat(parts);
    const req = https.request(
      { host: AP, port: 443, path: '/cgi-bin/cgi-upload', method: 'POST', rejectUnauthorized: false, headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length } },
      (res) => { let data2 = ''; res.on('data', (c) => (data2 += c)); res.on('end', () => { try { resolve(JSON.parse(data2)); } catch { reject(new Error(`non-JSON response: ${data2.slice(0, 300)}`)); } }); },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function main(): Promise<void> {
  // 1. Decrypt the bound web credential (usernamePassword secret).
  const secret = await getSecretFresh(SECRET_ID);
  const fields = (secret.fields ?? {}) as Record<string, string>;
  const username = fields.username;
  const password = fields.password;
  if (!username || !password) throw new Error(`secret ${SECRET_ID} has no username/password fields: ${JSON.stringify(Object.keys(fields))}`);
  log(`credentials loaded for user "${username}"`);

  // 2. ubus session login → real session token.
  const login = await ubusPost(['0'.repeat(32), 'session', 'login', { username, password, timeout: 900 }]);
  if (Array.isArray(login.result) && typeof login.result[1] === 'object' && login.result[1]?.ubus_rpc_session) {
    // ok
  } else {
    throw new Error(`login failed: ${JSON.stringify(login).slice(0, 300)}`);
  }
  const sid = String(login.result[1].ubus_rpc_session);
  log(`session token acquired (${sid.slice(0, 8)}…)`);

  // 3. Read the file to stage (or build a dummy).
  let payload: Buffer;
  let filename: string;
  if (DUMMY) {
    payload = Buffer.alloc(1024, 0x42);
    filename = 'probe-dummy.upx';
    log('DUMMY mode — sending 1 KB of junk to observe validation');
  } else {
    if (!UPX_PATH || !fs.existsSync(UPX_PATH)) throw new Error(`UPX_PATH not set or missing (${UPX_PATH})`);
    payload = fs.readFileSync(UPX_PATH);
    filename = UPX_PATH.split('/').pop() ?? 'firmware.upx';
    log(`staging real image ${filename} (${payload.length} bytes)`);
  }

  // 4. Stage the upload (NO firmwareUpgrade call — the device must not reboot).
  const t0 = Date.now();
  const up = await uploadFile(sid, filename, payload);
  log(`upload response after ${((Date.now() - t0) / 1000).toFixed(1)}s:`, JSON.stringify(up).slice(0, 600));

  // 5. Best-effort: read back the staged file's presence via lancomfile (metadata only).
  try {
    const meta = await ubusPost([sid, 'lancomfile', 'read', { path: 'metadata.json' }], 2);
    log('lancomfile.read metadata.json OK — session still valid after upload');
  } catch (e) {
    log(`lancomfile.read failed (informational): ${(e as Error).message}`);
  }

  // 6. Destroy the session (clean up).
  try { await ubusPost([sid, 'session', 'destroy', {}], 3); log('session destroyed'); } catch { /* best-effort */ }
}

main().then(() => process.exit(0)).catch((e) => { console.error('PROBE FAILED:', e instanceof Error ? e.message : e); process.exit(1); });
