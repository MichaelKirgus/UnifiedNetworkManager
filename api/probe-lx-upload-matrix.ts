/**
 * One-off probe (dev only): isolates WHY the plugin's postMultipart got a
 * non-JSON response from /cgi-bin/cgi-upload during E2E. Replays the EXACT
 * multipart encoding of webapi.ts postMultipart against AP_Wohnzimmer with a
 * matrix of payload contents / sizes / file names and prints raw status+body.
 * Staging only — NEVER calls firmwareUpgrade.
 *
 * Run inside the api container:  docker exec <api> sh -c "cd /app/api && node_modules/.bin/tsx probe-lx-upload-matrix.ts"
 */
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { getSecretFresh } from './src/secretsProvider';
import { setApiMtlsIdentity, setPluginTransports } from './src/utils/pluginHttp';

const TLS_DIR = '/data/tls';
setApiMtlsIdentity({
  keyPem: fs.readFileSync(`${TLS_DIR}/tls.key`, 'utf8'),
  certChainPem: fs.readFileSync(`${TLS_DIR}/tls.crt`, 'utf8'),
  caBundlePem: fs.readFileSync(`${TLS_DIR}/ca-bundle.pem`, 'utf8'),
});
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
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/** EXACT copy of webapi.ts postMultipart (same headers, same encoding). */
function postMultipartExact(
  fields: Array<[string, string]>,
  fileField: { name: string; filename: string; data: Buffer },
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const boundary = `----lcoslx${Date.now().toString(16)}${Math.random().toString(16).slice(2, 8)}`;
    const parts: Buffer[] = [];
    for (const [name, value] of fields) {
      parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
    }
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${fileField.name}"; filename="${fileField.filename.replace(/"/g, '')}"\r\nContent-Type: application/octet-stream\r\n\r\n`));
    parts.push(fileField.data, Buffer.from('\r\n'));
    parts.push(Buffer.from(`--${boundary}--\r\n`));
    const payload = Buffer.concat(parts);

    const req = https.request(
      {
        hostname: AP, port: 443, path: '/cgi-bin/cgi-upload', method: 'POST', rejectUnauthorized: false,
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          Accept: 'application/json',
          'Content-Length': payload.length,
          Connection: 'close',
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.setTimeout(120_000, () => req.destroy(new Error('timeout')));
    req.end(payload);
  });
}

async function main(): Promise<void> {
  const secret = await getSecretFresh(SECRET_ID);
  const fields = (secret.fields ?? {}) as Record<string, string>;
  if (!fields.username || !fields.password) throw new Error('no username/password in secret');
  const login = await ubusPost(['0'.repeat(32), 'session', 'login', { username: fields.username, password: fields.password, timeout: 900 }]);
  const sid = String(login.result?.[1]?.ubus_rpc_session ?? '');
  if (!sid) throw new Error(`login failed: ${JSON.stringify(login).slice(0, 200)}`);
  console.log('session acquired');

  const cases: Array<{ label: string; data: Buffer; filename: string }> = [
    { label: '1KB 0x42 (probe original)', data: Buffer.alloc(1024, 0x42), filename: 'probe-dummy.upx' },
    { label: '4KB zeros (E2E dummy)', data: Buffer.alloc(4096, 0), filename: 'LC-LX-6500-7.20.0192-RU1.upx' },
    { label: '4KB 0x42', data: Buffer.alloc(4096, 0x42), filename: 'LC-LX-6500-7.20.0192-RU1.upx' },
    { label: '4KB zeros, probe name', data: Buffer.alloc(4096, 0), filename: 'probe-dummy.upx' },
  ];

  for (const c of cases) {
    try {
      const r = await postMultipartExact([['sessionid', sid], ['filetype', 'firmware']], { name: 'filedata', filename: c.filename, data: c.data });
      console.log(`\n=== ${c.label} ===`);
      console.log(`HTTP ${r.status}: ${r.text.slice(0, 400)}`);
    } catch (e) {
      console.log(`\n=== ${c.label} === ERROR: ${(e as Error).message}`);
    }
  }

  try { await ubusPost([sid, 'session', 'destroy', {}], 2); } catch { /* best-effort */ }
  process.exit(0);
}

main().catch((e) => { console.error('PROBE FAILED:', e instanceof Error ? e.message : e); process.exit(1); });
