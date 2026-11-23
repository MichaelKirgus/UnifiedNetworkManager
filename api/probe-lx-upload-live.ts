/**
 * One-off probe (dev only): isolates WHY the real 70 MB firmware upload to
 * AP_Wohnzimmer's /cgi-bin/cgi-upload answered with the WEBconfig SPA shell
 * (HTTP 200 + HTML) instead of JSON, while 4 KB dummy uploads succeed.
 *
 * Matrix — each case uses a FRESH ubus session (login right before the POST):
 *   https + 4KB junk      (control: must return JSON like the earlier matrix probe)
 *   http  + 4KB junk      (does cgi-upload even exist over plain HTTP?)
 *   https + 8MB junk      (size ladder — find a threshold, if any)
 *   https + 64MB junk     (just under the real image size)
 *   https + REAL 70MB .upx (the exact failing payload; /tmp/fw-real.upx in this container)
 *   http  + REAL 70MB .upx (fallback-protocol hypothesis: plugin falls back to HTTP once on TLS failure)
 *
 * STAGING ONLY — never calls lxupdate.firmwareUpgrade. Staged junk/real images
 * sit in the AP's RAM (/tmp/cgi-firmware.upload) until reboot; harmless.
 *
 * Run inside the api container (needs secrets provider + LAN reachability):
 *   docker cp ~/Downloads/LC-LX-6500-7.20.0192-RU1.upx <api>:/tmp/fw-real.upx
 *   docker exec <api> sh -c "cd /app/api && node_modules/.bin/tsx probe-lx-upload-live.ts"
 */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import { getSecretFresh } from './src/secretsProvider';
import { setApiMtlsIdentity, setPluginTransports } from './src/utils/pluginHttp';

const TLS_DIR = '/data/tls';
setApiMtlsIdentity({ keyPem: fs.readFileSync(`${TLS_DIR}/tls.key`, 'utf8'), certChainPem: fs.readFileSync(`${TLS_DIR}/tls.crt`, 'utf8'), caBundlePem: fs.readFileSync(`${TLS_DIR}/ca-bundle.pem`, 'utf8') });
setPluginTransports([{ endpoint: 'http://secrets-provider-plugin:4080', tlsLive: true }]);

const AP = process.env.LX_AP ?? '10.25.1.2';
const SECRET_ID = process.env.LX_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';
const REAL_FILE = '/tmp/fw-real.upx';

// --- ubus login (same shape as webapi.ts) ------------------------------------

function ubusPost(params: unknown[], id = 1): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id, method: 'call', params });
    const req = https.request(
      { host: AP, port: 443, path: '/ubus', method: 'POST', rejectUnauthorized: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => { let data = ''; res.on('data', (c) => (data += c)); res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error(`non-JSON: ${data.slice(0, 200)}`)); } }); },
    );
    req.on('error', reject); req.write(body); req.end();
  });
}

async function freshSession(username: string, password: string): Promise<string> {
  const login = await ubusPost(['0'.repeat(32), 'session', 'login', { username, password, timeout: 900 }]);
  const sid = String(login.result?.[1]?.ubus_rpc_session ?? '');
  if (!sid) throw new Error(`login failed: ${JSON.stringify(login).slice(0, 200)}`);
  return sid;
}

// --- Multipart upload (exact replica of webapi.ts postMultipart framing) ------

interface UploadOutcome {
  protocol: 'https' | 'http';
  label: string;
  bytes: number;
  elapsedMs: number;
  status?: number;
  contentType?: string;
  bodyHead?: string;
  error?: string;
  bytesSentAtFailure?: number;
}

function multipartBody(sid: string, fileName: string, fileData: Buffer): { boundary: string; body: Buffer } {
  const boundary = `----LXProbe${Date.now().toString(16)}abc`;
  const parts: Buffer[] = [];
  const field = (name: string, value: string) => parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`, 'utf8'));
  field('sessionid', sid);
  field('filetype', 'firmware');
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="filedata"; filename="${fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n`, 'utf8'));
  parts.push(fileData, Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'));
  return { boundary, body: Buffer.concat(parts) };
}

function uploadOnce(protocol: 'https' | 'http', label: string, sid: string, fileName: string, fileData: Buffer): Promise<UploadOutcome> {
  const lib = protocol === 'https' ? https : http;
  const { boundary, body } = multipartBody(sid, fileName, fileData);
  const out: UploadOutcome = { protocol, label, bytes: fileData.length };
  return new Promise((resolve) => {
    const t0 = Date.now();
    let sent = 0;
    try {
      const req = lib.request(
        {
          host: AP, port: protocol === 'https' ? 443 : 80, path: '/cgi-bin/cgi-upload', method: 'POST',
          rejectUnauthorized: false,
          headers: {
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            Accept: 'application/json',
            'Content-Length': body.length,
            Connection: 'close',
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            out.elapsedMs = Date.now() - t0;
            out.status = res.statusCode;
            out.contentType = String(res.headers['content-type'] ?? '');
            const text = Buffer.concat(chunks).toString('utf8');
            out.bodyHead = text.slice(0, 300).replace(/\s+/g, ' ');
            resolve(out);
          });
        },
      );
      req.on('error', (e) => {
        out.elapsedMs = Date.now() - t0;
        out.error = `${e.code ?? ''} ${e.message}`.trim();
        out.bytesSentAtFailure = sent;
        resolve(out);
      });
      const writeChunk = (buf: Buffer): void => { sent += buf.length; req.write(buf, () => undefined); };
      // Write in 1 MB chunks so we can report how far the send got before a failure.
      for (let off = 0; off < body.length; off += 1_048_576) writeChunk(body.subarray(off, Math.min(off + 1_048_576, body.length)));
      req.end();
    } catch (e) {
      out.elapsedMs = Date.now() - t0;
      out.error = e instanceof Error ? `${e.code ?? ''} ${e.message}`.trim() : String(e);
      resolve(out);
    }
  });
}

// --- Matrix --------------------------------------------------------------------

async function main(): Promise<void> {
  const secret = await getSecretFresh(SECRET_ID);
  const f = (secret.fields ?? {}) as Record<string, string>;
  if (!f.username || !f.password) throw new Error('secret has no username/password fields');

  const realData = fs.existsSync(REAL_FILE) ? fs.readFileSync(REAL_FILE) : null;
  console.log(`real image: ${realData ? `${realData.length} bytes` : 'MISSING — skipping real-file cases'}`);

  const cases: Array<{ protocol: 'https' | 'http'; label: string; data: () => Buffer }> = [
    { protocol: 'https', label: '4KB junk (control)', data: () => Buffer.alloc(4096, 0) },
    { protocol: 'http', label: '4KB junk over plain HTTP', data: () => Buffer.alloc(4096, 1) },
    { protocol: 'https', label: '8MB junk', data: () => Buffer.alloc(8 * 1024 * 1024, 2) },
    { protocol: 'https', label: '64MB junk', data: () => Buffer.alloc(64 * 1024 * 1024, 3) },
  ];
  if (realData) cases.push({ protocol: 'https', label: `REAL ${realData.length} bytes`, data: () => realData });
  if (realData) cases.push({ protocol: 'http', label: `REAL over plain HTTP`, data: () => realData });

  for (const c of cases) {
    const sid = await freshSession(f.username, f.password);
    const out = await uploadOnce(c.protocol, c.label, sid, 'probe.upx', c.data());
    const verdict = out.error ? `ERROR ${out.error} after ${out.bytesSentAtFailure}/${out.bytes} bytes sent` : `HTTP ${out.status} [${out.contentType}] in ${out.elapsedMs}ms`;
    console.log(`\n=== ${c.protocol.toUpperCase()} · ${c.label}`);
    console.log(`  → ${verdict}`);
    if (out.bodyHead) console.log(`  body: ${out.bodyHead.slice(0, 240)}`);
    // Destroy the session so the next case starts clean.
    await ubusPost([sid, 'session', 'destroy', {}], 2).catch(() => undefined);
  }
}

main().then(() => process.exit(0)).catch((e) => { console.error('FAILED:', e instanceof Error ? e.message : e); process.exit(1); });
