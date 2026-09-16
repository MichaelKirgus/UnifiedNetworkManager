/**
 * One-off probe: verify the LANCOM-LX time OIDs on a live AP.
 * Raw SNMP v1/v2c GET over UDP (no snmp-client dependency) — run inside the API
 * container so it can read the DB + decrypt the device's SNMP secret:
 *   docker cp api/probe-lx-time.ts <api-c>:/app/api/ && \
 *   docker exec <api-c> sh -c "cd /app/api && npx ts-node --transpile-only probe-lx-time.ts"
 */
import dgram from 'node:dgram';
import { eq } from 'drizzle-orm';
import { db } from './src/db';
import * as schema from './src/db/schema';
import { getSecretFresh } from './src/secretsProvider';

const L = '.1.3.6.1.4.1.2356.13';
// sysDescr first as a sanity check that the request itself is well-formed.
const OIDS: Array<[string, string]> = [
  ['sysDescr', '.1.3.6.1.2.1.1.1.0'],
  ['currentTime', `${L}.1.18.0`], // lcosLXStatusCurrentTime — OCTET STRING (SIZE(0..20))
  ['epoch', `${L}.1.19.0`], // lcosLXStatusCurrentTimeEpoch — Unsigned32
  ['offset', `${L}.1.20.0`], // lcosLXStatusCurrentTimeOffset — Integer32
  ['tzEnum', `${L}.2.14.20.0`], // lcosLXSetupTimeTimezone — INTEGER enum (IANA-ish)
];

/* --- minimal BER encoding ------------------------------------------------ */

function encLen(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const bytes: number[] = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encLen(content.length), content]);
}

function encInt(v: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(v >>> 0);
  let i = 0;
  while (i < 3 && b[i] === 0 && !(b[i + 1] & 0x80)) i++; // minimal form, keep sign byte
  return encTlv(0x02, b.subarray(i));
}

function encOid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  const out: number[] = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const bytes: number[] = [];
    bytes.unshift(v & 0x7f);
    v >>= 7;
    while (v > 0) { bytes.unshift((v & 0x7f) | 0x80); v >>= 7; }
    out.push(...bytes);
  }
  return encTlv(0x06, Buffer.from(out));
}

/* --- minimal BER decoding ------------------------------------------------- */

function readLen(buf: Buffer, pos: number): [number, number] {
  const first = buf[pos];
  if (first < 0x80) return [first, pos + 1];
  const n = first & 0x7f;
  let v = 0;
  for (let i = 0; i < n; i++) v = v * 256 + buf[pos + 1 + i];
  return [v, pos + 1 + n];
}

function skipTlv(buf: Buffer, pos: number): number {
  const [len, after] = readLen(buf, pos + 1);
  return after + len;
}

/* --- SNMP GET ------------------------------------------------------------- */

interface VarbindValue { tag: number; value: Buffer }

function snmpGet(host: string, community: string, oids: string[], version: 'v1' | 'v2c'): Promise<Map<string, VarbindValue>> {
  const reqId = Math.floor(Math.random() * 0x7fffffff);
  // varbind list: one SEQUENCE per OID with a NULL value.
  const vbItems = oids.map((o) => encTlv(0x30, Buffer.concat([encOid(o), encTlv(0x05, Buffer.alloc(0))])));
  const varbinds = encTlv(0x30, Buffer.concat(vbItems));
  // GetRequest PDU: request-id + error-status(0) + error-index(0) + varbinds.
  // GetRequest PDU: v1 = tag 0xa5, v2c = tag 0xa0 (same inner layout).
  const pduTag = version === 'v1' ? 0xa5 : 0xa0;
  const pdu = encTlv(pduTag, Buffer.concat([encInt(reqId), encInt(0), encInt(0), varbinds]));
  // Full message: SEQUENCE { INTEGER version, OCTET STRING community, PDU }.
  const msg = encTlv(0x30, Buffer.concat([encInt(version === 'v1' ? 0 : 1), encTlv(0x04, Buffer.from(community)), pdu]));

  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const timer = setTimeout(() => { try { sock.close(); } catch { /* noop */ } reject(new Error(`timeout after ${host}`)); }, 6000);
    const done = (fn: () => void) => { clearTimeout(timer); try { sock.close(); } catch { /* noop */ } fn(); };
    sock.on('error', (e) => done(() => reject(e)));
    sock.on('message', (buf) => {
      done(() => {
        try { resolve(parseResponse(buf, version)); }
        catch (e) { reject(new Error(`${(e as Error).message} | raw=${buf.subarray(0, 96).toString('hex')}`)); }
      });
    });
    sock.send(msg, 161, host, (err) => { if (err) done(() => reject(err)); });
  });
}

function parseResponse(buf: Buffer, version: 'v1' | 'v2c'): Map<string, VarbindValue> {
  // GetResponse-PDU is tag 0x82 in BOTH v1 and v2c (v1 requests are 0xa5,
  // but the agent always answers with a GetResponse).
  let p = skipTlv(buf, 0); // outer SEQUENCE → start of contents (version INTEGER)
  if (p >= buf.length) throw new Error(`message too short (${buf.length} bytes): ${buf.toString('hex')}`);
  p = skipTlv(buf, p); // version
  p = skipTlv(buf, p); // community
  if (p >= buf.length || buf[p] !== 0x82) throw new Error(`unexpected PDU tag ${p < buf.length ? '0x' + buf[p].toString(16) : '<eof>'} — ${buf.subarray(p, Math.min(p + 48, buf.length)).toString('hex')}`);
  const [pduLen, pduStart] = readLen(buf, p + 1);
  let q = pduStart;
  q = skipTlv(buf, q); // request-id INTEGER
  if (buf[q] !== 0x02) throw new Error(`unexpected error-status tag 0x${buf[q].toString(16)} — ${buf.subarray(q, Math.min(q + 48, buf.length)).toString('hex')}`);
  const [esLen, esStart] = readLen(buf, q + 1);
  if (buf[esStart] !== 0) {
    // error-status non-zero → next INTEGER is the error index.
    const [, idxStart] = readLen(buf, esStart + esLen);
    throw new Error(`SNMP error status=${buf[esStart]} index=${buf[idxStart]} — check OIDs/community/version`);
  }
  q = skipTlv(buf, q); // error-status INTEGER
  q = skipTlv(buf, q); // error-index INTEGER
  if (buf[q] !== 0x30) throw new Error(`expected varbind list, got tag 0x${buf[q].toString(16)}`);
  const [vbLen, vbStart] = readLen(buf, q + 1);
  let r = vbStart;
  const end = vbStart + vbLen;
  const out = new Map<string, VarbindValue>();
  while (r < end) {
    if (buf[r] !== 0x30) throw new Error(`expected varbind SEQUENCE at ${r}`);
    const [vbItemLen, vbItemStart] = readLen(buf, r + 1);
    let s = vbItemStart;
    // OID
    if (buf[s] !== 0x06) throw new Error('expected OID in varbind');
    const [oidLen, oidStart] = readLen(buf, s + 1);
    const raw: number[] = [];
    for (let i = oidStart; i < oidStart + oidLen; i++) raw.push(buf[i]);
    const parts = [Math.floor(raw[0] / 40), raw[0] % 40];
    let v = 0;
    for (let i = 1; i < raw.length; i++) { v = (v << 7) | (raw[i] & 0x7f); if (!(raw[i] & 0x80)) { parts.push(v); v = 0; } }
    const oidStr = parts.join('.');
    s = oidStart + oidLen;
    // value TLV
    let tag: number, val: Buffer;
    if (s >= end) { tag = -1; val = Buffer.alloc(0); }
    else {
      tag = buf[s];
      const [vLen, vStart] = readLen(buf, s + 1);
      val = buf.subarray(vStart, vStart + vLen);
    }
    out.set(oidStr, { tag, value: Buffer.from(val) });
    r = vbItemStart + vbItemLen;
  }
  return out;
}

function fmt(tag: number, value: Buffer): string {
  const tagNames: Record<number, string> = { 2: 'INTEGER', 4: 'OCTET STRING', 6: 'OID', 16: 'NULL', 42: 'Counter32', 70: 'Counter64' };
  if (tag === -1) return '<no value>';
  const name = tagNames[tag] ?? `tag=0x${tag.toString(16)}`;
  let text: string;
  if (tag === 4 || tag === 6) {
    text = JSON.stringify(value.toString('utf8'));
    const printable = value.every((b) => b >= 0x20 && b < 0x7f);
    if (!printable) text += ` (hex ${value.toString('hex')})`;
  } else {
    let n = 0;
    for (const b of value) n = (n * 256 + b) >>> 0;
    const signed = value.length > 0 && (value[0] & 0x80) ? n - 2 ** (value.length * 8) : n;
    text = `${signed} (${n})`;
  }
  return `${name}: ${text}`;
}

/* --- main ------------------------------------------------------------------ */

async function main(): Promise<void> {
  const rows = await db.query.devicePlugins.findMany({ where: eq(schema.devicePlugins.pluginId, '00000000-0000-4000-8000-000000000004') });
  if (rows.length === 0) { console.log('no LX assignments found'); return; }

  const secretIds = [...new Set(rows.map((r) => r.secretId).filter(Boolean))] as string[];
  const secrets: Record<string, Record<string, string>> = {};
  for (const id of secretIds) {
    try {
      const s = await getSecretFresh(id);
      secrets[id] = s.fields ?? {};
    } catch (e) {
      console.log(`secret ${id}: FAILED ${(e as Error).message}`);
    }
  }

  for (const row of rows) {
    const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, row.deviceId) });
    if (!device) continue;
    const fields = row.secretId ? secrets[row.secretId] : undefined;
    // The literal may carry a CIDR prefix ("10.25.1.1/16") — strip it.
    const host = (device.managementAddress ?? '').split('/')[0];
    if (!fields) { console.log(`\n=== ${device.name} (${host}): no decrypted secret`); continue; }
    const community: string | undefined = fields.community ?? fields.readCommunity;
    const version: 'v1' | 'v2c' = fields.version === 'v1' ? 'v1' : 'v2c';
    console.log(`\n=== ${device.name} (${host}) v${version} secret=${row.secretId?.slice(0, 8)}… community=${community ? `"${community}"` : `NOT FOUND (fields: ${Object.keys(fields).join(',')})`}`);
    if (!community || !host) continue;
    try {
      const res = await snmpGet(host, community, OIDS.map(([, o]) => o), version);
      for (const [label, oid] of OIDS) {
        const v = res.get(oid);
        console.log(`  ${label.padEnd(10)} ${oid} → ${v ? fmt(v.tag, v.value) : 'NO SUCH OBJECT'}`);
      }
    } catch (e) {
      console.log(`  probe failed: ${(e as Error).message}`);
    }
  }
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
