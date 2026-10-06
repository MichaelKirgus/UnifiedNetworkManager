#!/usr/bin/env node
/**
 * Mock download server for the GeoIP / web-fetch e2e (scripts/e2e-geoip.cjs).
 *
 * Serves deterministic GeoIP database fixtures on plain HTTP:
 *   GET /health            — liveness probe (the e2e polls this)
 *   GET /sample.mmdb       — a hand-crafted, spec-valid MMDB (record size 28):
 *                             8.8.8.8 → US/United States/Mountain View
 *                             1.1.1.1 → AU/Australia/Sydney
 *   GET /dpip.csv          — dp-ip-style single-IP CSV (Country Code + Name)
 *   GET /lite.zip          — IP2Location-LITE-style ZIP (FromIP/ToIP ranges)
 *   GET /archive.tar.gz    — tar.gz wrapping sample.mmdb (MaxMind-style archive)
 *   anything else          — 404 (exercises the failure path)
 *
 * With --proxy it ALSO acts as a minimal forward proxy on the same port:
 *   CONNECT host:port      — TCP tunnel (what axios uses for https targets)
 *   GET http://host/path   — absolute-form request, served from this server
 * The e2e points webFetchProxyUrl at it to prove the whole chain works when
 * plain egress is unavailable and every hop must go through a proxy.
 *
 * Usage: node scripts/mock-webserver.cjs [port] [--proxy]
 */
const http = require('http');
const net = require('net');
const zlib = require('zlib');

const PORT = Number(process.argv[2]) || 9199;
const PROXY_MODE = process.argv.includes('--proxy');

// ── MMDB builder (hand-rolled, spec-valid) ───────────────────────────────────
// Layout: [search tree][16-byte separator][data section][marker][metadata map].
// The reader walks a depth-32 trie from node 0; a slot holding exactly
// `nodeCount` means "no entry", a value > nodeCount is resolved to an ABSOLUTE
// file offset (resolved = record - nodeCount + searchTreeSize). We build only
// the nodes on the two entries' paths — every other slot is the sentinel, so
// any other IP resolves to null.

function ipBits(ip) {
  const octets = ip.split('.').map(Number);
  const bits = [];
  for (let o = 0; o < 4; o++) for (let b = 7; b >= 0; b--) bits.push((octets[o] >> b) & 1);
  return bits; // 32 MSB-first bits
}

function buildMmdb() {
  const NODE_BYTES = 7; // record size 28 → 7 bytes per node
  const SEP = Buffer.concat([Buffer.from([0xab, 0xcd, 0xef]), Buffer.from('MaxMind.com', 'ascii'), Buffer.alloc(3)]); // 16 bytes
  const MARKER = Buffer.concat([Buffer.from([0xab, 0xcd, 0xef]), Buffer.from('MaxMind.com', 'ascii')]); // 14 bytes

  const entries = [
    { ip: '8.8.8.8', isoCode: 'US', countryName: 'United States', city: 'Mountain View' },
    { ip: '1.1.1.1', isoCode: 'AU', countryName: 'Australia', city: 'Sydney' },
  ];

  // Trie over the first 31 bits (levels 0..30); bit 31's record lives in the
  // level-30 node and points straight at the data section.
  const nodes = []; // [slot0, slot1] — null until assigned
  const newNode = () => { nodes.push([null, null]); return nodes.length - 1; };
  const root = newNode();

  let cursors = entries.map(() => root);
  for (let level = 0; level < 31; level++) {
    cursors = cursors.map((cur, e) => {
      const bit = ipBits(entries[e].ip)[level];
      if (nodes[cur][bit] === null) nodes[cur][bit] = newNode();
      return nodes[cur][bit];
    });
  }

  // Data-section encodings (the msgpack-like subset the reader supports).
  const str = (s) => {
    const b = Buffer.from(s, 'utf8');
    if (b.length >= 32) throw new Error('mock mmdb: string too long for fix encoding');
    return Buffer.concat([Buffer.from([(2 << 5) | b.length]), b]); // utf8_string
  };
  const uint32 = (v) => {
    const b = Buffer.alloc(5);
    b[0] = (6 << 5) | 4; // type=uint32, size=4 (all metadata values are non-negative)
    b.writeUInt32BE(v >>> 0, 1);
    return b;
  };
  const mapOf = (pairs) => Buffer.concat([Buffer.from([(7 << 5) | pairs.length]), ...pairs.flat()]);

  const entryBufs = entries.map((e) => {
    const country = mapOf([
      [str('iso_code'), str(e.isoCode)],
      [str('names'), mapOf([[str('en'), str(e.countryName)]])],
    ]);
    const city = mapOf([[str('names'), mapOf([[str('en'), str(e.city)]])]]);
    return mapOf([[str('country'), country], [str('city'), city]]);
  });

  // Serialize the tree. nodeCount must exceed every node number AND every data
  // pointer value; pointers resolve to absolute offsets, so compute them after N.
  const N = nodes.length;
  const searchTreeSize = N * NODE_BYTES;
  const dataStart = searchTreeSize + SEP.length;

  let offset = dataStart;
  const entryOffsets = entryBufs.map((b) => {
    const at = offset;
    offset += b.length;
    return at;
  });
  // record value that resolves to absolute file offset `at`:
  //   resolved = record - N + searchTreeSize === at  →  record = at - searchTreeSize + N.
  const dataPtr = (at) => at - searchTreeSize + N;

  for (let e = 0; e < entries.length; e++) {
    const bit = ipBits(entries[e].ip)[31];
    nodes[cursors[e]][bit] = dataPtr(entryOffsets[e]); // > N — a data pointer
  }

  const tree = Buffer.alloc(searchTreeSize);
  for (let i = 0; i < N; i++) {
    const [s0, s1] = nodes[i];
    const v0 = s0 === null ? N : s0; // unassigned slot = sentinel ("no entry")
    const v1 = s1 === null ? N : s1;
    const base = i * NODE_BYTES;
    tree.writeUIntBE(v0 & 0xffffff, base, 3);          // slot0 low 24 bits
    tree[base + 3] = ((v0 >>> 24) << 4) | (v1 >>> 28); // shared top-nibble byte
    tree.writeUIntBE(v1 & 0xffffff, base + 4, 3);      // slot1 low 24 bits
  }

  const dataSection = Buffer.concat(entryBufs);

  // Metadata map — every key the reader's Metadata class touches.
  const meta = mapOf([
    [str('binary_format_major_version'), uint32(2)],
    [str('binary_format_minor_version'), uint32(0)],
    [str('build_epoch'), uint32(Math.floor(Date.now() / 1000))],
    [str('database_type'), str('GeoLite2-City')],
    [str('description'), mapOf([[str('en'), str('UNM e2e sample database')]])],
    [str('ip_version'), uint32(4)],
    [str('languages'), str('en')],
    [str('node_count'), uint32(N)],
    [str('record_size'), uint32(28)],
  ]);

  return Buffer.concat([tree, SEP, dataSection, MARKER, meta]);
}

// ── CSV fixtures ─────────────────────────────────────────────────────────────

const DPIP_CSV = [
  'IP,Country Code,Country Name,City',
  '8.8.8.8,US,United States,Mountain View',
  '1.1.1.1,AU,Australia,Sydney',
  '93.184.216.34,DE,Germany,Frankfurt am Main',
].join('\n') + '\n';

const LITE_CSV = [
  'FromIP,ToIP,Country,City',
  '16777216,33554431,AU,Sydney',        // 1.0.0.0/8 → covers 1.1.1.1
  '134744064,134744319,US,Mountain View' // 8.8.8.0/24 → covers 8.8.8.8
].join('\n') + '\n';

// ── Minimal ZIP writer (store method — no compression needed) ────────────────

let CRC_TABLE = null;
function crc32(buf) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c;
    }
  }
  let c = ~0;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (~c) >>> 0;
}

function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const crc = crc32(data);

    const local = Buffer.alloc(30 + nameBuf.length); // zeroed: flags/method/times/extra-len = 0 (store)
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4);         // version needed
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size (store = same)
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(local, 30);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0); // central directory signature
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);    // local header offset
    nameBuf.copy(central, 46);

    locals.push(local, data);
    centrals.push(central);
    offset += local.length + data.length;
  }
  const centralDir = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);    // entries on this disk
  eocd.writeUInt16LE(files.length, 10);   // total entries
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);         // central dir offset
  return Buffer.concat([...locals, centralDir, eocd]);
}

// ── Minimal tar.gz writer (ustar headers, gzip via zlib) ─────────────────────

function buildTarGz(files) {
  const blocks = [];
  for (const f of files) {
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const header = Buffer.alloc(512); // zero-filled
    header.write(f.name, 0, 'utf8');                                  // name (≤100)
    header.write('0000644', 100, 'ascii');                            // mode
    header.write(data.length.toString(8).padStart(11, '0'), 124, 'ascii');   // size (octal)
    header.write(Math.floor(Date.now() / 1000).toString(8).padStart(12, '0'), 136, 'ascii'); // mtime
    header[156] = 0x30;                                               // typeflag '0' (regular file)
    header.write('ustar', 257, 'ascii');                              // magic — must exist BEFORE the checksum sum
    header.write('00', 263, 'ascii');                                 // version
    for (let i = 148; i < 156; i++) header[i] = 0x20;                 // checksum field = spaces while summing
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += header[i];
    header.write(sum.toString(8).padStart(6, '0'), 148, 'ascii');     // checksum + trailing space
    const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
    data.copy(padded);
    blocks.push(header, padded);
  }
  blocks.push(Buffer.alloc(1024)); // two zero blocks = end of archive
  return zlib.gzipSync(Buffer.concat(blocks));
}

// ── HTTP server (+ optional forward-proxy mode) ──────────────────────────────

const MMDB = buildMmdb();
const LITE_ZIP = buildZip([{ name: 'geoip-lite-ipv4.csv', data: LITE_CSV }]);
const TAR_GZ = buildTarGz([{ name: 'GeoLite2-City.mmdb', data: MMDB }]);

// Exported for scripts/e2e-geoip.cjs (fixture assertions) — requiring this file
// does NOT start the server.
module.exports = { buildMmdb, buildZip, buildTarGz, DPIP_CSV, LITE_CSV, MMDB, LITE_ZIP, TAR_GZ };

function serve(req, res) {
  const url = new URL(req.url, 'http://localhost');
  switch (url.pathname) {
    case '/health':
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, proxy: PROXY_MODE }));
      return;
    case '/sample.mmdb':
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': MMDB.length });
      res.end(MMDB);
      return;
    case '/dpip.csv':
      res.writeHead(200, { 'Content-Type': 'text/csv' });
      res.end(DPIP_CSV);
      return;
    case '/lite.zip':
      res.writeHead(200, { 'Content-Type': 'application/zip', 'Content-Length': LITE_ZIP.length });
      res.end(LITE_ZIP);
      return;
    case '/archive.tar.gz':
      res.writeHead(200, { 'Content-Type': 'application/gzip', 'Content-Length': TAR_GZ.length });
      res.end(TAR_GZ);
      return;
    default:
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end(`mock-webserver: no such fixture ${url.pathname}`);
  }
}

// Only start the server when run directly — requiring this file just gives
// callers the fixture builders (e2e-geoip.cjs).
if (require.main === module) {
  const server = http.createServer((req, res) => {
    // Absolute-form request (proxy client for an http target).
    if (PROXY_MODE && /^https?:\/\//i.test(req.url || '')) {
      try {
        const u = new URL(req.url);
        console.log(`[mock] proxy ${req.method} ${u.href}`);
        serve({ url: `${u.pathname}${u.search}`, method: req.method }, res);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end(`bad absolute-form URL: ${e.message}`);
      }
      return;
    }
    serve(req, res);
  });

  // CONNECT tunneling — axios uses this for https targets through a proxy.
  server.on('connect', (req, clientSocket) => {
    if (!PROXY_MODE) {
      clientSocket.destroy();
      return;
    }
    const [host, port] = String(req.url).split(':');
    console.log(`[mock] CONNECT ${req.url}`);
    const upstream = net.connect(Number(port) || 443, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', (e) => {
      console.log(`[mock] CONNECT ${req.url} failed: ${e.message}`);
      try { clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch { /* gone */ }
      clientSocket.destroy();
    });
    clientSocket.on('error', () => upstream.destroy());
  });

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[mock] mock-webserver listening on :${PORT} (proxy=${PROXY_MODE})`);
    console.log('[mock] fixtures: /sample.mmdb /dpip.csv /lite.zip /archive.tar.gz');
  });
}
