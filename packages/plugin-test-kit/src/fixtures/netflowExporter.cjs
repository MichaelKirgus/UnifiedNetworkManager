#!/usr/bin/env node
/**
 * Mock NetFlow v5 + v9 exporter for UNM flow-collector testing.
 *
 * Wire layout verified against scapy/layers/netflow.py and RFC 3954 §5:
 *   v5 header (24B): version(2)=5 count(2) sysUptime(4) unixSecs(4) unixNsecs(4)
 *                    flowSequence(4) engineType(1) engineId(1) samplingInterval(2)
 *   v5 record (48B × count): srcIP(4) dstIP(4) nextHop(4) inIf(2) outIf(2)
 *                    dPkts(4) dOctets(4) first(4) last(4) srcPort(2) dstPort(2)
 *                    pad1(1) tcpFlags(1) proto(1) tos(1) srcAS(2) dstAS(2)
 *                    srcMask(1) dstMask(1) pad2(2)
 *   v9 header (20B): version(2)=9 count(2) sysUptime(4) unixSecs(4)
 *                    packageSequence(4) SourceID(4)
 *   flow set: setId(2) length(2, includes the 4-byte set header) payload…
 *     template set (setId=0): [templateId(2) fieldCount(2) fieldType(2) fieldLen(2)]*
 *     data set (setId=N): records decoded with cached template N.
 *
 * The v9 mock sends ONE template datagram at startup, then DATA-ONLY datagrams —
 * proving the collector's per-SourceID template cache works across packets.
 *
 * Run standalone:  node packages/plugin-test-kit/src/fixtures/netflowExporter.cjs [host] [port]     (default 127.0.0.1 6343)
 * Env overrides:   SRC_IP DST_INTERNAL_IP DST_INTERNET_IP V9_SRC_IP SAMPLE_RATE V9_SAMPLE_RATE
 */

const dgram = require('dgram');

// Defaults are overridable per-call so the builders can be reused by tests.
const DEFAULTS = {
  srcIp: (process.env.SRC_IP || '192.168.1.50').split('.').map(Number),
  dstInternalIp: (process.env.DST_INTERNAL_IP || '192.168.1.10').split('.').map(Number),
  dstInternetIp: (process.env.DST_INTERNET_IP || '8.8.8.8').split('.').map(Number),
  v9SrcIp: (process.env.V9_SRC_IP || '192.168.1.75').split('.').map(Number),
  sampleRate: Number(process.env.SAMPLE_RATE) || 100, // v5 "1 in N" divisor
  v9SampleRate: Number(process.env.V9_SAMPLE_RATE) || 50,
};

const HOST = process.argv[2] || '127.0.0.1';
const PORT = Number(process.argv[3]) || 6343;
const SEND_INTERVAL_MS = Number(process.env.NF_SEND_INTERVAL_MS) || 2_000;

function ip4ToBuf(ip) { return Buffer.from([ip[0], ip[1], ip[2], ip[3]]); }

// ── NetFlow v5 ──────────────────────────────────────────────────────────────

/** One 48-byte v5 record. dOctets/dPkts are the SAMPLED (reported) counts. */
function v5Record(srcIp, dstIp, proto, dPkts, dOctets, srcPort = 0, dstPort = 0) {
  const b = Buffer.alloc(48);
  ip4ToBuf(srcIp).copy(b, 0);
  ip4ToBuf(dstIp).copy(b, 4);
  // nextHop @8 stays zero
  b.writeUInt16BE(1, 12); // inputIfIndex
  b.writeUInt16BE(2, 14); // outputIfIndex
  b.writeUInt32BE(dPkts, 16);
  b.writeUInt32BE(dOctets, 20);
  const now = Math.floor(Date.now() / 1000);
  b.writeUInt32BE(now - 5, 24); // first (sysuptime-ish seconds)
  b.writeUInt32BE(now, 28); // last
  b.writeUInt16BE(srcPort, 32);
  b.writeUInt16BE(dstPort, 34);
  b[36] = 0; // pad1
  b[37] = 0x18; // tcpFlags (SYN|ACK) — cosmetic for the mock
  b[38] = proto;
  b[39] = 0; // tos
  // srcAS/dstAS @40..42 stay zero; masks @44/45 = 24
  b[44] = 24;
  b[45] = 24;
  return b;
}

/** Build a v5 datagram with three records (internal TCP, internet UDP, internal TCP). */
function buildV5Datagram(seq = 1, opts = {}) {
  const d = Object.assign({}, DEFAULTS, opts);
  const count = 3;
  const hdr = Buffer.alloc(24);
  hdr.writeUInt16BE(5, 0); // version
  hdr.writeUInt16BE(count, 2);
  hdr.writeUInt32BE(Date.now() % 0xffffffff, 4); // sysUptime (ms)
  hdr.writeUInt32BE(Math.floor(Date.now() / 1000), 8); // unixSecs
  hdr.writeUInt32BE(0, 12); // unixNsecs
  hdr.writeUInt32BE(seq, 16); // flowSequence
  hdr[20] = 0; // engineType
  hdr[21] = 0; // engineId
  hdr.writeUInt16BE(d.sampleRate, 22); // samplingInterval ("1 in N")

  const recs = [
    v5Record(d.srcIp, d.dstInternalIp, 6, 15, 15_000, 443, 51234),
    v5Record(d.srcIp, d.dstInternetIp, 17, 8, 8_000, 53, 53),
    v5Record(d.srcIp, [d.dstInternalIp[0], d.dstInternalIp[1], d.dstInternalIp[2], 20], 6, 4, 4_000, 80, 60000),
  ];
  return Buffer.concat([hdr, ...recs]);
}

// ── NetFlow v9 (RFC 3954) ───────────────────────────────────────────────────

const V9_TEMPLATE_ID = 260;
const V9_SOURCE_ID = 1;

/** The template's field list: IN_BYTES, IN_PKTS, PROTOCOL, L4_SRC_PORT, IPV4_SRC_ADDR, L4_DST_PORT, IPV4_DST_ADDR, SAMPLING_INTERVAL. */
const V9_FIELDS = [
  { type: 1, len: 4 }, // IN_BYTES
  { type: 2, len: 4 }, // IN_PKTS
  { type: 4, len: 1 }, // PROTOCOL
  { type: 7, len: 2 }, // L4_SRC_PORT
  { type: 8, len: 4 }, // IPV4_SRC_ADDR
  { type: 11, len: 2 }, // L4_DST_PORT
  { type: 12, len: 4 }, // IPV4_DST_ADDR
  { type: 34, len: 4 }, // SAMPLING_INTERVAL
];

/** One v9 data record (25 bytes) matching V9_FIELDS. */
function v9Record(inBytes, inPkts, proto, srcPort, srcIp, dstPort, dstIp, samplingInterval) {
  const b = Buffer.alloc(25);
  let o = 0;
  b.writeUInt32BE(inBytes, o); o += 4;
  b.writeUInt32BE(inPkts, o); o += 4;
  b[o] = proto; o += 1;
  b.writeUInt16BE(srcPort, o); o += 2;
  ip4ToBuf(srcIp).copy(b, o); o += 4;
  b.writeUInt16BE(dstPort, o); o += 2;
  ip4ToBuf(dstIp).copy(b, o); o += 4;
  b.writeUInt32BE(samplingInterval, o); o += 4;
  return b;
}

/** Template Flow Set (setId=0) carrying the single V9 template. */
function v9TemplateSet() {
  const payload = Buffer.alloc(4 + V9_FIELDS.length * 4);
  payload.writeUInt16BE(V9_TEMPLATE_ID, 0);
  payload.writeUInt16BE(V9_FIELDS.length, 2);
  let o = 4;
  for (const f of V9_FIELDS) {
    payload.writeUInt16BE(f.type, o);
    payload.writeUInt16BE(f.len, o + 2);
    o += 4;
  }
  const set = Buffer.alloc(4 + payload.length);
  set.writeUInt16BE(0, 0); // setId: template flow set
  set.writeUInt16BE(set.length, 2);
  payload.copy(set, 4);
  return set;
}

/** v9 header (20 bytes). */
function v9Header(count) {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(9, 0); // version
  h.writeUInt16BE(count, 2);
  h.writeUInt32BE(Date.now() % 0xffffffff, 4); // sysUptime (ms)
  h.writeUInt32BE(Math.floor(Date.now() / 1000), 8); // unixSecs
  return h;
}

/**
 * Build a v9 datagram. With `includeTemplate` the template set is prepended
 * (self-contained packet); by default it's DATA-ONLY and relies on the
 * collector having cached the template from an earlier datagram.
 */
function buildV9DataDatagram(seq = 1, opts = {}) {
  const d = Object.assign({}, DEFAULTS, opts);
  const includeTemplate = !!d.includeTemplate;

  const recs = [
    v9Record(20_000, 20, 6, 443, d.v9SrcIp, 51234, d.dstInternalIp, d.v9SampleRate),
    v9Record(3_000, 3, 17, 53, d.v9SrcIp, 53, d.dstInternetIp, d.v9SampleRate),
  ];
  const recordLen = recs[0].length; // all records same length (fixed template)

  const dataSet = Buffer.alloc(4 + recs.length * recordLen);
  dataSet.writeUInt16BE(V9_TEMPLATE_ID, 0);
  dataSet.writeUInt16BE(dataSet.length, 2);
  let o = 4;
  for (const r of recs) { r.copy(dataSet, o); o += recordLen; }

  const sets = includeTemplate ? [v9TemplateSet(), dataSet] : [dataSet];
  // Count = total records: each template counts as one + data records.
  const count = (includeTemplate ? 1 : 0) + recs.length;
  const hdr = v9Header(count);
  hdr.writeUInt32BE(seq, 12); // packageSequence
  hdr.writeUInt32BE(V9_SOURCE_ID, 16); // SourceID

  return Buffer.concat([hdr, ...sets]);
}

// ── Standalone loop ─────────────────────────────────────────────────────────

if (require.main === module) {
  const sock = dgram.createSocket('udp4');
  let seq = 0;

  // One template datagram up front — subsequent v9 packets are data-only.
  sock.send(buildV9DataDatagram(++seq, { includeTemplate: true }), PORT, HOST);
  console.log(`[mock-netflow] sent v9 template (id=${V9_TEMPLATE_ID}, sourceId=${V9_SOURCE_ID}) → ${HOST}:${PORT}`);

  setInterval(() => {
    sock.send(buildV5Datagram(++seq), PORT, HOST);
    sock.send(buildV9DataDatagram(++seq), PORT, HOST); // data-only — exercises the cache
  }, SEND_INTERVAL_MS);
}

module.exports = { buildV5Datagram, buildV9DataDatagram, v9TemplateSet, V9_TEMPLATE_ID, V9_SOURCE_ID };
