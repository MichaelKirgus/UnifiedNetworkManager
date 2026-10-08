#!/usr/bin/env node
/**
 * Mock sFlow v5 exporter for UNM flow-collector testing (RFC 3176 wire format).
 *
 * Emits a datagram every SEND_INTERVAL_MS containing:
 *   - one IPv4 flow sample with two records: an internal→internal TCP flow and
 *     an internal→internet UDP flow (so the Flows page's egress + pair views
 *     both get data),
 *   - one IPv6 flow sample with a single record,
 *   - one counter sample (generic interface counters) to exercise the parser's
 *     skip path.
 *
 * Wire layout verified against gopacket/layers/sflow.go:
 *   datagram: version(4) agentAddrType(4) agentAddr(4|16) subAgentId(4) seqNo(4)
 *             uptime(4) numSamples(4)
 *   flow sample: format(4)=type1 sampleLen(4) seq(4) srcIdClass(4) samplingRate(4)
 *                pool(4) drops(4) inIf(4) outIf(4) numRecords(4) records…
 *   IPv4 record: format(4)=3 len(4)=32 pktLen(4) proto(4) srcIP(4) dstIP(4)
 *                portSrc(4) portDst(4) tcpFlags(4) tos(4)
 *   IPv6 record: format(4)=4 len(4)=56 pktLen(4) proto(4) srcIP(16) dstIP(16)
 *                portSrc(4) portDst(4) tcpFlags(4) priority(4)
 *   counter sample: format(4)=2 sampleLen(4) seq(4) srcIdClass(4) numRecords(4) records…
 *
 * Run standalone:  node packages/plugin-test-kit/src/fixtures/sflowExporter.cjs [host] [port]     (default 127.0.0.1 6343)
 * Env overrides:   SRC_IP DST_INTERNAL_IP DST_INTERNET_IP AGENT_IP SAMPLE_RATE
 */

const dgram = require('dgram');

// Defaults are overridable per-call so the builders can be reused by tests.
const DEFAULTS = {
  agentIp: (process.env.AGENT_IP || '192.168.1.1').split('.').map(Number),
  srcIp: (process.env.SRC_IP || '192.168.1.50').split('.').map(Number),
  dstInternalIp: (process.env.DST_INTERNAL_IP || '192.168.1.10').split('.').map(Number),
  dstInternetIp: (process.env.DST_INTERNET_IP || '8.8.8.8').split('.').map(Number),
  sampleRate: Number(process.env.SAMPLE_RATE) || 100,
  // ONLY_INTERNAL=1 → send just the internal→internal record (dedup test).
  onlyInternal: process.env.ONLY_INTERNAL === '1',
};

const HOST = process.argv[2] || '127.0.0.1';
const PORT = Number(process.argv[3]) || 6343;
const SEND_INTERVAL_MS = Number(process.env.SFLOW_SEND_INTERVAL_MS) || 2_000;

function ip4ToBuf(ip) { return Buffer.from([ip[0], ip[1], ip[2], ip[3]]); }

/** IPv4 flow record (recType 3, payload 32 bytes). */
function ipv4FlowRecord(srcIp, dstIp, proto, pktLen, portSrc = 0, portDst = 0) {
  const b = Buffer.alloc(8 + 32);
  b.writeUInt32BE((0 << 12) | 3, 0); // format: enterprise 0, type 3 (IPv4 flow)
  b.writeUInt32BE(32, 4); // record length (payload only)
  b.writeUInt32BE(pktLen, 8);
  b.writeUInt32BE(proto, 12);
  ip4ToBuf(srcIp).copy(b, 16);
  ip4ToBuf(dstIp).copy(b, 20);
  b.writeUInt32BE(portSrc, 24);
  b.writeUInt32BE(portDst, 28);
  b.writeUInt32BE(0x18, 32); // tcpFlags (SYN|ACK) — cosmetic for the mock
  b.writeUInt32BE(0, 36); // tos
  return b;
}

/** Expand an IPv6 literal (with optional :: compression) to a 16-byte buffer. */
function ip6ToBuf(addr) {
  let groups;
  if (addr.includes('::')) {
    const [left, right] = addr.split('::');
    const l = left ? left.split(':') : [];
    const r = right ? right.split(':') : [];
    groups = [...l, ...Array(8 - l.length - r.length).fill('0'), ...r];
  } else {
    groups = addr.split(':');
  }
  if (groups.length !== 8) throw new Error(`bad IPv6 literal: ${addr}`);
  const b16 = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) b16.writeUInt16BE(parseInt(groups[i], 16), i * 2);
  return b16;
}

/** IPv6 flow record (recType 4, payload 56 bytes). */
function ipv6FlowRecord(srcIp6, dstIp6, proto, pktLen) {
  const s16 = ip6ToBuf(srcIp6);
  const d16 = ip6ToBuf(dstIp6);

  const b = Buffer.alloc(8 + 56);
  b.writeUInt32BE((0 << 12) | 4, 0); // format: enterprise 0, type 4 (IPv6 flow)
  b.writeUInt32BE(56, 4);
  b.writeUInt32BE(pktLen, 8);
  b.writeUInt32BE(proto, 12);
  s16.copy(b, 16);
  d16.copy(b, 32);
  b.writeUInt32BE(0, 48); // portSrc
  b.writeUInt32BE(0, 52); // portDst
  b.writeUInt32BE(0, 56); // tcpFlags
  b.writeUInt32BE(0, 60); // priority
  return b;
}

/** Generic interface counters record (counter recType 1, payload 120 bytes). */
function genericInterfaceCountersRecord() {
  const b = Buffer.alloc(8 + 120);
  b.writeUInt32BE((0 << 12) | 1, 0); // format: enterprise 0, type 1 (generic if counters)
  b.writeUInt32BE(120, 4);
  b.writeUInt32BE(1, 8); // ifIndex
  b.writeUInt32BE(6, 12); // ifType (ethernetCsmacd)
  b.writeBigUInt64BE(BigInt(1_000_000_000), 16); // ifSpeed
  b.writeUInt32BE(0, 24); // ifDirection
  b.writeUInt32BE(1, 28); // ifStatus (up)
  for (let i = 0; i < 12; i++) b.writeBigUInt64BE(BigInt(1_000_000), 32 + i * 8);
  return b;
}

/** Flow sample wrapper: format(4) sampleLen(4) seq(4) srcIdClass(4) rate(4) pool(4) drops(4) inIf(4) outIf(4) numRecords(4). */
function flowSample(seq, records, sampleRate = DEFAULTS.sampleRate) {
  const payload = Buffer.concat(records);
  // Fixed header is format + 9 fields = 10 × u32 = 40 bytes.
  const b = Buffer.alloc(40 + payload.length);
  b.writeUInt32BE((0 << 12) | 1, 0); // format: enterprise 0, type 1 (flow sample)
  b.writeUInt32BE(payload.length, 4); // sampleLength — informational; the parser walks records
  b.writeUInt32BE(seq, 8);
  b.writeUInt32BE(1, 12); // srcIdClass = ifIndex
  b.writeUInt32BE(sampleRate, 16);
  b.writeUInt32BE(sampleRate * 1000, 20); // samplePool
  b.writeUInt32BE(0, 24); // drops
  b.writeUInt32BE(1, 28); // inIf
  b.writeUInt32BE(2, 32); // outIf
  b.writeUInt32BE(records.length, 36);
  payload.copy(b, 40);
  return b;
}

/** Counter sample wrapper: format(4) sampleLen(4) seq(4) srcIdClass(4) numRecords(4). */
function counterSample(seq, records) {
  const payload = Buffer.concat(records);
  const b = Buffer.alloc(20 + payload.length);
  b.writeUInt32BE((0 << 12) | 2, 0); // format: enterprise 0, type 2 (counter sample)
  b.writeUInt32BE(payload.length, 4);
  b.writeUInt32BE(seq, 8);
  b.writeUInt32BE(1, 12); // srcIdClass = ifIndex
  b.writeUInt32BE(records.length, 16);
  payload.copy(b, 20);
  return b;
}

/** Build one full sFlow datagram with the standard mock flow set. */
function buildDatagram(seqNo, opts = {}) {
  const d = { ...DEFAULTS, ...opts };
  // onlyInternal (env ONLY_INTERNAL=1): send JUST the internal→internal record —
  // used by the multi-exporter dedup test so a second agent duplicates exactly
  // one tuple while leaving the others single-observed.
  const samples = d.onlyInternal ? [
    flowSample(seqNo, [ipv4FlowRecord(d.srcIp, d.dstInternalIp, 6, 1_500)], d.sampleRate),
  ] : [
    // Internal → internal (TCP/443) + internal → internet (UDP/53).
    flowSample(seqNo, [
      ipv4FlowRecord(d.srcIp, d.dstInternalIp, 6, 1_500),
      ipv4FlowRecord(d.srcIp, d.dstInternetIp, 17, 800),
    ], d.sampleRate),
    // IPv6 internal → internet.
    flowSample(seqNo + 1, [ipv6FlowRecord('2001:db8::50', '2001:4860:4860::8888', 17, 600)], d.sampleRate),
    // Counter sample — exercises the parser's skip path.
    counterSample(seqNo + 2, [genericInterfaceCountersRecord()]),
  ];

  const header = Buffer.alloc(28);
  header.writeUInt32BE(5, 0); // version 5
  header.writeUInt32BE(1, 4); // agentAddrType: IPv4
  ip4ToBuf(d.agentIp).copy(header, 8);
  header.writeUInt32BE(0, 12); // subAgentId
  header.writeUInt32BE(seqNo, 16); // seqNo
  header.writeUInt32BE(Math.floor(process.uptime() * 1000), 20); // uptime ms
  header.writeUInt32BE(samples.length, 24); // numSamples

  return Buffer.concat([header, ...samples]);
}

module.exports = { buildDatagram, ipv4FlowRecord, ipv6FlowRecord, flowSample, counterSample, genericInterfaceCountersRecord };

if (require.main === module) {
  const socket = dgram.createSocket('udp4');
  let seqNo = 0;

  function sendOne() {
    seqNo += 1;
    const datagram = buildDatagram(seqNo);
    socket.send(datagram, PORT, HOST, (err) => {
      if (!err) console.log(`[mock-sflow] sent seq=${seqNo} (${datagram.length} bytes)`);
    });
  }

  socket.on('error', (err) => {
    console.error('[mock-sflow] socket error:', err.message);
    process.exit(1);
  });

  console.log(`[mock-sflow] exporting to udp://${HOST}:${PORT} every ${SEND_INTERVAL_MS}ms`);
  console.log(`[mock-sflow] flows: ${DEFAULTS.srcIp.join('.')} → ${DEFAULTS.dstInternalIp.join('.')} (tcp/443), ${DEFAULTS.srcIp.join('.')} → ${DEFAULTS.dstInternetIp.join('.')} (udp/53)`);
  sendOne();
  setInterval(sendOne, SEND_INTERVAL_MS);
}
