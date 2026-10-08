#!/usr/bin/env node
/**
 * Unit test for the flow-collector NetFlow v5/v9 parsers + dispatcher.
 *
 * Feeds datagrams built by the kit's netflow fixture
 * (packages/plugin-test-kit/src/fixtures/netflowExporter.cjs — the same byte construction
 * a real exporter would produce) through the compiled parsers and asserts every
 * expected flow is extracted with correct IPs, protocol, reported bytes and
 * sampling rate — including v9 template caching across datagrams.
 *
 * Run:  node scripts/verify-netflow-parser.cjs     (builds the plugin first if needed)
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const PLUGIN_DIR = path.join(ROOT, 'plugins', 'flow-collector');
const PARSER_JS = path.join(PLUGIN_DIR, 'dist', 'src', 'netflowParser.js');

// Build the plugin if the compiled parser is missing.
if (!fs.existsSync(PARSER_JS)) {
  console.log('[verify-netflow] building flow-collector plugin…');
  execSync('npx tsc', { cwd: PLUGIN_DIR, stdio: 'inherit' });
}

const { parseNetflowV5Datagram, parseNetflowV9Datagram, clearNetflowV9TemplateCache } = require(PARSER_JS);
const { parseFlowDatagram } = require(path.join(PLUGIN_DIR, 'dist', 'src', 'dispatch.js'));
const FIXTURES = path.join(ROOT, 'packages', 'plugin-test-kit', 'src', 'fixtures');
const mock = require(path.join(FIXTURES, 'netflowExporter.cjs'));
const sflowMock = require(path.join(FIXTURES, 'sflowExporter.cjs'));

let failures = 0;
function check(label, cond) {
  if (cond) console.log(`  ok   ${label}`);
  else { failures += 1; console.error(`  FAIL ${label}`); }
}

// ── Test 1: NetFlow v5 datagram (3 records) ─────────────────────────────────
console.log('test 1: netflow v5');
{
  const dgram = mock.buildV5Datagram(1);
  check(`datagram is 24 + 3×48 = 168 bytes (got ${dgram.length})`, dgram.length === 168);

  const flows = parseNetflowV5Datagram(dgram);
  check(`extracts 3 flows (got ${flows.length})`, flows.length === 3);

  const tcp = flows.find((f) => f.srcIp === '192.168.1.50' && f.dstIp === '192.168.1.10');
  check('internal→internal TCP flow present', !!tcp);
  if (tcp) {
    check(`proto=6 tcp (got ${tcp.proto})`, tcp.proto === 6);
    check(`reportedBytes=15_000 dOctets (rate applied once by API rollup) (got ${tcp.bytes})`, tcp.bytes === 15_000);
    check('packets=15', tcp.packets === 15);
    check('sampleRate=100', tcp.sampleRate === 100);
  }

  const udp = flows.find((f) => f.dstIp === '8.8.8.8');
  check('internal→internet UDP flow present', !!udp);
  if (udp) {
    check(`proto=17 udp (got ${udp.proto})`, udp.proto === 17);
    check(`reportedBytes=8_000 (got ${udp.bytes})`, udp.bytes === 8_000);
  }

  const tcp2 = flows.find((f) => f.dstIp === '192.168.1.20');
  check('third record present', !!tcp2 && tcp2.bytes === 4_000);
}

// ── Test 2: NetFlow v9 — template + data in one datagram ────────────────────
console.log('test 2: netflow v9 (template + data)');
{
  clearNetflowV9TemplateCache();
  const dgram = mock.buildV9DataDatagram(1, { includeTemplate: true });

  // Header(20) + template set(4+4+8×4=40) + data set(4+2×25=54) = 114 bytes.
  check(`datagram is 114 bytes (got ${dgram.length})`, dgram.length === 114);

  const flows = parseNetflowV9Datagram(dgram);
  check(`extracts 2 flows (got ${flows.length})`, flows.length === 2);

  const tcp = flows.find((f) => f.srcIp === '192.168.1.75' && f.dstIp === '192.168.1.10');
  check('v9 internal→internal TCP flow present', !!tcp);
  if (tcp) {
    check(`proto=6 tcp (got ${tcp.proto})`, tcp.proto === 6);
    check(`reportedBytes=20_000 IN_BYTES (got ${tcp.bytes})`, tcp.bytes === 20_000);
    check('packets=20', tcp.packets === 20);
    check('sampleRate=50 (SAMPLING_INTERVAL field)', tcp.sampleRate === 50);
  }

  const udp = flows.find((f) => f.dstIp === '8.8.8.8');
  check('v9 internal→internet UDP flow present', !!udp);
  if (udp) {
    check(`proto=17 udp (got ${udp.proto})`, udp.proto === 17);
    check(`reportedBytes=3_000 (got ${udp.bytes})`, udp.bytes === 3_000);
  }
}

// ── Test 3: NetFlow v9 — data-only datagram uses the cached template ────────
console.log('test 3: netflow v9 (data-only, cached template)');
{
  clearNetflowV9TemplateCache();
  // Prime the cache with a template-carrying datagram…
  parseNetflowV9Datagram(mock.buildV9DataDatagram(1, { includeTemplate: true }));
  // …then decode a data-only datagram (no template set at all).
  const flows = parseNetflowV9Datagram(mock.buildV9DataDatagram(2));
  check(`data-only datagram decodes via cache — 2 flows (got ${flows.length})`, flows.length === 2);

  // A data-only datagram with NO prior template must yield nothing, not throw.
  clearNetflowV9TemplateCache();
  const unknown = parseNetflowV9Datagram(mock.buildV9DataDatagram(3));
  check('data-only without cached template → no flows', unknown.length === 0);
}

// ── Test 4: v9 templates are scoped per SourceID ────────────────────────────
console.log('test 4: netflow v9 (per-SourceID cache scoping)');
{
  clearNetflowV9TemplateCache();
  // SourceID=1 with the standard template…
  parseNetflowV9Datagram(mock.buildV9DataDatagram(1, { includeTemplate: true }));

  // …and a DIFFERENT source (SourceID=2) reusing template id 260 must NOT be
  // decoded with source 1's cached template. Build it by patching the header.
  const dgram = mock.buildV9DataDatagram(2); // data-only, SourceID=1 → decodes fine
  check('same-source data-only still decodes', parseNetflowV9Datagram(dgram).length === 2);

  const otherSource = Buffer.from(dgram);
  otherSource.writeUInt32BE(2, 16); // SourceID := 2 (no template ever seen for it)
  check('different SourceID with same templateId → no flows', parseNetflowV9Datagram(otherSource).length === 0);
}

// ── Test 5: dispatcher — sFlow and NetFlow share the port, sniffed correctly ─
console.log('test 5: dispatcher (content-based)');
{
  const sf = parseFlowDatagram(sflowMock.buildDatagram(1));
  check(`sFlow datagram still parses via dispatcher (${sf.length} flows)`, sf.length === 3);

  clearNetflowV9TemplateCache();
  const nf5 = parseFlowDatagram(mock.buildV5Datagram(1));
  check('NetFlow v5 datagram parses via dispatcher', nf5.length === 3);

  parseNetflowV9Datagram(mock.buildV9DataDatagram(1, { includeTemplate: true }));
  const nf9 = parseFlowDatagram(mock.buildV9DataDatagram(2));
  check('NetFlow v9 datagram parses via dispatcher', nf9.length === 2);

  // A NetFlow v5 header (u32@0 = 0x0005_0003) must NOT be misread as sFlow:
  // its agentAddrType slot is count<<16 | sysUptime — never 1 or 2.
  check('v5 not confused with sFlow', parseFlowDatagram(mock.buildV5Datagram(9)).length === 3);
}

// ── Test 6: garbage + truncated input never throws ──────────────────────────
console.log('test 6: garbage + truncated input');
{
  check('empty buffer → no flows (v5)', parseNetflowV5Datagram(Buffer.alloc(0)).length === 0);
  check('short buffer → no flows (v9)', parseNetflowV9Datagram(Buffer.from([9, 0])).length === 0);

  const v5 = mock.buildV5Datagram(1);
  for (const cut of [23, 48, 70, 167]) {
    let ok = true;
    try { parseNetflowV5Datagram(v5.subarray(0, cut)); } catch { ok = false; }
    check(`v5 truncated at ${cut} bytes does not throw`, ok);
  }

  const v9 = mock.buildV9DataDatagram(1, { includeTemplate: true });
  for (const cut of [19, 24, 40, 60, 113]) {
    let ok = true;
    try { parseNetflowV9Datagram(v9.subarray(0, cut)); } catch { ok = false; }
    check(`v9 truncated at ${cut} bytes does not throw`, ok);
  }

  // Wrong version in the header → ignored.
  const bad = mock.buildV5Datagram(1);
  bad.writeUInt16BE(7, 0);
  check('wrong v5 version → no flows', parseNetflowV5Datagram(bad).length === 0);

  // Random garbage through the dispatcher → ignored.
  const junk = Buffer.from([9, 9, 9, 9, 1, 2, 3, 4, 5, 6, 7, 8]);
  check('random garbage via dispatcher → no flows', parseFlowDatagram(junk).length === 0);
}

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
