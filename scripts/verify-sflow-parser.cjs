#!/usr/bin/env node
/**
 * Unit test for the flow-collector sFlow parser (plugins/flow-collector/src/sflowParser.ts).
 *
 * Feeds datagrams built by scripts/mock-sflow.cjs (the same byte construction a
 * real exporter would produce) through the compiled parser and asserts every
 * expected flow is extracted with correct IPs, protocol and estimated bytes.
 *
 * Run:  node scripts/verify-sflow-parser.cjs     (builds the plugin first if needed)
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');
const PLUGIN_DIR = path.join(ROOT, 'plugins', 'flow-collector');
const PARSER_JS = path.join(PLUGIN_DIR, 'dist', 'src', 'sflowParser.js');

// Build the plugin if the compiled parser is missing.
if (!fs.existsSync(PARSER_JS)) {
  console.log('[verify-sflow] building flow-collector plugin…');
  execSync('npx tsc', { cwd: PLUGIN_DIR, stdio: 'inherit' });
}

const { parseSflowDatagram } = require(PARSER_JS);
const mock = require(path.join(ROOT, 'scripts', 'mock-sflow.cjs'));

let failures = 0;
function check(label, cond) {
  if (cond) console.log(`  ok   ${label}`);
  else { failures += 1; console.error(`  FAIL ${label}`); }
}

// ── Test 1: standard mock datagram (2×IPv4 + 1×IPv6 flows, 1 counter sample) ─
console.log('test 1: standard mock datagram');
{
  const dgram = mock.buildDatagram(1);
  const flows = parseSflowDatagram(dgram);

  check(`extracts 3 flows (got ${flows.length})`, flows.length === 3);

  const v4tcp = flows.find((f) => f.srcIp === '192.168.1.50' && f.dstIp === '192.168.1.10');
  check('internal→internal TCP flow present', !!v4tcp);
  if (v4tcp) {
    check(`proto=6 tcp (got ${v4tcp.proto})`, v4tcp.proto === 6);
    check(`reportedBytes=1500 (rate applied once by API rollup) (got ${v4tcp.bytes})`, v4tcp.bytes === 1_500);
    check('sampleRate=100', v4tcp.sampleRate === 100);
  }

  const v4udp = flows.find((f) => f.srcIp === '192.168.1.50' && f.dstIp === '8.8.8.8');
  check('internal→internet UDP flow present', !!v4udp);
  if (v4udp) {
    check(`proto=17 udp (got ${v4udp.proto})`, v4udp.proto === 17);
    check(`reportedBytes=800 (got ${v4udp.bytes})`, v4udp.bytes === 800);
  }

  const v6 = flows.find((f) => f.srcIp === '2001:db8::50');
  check('IPv6 flow present', !!v6);
  if (v6) {
    check(`dst=2001:4860:4860::8888 (got ${v6.dstIp})`, v6.dstIp === '2001:4860:4860::8888');
    check(`reportedBytes=600 (got ${v6.bytes})`, v6.bytes === 600);
  }

  // The counter sample must be skipped WITHOUT corrupting the flow records.
  check('counter sample did not produce spurious flows', !flows.some((f) => f.srcIp === '0.0.0.0'));
}

// ── Test 2: custom IPs + sampling rate (env-independent via opts) ────────────
console.log('test 2: custom ips + sample rate');
{
  const dgram = mock.buildDatagram(7, {
    srcIp: [10, 0, 0, 5],
    dstInternalIp: [10, 0, 0, 9],
    dstInternetIp: [1, 1, 1, 1],
    sampleRate: 64,
  });
  const flows = parseSflowDatagram(dgram);

  const f = flows.find((x) => x.srcIp === '10.0.0.5' && x.dstIp === '10.0.0.9');
  check('custom internal flow present', !!f);
  if (f) {
    check(`reportedBytes=1500 (rate applied once by API rollup) (got ${f.bytes})`, f.bytes === 1_500);
    check('sampleRate=64', f.sampleRate === 64);
  }
}

// ── Test 3: non-sFlow / malformed input is ignored, never throws ─────────────
console.log('test 3: garbage + truncated input');
{
  check('empty buffer → no flows', parseSflowDatagram(Buffer.alloc(0)).length === 0);
  check('short buffer → no flows', parseSflowDatagram(Buffer.from([1, 2, 3])).length === 0);
  check('wrong version → no flows', (() => {
    const b = mock.buildDatagram(1);
    b.writeUInt32BE(99, 0); // corrupt version
    return parseSflowDatagram(b).length === 0;
  })());
  check('truncated datagram does not throw', (() => {
    try {
      const full = mock.buildDatagram(1);
      parseSflowDatagram(full.subarray(0, 40)); // cut mid-header
      return true;
    } catch { return false; }
  })());
}

console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
