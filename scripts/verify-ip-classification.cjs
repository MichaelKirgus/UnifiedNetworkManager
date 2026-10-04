#!/usr/bin/env node
/**
 * Pure unit tests for api/src/utils/ipClassification.ts — no database needed.
 * Run: node scripts/verify-ip-classification.cjs   (from repo root)
 */

const path = require('node:path');
const { execFileSync } = require('node:child_process');

// Compile the TS module to a temp CJS file and load it.
const fs = require('node:fs');
const tsSrc = path.join(__dirname, '..', 'api', 'src', 'utils', 'ipClassification.ts');
// tsc lives in api/node_modules (no root node_modules). Compile to a temp dir.
const tscJs = require.resolve('typescript/lib/tsc.js', { paths: [path.join(__dirname, '..', 'api')] });
const tmpDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'unm-ipclass-'));
execFileSync(process.execPath, [
  tscJs,
  tsSrc,
  '--outDir', tmpDir,
  '--module', 'commonjs',
  '--target', 'es2020',
  '--moduleResolution', 'node',
  '--skipLibCheck',
], { stdio: 'pipe' });

const { parseCidrList, classifyIp } = require(path.join(tmpDir, 'ipClassification.js'));
fs.rmSync(tmpDir, { recursive: true, force: true });

let passed = 0;
let failed = 0;
function check(name, cond) {
  if (cond) { passed += 1; console.log(`  ok   ${name}`); }
  else { failed += 1; console.error(`  FAIL ${name}`); }
}

const RFC1918 = parseCidrList('10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16');
const EMPTY = { internal: [], external: [] };

console.log('\nparseCidrList');
{
  const e = parseCidrList('10.0.0.0/8, 192.168.1.0/24');
  check('parses two entries', e.length === 2);
  check('prefixLen kept', e[0].prefixLen === 8 && e[1].prefixLen === 24);
  check('bare IP → /32', parseCidrList('8.8.8.8')[0].prefixLen === 32);
  check('empty string → []', parseCidrList('').length === 0);
  check('whitespace segments ok', parseCidrList(' 10.0.0.0/8 , ').length === 1);
  // NOTE: a bare IP is VALID — it parses as /32 (documented behaviour).
  for (const bad of ['999.0.0.0/8', '10.0.0.0/33', 'abc']) {
    let threw = false;
    try { parseCidrList(bad); } catch { threw = true; }
    check(`throws on ${JSON.stringify(bad)}`, threw);
  }
}

console.log('\nclassifyIp — precedence');
{
  const net192 = [{ net: 0xc0a8_0100, mask: 0xffff_ff00, prefixLen: 24, deviceId: 'dev-a' }]; // 192.168.1.0/24

  check('exact hit wins over everything',
    classifyIp('8.8.8.8', 'dev-x', [], { internal: RFC1918, external: parseCidrList('8.8.8.8/32') })
      .deviceId === 'dev-x');

  // An explicit carve-out beats the BROAD matches (inventoried network,
  // internal ranges) — otherwise flowExternalRanges is useless for any IP
  // inside an inventoried LAN. Exact inventory hits still win over it.
  check('external carve-out beats inventoried network',
    classifyIp('192.168.1.50', null, net192, { internal: RFC1918, external: parseCidrList('192.168.1.0/24') }).cls === 'internet');

  check('exact hit still wins over carve-out',
    classifyIp('192.168.1.50', 'dev-a', net192, { internal: RFC1918, external: parseCidrList('192.168.1.0/24') }).cls === 'internal');

  check('external carve-out beats internal range',
    classifyIp('10.5.5.5', null, [], { internal: RFC1918, external: parseCidrList('10.5.0.0/16') })
      .cls === 'internet');

  check('RFC1918 default → internal (no inventory)',
    classifyIp('172.16.4.4', null, [], { internal: RFC1918, external: [] }).cls === 'internal');

  check('public IPv4 with no match → internet',
    classifyIp('1.2.3.4', null, [], EMPTY).cls === 'internet');

  check('link-local → unknown', classifyIp('169.254.10.10', null, [], EMPTY).cls === 'unknown');
  check('multicast → unknown', classifyIp('224.0.0.1', null, [], EMPTY).cls === 'unknown');
  check('IPv6 → unknown (v1 simplification)', classifyIp('fe80::1', null, [], EMPTY).cls === 'unknown');

  const r = classifyIp('192.168.1.50', null, net192, { internal: RFC1918, external: [] });
  check('network match carries deviceId', r.cls === 'internal' && r.deviceId === 'dev-a');

  // Longest-prefix wins between two overlapping inventory networks.
  const wider = [{ net: 0xc0a8_0000, mask: 0xffff_0000, prefixLen: 16, deviceId: 'wide' }];
  check('longest-prefix wins', classifyIp('192.168.1.50', null, [...net192, ...wider], EMPTY).deviceId === 'dev-a');

  // Carve-out semantics: an external range INSIDE the internal default makes
  // that subnet internet even though RFC1918 says internal.
  check('carved-out subnet → internet despite RFC1918',
    classifyIp('192.168.50.7', null, [], { internal: RFC1918, external: parseCidrList('192.168.50.0/24') }).cls === 'internet');
}

console.log(`\n${failed === 0 ? 'ALL PASS' : `${failed} FAILED`}: ${passed}/${passed + failed}`);
process.exit(failed === 0 ? 0 : 1);
