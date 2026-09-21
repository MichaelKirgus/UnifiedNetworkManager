/**
 * Permanent test suite for the canonical IP math module (packages/plugin-sdk/src/ip.ts)
 * and its browser mirror (webapp/src/utils/ip.ts).
 *
 * Covers every export: parsing (zone ids, IPv6 '::' compression, embedded-IPv4
 * tails), CIDR containment / network-address math, and all scope predicates —
 * including the regression cases that motivated the module (ULA fc00::/7 being
 * misclassified as public by a first-hextet bit mask). Also verifies the webapp
 * mirror stays in sync with the SDK source.
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/verify-ip-math.ts
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  stripZoneId,
  ipFamily,
  ipv4ToInt,
  ipv4FromInt,
  ipv6ToWords,
  ipv6FromWords,
  ipv6ToBigInt,
  ipv6FromBigInt,
  splitCidr,
  ipInCidr,
  v4PrefixMatch,
  v6PrefixMatch,
  subnetOf,
  isPrivateIpv4,
  isLoopbackIpv4,
  isLinkLocalIpv4,
  isMulticastIpv4,
  isReservedIpv4,
  isUlaIpv6,
  isLoopbackIpv6,
  isLinkLocalIpv6,
  isMulticastIpv6,
  isDocumentationIpv6,
  isPublicIpv4,
  isPublicIpv6,
  ipScope,
} from '../packages/plugin-sdk/src/ip';

let passed = 0;
let failed = 0;

function check(name: string, cond: boolean): void {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// Parsing — zone ids + family detection
// ---------------------------------------------------------------------------

check('stripZoneId removes %zone', stripZoneId('fe80::1%eth0') === 'fe80::1');
check('stripZoneId trims whitespace', stripZoneId('  192.168.1.5  ') === '192.168.1.5');
check('stripZoneId leaves bare addresses alone', stripZoneId('8.8.8.8') === '8.8.8.8');

check('ipFamily v4', ipFamily('192.168.1.5') === 'v4');
check('ipFamily v6', ipFamily('fd00::1') === 'v6');
check('ipFamily null for DNS name', ipFamily('router.local') === null);
check('ipFamily null for garbage', ipFamily('300.1.2.3') === null);

// ---------------------------------------------------------------------------
// IPv4 int round-trips
// ---------------------------------------------------------------------------

check('ipv4ToInt basic', ipv4ToInt('192.168.1.5') === 0xc0a80105);
check('ipv4ToInt broadcast', ipv4ToInt('255.255.255.255') === 0xffffffff);
check('ipv4ToInt rejects >255 octet', ipv4ToInt('256.1.2.3') === null);
check('ipv4ToInt rejects short form', ipv4ToInt('192.168.1') === null);
check('ipv4FromInt round-trip', ipv4FromInt(ipv4ToInt('10.0.0.1')!) === '10.0.0.1');

// ---------------------------------------------------------------------------
// IPv6 word expansion / canonical compression
// ---------------------------------------------------------------------------

const words = (w: number[]): string => w.map((x) => x.toString(16)).join(':');

check('ipv6ToWords full form', words(ipv6ToWords('2001:db8:0:0:0:ff00:42:8')!) === '2001:db8:0:0:0:ff00:42:8');
check("ipv6ToWords leading '::'", words(ipv6ToWords('::abcd')!) === '0:0:0:0:0:0:0:abcd');
check("ipv6ToWords middle '::'", words(ipv6ToWords('1::2')!) === '1:0:0:0:0:0:0:2');
check("ipv6ToWords trailing '::'", words(ipv6ToWords('1:2::')!) === '1:2:0:0:0:0:0:0');
check('ipv6ToWords embedded IPv4 tail', words(ipv6ToWords('::ffff:192.0.2.1')!) === '0:0:0:0:0:ffff:c000:201');
check("ipv6ToWords rejects two '::'", ipv6ToWords('1::2::3') === null);
check("ipv6ToWords rejects over-full '::'", ipv6ToWords('1:2:3:4:5:6:7:8::9') === null);
check('ipv6ToWords rejects non-hex group', ipv6ToWords('g001::1') === null);
check('ipv6ToWords accepts zone id', words(ipv6ToWords('fe80::1%eth0')!) === 'fe80:0:0:0:0:0:0:1');

check('ipv6FromWords compresses leftmost longest run', ipv6FromWords([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]) === '2001:db8::1');
check('ipv6FromWords keeps single zero group', ipv6FromWords([0, 1, 2, 3, 4, 5, 6, 7]) === '0:1:2:3:4:5:6:7');
check('ipv6FromWords all zeros', ipv6FromWords([0, 0, 0, 0, 0, 0, 0, 0]) === '::');
check('ipv6FromWords no compression needed', ipv6FromWords([1, 2, 3, 4, 5, 6, 7, 8]) === '1:2:3:4:5:6:7:8');

check('ipv6ToBigInt round-trip', ipv6FromBigInt(ipv6ToBigInt('2001:db8::ff')!) === '2001:db8::ff');
check('ipv6ToBigInt embedded IPv4 tail value', ipv6ToBigInt('::ffff:192.0.2.1')! === 0xffffc0000201n);

// ---------------------------------------------------------------------------
// CIDR math
// ---------------------------------------------------------------------------

check('splitCidr v4', JSON.stringify(splitCidr('192.168.1.0/24')) === JSON.stringify({ net: '192.168.1.0', prefix: 24 }));
check('splitCidr v6', JSON.stringify(splitCidr('fd00::/64')) === JSON.stringify({ net: 'fd00::', prefix: 64 }));
check('splitCidr rejects bare address', splitCidr('192.168.1.5') === null);
check('splitCidr rejects oversized v4 prefix', splitCidr('192.168.1.0/33') === null);

check('ipInCidr v4 inside', ipInCidr('192.168.1.55', '192.168.1.0/24'));
check('ipInCidr v4 outside', !ipInCidr('192.168.2.55', '192.168.1.0/24'));
check('ipInCidr /0 matches everything', ipInCidr('8.8.8.8', '0.0.0.0/0'));
check('ipInCidr v6 inside', ipInCidr('fd00:0:0:0::5', 'fd00::/64') && ipInCidr('fd00::abcd', 'fd00::/8'));
check('ipInCidr v6 outside (2nd group differs)', !ipInCidr('fd00:1::5', 'fd00::/64'));
check('ipInCidr family mismatch is false', !ipInCidr('::ffff:192.168.1.5', '192.168.1.0/24'));
check('ipInCidr /128 exact match', ipInCidr('fd00::1', 'fd00::1/128') && !ipInCidr('fd00::2', 'fd00::1/128'));

check('v4PrefixMatch boundary', v4PrefixMatch(ipv4ToInt('192.168.1.255')!, ipv4ToInt('192.168.1.0')!, 24) && !v4PrefixMatch(ipv4ToInt('192.168.2.0')!, ipv4ToInt('192.168.1.0')!, 24));
check('v6PrefixMatch boundary', v6PrefixMatch(ipv6ToWords('febf::1')!, ipv6ToWords('fe80::1')!, 10) && !v6PrefixMatch(ipv6ToWords('fec0::1')!, ipv6ToWords('fe80::1')!, 10));

check('subnetOf v4', subnetOf('192.168.1.55', 24) === '192.168.1.0/24');
check('subnetOf v4 /32 host route', subnetOf('10.0.0.7', 32) === '10.0.0.7/32');
check('subnetOf v6 /64', subnetOf('fd00::abcd', 64) === 'fd00::/64' && subnetOf('fd00:0:0:1::abcd', 64) === 'fd00:0:0:1::/64');
check('subnetOf v6 mid-group mask (/126)', subnetOf('::abcd', 126) === '::abcc/126');
check('subnetOf null prefix', subnetOf('192.168.1.5', null) === null);
check('subnetOf invalid ip', subnetOf('not-an-ip', 24) === null);

// ---------------------------------------------------------------------------
// Scope predicates — IPv4
// ---------------------------------------------------------------------------

for (const a of ['10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1']) check(`isPrivateIpv4 ${a}`, isPrivateIpv4(a));
for (const a of ['172.15.0.1', '172.32.0.1', '192.169.1.1', '8.8.8.8']) check(`!isPrivateIpv4 ${a}`, !isPrivateIpv4(a));

check('isLoopbackIpv4 127.0.0.1', isLoopbackIpv4('127.0.0.1'));
check('isLoopbackIpv4 127.255.255.255', isLoopbackIpv4('127.255.255.255'));
check('!isLoopbackIpv4 128.0.0.1', !isLoopbackIpv4('128.0.0.1'));

check('isLinkLocalIpv4 169.254.1.1', isLinkLocalIpv4('169.254.1.1'));
check('!isLinkLocalIpv4 169.253.1.1', !isLinkLocalIpv4('169.253.1.1'));

check('isMulticastIpv4 224.0.0.1', isMulticastIpv4('224.0.0.1'));
check('isMulticastIpv4 239.255.255.255', isMulticastIpv4('239.255.255.255'));
check('!isMulticastIpv4 223.0.0.1', !isMulticastIpv4('223.0.0.1'));

check('isReservedIpv4 240.0.0.1', isReservedIpv4('240.0.0.1'));
check('isReservedIpv4 broadcast', isReservedIpv4('255.255.255.255'));
check('!isReservedIpv4 239.255.255.255', !isReservedIpv4('239.255.255.255'));

// ---------------------------------------------------------------------------
// Scope predicates — IPv6 (incl. the ULA regression case)
// ---------------------------------------------------------------------------

for (const a of ['fd00::1', 'fc00::1', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']) check(`isUlaIpv6 ${a}`, isUlaIpv6(a));
check('REGRESSION !isUlaIpv6 ffff:ffff::1 (first-hextet mask bug)', !isUlaIpv6('ffff:ffff::1'));
check('!isUlaIpv6 fe80::1', !isUlaIpv6('fe80::1'));

check('isLoopbackIpv6 ::1', isLoopbackIpv6('::1'));
check('!isLoopbackIpv6 unspecified ::', !isLoopbackIpv6('::'));

for (const a of ['fe80::1', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff']) check(`isLinkLocalIpv6 ${a}`, isLinkLocalIpv6(a));
check('!isLinkLocalIpv6 fec0::1', !isLinkLocalIpv6('fec0::1'));

for (const a of ['ff02::1', 'ff0e::1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']) check(`isMulticastIpv6 ${a}`, isMulticastIpv6(a));
check('!isMulticastIpv6 fe80::1', !isMulticastIpv6('fe80::1'));

check('isDocumentationIpv6 2001:db8::1', isDocumentationIpv6('2001:db8::1'));
check('!isDocumentationIpv6 2001:db9::1', !isDocumentationIpv6('2001:db9::1'));

// ---------------------------------------------------------------------------
// Public composites (what the import filters use)
// ---------------------------------------------------------------------------

for (const a of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) check(`isPublicIpv4 ${a}`, isPublicIpv4(a));
for (const a of ['10.0.0.1', '172.16.5.5', '192.168.1.1', '127.0.0.1', '169.254.1.1', '224.0.0.1', '255.255.255.255']) check(`!isPublicIpv4 ${a}`, !isPublicIpv4(a));

for (const a of ['2001:4860:4860::8888', '2606:4700:4700::1111']) check(`isPublicIpv6 ${a}`, isPublicIpv6(a));
check('REGRESSION !isPublicIpv6 fd00::1 (ULA was misclassified public)', !isPublicIpv6('fd00::1'));
for (const a of ['fe80::1', '::1', 'ff02::1', '2001:db8::1', '::']) check(`!isPublicIpv6 ${a}`, !isPublicIpv6(a));

// ---------------------------------------------------------------------------
// One-shot classifier
// ---------------------------------------------------------------------------

check("ipScope v4 private", ipScope('192.168.1.5') === 'private');
check("ipScope v4 loopback", ipScope('127.0.0.1') === 'loopback');
check("ipScope v4 link-local", ipScope('169.254.10.10') === 'link-local');
check("ipScope v4 multicast", ipScope('239.1.1.1') === 'multicast');
check("ipScope v4 reserved", ipScope('240.0.1.1') === 'reserved');
check("ipScope v4 public", ipScope('8.8.8.8') === 'public');

check("ipScope v6 ULA → private", ipScope('fd00::1') === 'private');
check("ipScope v6 loopback", ipScope('::1') === 'loopback');
check("ipScope v6 link-local", ipScope('fe80::1%eth0') === 'link-local');
check("ipScope v6 multicast", ipScope('ff02::1') === 'multicast');
check("ipScope v6 doc space → reserved", ipScope('2001:db8::1') === 'reserved');
check("ipScope v6 GUA public", ipScope('2001:4860:4860::8888') === 'public');

check('ipScope CIDR classifies network address only', ipScope('192.168.1.5/32') === 'private' && ipScope('fd00::abcd/126') === 'private');
check('ipScope null for DNS name', ipScope('router.local') === null);

// ---------------------------------------------------------------------------
// Webapp mirror stays in sync with the SDK source
// ---------------------------------------------------------------------------

function normalizedSource(file: string): string {
  const raw = readFileSync(path.resolve(process.cwd(), file), 'utf8');
  // Drop the leading doc comment (the two files intentionally differ only there)
  // and all blank lines, so formatting drift is what gets compared.
  return raw.replace(/^\/\*[\s\S]*?\*\/\s*/, '').split('\n').filter((l) => l.trim() !== '').join('\n');
}

const sdkSrc = normalizedSource('packages/plugin-sdk/src/ip.ts');
const webappSrc = normalizedSource('webapp/src/utils/ip.ts');
check('webapp mirror matches SDK source (modulo header comment)', sdkSrc === webappSrc);

// ---------------------------------------------------------------------------

console.log(`\nip-math: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
