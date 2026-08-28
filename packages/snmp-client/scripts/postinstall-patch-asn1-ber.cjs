/**
 * Postinstall patch for asn1-ber (transitive dep of net-snmp).
 *
 * Real devices encode Counter64 per RFC 2578 as tag 0x04 + exactly 8 bytes.
 * asn1-ber's readInt() throws "Integer not representable as javascript number"
 * for any such value above Number.MAX_SAFE_INTEGER, which would crash the whole
 * session on the first large ifHCInOctets/ifHCOutOctets counter. (The npm
 * net-snmp agent's own mock encodes Counter64 with a non-standard tag 70, so
 * this bug is invisible in-process — only real devices trigger it.)
 *
 * The patch makes readInt() return the decimal STRING for integers whose value
 * exceeds MAX_SAFE_INTEGER (only possible for ≥8-byte values). net-snmp's
 * Counter64 path (readUint64) already expects a decimal string, and no other
 * SNMP PDU field is ever that wide. Idempotent — safe to run on every install.
 */
const fs = require('fs');
const path = require('path');

function patch(file) {
  const src = fs.readFileSync(file, 'utf8');
  if (src.includes('UNM-COUNTER64-PATCH')) return false; // already patched

  // Whitespace-tolerant: the file uses tabs in some versions.
  const needle = /if \( ! Number\.isSafeInteger\(value\) \)\s*\n\s*throw InvalidAsn1Error\('Integer not representable as javascript number'\);/;
  if (!needle.test(src)) {
    console.warn('[snmp-client] asn1-ber patch: expected text not found — skipping (check asn1-ber version)');
    return false;
  }

  const replacement = `if ( ! Number.isSafeInteger(value) ) {
\t// UNM-COUNTER64-PATCH: RFC 2578 Counter64 arrives as an 8-byte integer value.
\t// Values above MAX_SAFE_INTEGER cannot be JS numbers — return the decimal
\t// string instead of throwing (net-snmp's readUint64 expects exactly that).
\tlet big = 0n;
\tfor (var j = 0; j < this.length; j++) big = (big << 8n) + BigInt(this._buf[o + j]);
\treturn big.toString(10);
}`;

  fs.writeFileSync(file, src.replace(needle, replacement));
  console.log('[snmp-client] patched asn1-ber readInt for RFC 2578 Counter64');
  return true;
}

const candidates = [
  path.join(__dirname, '..', 'node_modules', 'asn1-ber', 'lib', 'ber', 'reader.js'),
];

// When installed as a file: dependency inside a plugin's node_modules, npm may
// hoist or nest asn1-ber — also check the parent tree.
const here = __dirname; // packages/snmp-client/scripts
for (let dir = path.dirname(here); ; dir = path.dirname(dir)) {
  candidates.push(path.join(dir, 'node_modules', 'asn1-ber', 'lib', 'ber', 'reader.js'));
  if (dir === path.dirname(dir) || !fs.existsSync(path.join(dir, 'package.json'))) break;
}

let patched = false;
for (const file of candidates) {
  try {
    if (fs.existsSync(file)) patched = patch(file) || patched;
  } catch (err) {
    console.warn(`[snmp-client] asn1-ber patch failed for ${file}:`, err.message);
  }
}

if (!patched) {
  // Not fatal locally (dev may run before install completes), but warn loudly.
  console.warn('[snmp-client] asn1-ber Counter64 patch not applied — Counter64 values > 2^53 will fail');
}
