/**
 * @unm/plugin-test-kit — pure-JS SNMP v2c agent mock (RFC 3416 wire format).
 *
 * Answers GET and GetBulk requests over UDP against a small in-memory MIB, so
 * the LANCOM plugins (lancom-lcos / lancom-sx / lancom-lx) can be exercised
 * without a native SNMP stack or a privileged port. The client
 * (@unm/snmp-client → net-snmp) sends:
 *   - probes as plain GET of one scalar;
 *   - inventory as ONE combined GetBulk stream (nonRepeaters=0, maxReps per PDU),
 *     one varbind per subtree cursor.
 * We emit standards-compliant SNMPv2c responses: a Response-PDU whose varbinds
 * are in ascending OID order — for each request cursor, up to `maxRepetitions`
 * successive getNext results (global MIB order), terminated by an EndOfMibView
 * error varbind once the walk runs past the end of the MIB. The client filters
 * each cursor's varbinds back into its own subtree via oidInSubtree(), so a
 * cursor whose global-next leaks into another branch is simply dropped there.
 *
 * Value types we emit (matching @unm/snmp-client normalizeValue):
 *   'int'  → Integer32 (tag 0x02)            → number
 *   'str'  → OCTET STRING / DisplayString    → string (printable ASCII)
 *   'c64'  → Counter64 (tag 70, 8-byte BE)   → bigint
 */

import dgram from 'node:dgram';

// ── BER encoding helpers ───────────────────────────────────────────────────────

/** Base-128 encode one sub-id (high bit set on all but the last byte). */
function base128(n) {
  if (n === 0) return [0];
  const bytes = [];
  let x = n >>> 0;
  bytes.unshift(x & 0x7f);
  x >>>= 7;
  while (x > 0) {
    bytes.unshift((x & 0x7f) | 0x80);
    x >>>= 7;
  }
  return bytes;
}

/** Encode a dotted OID string into its BER content octets. */
function encodeOidContent(oidStr) {
  const parts = oidStr.replace(/^\./, '').split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) out.push(...base128(parts[i]));
  return Buffer.from(out);
}

/** Wrap content in a BER TLV with the given tag byte. */
function tlv(tag, content) {
  const len = content.length;
  if (len < 0x80) return Buffer.concat([Buffer.from([tag, len]), content]);
  const lb = [];
  let x = len;
  while (x > 0) {
    lb.unshift(x & 0xff);
    x >>>= 8;
  }
  return Buffer.concat([Buffer.from([tag, 0x80 | lb.length]), Buffer.from(lb), content]);
}

/** OID varbind name TLV (tag 0x06). */
function oidTlv(oidStr) {
  return tlv(0x06, encodeOidContent(oidStr));
}

/** Signed 32-bit INTEGER (tag 0x02), big-endian. */
function int32(v) {
  const b = Buffer.alloc(4);
  b.writeInt32BE(Math.trunc(v) | 0, 0);
  return tlv(0x02, b);
}

/** OCTET STRING / DisplayString (tag 0x04). */
function octetStr(s) {
  const b = Buffer.isBuffer(s) ? s : Buffer.from(String(s), 'utf8');
  return tlv(0x04, b);
}

/** Counter64 — tag 70 (0x46), 8-byte big-endian. */
function counter64(v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v), 0);
  return tlv(0x46, b);
}

/** Encode one typed MIB value into its BER TLV. */
function encodeValue(val) {
  switch (val.type) {
    case 'int': return int32(val.data);
    case 'c64': return counter64(val.data);
    default: return octetStr(val.data); // 'str' / DisplayString
  }
}

/** A normal varbind SEQUENCE { OID, value }. */
function varbind(oid, val) {
  return tlv(0x30, Buffer.concat([oidTlv(oid), encodeValue(val)]));
}

// SNMPv2c error varbind tags (net-snmp ObjectType == wire tag byte):
const TAG_NO_SUCH_OBJECT = 0x80;
const TAG_NO_SUCH_INSTANCE = 0x81;
const TAG_END_OF_MIB_VIEW = 0x82;

/**
 * An error varbind: SEQUENCE { OID name, <tag> 0 }. The value is a bare tag byte
 * with zero length (RFC 3416) — net-snmp's readVarbinds peeks the tag and maps it
 * to NoSuchObject / NoSuchInstance / EndOfMibView via ObjectType.
 */
function errorVarbind(nameOid, tag = TAG_END_OF_MIB_VIEW) {
  return tlv(0x30, Buffer.concat([oidTlv(nameOid), Buffer.from([tag, 0])]));
}

// ── BER decoding helpers (for incoming requests) ───────────────────────────────

/** Read a BER TLV at `off`; returns [tag, contentBuffer, nextOffset]. */
function readTlv(buf, off) {
  const tag = buf[off];
  let len = buf[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < nBytes; i++) len = len * 256 + buf[p++];
  }
  return [tag, buf.slice(p, p + len), p + len];
}

/** Decode a dotted OID from its BER content octets. */
function decodeOidContent(content) {
  const parts = [];
  if (content.length === 0) return '';
  parts.push(Math.floor(content[0] / 40), content[0] % 40);
  let cur = 0;
  for (let i = 1; i < content.length; i++) {
    cur = (cur << 7) | (content[i] & 0x7f);
    if (!(content[i] & 0x80)) {
      parts.push(cur);
      cur = 0;
    }
  }
  return '.' + parts.join('.');
}

/** Read an INTEGER TLV's value as a signed 32-bit number. */
function readInt(buf, off) {
  const [, content] = readTlv(buf, off);
  let v = 0;
  for (let i = 0; i < content.length; i++) v = v * 256 + content[i];
  // Two's-complement if the high bit is set.
  if (content[0] & 0x80) v -= Math.pow(2, content.length * 8);
  return v;
}

/** Parse an incoming SNMPv1/v2c request datagram (GET / GetNext / GetBulk). */
function parseRequest(buf) {
  // SEQUENCE { INTEGER version, OCTET STRING community, PDU }
  const [, seq] = readTlv(buf, 0);
  let off = 0;
  const versionTlv = seq.slice(0, tlvSize(seq, 0)); // full TLV — echoed verbatim in the response
  off += tlvSize(seq, 0); // skip version TLV
  const [, community] = readTlv(seq, off);
  off += tlvSize(seq, off); // skip community TLV
  const [pduTag, pduContent] = readTlv(seq, off);

  let p = 0;
  const requestIdRaw = pduContent.slice(p, p + tlvSize(pduContent, p)); // int #1: requestId (echoed verbatim)
  p += tlvSize(pduContent, p);

  let maxRepetitions = 50;
  if (pduTag === 0xa5) {
    // GetBulkRequest: int #2 = non-repeaters (client always sends 0), int #3 = max-repetitions.
    p += tlvSize(pduContent, p); // skip non-repeaters
    maxRepetitions = readInt(pduContent, p); p += tlvSize(pduContent, p);
  } else {
    // GET / GetNext: int #2 = errorStatus (0), int #3 = errorIndex (0).
    p += tlvSize(pduContent, p);
    p += tlvSize(pduContent, p);
  }

  // SEQUENCE OF VarBind
  const [, vbList] = readTlv(pduContent, p);
  let q = 0;
  const varbinds = [];
  while (q < vbList.length) {
    const [, vb] = readTlv(vbList, q); q += tlvSize(vbList, q);
    const [nameTag, nameContent] = readTlv(vb, 0);
    varbinds.push({ oid: decodeOidContent(nameContent), tag: nameTag });
  }

  return {
    pduTag,
    versionTlv,
    community: community.toString('utf8'),
    requestIdRaw,
    maxRepetitions,
    varbinds,
  };
}

function tlvSize(buf, off) {
  let len = buf[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    for (let i = 0; i < nBytes; i++) p++;
    return p - off + len;
  }
  return p - off + len;
}

// ── MIB + getNext semantics ────────────────────────────────────────────────────

/** Split a dotted OID into numeric sub-ids for comparison. */
function oidParts(s) {
  return s.replace(/^\./, '').split('.').map(Number);
}

/** Lexicographic numeric compare of two dotted OIDs (negative/0/positive). */
function cmpOid(a, b) {
  const A = oidParts(a);
  const B = oidParts(b);
  const n = Math.max(A.length, B.length);
  for (let i = 0; i < n; i++) {
    const x = A[i] ?? -1;
    const y = B[i] ?? -1;
    if (x !== y) return x - y;
  }
  return 0;
}

/** First MIB entry whose OID is strictly greater than `cursor` (or null). */
function nextEntry(mib, cursor) {
  for (const e of mib) if (cmpOid(e.oid, cursor) > 0) return e;
  return null;
}

// ── Response builders ──────────────────────────────────────────────────────────

/** Build a full SNMPv2c Response datagram (tag 0xa2), echoing version + requestId verbatim. */
function buildResponse(req, varbindTlvs) {
  const vbList = tlv(0x30, Buffer.concat(varbindTlvs));
  const pdu = tlv(0xa2, Buffer.concat([req.requestIdRaw, int32(0), int32(0), vbList]));
  return Buffer.concat([tlv(0x30, Buffer.concat([req.versionTlv, octetStr(req.community), pdu]))]);
}

/** GET response: exact value per requested OID, else noSuchObject error varbind. */
function buildGetResponse(req, mib) {
  const vbs = req.varbinds.map((vb) => {
    const hit = mib.find((e) => e.oid === vb.oid);
    return hit ? varbind(hit.oid, hit.value) : errorVarbind(vb.oid, TAG_NO_SUCH_OBJECT);
  });
  return buildResponse(req, vbs);
}

/**
 * GetBulk response (RFC 3416). The client sends one cursor per subtree with
 * nonRepeaters=0; net-snmp regroups the flat response positionally — varbind at
 * index i belongs to cursor (i % N) — so we MUST emit in round-robin order:
 * for each of `maxRepetitions` rounds, advance EVERY still-active cursor by one
 * global getNext. A cursor that exhausts its MIB emits an EndOfMibView varbind
 * (named with the OID it was last at) and is dropped from later rounds. This
 * matches net-snmp's own Agent.getBulkRequest emission exactly.
 */
function buildGetBulkResponse(req, mib) {
  const cursors = req.varbinds.map((c) => c.oid); // current OID per cursor (mutated in place)
  const vbs = [];
  for (let round = 0; round < req.maxRepetitions; round++) {
    let anyEom = false;
    // Advance EVERY cursor by one global getNext this round — the response must
    // stay N-aligned (one varbind per request cursor) or net-snmp's positional
    // regrouping (index i → cursor i % N) scrambles. A cursor that exhausts its
    // MIB emits an EndOfMibView (named with the OID it was last at).
    for (let i = 0; i < cursors.length; i++) {
      const e = nextEntry(mib, cursors[i]);
      if (!e) {
        vbs.push(errorVarbind(cursors[i], TAG_END_OF_MIB_VIEW));
        anyEom = true;
      } else {
        vbs.push(varbind(e.oid, e.value));
        cursors[i] = e.oid;
      }
    }
    // net-snmp stops the whole response after the round in which ANY cursor hit
    // EOM (the client re-requests still-active cursors in a follow-up PDU).
    if (anyEom) break;
  }
  return buildResponse(req, vbs);
}

// ── Mock entry point ───────────────────────────────────────────────────────────

/**
 * Starts a pure-JS SNMP v2c agent on an ephemeral loopback UDP port.
 *
 * @param {{mib: Array<{oid:string, value:{type:'int'|'str'|'c64', data:any}}>, community?: string}} opts
 *   `mib` is the in-memory MIB (need not be pre-sorted — it's sorted here).
 *   `community` (default 'public') is accepted verbatim; any other community is
 *   answered with an empty response so probes read as "no such object".
 * @returns {Promise<{port:number, host:string, requests:Array, stop:()=>Promise<void>}>}
 */
export function startSnmpMock({ mib, community = 'public' } = {}) {
  const rows = [...(mib ?? [])].sort((a, b) => cmpOid(a.oid, b.oid));
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const requests = [];
    sock.on('error', (err) => {
      if (!sock.__started) reject(err);
    });
    sock.on('message', (msg, rinfo) => {
      let req;
      try {
        req = parseRequest(msg);
      } catch {
        return; // malformed — a real agent would drop it too
      }
      requests.push({ pdu: req.pduTag === 0xa5 ? 'getbulk' : req.pduTag === 0xa0 ? 'get' : `tag${req.pduTag}`, oids: req.varbinds.map((v) => v.oid), community: req.community });
      if (req.community !== community) return; // wrong community → silence (client times out)
      const reply = req.pduTag === 0xa5 ? buildGetBulkResponse(req, rows) : buildGetResponse(req, rows);
      if (process.env.SNMP_DEBUG) {
        console.error('[snmpMock] REPLY (' + reply.length + 'b):');
        for (let i = 0; i < reply.length; i += 16) console.error('   ', String(i).padStart(4), reply.slice(i, i + 16).toString('hex').replace(/(.{2})/g, '$1 ').trim());
      }
      sock.send(reply, rinfo.port, rinfo.address);
    });
    sock.bind(0, '127.0.0.1', () => {
      sock.__started = true;
      const port = sock.address().port;
      resolve({
        port,
        host: '127.0.0.1',
        requests,
        stop: () => new Promise((res) => sock.close(() => res())),
      });
    });
  });
}
