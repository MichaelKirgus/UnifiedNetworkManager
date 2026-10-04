/**
 * NetFlow v5 + v9 (RFC 3954) datagram parsers — pure, side-effect-free.
 *
 * Wire format verified against scapy/layers/netflow.py and RFC 3954 §5:
 *
 * v5 header (24 bytes):
 *   version u16=5 | count u16 | sysUptime u32 | unixSecs u32 | unixNsecs u32
 *   | flowSequence u32 | engineType u8 | engineId u8 | samplingInterval u16.
 * v5 record (48 bytes × count):
 *   srcIP(4) dstIP(4) nextHop(4) inputIf(2) outputIf(2) dPkts(4) dOctets(4)
 *   first(4) last(4) srcPort(2) dstPort(2) pad1(1) tcpFlags(1) proto(1) tos(1)
 *   srcAS(2) dstAS(2) srcMask(1) dstMask(1) pad2(2).
 * `samplingInterval` is a "1 in N" divisor (0 = unsampled → rate 1); dOctets/
 * dPkts are the SAMPLED counts, so reported bytes × interval ≈ true volume.
 *
 * v9 header (20 bytes — NO unixNsecs, unlike v5):
 *   version u16=9 | count u16 | sysUptime u32 | unixSecs u32
 *   | packageSequence u32 | SourceID u32.
 * Payload = a sequence of flow sets: setId u16 + length u16 (length includes
 * the 4-byte set header). setId 0 = Template Flow Set (one or more templates),
 * setId 2 = Options Template Flow Set, any other id = Data Flow Set whose
 * records are decoded with the template of that id. Templates are scoped per
 * SourceID and cached module-wide so data-only datagrams decode without a
 * repeated template set.
 *
 * Template entry: templateId u16 | fieldCount u16 | per-field (fieldType u16
 * + fieldLength u16); the top bit of fieldType marks an enterprise type, in
 * which case a 4-byte enterprise number follows.
 */

import { readRawIp4, readRawIp6, type ParsedFlow } from './ipHelpers';

// ── NetFlow v5 ──────────────────────────────────────────────────────────────

/** Parse one NetFlow v5 datagram (24B header + 48B records). Never throws. */
export function parseNetflowV5Datagram(buf: Buffer): ParsedFlow[] {
  const flows: ParsedFlow[] = [];
  if (buf.length < 24) return flows;
  if (buf.readUInt16BE(0) !== 5) return flows;

  const count = buf.readUInt16BE(2);
  // samplingInterval u16@22: "1 in N" divisor; 0 means unsampled.
  const sampleRate = Math.max(1, buf.readUInt16BE(22));

  let off = 24;
  for (let i = 0; i < count && off + 48 <= buf.length; i++) {
    const srcIp = readRawIp4(buf, off);
    const dstIp = readRawIp4(buf, off + 4);
    if (!srcIp || !dstIp) break; // truncated — stop safely
    flows.push({
      srcIp,
      dstIp,
      proto: buf[off + 38],
      srcPort: buf.readUInt16BE(off + 32),
      dstPort: buf.readUInt16BE(off + 34),
      bytes: buf.readUInt32BE(off + 20), // dOctets — reported (sampled) count
      packets: buf.readUInt32BE(off + 16), // dPkts
      sampleRate,
    });
    off += 48;
  }
  return flows;
}

// ── NetFlow v9 ──────────────────────────────────────────────────────────────

interface V9Field { type: number; length: number }

/** Module-level template cache, keyed `${sourceId}:${templateId}`. */
const templateCache = new Map<string, V9Field[]>();

/** Drop all cached v9 templates (test hook). */
export function clearNetflowV9TemplateCache(): void {
  templateCache.clear();
}

/** Read `fieldCount` field entries; returns the fields + offset past them. */
function readTemplateFields(buf: Buffer, off: number, end: number, fieldCount: number): { fields: V9Field[]; next: number } | null {
  const fields: V9Field[] = [];
  for (let i = 0; i < fieldCount; i++) {
    if (off + 4 > end) return null; // truncated — stop safely
    const rawType = buf.readUInt16BE(off);
    const length = buf.readUInt16BE(off + 2);
    off += 4;
    let type = rawType & 0x7fff;
    if (rawType & 0x8000) {
      // Enterprise bit set — a 4-byte enterprise number follows the entry.
      if (off + 4 > end) return null;
      off += 4;
    }
    fields.push({ type, length });
  }
  return { fields, next: off };
}

/** Decode one v9 data record against a template. Returns null when the tuple can't be normalized. */
function decodeV9Record(buf: Buffer, recStart: number, recEnd: number, fields: V9Field[]): ParsedFlow | null {
  let off = recStart;
  let srcIp: string | null = null;
  let dstIp: string | null = null;
  let proto = -1;
  let bytes = 0;
  let packets = 0;
  let sampleRate = 1;
  let srcPort = 0;
  let dstPort = 0;

  for (const f of fields) {
    if (off + f.length > recEnd || off + f.length > buf.length) return null; // truncated — stop safely
    switch (f.type) {
      case 8: srcIp = readRawIp4(buf, off); break; // IPV4_SRC_ADDR
      case 27: srcIp = readRawIp6(buf, off); break; // IPV6_SRC_ADDR
      case 12: dstIp = readRawIp4(buf, off); break; // IPV4_DST_ADDR
      case 28: dstIp = readRawIp6(buf, off); break; // IPV6_DST_ADDR
      case 4: if (f.length >= 1) proto = buf[off]; break; // PROTOCOL
      case 10: if (f.length >= 2) srcPort = buf.readUInt16BE(off); break; // L4_SRC_PORT
      case 11: if (f.length >= 2) dstPort = buf.readUInt16BE(off); break; // L4_DST_PORT
      case 1: if (f.length >= 4) bytes += buf.readUInt32BE(off); break; // IN_BYTES
      case 23: if (f.length >= 4) bytes += buf.readUInt32BE(off); break; // OUT_BYTES
      case 2: if (f.length >= 4) packets += buf.readUInt32BE(off); break; // IN_PKTS
      case 24: if (f.length >= 4) packets += buf.readUInt32BE(off); break; // OUT_PKTS
      case 34: if (f.length >= 4) sampleRate = Math.max(1, buf.readUInt32BE(off)); break; // SAMPLING_INTERVAL
      case 50: if (f.length >= 4) sampleRate = Math.max(1, buf.readUInt32BE(off)); break; // FLOW_SAMPLER_RANDOM_INTERVAL
      default: break; // unknown/irrelevant field — skip by length
    }
    off += f.length;
  }

  if (!srcIp || !dstIp || proto < 0) return null;
  return { srcIp, dstIp, proto, srcPort, dstPort, bytes, packets, sampleRate };
}

/** Parse one NetFlow v9 datagram (20B header + flow sets). Never throws. */
export function parseNetflowV9Datagram(buf: Buffer): ParsedFlow[] {
  const flows: ParsedFlow[] = [];
  if (buf.length < 20) return flows;
  if (buf.readUInt16BE(0) !== 9) return flows;

  // SourceID scopes the template cache — different exporters/observation
  // domains may reuse template ids independently.
  const sourceId = buf.readUInt32BE(16);

  let off = 20;
  while (off + 4 <= buf.length) {
    const setId = buf.readUInt16BE(off);
    const setLen = buf.readUInt16BE(off + 2);
    if (setLen < 4 || off + setLen > buf.length) break; // truncated — stop safely
    const setStart = off + 4;
    const setEnd = off + setLen;

    if (setId === 0) {
      // Template Flow Set: one or more template entries.
      let t = setStart;
      while (t + 4 <= setEnd) {
        const templateId = buf.readUInt16BE(t);
        const fieldCount = buf.readUInt16BE(t + 2);
        if (fieldCount === 0 || t + 4 + fieldCount * 4 > setEnd) break; // malformed — stop safely
        const parsed = readTemplateFields(buf, t + 4, setEnd, fieldCount);
        if (!parsed) break;
        templateCache.set(`${sourceId}:${templateId}`, parsed.fields);
        t = parsed.next;
      }
    } else if (setId === 2) {
      // Options Template Flow Set — not needed for flow normalization. Skip.
    } else {
      // Data Flow Set — decode records with the cached template of this id.
      const fields = templateCache.get(`${sourceId}:${setId}`);
      if (fields) {
        const recordLen = fields.reduce((s, f) => s + f.length, 0);
        if (recordLen > 0) {
          for (let r = setStart; r + recordLen <= setEnd; r += recordLen) {
            const flow = decodeV9Record(buf, r, r + recordLen, fields);
            if (flow) flows.push(flow);
          }
        }
      }
      // Unknown template id → skip the whole set silently.
    }

    off = setEnd;
  }
  return flows;
}
