/**
 * Shared raw-IP decoding helpers + normalized flow type for the flow parsers
 * (sFlow, NetFlow v5/v9). Pure functions over Buffers — no I/O, unit-testable.
 */

/** One normalized flow extracted from a datagram (any protocol). */
export interface ParsedFlow {
  srcIp: string;
  dstIp: string;
  proto: number;
  /**
   * REPORTED (sampled) bytes — the byte count as observed by the exporter
   * (packet/frame length for sFlow, dOctets for NetFlow v5). The sampling
   * rate is carried separately in `sampleRate`; the API rollup applies it
   * exactly once when computing estBytes. Do NOT pre-multiply here — that
   * would double-count the rate.
   */
  bytes: number;
  packets: number;
  sampleRate: number;
}

/** Read a raw IPv4 address (4 bytes) from the buffer at offset. */
export function readRawIp4(buf: Buffer, off: number): string | null {
  if (off + 4 > buf.length) return null;
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

/** Compress an IPv6 group list to its canonical RFC 5952 form (longest zero run → "::"). */
export function compressIpv6(groups: number[]): string {
  const hex = groups.map((g) => g.toString(16));
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen += 1;
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  // RFC 5952: only compress runs of length ≥ 2 (a single zero group stays "0").
  if (bestLen < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

/** Read a raw IPv6 address (16 bytes) from the buffer at offset. */
export function readRawIp6(buf: Buffer, off: number): string | null {
  if (off + 16 > buf.length) return null;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(off + i));
  return compressIpv6(groups);
}
