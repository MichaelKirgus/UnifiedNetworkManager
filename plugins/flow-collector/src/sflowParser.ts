/**
 * sFlow v5 (RFC 3176) datagram parser — pure, side-effect-free.
 *
 * Wire format verified against gopacket/layers/sflow.go (DecodeFromBytes,
 * decodeFlowSample, decodeCounterSample, decodeSFlowIpv4Record,
 * decodeSFlowIpv6Record, decodeRawPacketFlowRecord). Kept in its own module so
 * it can be unit-tested without booting the plugin server.
 *
 * Datagram header (variable length):
 *   version u32 | agentAddrType u32 (1=v4, 2=v6) | agentAddr (4|16 bytes)
 *   | subAgentId u32 | seqNo u32 | uptime u32 | numSamples u32
 *
 * Each sample: format u32 (enterprise<<12 | type) + payload.
 *   Flow sample (type 1): sampleLen(4) seq(4) srcIdClass(4) samplingRate(4)
 *     pool(4) drops(4) inIf(4) outIf(4) numRecords(4) records…
 *   Counter sample (type 2): skipped record-by-record.
 *
 * Each record: format u32 (enterprise<<12 | recType) + length u32 + payload,
 * padded to a 4-byte boundary when advancing.
 *   IPv4 flow (recType 3): pktLen(4) proto(4) srcIP(4 raw) dstIP(4 raw)
 *     portSrc(4) portDst(4) tcpFlags(4) tos(4).
 *   IPv6 flow (recType 4): pktLen(4) proto(4) srcIP(16 raw) dstIP(16 raw)
 *     portSrc(4) portDst(4) tcpFlags(4) priority(4).
 *   Raw packet (recType 1): hdrProto(4) frameLen(4) stripped(4) hdrLen(4)
 *     headerBytes(hdrLen, padded to a 4-byte boundary).
 */

/** One normalized flow extracted from a datagram. */
export interface ParsedFlow {
  srcIp: string;
  dstIp: string;
  proto: number;
  /** Estimated bytes (packet/frame length × sampling rate). */
  bytes: number;
  packets: number;
  sampleRate: number;
}

/** Read a raw IPv4 address (4 bytes) from the buffer at offset. */
function readRawIp4(buf: Buffer, off: number): string | null {
  if (off + 4 > buf.length) return null;
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

/** Compress an IPv6 group list to its canonical RFC 5952 form (longest zero run → "::"). */
function compressIpv6(groups: number[]): string {
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
function readRawIp6(buf: Buffer, off: number): string | null {
  if (off + 16 > buf.length) return null;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(off + i));
  return compressIpv6(groups);
}

/** Parse an Ethernet frame header to extract src/dst IP + protocol. */
function parseEthernetHeader(hdr: Buffer): { srcIp: string; dstIp: string; proto: number } | null {
  if (hdr.length < 34) return null;
  const ethertype = hdr.readUInt16BE(12);
  if (ethertype === 0x800 && hdr.length >= 34) {
    // IPv4: proto at +9, srcIp at +12..15, dstIp at +16..19.
    const ipStart = 14;
    return {
      proto: hdr[ipStart + 9],
      srcIp: `${hdr[ipStart + 12]}.${hdr[ipStart + 13]}.${hdr[ipStart + 14]}.${hdr[ipStart + 15]}`,
      dstIp: `${hdr[ipStart + 16]}.${hdr[ipStart + 17]}.${hdr[ipStart + 18]}.${hdr[ipStart + 19]}`,
    };
  }
  if (ethertype === 0x86dd && hdr.length >= 54) {
    // IPv6: nextHeader at +6, srcIp at +8..23, dstIp at +24..39.
    const ipStart = 14;
    const groups: number[] = [];
    for (let i = 0; i < 16; i += 2) groups.push(hdr.readUInt16BE(ipStart + 8 + i));
    const srcIp = compressIpv6(groups);
    const groups6: number[] = [];
    for (let i = 0; i < 16; i += 2) groups6.push(hdr.readUInt16BE(ipStart + 24 + i));
    return { proto: hdr[ipStart + 6], srcIp, dstIp: compressIpv6(groups6) };
  }
  return null;
}

/**
 * Parses one sFlow datagram and returns every flow it contains. Non-sFlow or
 * malformed input yields an empty array (the UDP port may carry other traffic).
 */
export function parseSflowDatagram(buf: Buffer): ParsedFlow[] {
  const flows: ParsedFlow[] = [];

  // Minimum header: version(4) + agentAddrType(4) + agentAddr(4 min)
  //   + subAgentId(4) + seqNo(4) + uptime(4) + numSamples(4) = 28 bytes.
  if (buf.length < 28) return flows;

  const version = buf.readUInt32BE(0);
  if (version !== 1 && version !== 5) return flows; // not sFlow — ignore silently

  const agentAddrType = buf.readUInt32BE(4);
  const agentAddrLen = agentAddrType === 1 ? 4 : agentAddrType === 2 ? 16 : 0;
  if (agentAddrLen === 0 || buf.length < 8 + agentAddrLen + 16) return flows; // malformed header

  // After the agent address: subAgentId(4) seqNo(4) uptime(4), THEN numSamples.
  const numSamples = buf.readUInt32BE(8 + agentAddrLen + 12);
  let off = 8 + agentAddrLen + 16;

  for (let i = 0; i < numSamples && off + 4 <= buf.length; i++) {
    // Sample format field: top 20 bits = enterprise, bottom 12 bits = type.
    const sampleFormat = buf.readUInt32BE(off);
    const sampleType = sampleFormat & 0xfff;

    if (sampleType === 1) {
      // Flow sample — parse records within it.
      // Layout after format(4): sampleLen(4) seq(4) srcIdClass(4) samplingRate(4)
      //   pool(4) drops(4) inIf(4) outIf(4) numRecords(4) → records at +40 from sample start.
      if (off + 40 > buf.length) break;
      const samplingRate = Math.max(1, buf.readUInt32BE(off + 16));
      const numRecords = buf.readUInt32BE(off + 36);
      let roff = off + 40;

      for (let r = 0; r < numRecords && roff + 8 <= buf.length; r++) {
        // Record format: top 20 bits = enterprise, bottom 12 bits = record type.
        const recFormat = buf.readUInt32BE(roff);
        const recType = recFormat & 0xfff;
        const recLen = buf.readUInt32BE(roff + 4);
        if (recLen < 8 || roff + recLen > buf.length) break; // truncated — stop safely

        const payloadStart = roff + 8;

        if (recType === 3 && recLen >= 32) {
          // IPv4 flow record payload (32 bytes): pktLen(4) proto(4) srcIP(4) dstIP(4)
          //   portSrc(4) portDst(4) tcpFlags(4) tos(4).
          const pktLen = buf.readUInt32BE(payloadStart);
          const proto = buf.readUInt32BE(payloadStart + 4);
          const srcIp = readRawIp4(buf, payloadStart + 8);
          const dstIp = readRawIp4(buf, payloadStart + 12);
          if (srcIp && dstIp) {
            flows.push({ srcIp, dstIp, proto, bytes: pktLen * samplingRate, packets: 1, sampleRate: samplingRate });
          }
        } else if (recType === 4 && recLen >= 56) {
          // IPv6 flow record payload (56 bytes): pktLen(4) proto(4) srcIP(16) dstIP(16)
          //   portSrc(4) portDst(4) tcpFlags(4) priority(4).
          const pktLen = buf.readUInt32BE(payloadStart);
          const proto = buf.readUInt32BE(payloadStart + 4);
          const srcIp = readRawIp6(buf, payloadStart + 8);
          const dstIp = readRawIp6(buf, payloadStart + 24);
          if (srcIp && dstIp) {
            flows.push({ srcIp, dstIp, proto, bytes: pktLen * samplingRate, packets: 1, sampleRate: samplingRate });
          }
        } else if (recType === 1 && recLen >= 20) {
          // Raw packet flow record payload: hdrProto(4) frameLen(4) stripped(4) hdrLen(4)
          //   headerBytes(hdrLen)…
          const frameLen = buf.readUInt32BE(payloadStart + 4);
          const hdrLen = buf.readUInt32BE(payloadStart + 12);
          const hdrMax = Math.min(hdrLen, recLen - 20); // don't read past record end
          if (hdrMax >= 34) {
            const parsed = parseEthernetHeader(buf.subarray(payloadStart + 16, payloadStart + 16 + hdrMax));
            if (parsed) {
              flows.push({ srcIp: parsed.srcIp, dstIp: parsed.dstIp, proto: parsed.proto, bytes: frameLen * samplingRate, packets: 1, sampleRate: samplingRate });
            }
          }
        }

        // Advance past this record: format(4) + length(4) + payload, where the
        // LENGTH FIELD IS PAYLOAD-ONLY and the whole record is padded to a
        // 4-byte boundary (gopacket's skipRecord: (len + pad) + 8).
        const padded = recLen + ((4 - (recLen % 4)) % 4);
        roff += 8 + padded;
      }

      // Records ARE the entire payload of the flow sample — `roff` now points
      // at the next sample. (gopacket advances its cursor identically.)
      off = roff;
    } else {
      // Counter sample or unknown type — skip record-by-record like gopacket.
      // The counter header is format(4) sampleLen(4) seq(4) srcIdClass(4) numRecords(4).
      if (off + 20 > buf.length) break;
      const counterNumRecords = buf.readUInt32BE(off + 16);
      let coff = off + 20;
      for (let r = 0; r < counterNumRecords && coff + 8 <= buf.length; r++) {
        const recLen = buf.readUInt32BE(coff + 4);
        if (recLen < 8 || coff + recLen > buf.length) break; // truncated — stop safely
        coff += 8 + recLen + ((4 - (recLen % 4)) % 4);
      }
      off = coff;
    }
  }

  return flows;
}
