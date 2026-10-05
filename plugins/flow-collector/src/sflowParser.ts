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

import { compressIpv6, readRawIp4, readRawIp6, type ParsedFlow } from './ipHelpers';

/** Normalized flow shape — shared with the NetFlow parsers (re-exported). */
export type { ParsedFlow };

/** Parse an Ethernet frame header to extract src/dst IP + protocol (+ TCP/UDP ports when present). */
function parseEthernetHeader(hdr: Buffer): { srcIp: string; dstIp: string; proto: number; srcPort: number; dstPort: number } | null {
  if (hdr.length < 34) return null;
  const ethertype = hdr.readUInt16BE(12);
  if (ethertype === 0x800 && hdr.length >= 34) {
    // IPv4: proto at +9, srcIp at +12..15, dstIp at +16..19. TCP/UDP headers
    // start right after the fixed 20-byte IPv4 header (no option skipping —
    // sampled frames rarely carry IP options; ports default to 0 otherwise).
    const ipStart = 14;
    const proto = hdr[ipStart + 9];
    let srcPort = 0, dstPort = 0;
    if ((proto === 6 || proto === 17) && hdr.length >= ipStart + 32) {
      srcPort = hdr.readUInt16BE(ipStart + 20);
      dstPort = hdr.readUInt16BE(ipStart + 22);
    }
    return {
      proto,
      srcIp: `${hdr[ipStart + 12]}.${hdr[ipStart + 13]}.${hdr[ipStart + 14]}.${hdr[ipStart + 15]}`,
      dstIp: `${hdr[ipStart + 16]}.${hdr[ipStart + 17]}.${hdr[ipStart + 18]}.${hdr[ipStart + 19]}`,
      srcPort,
      dstPort,
    };
  }
  if (ethertype === 0x86dd && hdr.length >= 54) {
    // IPv6: nextHeader at +6, srcIp at +8..23, dstIp at +24..39. TCP/UDP start
    // after the fixed 40-byte header (extension headers not followed).
    const ipStart = 14;
    const proto = hdr[ipStart + 6];
    let srcPort = 0, dstPort = 0;
    if ((proto === 6 || proto === 17) && hdr.length >= ipStart + 52) {
      srcPort = hdr.readUInt16BE(ipStart + 40);
      dstPort = hdr.readUInt16BE(ipStart + 42);
    }
    const groups: number[] = [];
    for (let i = 0; i < 16; i += 2) groups.push(hdr.readUInt16BE(ipStart + 8 + i));
    const srcIp = compressIpv6(groups);
    const groups6: number[] = [];
    for (let i = 0; i < 16; i += 2) groups6.push(hdr.readUInt16BE(ipStart + 24 + i));
    return { proto, srcIp, dstIp: compressIpv6(groups6), srcPort, dstPort };
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

  // The exporter's own address — identifies WHICH device observed the flow.
  const agentIp = agentAddrType === 1 ? readRawIp4(buf, 8)! : readRawIp6(buf, 8)!;

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
            flows.push({
              agentIp, srcIp, dstIp, proto,
              srcPort: buf.readUInt32BE(payloadStart + 16),
              dstPort: buf.readUInt32BE(payloadStart + 20),
              bytes: pktLen, packets: 1, sampleRate: samplingRate,
            });
          }
        } else if (recType === 4 && recLen >= 56) {
          // IPv6 flow record payload (56 bytes): pktLen(4) proto(4) srcIP(16) dstIP(16)
          //   portSrc(4) portDst(4) tcpFlags(4) priority(4).
          const pktLen = buf.readUInt32BE(payloadStart);
          const proto = buf.readUInt32BE(payloadStart + 4);
          const srcIp = readRawIp6(buf, payloadStart + 8);
          const dstIp = readRawIp6(buf, payloadStart + 24);
          if (srcIp && dstIp) {
            flows.push({
              agentIp, srcIp, dstIp, proto,
              srcPort: buf.readUInt32BE(payloadStart + 40),
              dstPort: buf.readUInt32BE(payloadStart + 44),
              bytes: pktLen, packets: 1, sampleRate: samplingRate,
            });
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
              flows.push({ agentIp, srcIp: parsed.srcIp, dstIp: parsed.dstIp, proto: parsed.proto, srcPort: parsed.srcPort, dstPort: parsed.dstPort, bytes: frameLen, packets: 1, sampleRate: samplingRate });
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
