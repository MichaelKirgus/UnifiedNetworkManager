/**
 * Content-based protocol dispatcher for the shared UDP receive port.
 *
 * sFlow and NetFlow v5 BOTH advertise version 5 in their first field, so a
 * bare version check is ambiguous:
 *   - sFlow header starts `version u32 | agentAddrType u32 (1=v4, 2=v6)`.
 *     → sniffed as sFlow when u32@0 ∈ {1,5} AND u32@4 ∈ {1,2}.
 *   - NetFlow v5 header starts `version u16=5 | count u16 …` (24 bytes).
 *   - NetFlow v9 header starts `version u16=9 | count u16 …` (20 bytes).
 * Anything else is ignored silently — the port may carry other traffic.
 */

import { parseSflowDatagram } from './sflowParser';
import { parseNetflowV5Datagram, parseNetflowV9Datagram } from './netflowParser';
import type { ParsedFlow } from './ipHelpers';

/**
 * Parse one UDP datagram as sFlow or NetFlow v5/v9. Never throws.
 * `agentIp` = the UDP source address of the datagram — the exporter identity
 * for NetFlow (which carries none in-payload); sFlow ignores it and uses its
 * own header agent address instead.
 */
export function parseFlowDatagram(buf: Buffer, agentIp: string): ParsedFlow[] {
  if (buf.length < 8) return [];

  const u32v = buf.readUInt32BE(0);
  // sFlow: version is a full u32 (1 or 5) followed by agentAddrType ∈ {1,2}.
  if ((u32v === 1 || u32v === 5) && (buf.readUInt32BE(4) === 1 || buf.readUInt32BE(4) === 2)) {
    return parseSflowDatagram(buf);
  }

  const u16v = buf.readUInt16BE(0);
  if (u16v === 5 && buf.length >= 24) return parseNetflowV5Datagram(buf, agentIp);
  if (u16v === 9 && buf.length >= 20) return parseNetflowV9Datagram(buf, agentIp);

  return [];
}
