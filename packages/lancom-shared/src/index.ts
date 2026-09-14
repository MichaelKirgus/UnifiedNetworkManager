/**
 * @unm/lancom-shared — shared LANCOM MIB collection helpers.
 *
 * Consolidates the code that was copy-pasted across the three LANCOM plugins
 * (lancom-lcos routers, lancom-lx APs, lancom-sx switches):
 *   - column-first OID row decoding + enum/integer pickers  (rowDecoding.ts)
 *   - the TTL + last-known snapshot cache trio              (snapshotCache.ts)
 *   - the generic slow-path runner                          (slowPath.ts)
 *   - fast-path counter-rate accumulation                   (fastPath.ts)
 *
 * The per-plugin MIB OID maps, snapshot types and parse bodies stay in each
 * plugin — they are vendor content, not shared infrastructure.
 */

export {
  splitRow,
  decodePrefixedText,
  decodeSingleText,
  decodeIpIndex,
  decodeIpTextIndex,
  decodeMacIndex,
  decodeColonMacText,
  decodeBssidIndex,
  decodeTextMac,
  decodeTextNumber,
  decodeNumberText,
  decodeChannelIfcBand,
  decodeStationIndex,
  decodeIpAddrIndex,
  decodeApConnIndex,
  label,
  toInt,
  netmaskToPrefix,
} from './rowDecoding';
export type { LcosRow } from './rowDecoding';

export { createSnapshotCaches } from './snapshotCache';
export type { SnapshotCaches } from './snapshotCache';

export { runSlowPath } from './slowPath';
export type { LcosLogSink, ProbeOutcome, SlowPathErrors, SlowPathConfig, SlowPathResult } from './slowPath';

export { accumulateRate } from './fastPath';
export type { RatePair } from './fastPath';
