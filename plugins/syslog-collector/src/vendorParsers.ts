/**
 * Vendor-specific src/dst IP extraction from the free-form message text.
 *
 * The syslog protocol itself carries no addressing — IPs live in the message
 * body, formatted per vendor. These extractors cover the common firewall /
 * router drop-and-accept log shapes; anything unrecognized yields null and
 * the row is stored without src/dst (the API's security-event UI still shows
 * hostname + message). Keep this list deliberately modest: one regex per
 * well-known format, no heuristics.
 */

export interface VendorIps {
  srcIp?: string;
  dstIp?: string;
}

const IPV4 = '(\\d{1,3}(?:\\.\\d{1,3}){3})';

/** OPNsense / pf-style firewall log: "… 203.0.113.7:51234 -> 198.51.100.1:443 …" */
const RE_ARROW = new RegExp(`${IPV4}:(\\d+)\\s*->\\s*${IPV4}:(\\d+)`);

/** MikroTik RouterOS firewall log: "drop packet from 203.0.113.7 to 198.51.100.1, in: ether1" */
const RE_FROM_TO = new RegExp(`from\\s+${IPV4}\\b[^,]*?to\\s+${IPV4}\\b`);

/** Linux netfilter / kernel drop log: "… SRC=203.0.113.7 DST=198.51.100.1 …" */
const RE_SRC_DST = new RegExp(`SRC=${IPV4}\\s+DST=${IPV4}`);

export function extractVendorIps(message: string): VendorIps | null {
  let m: RegExpExecArray | null;
  if ((m = RE_ARROW.exec(message))) return { srcIp: m[1], dstIp: m[3] };
  if ((m = RE_FROM_TO.exec(message))) return { srcIp: m[1], dstIp: m[2] };
  if ((m = RE_SRC_DST.exec(message))) return { srcIp: m[1], dstIp: m[2] };
  return null;
}
