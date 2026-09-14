/**
 * LANCOM column-first OID row decoding.
 *
 * LANCOM's LCOS agent addresses table rows COLUMN-FIRST (standard SNMP is
 * index-first):
 *   <table>.1.<column>.<index…>          — the leading "1" is the not-accessible
 *                                          entry object, always sub-identifier 1
 *                                          in every LCOS table (`::= { <table> 1 }`).
 * and encodes OCTET STRING indices as LENGTH-PREFIXED decimal octets:
 *   "WLAN-1" → 6.87.76.65.78.45.49       (len=6, then ASCII bytes)
 * IP-address indices are the raw four decimal octets ("10.25.1.1" → 10.25.1.1);
 * MAC-address indices are the raw six decimal octets (no length prefix):
 *   00:A0:57:7F:7E:51 → 0.160.87.127.126.81
 * Index columns are not-accessible, so row keys can ONLY be recovered from the
 * OID suffix — every table in the LANCOM plugins has its index shape verified
 * against the MIB / live hardware.
 *
 * These decoders were copy-pasted across lancom-lcos, lancom-lx and lancom-sx;
 * they now live here once. They are pure functions of (oid, base) — no state.
 */

import { SnmpValue, suffixOf, normalizeMac } from '@unm/snmp-client';

/** A decoded column-first row: the column number + its index components. */
export interface LcosRow {
  col: number;
  idx: string[];
}

/**
 * Splits a column-first row OID into column number + index components.
 * Row shape relative to the table base: `<base>.1.<column>.<index…>`.
 * Returns null when the oid is not under `base` or has no valid entry/col parts.
 */
export function splitRow(oid: string, base: string): LcosRow | null {
  const suffix = suffixOf(oid, base); // "<entry>.<col>.<idx…>"
  if (!suffix) return null;
  const parts = suffix.split('.');
  if (parts.length < 3 || parts[0] !== '1') return null; // entry + col + ≥1 idx part
  const col = Number(parts[1]);
  if (!Number.isInteger(col)) return null;
  return { col, idx: parts.slice(2) };
}

/** Decodes one length-prefixed OCTET STRING index component (e.g. "WLAN-1"). */
export function decodePrefixedText(parts: string[], start: number): { text: string; next: number } | null {
  const len = Number(parts[start]);
  if (!Number.isInteger(len) || len <= 0 || len > 64 || start + 1 + len > parts.length) return null;
  let text = '';
  for (let i = 1; i <= len; i++) {
    const p = parts[start + i];
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    text += n >= 32 && n <= 126 ? String.fromCharCode(n) : ''; // non-printable → drop
  }
  return { text, next: start + 1 + len };
}

/** Decodes a single-component text index ("WLAN-1", "LAN-1", peer names). */
export function decodeSingleText(idx: string[]): string | null {
  const d = decodePrefixedText(idx, 0);
  return d && d.next === idx.length ? d.text : null;
}

/** Decodes a raw four-octet IPv4 index run to dotted-quad (or null). */
export function decodeIpIndex(parts: string[], start: number): string | null {
  if (start + 4 > parts.length) return null;
  const octets = parts.slice(start, start + 4);
  if (!octets.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) return null;
  return octets.map(Number).join('.');
}

/** Decodes a [ip(4 octets), text] index (DHCP leases). */
export function decodeIpTextIndex(idx: string[]): { ip: string; text: string } | null {
  const ip = decodeIpIndex(idx, 0);
  if (!ip) return null;
  const d = decodePrefixedText(idx, 4);
  return d && d.next === idx.length ? { ip, text: d.text } : null;
}

/** Decodes a raw six-octet MAC index run to aa:bb:cc:dd:ee:ff (or null). */
export function decodeMacIndex(parts: string[], start: number): string | null {
  if (start + 6 > parts.length) return null;
  const hex = parts.slice(start, start + 6).map((p) => Number(p).toString(16).padStart(2, '0')).join('');
  // Reuse the shared MAC normalizer so the output is always lowercase colon form.
  return normalizeMac(hex);
}

/** Decodes a length-prefixed colon-MAC text index ("c2:a0:57:7f:92:a0"). */
export function decodeColonMacText(parts: string[], start: number): { mac: string; next: number } | null {
  const d = decodePrefixedText(parts, start);
  if (!d) return null;
  const mac = normalizeMac(d.text);
  return mac ? { mac, next: d.next } : null;
}

/** Decodes a single colon-MAC-text index (ENV_SCAN / competing BSSIDs). */
export function decodeBssidIndex(idx: string[]): string | null {
  const m = decodeColonMacText(idx, 0);
  return m && m.next === idx.length ? m.mac : null;
}

/** Decodes a [text, colon-MAC-text] index (WDS links — both parts prefixed). */
export function decodeTextMac(idx: string[]): { text: string; mac: string } | null {
  const d = decodePrefixedText(idx, 0);
  if (!d) return null;
  const m = decodeColonMacText(idx, d.next);
  return m && m.next === idx.length ? { text: d.text, mac: m.mac } : null;
}

/** Decodes a two-component [text, number] index (WLAN_IF: name + band). */
export function decodeTextNumber(idx: string[]): { text: string; num: number } | null {
  const d = decodePrefixedText(idx, 0);
  if (!d || d.next !== idx.length - 1) return null;
  const n = Number(idx[d.next]);
  if (!Number.isInteger(n)) return null;
  return { text: d.text, num: n };
}

/** Decodes a [number, text] index (BRIDGE_VLAN: vlanId + ifname). */
export function decodeNumberText(idx: string[]): { num: number; text: string } | null {
  const n = Number(idx[0]);
  if (!Number.isInteger(n) || idx.length < 2) return null;
  const d = decodePrefixedText(idx, 1);
  return d && d.next === idx.length ? { num: n, text: d.text } : null;
}

/** Decodes a [channel, ifcText, band] index (DFS scan results). */
export function decodeChannelIfcBand(idx: string[]): { channel: number; ifc: string; band: number } | null {
  const ch = Number(idx[0]);
  if (!Number.isInteger(ch) || idx.length < 2) return null;
  const d = decodePrefixedText(idx, 1);
  if (!d || d.next !== idx.length - 1) return null;
  const band = Number(idx[d.next]);
  if (!Number.isInteger(band)) return null;
  return { channel: ch, ifc: d.text, band };
}

/** Decodes a STATION index (raw six-octet MAC) — the row key. */
export function decodeStationIndex(idx: string[]): string | null {
  if (idx.length !== 6) return null;
  return decodeMacIndex(idx, 0);
}

/**
 * Decodes an IP_ADDR index [ifnameText, version, source, addrLiteral…]. The
 * literal carries a CIDR prefix ("10.25.1.1/16") which is stripped — the
 * generic inventory contract expects bare addresses. `versionMap` maps the raw
 * version sub-identifier to '4'/'6' (defaults to the standard {1:'4', 2:'6'}).
 */
export function decodeIpAddrIndex(
  idx: string[],
  versionMap: Record<number, '4' | '6'> = { 1: '4', 2: '6' }
): { ifname: string; version: '4' | '6'; address: string } | null {
  const d = decodePrefixedText(idx, 0);
  if (!d) return null;
  const rest = idx.slice(d.next);
  if (rest.length < 3) return null; // need version + source + ≥1 addr part
  const version = versionMap[Number(rest[0])];
  if (!version) return null;
  const addrParts = rest.slice(2);
  let address: string;
  if (version === '4') {
    if (addrParts.length !== 4 || !addrParts.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) return null;
    address = addrParts.map(Number).join('.');
  } else {
    // IPv6 literal as ASCII octets ("fe80::2a0:…/64" / "::") — decode the text.
    const lit = decodePrefixedText(addrParts, 0);
    if (!lit || lit.next !== addrParts.length) return null;
    address = lit.text;
  }
  const slash = address.lastIndexOf('/');
  if (slash > 0) address = address.slice(0, slash);
  return { ifname: d.text, version, address };
}

/** Decodes an AP_CONN index (length-prefixed IP literal or hostname text). */
export function decodeApConnIndex(idx: string[]): string | null {
  const d = decodePrefixedText(idx, 0);
  return d && d.next === idx.length ? d.text : null;
}

/* ------------------------------------------------------------------ *
 * Enum label + integer pickers (verbatim across all three plugins)
 * ------------------------------------------------------------------ */

/** Maps a raw SNMP enum value to its display label ('' when absent/unknown). */
export function label(map: Record<number, string>, raw: SnmpValue | undefined): string {
  if (raw === undefined || raw === '') return '';
  const n = Number(raw);
  return Number.isFinite(n) ? map[n] ?? String(n) : String(raw);
}

/** Integer or null when absent/non-numeric. */
export function toInt(value: SnmpValue | undefined): number | null {
  if (value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/** Converts a dotted-quad netmask to its CIDR prefix length (null on bad input). */
export function netmaskToPrefix(netmask: SnmpValue | undefined): number | null {
  const parts = String(netmask ?? '').split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  let prefix = 0;
  for (const part of parts) {
    let octet = part;
    while (octet & 0x80) { prefix++; octet = (octet << 1) & 0xff; }
    if (octet !== 0) return null; // non-contiguous mask — don't guess
  }
  return prefix === 0 ? null : prefix;
}
