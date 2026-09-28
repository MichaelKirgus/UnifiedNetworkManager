/**
 * LCOS LCF configuration-text parser.
 *
 * `readconfig` (CLI) and the SFTP virtual file `/config` both export the running
 * configuration as an LCF document:
 *
 *   [TYPE: LCF; VERSION: 1.00; HASHTYPE: none; STATUS: ...]
 *       1.2.1 = WLC01.management.kirgus.intra        ← scalar (4-space indent)
 *       <1.2.93.3.2>                                 ← table node
 *         (1.2.93.3.2.1.1) = DEFAULT                 ← cell row (6-space indent)
 *         (1.2.93.3.2.1.2) = 0.0.0.0
 *       {WAN}                                        ← display section marker
 *   [END: LCF;]
 *
 * The same row-first OID addressing family as the lancom-lx GetConfig document,
 * but under LCOS's own tree (base .1.3.6.1.4.1.2356.11 — NOT 2356.13). This
 * parser is deliberately tolerant: it never throws on unknown lines and keeps
 * the raw text so callers can fall back to byte-level comparisons.
 */

/** One parsed LCF document. */
export interface LcfDocument {
  /** Scalar values keyed by OID (e.g. "1.2.1" → device name). */
  scalars: Map<string, string>;
  /** Table cells keyed by full cell OID (e.g. "1.2.93.3.2.1.1"). */
  cells: Map<string, string>;
  /** Display section markers in document order ("WAN", "TCP/IP", ...). */
  sections: string[];
  /** The [TYPE: LCF; ...] header line (null when absent — e.g. a truncated dump). */
  typeHeader: string | null;
  /** True when the document ends with [END: LCF;]. */
  complete: boolean;
  /** Raw text as received. */
  raw: string;
}

/** Scalar line: `    <oid> = value` (4-space indent, no parentheses). */
const SCALAR_RE = /^\s{2,6}(\d+(?:\.\d+)+)\s*=\s*(.*)$/;
/** Cell line: `      (<oid>) = value` (parenthesized OID inside a table node). */
const CELL_RE = /^\s{4,8}\((\d+(?:\.\d+)+)\)\s*=\s*(.*)$/;
/** Table-node opener: `    <1.2.93.3.2>` (no value — the rows follow indented). */
const TABLE_NODE_RE = /^\s{2,6}<(\d+(?:\.\d+)*)>\s*$/;

/** Parses an LCF document from readconfig / SFTP `/config` text. Never throws. */
export function parseLcf(text: string): LcfDocument {
  const scalars = new Map<string, string>();
  const cells = new Map<string, string>();
  const sections: string[] = [];
  let typeHeader: string | null = null;
  let complete = false;

  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('[TYPE: LCF')) {
      typeHeader = line.trim();
      continue;
    }
    if (/\[END:\s*LCF\s*;?\]/i.test(line)) {
      complete = true;
      continue;
    }
    // Display section marker, e.g. `  {WAN}` — not part of the OID tree.
    const sec = /^\s*\{([^\}]+)\}\s*$/.exec(line);
    if (sec) {
      sections.push(sec[1]);
      continue;
    }
    // Cell rows take precedence over scalars (they are more specific).
    const cell = CELL_RE.exec(line);
    if (cell) {
      cells.set(cell[1], cell[2].trim());
      continue;
    }
    const scalar = SCALAR_RE.exec(line);
    if (scalar && !TABLE_NODE_RE.test(line)) {
      scalars.set(scalar[1], scalar[2].trim());
      continue;
    }
    // Table-node openers, comments and banner lines are skipped.
  }

  return { scalars, cells, sections, typeHeader, complete, raw: text };
}

/** True when the text looks like an LCOS LCF document (header + OID rows). */
export function isLcfDocument(text: string): boolean {
  if (!/\[TYPE:\s*LCF/i.test(text)) return false;
  // At least a handful of scalar/cell rows — rejects truncated or wrong files.
  let rows = 0;
  for (const line of text.split(/\r?\n/)) {
    if (SCALAR_RE.test(line) || CELL_RE.test(line)) rows++;
    if (rows >= 10) return true;
  }
  return false;
}

/**
 * Reads one scalar value from a parsed document. LCOS stores some strings as
 * length-prefixed decimal octet runs (the same encoding the SNMP MIB uses, e.g.
 * NTP server "ntp1" → "4.110.116.112.49"); plain values are returned verbatim.
 */
export function lcfScalar(doc: LcfDocument, oid: string): string | null {
  const v = doc.scalars.get(oid);
  if (v === undefined) return null;
  // Length-prefixed decimal octets: first number = length of the rest.
  const parts = v.split('.');
  if (parts.length >= 2 && parts.every((p) => /^\d+$/.test(p))) {
    const len = Number(parts[0]);
    if (len > 0 && len === parts.length - 1 && len <= 255) {
      try {
        return Buffer.from(parts.slice(1).map(Number)).toString('utf8');
      } catch {
        return v; // not valid UTF-8 — keep the raw run
      }
    }
  }
  return v;
}

/** Decodes a length-prefixed decimal-octet text index (inverse of encodeTextIndex). */
export function decodePrefixedText(v: string): string | null {
  const parts = v.split('.');
  if (parts.length < 2 || !parts.every((p) => /^\d+$/.test(p))) return null;
  const len = Number(parts[0]);
  if (len <= 0 || len > 255 || len !== parts.length - 1) return null;
  try {
    return Buffer.from(parts.slice(1).map(Number)).toString('utf8');
  } catch {
    return null;
  }
}
