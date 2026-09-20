/**
 * Client-side CSV parsing for the documented-hosts import. The webapp parses
 * the file and maps its (arbitrary) headers onto the documented-host fields;
 * only the structured rows are sent to the API — so any spreadsheet export
 * works as long as the user can point each field at a column.
 */

/** Fields a CSV column can be mapped to in the documented-hosts import. */
export type CsvImportField =
  | 'dnsNames'
  | 'friendlyName'
  | 'description'
  | 'siteId'
  | 'layerId'
  | 'address'
  | 'mac'
  | 'networkLabel';

/** Human labels + hints for each mappable field (shown in the mapping UI). */
export const CSV_IMPORT_FIELDS: { field: CsvImportField; label: string; hint: string }[] = [
  { field: 'dnsNames', label: 'DNS name(s)', hint: 'One or more DNS names / FQDNs, comma-separated within one cell' },
  { field: 'address', label: 'IP address(es)', hint: 'One or more IP addresses (IPv4/IPv6), comma- or space-separated within one cell' },
  { field: 'mac', label: 'MAC address', hint: 'Documented (expected) MAC; auto-filled from live data when the host is known' },
  { field: 'networkLabel', label: 'Network', hint: 'Known network name/CIDR or a free-form label for unknown networks' },
  { field: 'friendlyName', label: 'Friendly name', hint: 'Optional human-friendly label' },
  { field: 'description', label: 'Description', hint: 'Optional documentation text' },
  { field: 'siteId', label: 'Site', hint: 'Site NAME (resolved to the site id on import)' },
  { field: 'layerId', label: 'Layer', hint: 'Topology layer NAME (resolved to the layer id on import)' },
];

/**
 * Parses CSV text into a matrix of cells. RFC-4180 style: double quotes wrap
 * fields, doubled quotes escape a quote inside a quoted field; CRLF and LF
 * line endings both work. A leading UTF-8 BOM is stripped (Excel exports).
 */
export function parseCsv(text: string): string[][] {
  const input = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && input[i + 1] === '\n') i++;
      row.push(cell);
      cell = '';
      rows.push(row);
      row = [];
    } else {
      cell += ch;
    }
  }
  // Flush the last cell/row (files without a trailing newline).
  if (cell !== '' || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c.trim() !== ''));
}

/** Splits one cell into multiple values (comma / semicolon / whitespace separated). */
export function splitCellValues(value: string): string[] {
  return value
    .split(/[,;\s]+/)
    .map((v) => v.trim())
    .filter((v) => v !== '');
}

/**
 * Heuristic header → field mapping. Returns a map of field -> column index
 * (-1 = not mapped). Each column is claimed by at most one field; the first
 * matching field wins, so ambiguous headers (e.g. "Name") go to dnsNames.
 */
export function suggestHeaderMapping(headers: string[]): Partial<Record<CsvImportField, number>> {
  const mapping: Partial<Record<CsvImportField, number>> = {};
  for (const f of CSV_IMPORT_FIELDS) mapping[f.field] = -1;

  // Ordered by priority — earlier fields claim ambiguous columns first.
  const patterns: [CsvImportField, RegExp][] = [
    ['mac', /(^|[^a-z])mac/i],
    ['address', /\b(ip|ips|addr(?:ess)?s?)\b/i],
    ['dnsNames', /(hostname|host\s?name|fqdn|\bdns\b|computer\s?name|device\s?name)/i],
    ['friendlyName', /(friendly|alias|label|bezeichnung|anzeige)/i],
    ['description', /(desc(?:ription)?|comment|note|bemerkung|beschreibung)/i],
    ['siteId', /\b(site|standort)\b/i],
    ['layerId', /\b(layer|ebene|tier)\b/i],
    ['networkLabel', /(network|netzwerk|subnet|vlan|segment)/i],
  ];

  const claimed = new Set<number>();
  for (const [field, re] of patterns) {
    // Each field claims the FIRST unclaimed column whose header matches —
    // higher-priority fields run first and win ambiguous columns.
    for (let col = 0; col < headers.length; col++) {
      if (claimed.has(col)) continue;
      const h = headers[col].trim();
      if (!h) continue;
      if (re.test(h)) {
        mapping[field] = col;
        claimed.add(col);
        break;
      }
    }
  }

  // "Name" alone → dnsNames when nothing better was found for it.
  if ((mapping.dnsNames ?? -1) < 0) {
    for (let col = 0; col < headers.length; col++) {
      if (claimed.has(col)) continue;
      const h = headers[col].trim().toLowerCase();
      if (h === 'name' || h === 'names') {
        mapping.dnsNames = col;
        claimed.add(col);
        break;
      }
    }
  }

  return mapping;
}
