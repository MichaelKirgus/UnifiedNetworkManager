/**
 * LCOS WLAN SSID slot read-modify-write over the interactive CLI.
 *
 * LCOS routers have a FIXED set of WLAN slots (WLAN-1, WLAN-2 and sub-slots
 * WLAN-N-M) — you cannot create or delete SSIDs, only configure existing
 * slots. The CLI does NOT support targeted column sets on these tables
 * (probed live: `set <row> <col> ?` → "Value invalid", full-path form → same),
 * so a slot is updated by rewriting its ENTIRE row positionally — exactly the
 * form `readscript -d` emits. To do that safely we parse the current row from
 * `dir -a` (fixed-width columns, offsets derived from the `[N]` column-number
 * line) and only write back when every field parsed cleanly. Any parse doubt
 * → hard error, no write.
 *
 * Verified against GW_Ralf (LANCOM 1803VAW-5G, LCOS 10.94):
 *   Interfaces/WLAN/Network    — 28 visible columns in tab order:
 *     Ifc Operating Network-Name UTF-8-Network-Name MAC-Filter RADIUS-Accounting
 *     Accounting-Server Accounting-Start-Condition Dyn-Auth Closed-Network
 *     Max-Stations Min-Client-Strength Inter-Station-Traffic Transmit-only-Unicasts
 *     APSD Cl.-Brg.-Support Aironet-Extensions Include-UUID Summaric-Tx-Limit
 *     Summaric-Rx-Limit Per-Client-Tx-Limit Per-Client-Rx-Limit LBS-Tracking
 *     LBS-Tracking-List Dyn.-VLAN-Trunk-Ports Assisted-Roaming Timeframe
 *     Min-Client-Disassoc-Strength
 *   Interfaces/WLAN/Encryption — 24 visible columns in tab order:
 *     Ifc Encryption Default-Key Method Key RADIUS-Profile WPA-Version
 *     WPA1-Session-Keytypes WPA2-3-Session-Keytypes WPA-Rekeying-Cycle
 *     WPA2-Key-Management SAE-Groups SAE-Variants Prot.-Mgmt-Frames PMK-Caching
 *     Transition-Termination Client-EAP-Method Pre-Authentication
 *     WPA-802.1X-Security-Level OKC Fast-Roaming-Over-the-DS Enhanced-Open-Groups
 *     PMK-IAPP-Secret Authentication
 * String columns (double-quoted in the set line): Network, Accounting-Server /
 * LBS-Tracking-List / Timeframe; Encryption: Key / RADIUS-Profile /
 * PMK-IAPP-Secret. Everything else is a bare enum/number.
 */

import type { SshCredentials } from '@unm/plugin-sdk';
import { runLcosCliCommands, stripCommandEcho } from '../lcosCli';
import type { ActionContext } from './types';

/** The 28 visible columns of Interfaces/WLAN/Network in tab (set) order. */
export const WLAN_NETWORK_COLS = [
  'Ifc', 'Operating', 'Network-Name', 'UTF-8-Network-Name', 'MAC-Filter', 'RADIUS-Accounting',
  'Accounting-Server', 'Accounting-Start-Condition', 'Dyn-Auth', 'Closed-Network', 'Max-Stations',
  'Min-Client-Strength', 'Inter-Station-Traffic', 'Transmit-only-Unicasts', 'APSD', 'Cl.-Brg.-Support',
  'Aironet-Extensions', 'Include-UUID', 'Summaric-Tx-Limit', 'Summaric-Rx-Limit', 'Per-Client-Tx-Limit',
  'Per-Client-Rx-Limit', 'LBS-Tracking', 'LBS-Tracking-List', 'Dyn.-VLAN-Trunk-Ports', 'Assisted-Roaming',
  'Timeframe', 'Min-Client-Disassoc-Strength',
] as const;

/** The 24 visible columns of Interfaces/WLAN/Encryption in tab (set) order. */
export const WLAN_ENCRYPTION_COLS = [
  'Ifc', 'Encryption', 'Default-Key', 'Method', 'Key', 'RADIUS-Profile', 'WPA-Version',
  'WPA1-Session-Keytypes', 'WPA2-3-Session-Keytypes', 'WPA-Rekeying-Cycle', 'WPA2-Key-Management',
  'SAE-Groups', 'SAE-Variants', 'Prot.-Mgmt-Frames', 'PMK-Caching', 'Transition-Termination',
  'Client-EAP-Method', 'Pre-Authentication', 'WPA-802.1X-Security-Level', 'OKC',
  'Fast-Roaming-Over-the-DS', 'Enhanced-Open-Groups', 'PMK-IAPP-Secret', 'Authentication',
] as const;

/** Columns whose values are double-quoted in the positional set line. */
const QUOTED_COLS: Record<string, Set<string>> = {
  Network: new Set(['Network-Name', 'Accounting-Server', 'LBS-Tracking-List', 'Timeframe']),
  Encryption: new Set(['Key', 'RADIUS-Profile', 'PMK-IAPP-Secret']),
};

/** PTY width used for the CLI session (must match LcosCli's default). */
const COLS = 240;

export interface WlanTable {
  /** Column names in tab order. */
  cols: readonly string[];
  /** ifc → row values in tab order (unquoted, trimmed). */
  rows: Map<string, string[]>;
}

/**
 * Reads one WLAN table via `dir -a` and parses its fixed-width rows.
 * Throws on any structural surprise — callers must treat that as "cannot
 * determine current state" and NOT write anything.
 */
export async function readWlanTable(ctx: ActionContext, creds: SshCredentials, table: 'Network' | 'Encryption'): Promise<WlanTable> {
  const results = await runLcosCliCommands(
    ctx.terminalPool,
    { host: ctx.address, port: ctx.sshPort ?? 22, creds, cols: COLS },
    [`cd /Setup/Interfaces/WLAN/${table}`, 'dir -a']
  );
  if (!results[1]?.completed) throw new Error(`CLI session timed out reading WLAN ${table} table`);
  const text = stripCommandEcho(results[1].raw, 'dir -a');
  return parseWlanDir(text, table);
}

/** Parses the `dir -a` output of a WLAN table (pure — exported for tests). */
export function parseWlanDir(raw: string, table: 'Network' | 'Encryption'): WlanTable {
  const expectedCols = table === 'Network' ? WLAN_NETWORK_COLS : WLAN_ENCRYPTION_COLS;
  const phys = raw.split('\n').map((l) => l.replace(/\r/g, ''));

  // Locate the OID header line "[…][…]" — everything before it is framing.
  let start = -1;
  for (let i = 0; i < phys.length; i++) {
    if (/^\[\d/.test(phys[i].trim()) && phys[i].includes('][')) { start = i + 1; break; }
  }
  if (start < 0) throw new Error(`WLAN ${table}: could not find the table header in dir output`);

  // Find the separator line (all '='/'-') to derive the total table width W.
  let sepStart = -1;
  for (let i = start; i < phys.length; i++) {
    const t = phys[i].trim();
    if (t.length > 50 && /^[=|-]+$/.test(t)) { sepStart = i; break; }
  }
  if (sepStart < 0) throw new Error(`WLAN ${table}: could not find the column separator in dir output`);
  let width = 0;
  for (let i = sepStart; i < phys.length; i++) {
    const t = phys[i].trim();
    if (t === '' || /^[=|-]+$/.test(t)) { width += t.length; continue; }
    break;
  }
  if (width < 100) throw new Error(`WLAN ${table}: implausible table width ${width}`);

  // Unwrap: every logical line occupies exactly K = ceil(W/COLS) physical lines.
  const k = Math.ceil(width / COLS);
  const unwrap = (from: number): { text: string; next: number } => {
    let out = '';
    for (let i = from; i < Math.min(from + k, phys.length); i++) out += phys[i];
    return { text: out, next: from + k };
  };

  // Name line → [N] line → separator → rows.
  const nameLine = unwrap(start).text;
  const numLine = unwrap(unwrap(start).next).text;
  const afterSep = unwrap(sepStart).next;

  // Column start offsets from the "[N]" tokens (tab order = appearance order).
  const offsets: number[] = [];
  for (const m of numLine.matchAll(/\[\d+\]/g)) offsets.push(m.index ?? 0);
  if (offsets.length !== expectedCols.length) {
    throw new Error(`WLAN ${table}: expected ${expectedCols.length} columns, found ${offsets.length}`);
  }

  // Rows: each row STARTS at a physical line matching the Ifc pattern. The
  // chunk for a row runs until the NEXT row start — robust against dropped
  // trailing (all-whitespace) wrap lines, which would break fixed-K chunking.
  const starts: number[] = [];
  for (let i = afterSep; i < phys.length; i++) {
    if (/^WLAN-[12](?:-\d)?\s/.test(phys[i])) starts.push(i);
  }
  if (starts.length === 0) throw new Error(`WLAN ${table}: no WLAN slot rows found in dir output`);

  const rows = new Map<string, string[]>();
  for (let r = 0; r < starts.length; r++) {
    const s = starts[r];
    const end = r + 1 < starts.length ? starts[r + 1] : phys.length;
    let chunk = '';
    for (let i = s; i < end; i++) chunk += phys[i];
    const values: string[] = [];
    for (let c = 0; c < offsets.length; c++) {
      const a = offsets[c];
      const b = c + 1 < offsets.length ? offsets[c + 1] : width;
      values.push(chunk.slice(a, Math.max(a, b)).trim());
    }
    if (!/^WLAN-[12](?:-\d)?$/.test(values[0])) {
      throw new Error(`WLAN ${table}: misaligned row parse (first field "${values[0]}") — refusing to use this table`);
    }
    rows.set(values[0], values);
  }

  return { cols: expectedCols, rows };
}

/** Renders a full row (tab order, incl. Ifc at [0]) into the positional set value list. */
export function renderWlanSet(table: 'Network' | 'Encryption', values: string[]): string[] {
  const cols = table === 'Network' ? WLAN_NETWORK_COLS : WLAN_ENCRYPTION_COLS;
  const quoted = QUOTED_COLS[table];
  return values.map((v, idx) => (quoted.has(cols[idx] ?? '') ? `"${v}"` : v));
}

/**
 * Rewrites one slot's row positionally and verifies by re-reading the table.
 * `overrides` maps column name → new value (only listed columns change).
 */
export async function writeWlanSlot(
  ctx: ActionContext,
  creds: SshCredentials,
  table: 'Network' | 'Encryption',
  ifc: string,
  overrides: Record<string, string>
): Promise<{ ok: boolean; detail: string }> {
  const t = await readWlanTable(ctx, creds, table);
  const current = t.rows.get(ifc);
  if (!current) return { ok: false, detail: `slot ${ifc} not present in WLAN/${table}` };

  const cols = table === 'Network' ? WLAN_NETWORK_COLS : WLAN_ENCRYPTION_COLS;
  const colNames: readonly string[] = cols;
  const next = [...current];
  for (const [col, val] of Object.entries(overrides)) {
    const idx = colNames.indexOf(col);
    if (idx < 0) return { ok: false, detail: `unknown column ${col} in WLAN/${table}` };
    next[idx] = val;
  }

  const rendered = renderWlanSet(table, next);
  const setLine = `set ${[next[0], ...rendered.slice(1)].join(' ')}`;
  const results = await runLcosCliCommands(
    ctx.terminalPool,
    { host: ctx.address, port: ctx.sshPort ?? 22, creds, cols: COLS },
    [`cd /Setup/Interfaces/WLAN/${table}`, setLine]
  );
  if (!results[1]?.completed) return { ok: false, detail: `CLI session timed out writing WLAN/${table} ${ifc}` };

  // Verify by re-reading.
  try {
    const after = await readWlanTable(ctx, creds, table);
    const row = after.rows.get(ifc);
    if (!row) return { ok: false, detail: `slot ${ifc} vanished after write` };
    for (const [col, val] of Object.entries(overrides)) {
      const idx = colNames.indexOf(col);
      if (idx >= 0 && row[idx] !== val) {
        return { ok: false, detail: `verification failed: WLAN/${table} ${ifc}.${col} is "${row[idx]}", expected "${val}"` };
      }
    }
    return { ok: true, detail: `WLAN/${table} slot ${ifc} updated (${Object.keys(overrides).join(', ')}) — verified by re-read` };
  } catch (e) {
    return { ok: false, detail: `write sent but verification read failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}
