/**
 * LCOS-LX web-UI API client (ubus JSON-RPC over HTTPS).
 *
 * The vendor MIB is read-only — ALL configuration of an LX access point goes
 * through the embedded "WEBconfig" SPA's backend: a JSON-RPC 2.0 endpoint at
 * `POST /ubus` with session-based auth. Reverse-engineered from the v7.14
 * bundle + live probes against an LX-6500 (see repo memory lancom-lx-webapi.md):
 *
 *   login:    params:["<32 zeros>","session","login",{username,password,timeout}]
 *             → result[1].ubus_rpc_session = session token
 *   read/write: params:[SID,"lxcd","handleTransactionStream",
 *                    {transaction:{id,inp:false,ignoreerr:true,cmd:[{func,param}]} }]
 *   GetConfig:  params:[SID,"lxcd","GetConfig",{}] → result[1].config (LCOS text)
 *   SetConfig:  params:[SID,"lxcd","SetConfig",{config,noflash}]
 *   persist:    transaction cmd {func:"setFlashMode",param:["1"]}
 *   files:      params:[SID,"lancomfile","read",{path}] → result[1].data
 *
 * OIDs are the numeric MIB OIDs (13.2.* config mirror, 13.1.* status). Table
 * rows are addressed COLUMN-FIRST: <table>.<col>.<index…>.
 */

import http from 'node:http';
import https from 'node:https';

// --- Wire types -----------------------------------------------------------------

/** One command inside a transaction (getScalar/getTable/setScalar/updateTableRow/…). */
export interface UbusCmd {
  func: string;
  param: unknown[];
}

/** The default session id the SPA's interceptor splices into params[0] of EVERY request. */
const DEFAULT_SESSION_ID = '00000000000000000000000000000000';

export interface LcosWebOptions {
  /** Per-request timeout (ms). */
  timeoutMs: number;
}

/** A single per-command result inside a transaction response. */
export interface UbusCmdResult {
  oid?: string;
  errortag: number;
  val?: unknown;
}

/**
 * Per-command errortags that mean "accepted": 0 = applied, 1020 = the value
 * already equals the requested one (no-op write). Verified live against an
 * LX-6500: a no-op setScalar keeps the TOP-LEVEL transaction ErrorTag at 0 and
 * reports cmd errortag 1020 — the vendor SPA only checks the top-level tag, so
 * it shows such saves as success. 101 = not-found / bad OID / read-only object.
 */
export function isWriteOk(errortag: number): boolean {
  return errortag === 0 || errortag === 1020;
}

/** Parsed transaction outcome — one entry per submitted command, in order. */
export interface TransactionOutcome {
  /** True when every command reported errortag 0. */
  ok: boolean;
  results: UbusCmdResult[];
  /** Raw device error description (when the transaction itself failed). */
  descr?: string;
}

// --- HTTP transport -----------------------------------------------------------------

/**
 * Performs one raw HTTPS/HTTP request with a JSON body. Fresh connection per
 * call (`Connection: close`) — embedded web servers are finicky about pooled
 * sockets. Accepts self-signed certificates (LCOS default). `auto` prefers
 * HTTPS and falls back to HTTP once when TLS fails entirely.
 */
function postJson(
  address: string,
  path: string,
  body: unknown,
  transport: 'auto' | 'http' | 'https',
  timeoutMs: number,
  ports?: { httpsPort?: number; httpPort?: number }
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    let start: URL;
    try {
      const base = address.includes('://')
        ? address
        : transport === 'http'
          ? `http://${address}${ports?.httpPort && ports.httpPort !== 80 ? `:${ports.httpPort}` : ''}`
          : `https://${address}${ports?.httpsPort && ports.httpsPort !== 443 ? `:${ports.httpsPort}` : ''}`;
      start = new URL(path, base);
    } catch (err) {
      return reject(new Error(`Invalid management address "${address}": ${(err as Error).message}`));
    }

    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const preferHttps = transport !== 'http';
    let settled = false;
    const done = (fn: () => void) => { if (!settled) { settled = true; fn(); } };

    const attempt = (url: URL, onFallback: boolean) => {
      const scheme = url.protocol === 'http:' ? 'http' : 'https';
      const lib = scheme === 'https' ? https : http;
      const req = lib.request(
        {
          hostname: url.hostname,
          port: url.port || (scheme === 'https' ? 443 : 80),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'Content-Length': payload.length,
            Connection: 'close',
          },
          rejectUnauthorized: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => done(() => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') })));
          res.on('error', () => done(() => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') })));
        }
      );
      req.on('error', (err) => {
        if (!onFallback && preferHttps) {
          const httpUrl = new URL(url);
          httpUrl.protocol = 'http:';
          if (ports?.httpPort && ports.httpPort !== 80) httpUrl.port = String(ports.httpPort);
          attempt(httpUrl, true);
        } else {
          done(() => reject(new Error(`Web-UI request failed: ${err.message}`)));
        }
      });
      req.setTimeout(timeoutMs, () => req.destroy(new Error(`Web-UI request timed out after ${timeoutMs}ms`)));
      req.end(payload);
    };

    attempt(start, false);
  });
}

// --- Client ---------------------------------------------------------------------------

/**
 * One authenticated ubus session against a single AP. Sessions are cheap to
 * create (one POST) and expire server-side after `timeout` seconds — the client
 * transparently re-logins when a call reports an invalid/expired session.
 */
export class LcosWebClient {
  private sessionId: string | null = null;

  constructor(
    private readonly address: string,
    private readonly username: string,
    private readonly password: string,
    private readonly opts: LcosWebOptions,
    private readonly transport: 'auto' | 'http' | 'https' = 'auto',
    private readonly ports?: { httpsPort?: number; httpPort?: number }
  ) {}

  /** True when a `web` credential is usable at all. */
  static hasCredentials(username: string | undefined, password: string | undefined): boolean {
    return typeof username === 'string' && username.length > 0;
  }

  private async call(params: unknown[]): Promise<{ status: number; body: any }> {
    const res = await postJson(this.address, '/ubus', { jsonrpc: '2.0', id: 1, method: 'call', params }, this.transport, this.opts.timeoutMs, this.ports);
    if (res.status !== 200) throw new Error(`Web-UI returned HTTP ${res.status} for /ubus`);
    let body: any;
    try {
      body = JSON.parse(res.text);
    } catch {
      throw new Error('Web-UI returned a non-JSON response from /ubus');
    }
    if (body.error) throw new Error(`ubus error ${body.error.code}: ${body.error.message}`);
    return { status: res.status, body };
  }

  /** Establishes a fresh session (idempotent — replaces any previous one). */
  async login(): Promise<void> {
    const { body } = await this.call([DEFAULT_SESSION_ID, 'session', 'login', { username: this.username, password: this.password, timeout: 900 }]);
    const sid = body?.result?.[1]?.ubus_rpc_session;
    if (typeof sid !== 'string' || sid.length === 0) throw new Error('Login succeeded but no session token was returned');
    this.sessionId = sid;
  }

  /** Destroys the current session (best-effort). */
  async destroy(): Promise<void> {
    if (!this.sessionId) return;
    const sid = this.sessionId;
    this.sessionId = null;
    try { await this.call([sid, 'session', 'destroy', {}]); } catch { /* session may already be gone */ }
  }

  /** Ensures a live session and returns its token. */
  private async sid(): Promise<string> {
    if (!this.sessionId) await this.login();
    return this.sessionId as string;
  }

  /** Runs one or more commands in a single transaction; re-logins once on session expiry. */
  async transact(cmds: UbusCmd[]): Promise<TransactionOutcome> {
    const run = async (sid: string): Promise<{ expired: boolean; outcome?: TransactionOutcome }> => {
      const txBody = { id: Date.now().toString(), inp: false, ignoreerr: true, cmd: cmds };
      try {
        const { body } = await this.call([sid, 'lxcd', 'handleTransactionStream', { transaction: txBody }]);
        const payload = body?.result?.[1]?.transaction;
        if (!payload) return { expired: false, outcome: { ok: false, results: [], descr: `Unexpected response shape: ${JSON.stringify(body).slice(0, 200)}` } };
        // On success Descr is an object; on error it arrives as a JSON string.
        let inner = payload.Descr;
        if (typeof inner === 'string') { try { inner = JSON.parse(inner); } catch { /* keep raw */ } }
        const cmdResults: UbusCmdResult[] = Array.isArray(inner?.transaction?.cmd) ? inner.transaction.cmd : [];
        // Top-level ErrorTag must be 0 AND every per-command tag accepted
        // (1020 = no-op "value unchanged" is fine — see isWriteOk).
        const ok = Number(payload.ErrorTag ?? 0) === 0 && cmdResults.every((c) => isWriteOk(c.errortag));
        return { expired: false, outcome: { ok, results: cmdResults, descr: ok ? undefined : (typeof payload.Descr === 'string' ? payload.Descr : JSON.stringify(inner).slice(0, 400)) } };
      } catch (err) {
        const msg = (err as Error).message;
        // -32002 "Access denied" / session errors → the token is stale.
        if (/access denied|session/i.test(msg)) return { expired: true };
        throw err;
      }
    };

    let sid = await this.sid();
    let first = await run(sid);
    if (first.expired) {
      // Session died server-side — re-login once and retry.
      sid = await this.login().then(() => this.sessionId as string);
      first = await run(sid);
    }
    return first.outcome ?? { ok: false, results: [], descr: 'Transaction failed without a result' };
  }

  /** Reads one scalar OID (null when absent / errortag != 0). */
  async getScalar(oid: string): Promise<string | null> {
    const out = await this.transact([{ func: 'getScalar', param: [oid] }]);
    const r = out.results[0];
    if (!r || r.errortag !== 0) return null;
    return typeof r.val === 'string' ? r.val : r.val == null ? null : String(r.val);
  }

  /** Reads a whole table (header + rows). Null when the OID is not a table. */
  async getTable(tableOid: string): Promise<{ header: { oid: string; idx: boolean; val?: unknown }[]; rows: any[][] } | null> {
    const out = await this.transact([{ func: 'getTable', param: [tableOid] }]);
    const r = out.results[0];
    if (!r || r.errortag !== 0) return null;
    const v = r.val as any;
    if (!v || !Array.isArray(v.rows)) return null;
    return { header: Array.isArray(v.header) ? v.header : [], rows: v.rows };
  }

  /** Writes one scalar (setScalar). Returns the device's errortag. */
  async setScalar(oid: string, value: string | number): Promise<number> {
    const out = await this.transact([{ func: 'setScalar', param: [oid, String(value)] }]);
    return out.results[0]?.errortag ?? -1;
  }

  /**
   * Updates one table row (updateTableRow). Cells are addressed ROW-FIRST:
   * full cell OID = `<table>.<rowIndex>.<colOid>` (verified against the GetConfig
   * dump and metadata.json header OIDs, which are plain column numbers).
   */
  async updateTableRow(tableOid: string, rowIndex: string | number, cells: Record<string, string | number>): Promise<number> {
    const param = Object.entries(cells).map(([col, val]) => ({ oid: `${tableOid}.${rowIndex}.${col}`, val: String(val) }));
    const out = await this.transact([{ func: 'updateTableRow', param: [tableOid, param] }]);
    return out.results[0]?.errortag ?? -1;
  }

  /** Adds one table row (addTableRow). */
  async addTableRow(tableOid: string, cells: Record<string, string | number>): Promise<number> {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(cells)) obj[k] = String(v);
    const out = await this.transact([{ func: 'addTableRow', param: [tableOid, obj, 1] }]);
    return out.results[0]?.errortag ?? -1;
  }

  /**
   * Deletes one table row (delTableRow) — identified by its index-column value(s).
   * `indexCells` overrides the default single-index addressing for multi-column-
   * index tables (e.g. Untagged-VLAN 13.2.70.8, keyed by Port + VLAN): pass
   * `{ '1': 'ETH1', '2': '5' }` to address the composite row explicitly.
   */
  async delTableRow(tableOid: string, rowIndex: string | number, indexCells?: Record<string, string>): Promise<number> {
    const param = indexCells
      ? Object.entries(indexCells).map(([col, val]) => ({ oid: `${tableOid}.${rowIndex}.${col}`, val }))
      : [{ oid: `${tableOid}.${rowIndex}.1`, val: String(rowIndex) }];
    const out = await this.transact([{ func: 'delTableRow', param: [tableOid, param] }]);
    return out.results[0]?.errortag ?? -1;
  }

  /**
   * Reads a LIVE status table (13.1.x) via getTable — these OIDs are NOT part of
   * the GetConfig text dump. Returns rows as `{ indexPath, cells }` where
   * `indexPath` is the dot-joined values of all idx-flagged columns in header
   * order and `cells` maps column oid → string value (empty for missing).
   */
  async getStatusTable(tableOid: string): Promise<{ indexPath: string; cells: Map<string, string> }[] | null> {
    const t = await this.getTable(tableOid);
    if (!t) return null;
    // Header order defines the index-path segment order.
    const idxCols = t.header.filter((h) => h.idx).map((h) => String(h.oid));
    return t.rows.map((row: any[]) => {
      const cells = new Map<string, string>();
      for (const c of row ?? []) cells.set(String(c.oid), c.val == null ? '' : String(c.val));
      const indexPath = idxCols.length > 0 ? idxCols.map((c) => cells.get(c) ?? '').join('.') : '1';
      return { indexPath, cells };
    });
  }

  /** Persists the running config to flash (makeChangesPermanent). */
  async makePersistent(): Promise<number> {
    const out = await this.transact([{ func: 'setFlashMode', param: ['1'] }]);
    return out.results[0]?.errortag ?? -1;
  }

  /** Fetches the complete running configuration as LCOS text. */
  async getConfigText(): Promise<string> {
    const sid = await this.sid();
    const { body } = await this.call([sid, 'lxcd', 'GetConfig', {}]);
    const cfg = body?.result?.[1]?.config;
    if (typeof cfg !== 'string' || cfg.length === 0) throw new Error('GetConfig returned no configuration text');
    return cfg;
  }

  /**
   * Replaces the ENTIRE running configuration with the given LCOS text
   * (`SetConfig` — the same call the web UI's config import performs).
   * `noflash=false` (default) also writes it to flash so it survives a reboot.
   */
  async setConfigText(config: string, noflash = false): Promise<void> {
    const sid = await this.sid();
    const { body } = await this.call([sid, 'lxcd', 'SetConfig', { config, noflash: noflash ? 1 : 0 }]);
    // SetConfig answers with a transaction-style result; surface any error tag.
    const errtag = Number(body?.result?.[1]?.errortag ?? body?.result?.[1]?.ErrorTag ?? 0);
    if (errtag !== 0) throw new Error(`SetConfig failed with errortag ${errtag}`);
  }

  /** Reads a device file (metadata.json, sysinfo.json, …). */
  async readFile(path: string): Promise<string> {
    const sid = await this.sid();
    const { body } = await this.call([sid, 'lancomfile', 'read', { path }]);
    const data = body?.result?.[1]?.data;
    if (typeof data !== 'string' || data.length === 0) throw new Error(`lancomfile.read returned no data for ${path}`);
    return data;
  }
}

// --- LCOS config-text parsing -----------------------------------------------------------

/**
 * Parses the GetConfig text dump into a flat OID → value map plus table rows.
 * Format (verified live against an LX-6500 v7.14 dump):
 *   `    13.2.1 = AP_Wohnzimmer`                       — scalar line
 *   `    <13.2.20.8>`                                  — table block start (ONE row per block)
 *   `      (13.2.20.8.1.1) = WLAN-1`                   — row cell, full OID `<table>.<col>.<idx…>`
 *   The block has NO closing tag — it ends at the next scalar line or table tag.
 */
export interface ParsedLcosConfig {
  /** Scalar OIDs → string values. */
  scalars: Map<string, string>;
  /** Table base OID → rows; each row = map of full cell OID → value (insertion order). */
  tables: Map<string, Map<string, string>[]>;
}

export function parseLcosConfigText(text: string): ParsedLcosConfig {
  const scalars = new Map<string, string>();
  const tables = new Map<string, Map<string, string>[]>();
  let currentTable: string | null = null;
  let currentRow: Map<string, string> | null = null;

  const pushRow = () => {
    if (currentTable && currentRow) {
      let rows = tables.get(currentTable);
      if (!rows) { rows = []; tables.set(currentTable, rows); }
      rows.push(currentRow);
    }
    currentTable = null;
    currentRow = null;
  };

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    // Table block start: <13.2.x.y> — each block holds exactly ONE row.
    const tableOpen = line.match(/^<(\d+(?:\.\d+)*)>\s*$/);
    if (tableOpen) {
      pushRow();
      currentTable = tableOpen[1];
      currentRow = new Map<string, string>();
      continue;
    }
    // Row cell: (13.2.x.y.z.w) = value — only valid inside a table block.
    const cell = line.match(/^\((\d+(?:\.\d+)*)\) = ?(.*)$/);
    if (cell && currentTable && currentRow) {
      currentRow.set(cell[1], cell[2]);
      continue;
    }
    // Scalar: 13.2.x = value — also terminates an open table block.
    const scalar = line.match(/^(\d+(?:\.\d+)*) = ?(.*)$/);
    if (scalar) {
      pushRow();
      scalars.set(scalar[1], scalar[2]);
      continue;
    }
    // Header lines like "(Configuration of …)" or "[TYPE: LCF…]" — ignored.
  }
  pushRow();
  return { scalars, tables };
}

/**
 * Derives the row-index path of a parsed table row from any cell key.
 * Cell OIDs are ROW-FIRST: `<table>.<rowIdx…>.<col>` → returns `rowIdx…`
 * (e.g. "1", or "3.2" for multi-column-index tables).
 */
export function rowIndexOf(parsed: ParsedLcosConfig, tableOid: string, rowIdx: number): string | null {
  const rows = parsed.tables.get(tableOid);
  const row = rows?.[rowIdx];
  if (!row) return null;
  for (const k of row.keys()) {
    if (k.startsWith(`${tableOid}.`)) {
      // rest = [idx…, col] — drop the trailing column segment.
      const rest = k.slice(tableOid.length + 1).split('.');
      return rest.slice(0, -1).join('.') || null;
    }
  }
  return null;
}

/** Convenience: all row-index paths of a table (in dump order). */
export function tableRowIndices(parsed: ParsedLcosConfig, tableOid: string): string[] {
  const rows = parsed.tables.get(tableOid);
  if (!rows) return [];
  const out: string[] = [];
  for (let i = 0; i < rows.length; i++) {
    const idx = rowIndexOf(parsed, tableOid, i);
    if (idx != null) out.push(idx);
  }
  return out;
}

/** Convenience: read one cell value from a parsed table by column oid + row-index path. */
export function tableCell(parsed: ParsedLcosConfig, tableOid: string, colOid: string, rowIndexPath: string): string | undefined {
  const rows = parsed.tables.get(tableOid);
  if (!rows) return undefined;
  for (const row of rows) {
    // Exact cell OID first.
    const exact = `${tableOid}.${rowIndexPath}.${colOid}`;
    if (row.has(exact)) return row.get(exact);
    // Multi-column-index tables: the cell may carry extra index segments — match by prefix.
    for (const [k, v] of row) {
      if (k.startsWith(`${exact}.`)) return v;
    }
  }
  return undefined;
}

// --- Sensitive-field redaction ---------------------------------------------------------------

/** OIDs whose values must never leave the plugin (passwords, hashes, secrets). */
const SENSITIVE_SCALAR_OIDS = new Set([
  '13.2.11.99',   // root hashed password
  '13.2.11.100',  // snmp root hash
]);

/** (tableOid, colOid) pairs holding secrets. */
const SENSITIVE_CELLS = new Set([
  `${'13.2.20.1'}.100`,   // WLAN network WPA key
  `${'13.2.30.3'}.4`,     // RADIUS shared secret
  `${'13.2.30.3'}.14`,    // (accounting secret variant)
  `${'13.2.102.2'}.3`,    // LMC proxy password
  `${'13.2.20.133.3'}.3`, // LEPS per-user PSK
  `${'13.2.61.1'}.5`,     // L2TP password
  `${'13.2.30.11'}.4`,    // 802.1X LAN supplicant password
]);

export const REDACTED = '••••••••';

/** Returns a copy of the parsed config with all sensitive values replaced by REDACTED. */
export function redactConfig(parsed: ParsedLcosConfig): ParsedLcosConfig {
  const scalars = new Map<string, string>();
  for (const [k, v] of parsed.scalars) scalars.set(k, SENSITIVE_SCALAR_OIDS.has(k) ? REDACTED : v);
  const tables = new Map<string, Map<string, string>[]>();
  for (const [t, rows] of parsed.tables) {
    // Sensitive entries are `<table>.<col>`; cell keys are ROW-FIRST `<table>.<idx…>.<col>`.
    const sensitiveCols = [...SENSITIVE_CELLS].filter((e) => e.startsWith(`${t}.`)).map((e) => e.slice(t.length + 1));
    const nr: Map<string, string>[] = [];
    for (const row of rows) {
      const nrow = new Map<string, string>();
      for (const [k, v] of row) {
        const col = k.split('.').pop() ?? '';
        nrow.set(k, sensitiveCols.includes(col) ? REDACTED : v);
      }
      nr.push(nrow);
    }
    tables.set(t, nr);
  }
  return { scalars, tables };
}
