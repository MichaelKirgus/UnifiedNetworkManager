/**
 * SSH data path for OpenWRT — wraps the SDK's process-wide SSH pool and adds
 * the two primitives every collector needs:
 *
 *   - exec(): one remote command (reuses the pooled session per host).
 *   - runSections(): MANY read commands in ONE round-trip, marker-delimited —
 *     the opnsense zfsSsh pattern. OpenWRT boxes are often low-end; a single
 *     SSH channel carrying 8 small reads beats 8 sequential execs.
 *
 * Plus uci helpers: parsing `uci show` output into nested objects and building
 * quoted uci set/add_list/del/commit command strings for the action layer.
 *
 * Security: host-key pinning runs inside the handshake via the SDK's
 * dynamicSshHostVerifier (resolves UNM's current trusted fingerprint per
 * device — a re-keyed box is verified against the CURRENT inventory, not one
 * baked in at pool-creation time). Credentials come exclusively from the UNM
 * secrets pipeline (resolveSshCredentials) and are never logged.
 */

import {
  createSshPool,
  dynamicSshHostVerifier,
  resolveSshCredentials,
} from '@unm/plugin-sdk';
import type { ExecResult, SshClient, SshCredentials } from '@unm/plugin-sdk';

/** Process-wide SSH pool (one session per host|port|username). */
const sshPool = createSshPool();

/** Closes every pooled connection on shutdown (opnsense zfsSsh convention). */
export function closeSshPools(): void {
  try {
    sshPool.closeAll();
  } catch {
    /* noop */
  }
}

const DEFAULT_EXEC_TIMEOUT_MS = 15_000;
/** Marker prefix/suffix for runSections — must not appear in command output. */
const MARKER = 'UNM_SECTION';

/** One named section of a combined exec. */
export interface SshSection {
  name: string;
  cmd: string;
}

/** A bound SSH backend for one host (credentials + port resolved). */
export class SshBackend {
  constructor(
    readonly host: string,
    readonly port: number,
    private readonly creds: SshCredentials
  ) {}

  /** One remote command. Throws on transport/auth/host-key failure. */
  async exec(command: string, timeoutMs = DEFAULT_EXEC_TIMEOUT_MS): Promise<ExecResult> {
    const client: SshClient = await sshPool.get(this.host, this.port, this.creds, {
      hostKeyVerifier: dynamicSshHostVerifier(this.host, this.port),
      timeoutMs,
    });
    return client.exec(command, this.creds);
  }

  /**
   * Runs several read commands in ONE exec. Each section's stdout is captured
   * between markers; per-section exit codes are ignored (best-effort reads — a
   * missing file must not sink the batch). Returns name → combined output.
   */
  async runSections(sections: SshSection[], timeoutMs = DEFAULT_EXEC_TIMEOUT_MS): Promise<Map<string, string>> {
    const parts: string[] = [];
    for (const s of sections) {
      // `2>&1` merges stderr so a "No such file" lands in the section too;
      // `|| true` keeps the shell going when one command fails.
      parts.push(`echo "${MARKER}:${s.name}:BEGIN"; (${s.cmd}) 2>&1 || true; echo "${MARKER}:${s.name}:END"`);
    }
    const r = await this.exec(parts.join('\n'), timeoutMs);
    return parseSections(r.stdout);
  }
}

/** Parses marker-delimited combined output into a name → text map. */
export function parseSections(stdout: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | null = null;
  let buf = '';
  for (const line of stdout.split('\n')) {
    const m = line.match(new RegExp(`^${MARKER}:(.+?):(BEGIN|END)$`));
    if (m) {
      if (current !== null && m[2] === 'END') out.set(current, buf.replace(/\n$/, ''));
      current = m[2] === 'BEGIN' ? m[1] : null;
      buf = '';
      continue;
    }
    if (current !== null) buf += line + '\n';
  }
  return out;
}

/** Resolves SSH credentials for this plugin: the bound `ssh` slot first, then
 *  a top-level username/password primary secret (the common OpenWRT case — one
 *  root login feeds both LuCI and SSH). Returns undefined when nothing usable. */
export function resolveOpenWrtSshCredentials(creds?: Record<string, unknown> | null): SshCredentials | undefined {
  return resolveSshCredentials(creds);
}

// ---------------------------------------------------------------------------
// uci helpers — parsing + command building
// ---------------------------------------------------------------------------

/** Shell single-quote escaping (the only safe way to embed values in commands). */
export function shq(value: string): string {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

/** Parses one uci value token: 'quoted' (with \' and \\ escapes) or bare. */
function parseUciValue(raw: string): string {
  const v = raw.trim();
  if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) {
    return v.slice(1, -1).replace(/\\'/g, "'").replace(/\\\\/g, '\\');
  }
  return v;
}

/**
 * Parses `uci show [pkg]` output into nested objects:
 *   network.lan.ipaddr='192.168.1.1'      → { network: { lan: { ipaddr: '...' } } }
 *   firewall.@rule[0].name='Allow-LAN'    → { firewall: { '@rule[0]': { name: '...' } } }
 * Option values are kept as STRINGS (uci semantics); callers convert.
 */
export function parseUciShow(text: string): Record<string, Record<string, Record<string, string>>> {
  const tree: Record<string, Record<string, Record<string, string>>> = {};
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const lhs = line.slice(0, eq).trim();
    const value = parseUciValue(line.slice(eq + 1));

    // lhs: pkg.section.option... or pkg.@type[idx].option...
    const dotIdx = lhs.indexOf('.');
    if (dotIdx <= 0) continue;
    const pkg = lhs.slice(0, dotIdx);
    const rest = lhs.slice(dotIdx + 1);

    // Split section from options: first segment is the section name.
    const segs = rest.split('.');
    const section = segs[0];
    const optionPath = segs.slice(1).join('.');
    if (!optionPath) continue;

    (tree[pkg] ??= {});
    (tree[pkg][section] ??= {});
    tree[pkg][section][optionPath] = value;
  }
  return tree;
}

/** All sections of one type in a parsed uci tree, in index order. */
export function uciSectionsByType(
  pkg: Record<string, Record<string, string>> | undefined,
  typeName: string
): Array<{ key: string; options: Record<string, string> }> {
  if (!pkg) return [];
  const out: Array<{ key: string; options: Record<string, string> }> = [];
  for (const [key, options] of Object.entries(pkg)) {
    // @type[idx] form — the canonical list-section shape.
    const m = key.match(/^@(\w+)\[(\d+)\]$/);
    if (m && m[1] === typeName) out.push({ key, options });
  }
  return out.sort((a, b) => {
    const ia = Number(a.key.match(/\[(\d+)\]/)?.[1] ?? 0);
    const ib = Number(b.key.match(/\[(\d+)\]/)?.[1] ?? 0);
    return ia - ib;
  });
}

/** Reads one option from a uci section (undefined when absent). */
export function uciOpt(options: Record<string, string>, name: string): string | undefined {
  const v = options[name];
  return v === undefined ? undefined : v;
}

// --- Command builders for the action layer ---------------------------------

/** `uci set pkg.section.option=value` (section must exist — use addSection first). */
export function uciSetCmd(pkg: string, section: string, option: string, value: string): string {
  return `uci set ${pkg}.${section}.${option}=${shq(value)}`;
}

/** `uci add_list pkg.section.option=value` (appends one list entry). */
export function uciAddListCmd(pkg: string, section: string, option: string, value: string): string {
  return `uci add_list ${pkg}.${section}.${option}=${shq(value)}`;
}

/** `uci del pkg.section` (removes a whole section). */
export function uciDelCmd(pkg: string, section: string): string {
  return `uci del ${pkg}.${section}`;
}

/**
 * Commands to create a new list-type section and set options on it. `nextIndex`
 * is the index `uci add pkg type` will assign (the count of existing @type[i]
 * sections from a prior read). Returns the concrete section key so callers can
 * reference it in later commands / results.
 */
export function uciAddSectionCmds(
  pkgName: string,
  typeName: string,
  nextIndex: number,
  initialOptions?: Record<string, string>
): { sectionKey: string; cmds: string[] } {
  const sectionKey = `@${typeName}[${nextIndex}]`;
  const cmds: string[] = [`uci add ${pkgName} ${typeName}`];
  for (const [option, value] of Object.entries(initialOptions ?? {})) {
    cmds.push(uciSetCmd(pkgName, sectionKey, option, value));
  }
  return { sectionKey, cmds };
}

/** Counts existing @type[i] sections in a parsed uci package tree. */
export function uciSectionCount(pkg: Record<string, Record<string, string>> | undefined, typeName: string): number {
  if (!pkg) return 0;
  let n = 0;
  for (const key of Object.keys(pkg)) {
    const m = key.match(/^@(\w+)\[(\d+)\]$/);
    if (m && m[1] === typeName) n++;
  }
  return n;
}

/** `uci commit [pkg]` — persists pending changes (and triggers procd reloads). */
export function uciCommitCmd(pkg?: string): string {
  return pkg ? `uci commit ${pkg}` : 'uci commit';
}
