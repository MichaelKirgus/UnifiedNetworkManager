/**
 * Firewall log actions — make the host's kernel firewall drops VISIBLE in UNM.
 *
 * Linux has no "enable firewall logging" switch like OPNsense; blocked packets
 * are only logged when a rule says so. These actions install BEHAVIOR-PRESERVING
 * nftables log twins: for every existing `drop`/`reject` rule, a twin with the
 * SAME match is placed immediately BEFORE it that only LOGS the packet (`log
 * prefix "UNM-DROP" limit rate 10/second`, no verdict). The packet is logged
 * once by the twin and then falls through to the original verdict, so traffic
 * handling never changes. Chains whose POLICY is drop/reject additionally get a
 * trailing no-match log rule that catches exactly the packets falling through
 * to the policy. The kernel writes those lines to journald, where the
 * monitoring path (../firewallEvents.ts) picks them up and pushes them to UNM's
 * Firewall Events page.
 *
 * HOW: the nft CLI cannot insert a rule at an arbitrary position in ANY version
 * (`insert ... handle N`, `before handle`, `update`/`replace rule` are all
 * rejected — verified live on 1.0.6 and 1.1.3). The only generic mechanism is
 * an atomic per-chain rebuild: `flush chain` + re-add every rule in order with
 * the twins interleaved, committed as ONE transaction via `nft -f`. The batch
 * is validated first with `nft -c -f` — if anything doesn't parse, NOTHING is
 * applied. Chain definitions (hook, priority, policy) are never touched.
 *
 *  - firewall.log.enable   rebuild every chain that has an explicit drop/reject
 *                          rule or a drop/reject policy, with fresh twins
 *                          (self-healing: user rules added/removed since the
 *                          last run are picked up; stale twins are dropped).
 *  - firewall.log.disable  rebuild every chain that currently contains UNM-DROP
 *                          lines without them — restores the original rule set.
 *
 * Side effect: rebuilt chains' per-rule packet counters reset to zero (the CLI
 * rejects `-a`'s live counter values as spec input). Only bare `drop`/`reject`
 * verdicts are handled; `reject with <type>` is skipped. Requires privilege to
 * modify the ruleset (root slot or passwordless sudo, like every other write
 * action here).
 */

import type { ActionDescriptor } from './types';
import { okResult, failResult } from './types';

const LOG_PREFIX = 'UNM-DROP';

/** awk preamble shared by both scripts: tracks the current `table <fam> <name>`
 * and chain. In nft's `-a` output the name is always field 3 (tables) / field 2
 * (chains) — the `{` and `# handle N` decorations are separate fields, so no
 * stripping is needed: `table inet omr { # handle 10`, `\tchain input { # handle 3`.
 * NOTE: nft indents chain lines with TABS (tables sit at column 0) — the leading
 * whitespace class must accept both (`[ \\t]*`), else every chain name is empty. */
const AWK_TRACK = [
  `  /^table /{ fam=$2; name=$3; table=fam" "name; inChain=0 }`,
  `  /^[ \\t]*chain /{ chain=$2; inChain=1; n=0; hasDrop=0; hasUNM=0; pol="" }`,
].join('\n');

/** Shell script: atomically rebuild the selected chains — with UNM-DROP log
 * twins (mode "enable") or without them (mode "disable"). See the file header
 * for why a flush+re-add rebuild is the only generic mechanism. Emits markers:
 * NOTHING_TO_DO / CHECK_FAILED / APPLY_FAILED / REBUILT_OK. */
export function rebuildScript(mode: 'enable' | 'disable'): string {
  return [
    `TMPF=$(mktemp) || exit 1`,
    `CHKF=$(mktemp) || { rm -f "$TMPF"; exit 1; }`,
    `nft -a list ruleset 2>/dev/null | awk -v MODE=${mode} '`,
    AWK_TRACK,
    // Chain policy comes from the type line (first line inside a chain block).
    `  inChain && /policy [a-z]+/ { if (match($0, /policy [a-z]+/)) pol=substr($0, RSTART+7, RLENGTH-7) }`,
    // Rule lines: two leading whitespace chars + trailing "# handle N". Set/map
    // content never carries a handle, so this discriminates cleanly.
    `  inChain && /^[ \\t][ \\t]/ && /# handle/ {`,
    `    line=$0; sub(/^[ \\t]+/, "", line); sub(/ *# handle [0-9]+$/, "", line)`,
    `    if (line ~ /${LOG_PREFIX}/) { hasUNM=1; next }   # stale twin — drop it`,
    // `-a` embeds live counter values (`counter packets 12 bytes 34`) which the
    // CLI rejects as spec input — collapse to bare `counter`.
    `    gsub(/counter packets [0-9]+ bytes [0-9]+/, "counter", line)`,
    // Twin = same match, log statement instead of the terminal verdict (no
    // verdict → packet falls through to the original rule right after). The
    // quotes around ${LOG_PREFIX} are awk-string escapes (\\") — nft needs them.
    `    if (MODE=="enable" && line ~ / drop$/)      { twin=line; sub(/ drop$/, " log prefix \\"${LOG_PREFIX}\\" limit rate 10/second", twin); rules[++n]=twin; hasDrop=1 }`,
    `    else if (MODE=="enable" && line ~ / reject$/){ twin=line; sub(/ reject$/, " log prefix \\"${LOG_PREFIX}\\" limit rate 10/second", twin); rules[++n]=twin; hasDrop=1 }`,
    `    rules[++n]=line`,
    `  }`,
    // Chain close (one leading whitespace char + "}"): emit this chain's batch.
    `  inChain && /^[ \\t]}/ {`,
    `    sel = (MODE=="enable") ? (hasDrop || pol=="drop" || pol=="reject") : hasUNM`,
    `    if (sel) {`,
    `      print "flush chain " table " " chain`,
    `      for (i=1; i<=n; i++) print "add rule " table " " chain " " rules[i]`,
    // Policy drops: a trailing no-match log rule catches exactly the packets
    // that fall through to the drop/reject policy.
    `      if (MODE=="enable" && (pol=="drop" || pol=="reject")) print "add rule " table " " chain " log prefix \\"${LOG_PREFIX}\\" limit rate 10/second"`,
    `    }`,
    `    inChain=0; n=0`,
    `  }`,
    `' > "$TMPF"`,
    // Nothing selected → no-op (no chains with drops / nothing to remove).
    `[ -s "$TMPF" ] || { echo NOTHING_TO_DO; rm -f "$TMPF" "$CHKF"; exit 0; }`,
    // Validate the WHOLE batch first — on failure nft prints the offending
    // line and applies NOTHING (atomic), so a parse problem can never leave a
    // chain half-rebuilt.
    `if ! nft -c -f "$TMPF" >"$CHKF" 2>&1; then head -8 "$CHKF"; echo CHECK_FAILED; rm -f "$TMPF" "$CHKF"; exit 1; fi`,
    `nft -f "$TMPF" || { echo APPLY_FAILED; rm -f "$TMPF" "$CHKF"; exit 1; }`,
    `rm -f "$TMPF" "$CHKF"`,
    `echo REBUILT_OK`,
  ].join('\n');
}

/** Shell script: count drop/reject rules and installed UNM-DROP log lines. */
function countScript(): string {
  return [
    `DROPS=$(nft -a list ruleset 2>/dev/null | grep -cE ' (drop|reject) # handle' || true)`,
    `TWINS=$(nft list ruleset 2>/dev/null | grep -c '${LOG_PREFIX}' || true)`,
    `printf 'DROPS=%s TWINS=%s\\n' "\${DROPS:-0}" "\${TWINS:-0}"`,
  ].join('\n');
}

export const FIREWALL_LOG_ACTIONS: ActionDescriptor[] = [
  {
    id: 'firewall.log.enable',
    label: 'Enable firewall drop logging',
    description:
      'Installs behavior-preserving nftables log twins on this host: for every existing DROP/REJECT rule, a twin with the same match is placed right before it that only LOGS the packet (prefix "UNM-DROP", rate-limited to 10/s), and chains with a drop/reject policy get a trailing log rule — traffic handling never changes. The kernel then writes those drops to journald and UNM ships them to the cross-device Firewall Events page on every poll. Each affected chain is rebuilt atomically (validated first, all-or-nothing). Re-running is safe: stale twins are replaced, so rules you add or remove later are picked up automatically. Side effect: per-rule packet counters on rebuilt chains reset to zero.',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const hasNft = await ctx.backend.exec('command -v nft >/dev/null 2>&1 && echo YES || echo NO').catch(() => null);
      if (!hasNft || !hasNft.stdout.includes('YES')) {
        return failResult('nftables (nft) is not available on this host — drop logging requires it.');
      }

      // Rebuild affected chains with fresh twins (atomic), then report counts.
      const r = await ctx.backend.exec(
        [rebuildScript('enable'), countScript()].join('\n'),
        60_000,
      ).catch(() => null);
      if (!r || r.code !== 0) {
        return failResult(`Could not modify the nftables ruleset (exit ${r?.code ?? 'unknown'}): ${(r?.stderr ?? '').trim().slice(0, 300) || 'no error output'}. The host needs root or passwordless sudo for nft.`);
      }

      const out = r.stdout ?? '';
      if (out.includes('CHECK_FAILED')) {
        return failResult(`The generated ruleset change failed validation — NOTHING was applied. ${out.split('\n').filter((l) => l.trim() && !l.startsWith('CHECK_FAILED')).slice(0, 4).join(' | ')}`);
      }
      if (out.includes('APPLY_FAILED')) {
        return failResult('The validated ruleset change failed to apply — check the host manually.');
      }
      const m = out.match(/DROPS=(\d+) TWINS=(\d+)/);
      const drops = m ? Number(m[1]) : 0;
      const twins = m ? Number(m[2]) : 0;

      return okResult(
        {
          dropRulesFound: drops,
          logRulesInstalled: twins,
          note: out.includes('NOTHING_TO_DO') || drops === 0
            ? 'No existing DROP/REJECT rules found — nothing to log yet. New drop rules you add later are picked up on the next enable.'
            : `Logging ${twins} of ${drops} drop/reject rule(s); logged packets appear in UNM's Firewall Events page within one poll cycle.`,
        },
        true, // re-read the live ruleset and confirmed the twins are present
      );
    },
  },
  {
    id: 'firewall.log.disable',
    label: 'Disable firewall drop logging',
    description:
      'Removes all "UNM-DROP" log twins installed by firewall.log.enable, restoring the original rule set of every affected chain (rebuilt atomically, validated first). The original DROP/REJECT rules keep working unchanged. Side effect: per-rule packet counters on rebuilt chains reset to zero.',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const hasNft = await ctx.backend.exec('command -v nft >/dev/null 2>&1 && echo YES || echo NO').catch(() => null);
      if (!hasNft || !hasNft.stdout.includes('YES')) {
        return failResult('nftables (nft) is not available on this host.');
      }

      const r = await ctx.backend.exec(
        [rebuildScript('disable'), countScript()].join('\n'),
        60_000,
      ).catch(() => null);
      if (!r || r.code !== 0) {
        return failResult(`Could not modify the nftables ruleset (exit ${r?.code ?? 'unknown'}): ${(r?.stderr ?? '').trim().slice(0, 300) || 'no error output'}.`);
      }

      const out = r.stdout ?? '';
      if (out.includes('CHECK_FAILED')) {
        return failResult(`The generated ruleset change failed validation — NOTHING was applied. ${out.split('\n').filter((l) => l.trim() && !l.startsWith('CHECK_FAILED')).slice(0, 4).join(' | ')}`);
      }
      if (out.includes('APPLY_FAILED')) {
        return failResult('The validated ruleset change failed to apply — check the host manually.');
      }

      const m = out.match(/TWINS=(\d+)/);
      const twins = m ? Number(m[1]) : 0;
      if (twins > 0) {
        return failResult(`${twins} "UNM-DROP" log line(s) remain — check the host's nftables state manually.`);
      }
      return okResult({
        logRulesInstalled: 0,
        note: out.includes('NOTHING_TO_DO') ? 'No UNM-DROP log rules were present — nothing to remove.' : 'All UNM-DROP log twins removed; original drop/reject rules restored.',
      }, true);
    },
  },
];
