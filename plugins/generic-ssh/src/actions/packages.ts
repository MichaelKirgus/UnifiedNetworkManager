/**
 * OS package actions — read upgradable packages, apply upgrades via the host's
 * package manager (apt/dnf/yum/pacman/apk, auto-detected by the SDK).
 *
 * `packages.update` is DANGEROUS on purpose: a full OS upgrade on a production
 * server can restart services and consume significant bandwidth — it must go
 * through the plan workflow with 2FA + explicit confirm. The apply step runs
 * the manager's upgrade command, then VERIFIES by re-querying the upgradable
 * list (the target package must be gone) so the plan executor can mark the
 * result verified:true instead of leaving the plan 'unverified'.
 *
 * Privilege: both actions run through the privilege-aware backend — a non-root
 * login user with passwordless sudo (or a bound root slot) gets elevated
 * automatically; without elevation the package manager simply reports nothing
 * upgradable, exactly like before.
 */

import {
  DETACHED_ALREADY_RUNNING_EXIT,
  buildDetachedUpgradeScript,
  buildUpgradeStatusScript,
  detectPackageManager,
  listHeldPackages,
  listUpgradablePackages,
  parseDetachedUpgradeStatus,
  runForceFullUpgrade,
  runPackageUpgrade,
  runPackageUpgradeList,
  holdPackages,
  unholdPackages,
} from '@unm/plugin-sdk';
import type { DetachedUpgradeStatus } from '@unm/plugin-sdk';
import type { ActionDescriptor } from './types';
import { failResult, okResult, shq } from './types';

/** Conservative package-name charset — anything else is rejected before it touches a shell. */
function isSafePackageName(s: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9._:+@-]{0,127}$/.test(s);
}

// --- Detached dist-upgrade (minutes to HOURS — never hold an SSH session open) --
// The upgrade runs under nohup so the launching exec returns in ~1 s; we then poll a
// status probe. A dedicated non-pooled session is NOT needed: no single exec stays
// open for hours, so nothing blocks other execs on the host and there's no idle-drop risk.
const DIST_LOG = '/var/tmp/unm-dist-upgrade.log';
const DIST_PID = '/var/tmp/unm-dist-upgrade.pid';
/** How long packages.dist-upgrade waits (best-effort) before reporting "still running". */
const DIST_WAIT_MS = 10 * 60_000;

/** The heaviest full-OS update a manager offers: apt's dist-upgrade, else its plain
 *  bulk upgrade (dnf/yum/pacman/apk already resolve deps by adding/removing packages). */
function distUpgradeCmds(adapter: { distUpgrade?: () => string[] | null; upgrade: (pkg?: string) => string[] }): string[] {
  return adapter.distUpgrade?.() ?? adapter.upgrade();
}

/** Polls a detached upgrade until it finishes or the budget elapses. */
async function pollDetached(backend: { exec(command: string, timeoutMs?: number): Promise<{ code: number; stdout: string; stderr?: string }> }, logFile: string, pidFile: string, budgetMs: number): Promise<DetachedUpgradeStatus> {
  const deadline = Date.now() + budgetMs;
  let last: DetachedUpgradeStatus = { state: 'unknown', tail: '' };
  for (;;) {
    try {
      const r = await backend.exec(buildUpgradeStatusScript(logFile, pidFile), 15_000);
      last = parseDetachedUpgradeStatus(r.stdout);
      if (last.state !== 'running') return last; // done or failed — stop early
    } catch { /* transient SSH blip — keep polling */ }
    if (Date.now() >= deadline) break;
    await new Promise((res) => setTimeout(res, 5_000));
  }
  return last; // still running after the budget
}

export const PACKAGES_ACTIONS: ActionDescriptor[] = [
  {
    id: 'packages.read',
    label: 'List upgradable packages',
    description:
      'Detects the host package manager (apt/dnf/yum/pacman/apk) and lists every package with an update available, with current → latest versions.',
    module: 'Packages',
    riskLevel: 'read',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {},
    execute: async (ctx) => {
      const pm = await detectPackageManager(ctx.backend);
      if (!pm) return failResult('No known package manager detected on this host.');
      // Same query path as monitoring so results match the Updates page.
      const rows = await listUpgradablePackages(ctx.backend);
      return okResult({ pm: pm.id, count: rows.length, packages: rows.map((r) => ({ name: r.name, currentVersion: r.currentVersion, latestVersion: r.latestVersion })) });
    },
  },
  {
    id: 'packages.update',
    label: 'Update OS packages',
    description:
      'Upgrades one package (input `package`), an explicit list (`packages`) or ALL upgradable packages when both are omitted. Runs the host package manager non-interactively, then verifies by re-querying the upgradable list. DANGEROUS — a full upgrade can restart services; use per-package updates for surgical changes. Set `force: true` to ALSO install held / kept-back packages (apt: dist-upgrade with --allow-change-held-packages); the hold flag stays set afterwards.',
    module: 'Packages',
    riskLevel: 'dangerous',
    deviceCount: 1,
    // Full OS upgrades are slow (hundreds of MB on a server) — generous budget.
    timeoutMs: 600_000,
    inputSchema: {
      package: { type: 'string', description: 'Package name to upgrade (e.g. "curl"). Omit/empty = upgrade ALL upgradable packages.' },
      packages: { type: 'array', items: { type: 'string' }, description: 'Explicit list of package names to upgrade in ONE run (single lock acquisition). Takes precedence over `package`.' },
      force: { type: 'boolean', default: false, description: 'Also install held / kept-back packages. Ignored when a specific `package`/`packages` list is given — those must be unheld first via packages.unhold.' },
    },
    execute: async (ctx, input) => {
      const pkgRaw = typeof input['package'] === 'string' ? (input['package'] as string).trim() : '';
      const pkg = pkgRaw !== '' ? pkgRaw : undefined;
      if (pkg && !isSafePackageName(pkg)) {
        return failResult(`Invalid package name: ${shq(pkg)}`);
      }

      // Explicit list mode — e.g. "everything that does not need a reboot".
      const pkgsRaw = Array.isArray(input['packages']) ? input['packages'] : [];
      const pkgs = pkgsRaw.filter((p): p is string => typeof p === 'string' && p.trim() !== '').map((p) => p.trim());
      for (const p of pkgs) {
        if (!isSafePackageName(p)) return failResult(`Invalid package name: ${shq(p)}`);
      }

      // Force mode only makes sense for the FULL upgrade — a held package in an
      // explicit list is a caller bug (the webapp excludes them), so refuse it.
      const force = input['force'] === true;
      if (force && (pkg || pkgs.length > 0)) {
        return failResult('`force` only applies to the full upgrade — unheld specific packages first via packages.unhold.');
      }

      const res = force
        ? await runForceFullUpgrade(ctx.backend)
        : pkgs.length > 0
          ? await runPackageUpgradeList(ctx.backend, pkgs)
          : await runPackageUpgrade(ctx.backend, pkg);
      if (!res.ok) {
        return failResult(
          `Package upgrade failed (${res.pm ?? 'unknown manager'}): ${(res.stderr || res.stdout).slice(-500) || 'no output'}`
        );
      }

      // Verify: the target must no longer be listed as upgradable. A full
      // upgrade verifies by re-detecting — but apt SKIPS some "upgradable" rows on
      // purpose and they stay listed forever, so they don't count against
      // verification (they're reported instead): held (apt-mark hold), phased
      // (Ubuntu rollout cohort not reached yet) and kept-back (blocked deps).
      let verified = true;
      const skippedRemaining: Record<string, string[]> = { held: [], phased: [], keptBack: [] };
      try {
        const remaining = await listUpgradablePackages(ctx.backend);
        if (pkgs.length > 0) {
          // List mode: every requested package must be gone from the upgradable list.
          verified = !remaining.some((r) => pkgs.includes(r.name));
        } else if (pkg) {
          verified = !remaining.some((r) => r.name === pkg);
        } else {
          for (const r of remaining) {
            if (r.extra?.['held'] === true) skippedRemaining.held.push(r.name);
            if (r.extra?.['phased'] === true) skippedRemaining.phased.push(r.name);
            if (r.extra?.['keptBack'] === true) skippedRemaining.keptBack.push(r.name);
          }
          // Verified when every leftover is one apt skips on purpose; anything
          // else (e.g. a version published into the index mid-run) is real work left.
          verified = remaining.every((r) => r.extra?.['held'] === true || r.extra?.['phased'] === true || r.extra?.['keptBack'] === true);
        }
      } catch {
        verified = false; // verification query failed — don't claim success we can't prove
      }

      const skippedCount = Object.values(skippedRemaining).reduce((n, a) => n + a.length, 0);
      return okResult(
        {
          pm: res.pm,
          package: pkg ?? null,
          ...(pkgs.length > 0 ? { packages: pkgs } : {}),
          upgradedAll: pkg === undefined && pkgs.length === 0,
          ...(force ? { forced: true, note: 'Held/kept-back packages were installed; their hold flags remain set.' } : {}),
          ...(pkg === undefined && pkgs.length === 0 && skippedCount > 0 ? { skippedRemaining } : {}),
        },
        verified // top-level flag — the plan executor marks the plan 'unverified' without it
      );
    },
  },
  {
    id: 'packages.hold',
    label: 'Hold package(s) against updates',
    description:
      'Marks the given package(s) as HELD so bulk upgrades skip them on purpose (apt: `apt-mark hold`, dnf: version lock). The package stays listed as upgradable with a "held" badge until released via packages.unhold. Managers without a hold concept report not-supported.',
    module: 'Packages',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {
      package: { type: 'string', description: 'Package name to hold (e.g. "zabbix-agent2").' },
      packages: { type: 'array', items: { type: 'string' }, description: 'Explicit list of package names to hold.' },
    },
    execute: async (ctx, input) => {
      const pkgRaw = typeof input['package'] === 'string' ? (input['package'] as string).trim() : '';
      const pkgsRaw = Array.isArray(input['packages']) ? input['packages'] : [];
      const pkgs = [...(pkgRaw !== '' ? [pkgRaw] : []), ...pkgsRaw.filter((p): p is string => typeof p === 'string' && p.trim() !== '')].map((p) => p.trim());
      if (pkgs.length === 0) return failResult('No package name given.');
      for (const p of pkgs) {
        if (!isSafePackageName(p)) return failResult(`Invalid package name: ${shq(p)}`);
      }

      const res = await holdPackages(ctx.backend, pkgs);
      if (!res.ok) return failResult(res.error ?? 'Hold failed');

      // Verify: every requested package must now be in the manager's held set.
      let verified = false;
      try {
        const st = await listHeldPackages(ctx.backend);
        if (st.supported) {
          const heldSet = new Set(st.held.map((h) => h.split(' ')[0])); // dnf lists "name.arch"
          verified = pkgs.every((p) => heldSet.has(p));
        } else {
          return okResult({ pm: res.pm, held: pkgs, note: 'Manager has no hold concept — nothing was changed.' }, false);
        }
      } catch { /* verification query failed */ }
      return okResult({ pm: res.pm, held: pkgs }, verified);
    },
  },
  {
    id: 'packages.unhold',
    label: 'Release package(s) from hold',
    description:
      'Releases previously held packages so bulk upgrades install them again (apt: `apt-mark unhold`, dnf: version lock remove). Idempotent — releasing a package that is not held succeeds. Managers without a hold concept report not-supported.',
    module: 'Packages',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {
      package: { type: 'string', description: 'Package name to release (e.g. "zabbix-agent2").' },
      packages: { type: 'array', items: { type: 'string' }, description: 'Explicit list of package names to release.' },
    },
    execute: async (ctx, input) => {
      const pkgRaw = typeof input['package'] === 'string' ? (input['package'] as string).trim() : '';
      const pkgsRaw = Array.isArray(input['packages']) ? input['packages'] : [];
      const pkgs = [...(pkgRaw !== '' ? [pkgRaw] : []), ...pkgsRaw.filter((p): p is string => typeof p === 'string' && p.trim() !== '')].map((p) => p.trim());
      if (pkgs.length === 0) return failResult('No package name given.');
      for (const p of pkgs) {
        if (!isSafePackageName(p)) return failResult(`Invalid package name: ${shq(p)}`);
      }

      const res = await unholdPackages(ctx.backend, pkgs);
      if (!res.ok) return failResult(res.error ?? 'Unhold failed');

      // Verify: none of the requested packages may remain in the held set.
      let verified = false;
      try {
        const st = await listHeldPackages(ctx.backend);
        if (st.supported) {
          const heldSet = new Set(st.held.map((h) => h.split(' ')[0])); // dnf lists "name.arch"
          verified = !pkgs.some((p) => heldSet.has(p));
        } else {
          return okResult({ pm: res.pm, released: pkgs, note: 'Manager has no hold concept — nothing was changed.' }, false);
        }
      } catch { /* verification query failed */ }
      return okResult({ pm: res.pm, released: pkgs }, verified);
    },
  },
  {
    id: 'packages.dist-upgrade',
    label: 'Distro upgrade (dist-upgrade)',
    description:
      'Runs the manager\'s DISTRO-LEVEL upgrade — on Debian/Ubuntu this is `apt-get dist-upgrade`, which may add or remove packages to resolve dependencies. Launched DETACHED (nohup) so it can run for minutes to hours without holding an SSH session; the step waits up to 10 min and reports the live state, then you re-check with "Distro upgrade status". DANGEROUS — a distro upgrade can change service behavior or require a reboot.',
    module: 'Packages',
    riskLevel: 'dangerous',
    deviceCount: 1,
    // Launch is ~1 s; the best-effort wait dominates. The API dispatch window must cover it.
    timeoutMs: DIST_WAIT_MS + 60_000,
    inputSchema: {},
    execute: async (ctx) => {
      const adapter = await detectPackageManager(ctx.backend);
      if (!adapter) return failResult('No known package manager detected on this host.');

      // Launch detached. A concurrent run is refused cleanly (exit 97).
      const launch = buildDetachedUpgradeScript(distUpgradeCmds(adapter), DIST_LOG, DIST_PID);
      let launched: { code: number; stdout: string };
      try {
        launched = await ctx.backend.exec(launch, 30_000);
      } catch (err) {
        return failResult(`Could not launch dist-upgrade: ${(err as Error).message}`);
      }
      if (launched.code === DETACHED_ALREADY_RUNNING_EXIT) {
        const st = await pollDetached(ctx.backend, DIST_LOG, DIST_PID, 0); // single status read
        return okResult({ pm: adapter.id, alreadyRunning: true, state: st.state, tail: st.tail.slice(-400) }, false);
      }
      if (launched.code !== 0) {
        return failResult(`dist-upgrade launch failed (exit ${launched.code}): ${(launched.stdout || '').slice(-300)}`);
      }

      // Best-effort wait: report the outcome when it finishes within budget, else "still running".
      const st = await pollDetached(ctx.backend, DIST_LOG, DIST_PID, DIST_WAIT_MS);
      if (st.state === 'done') {
        return okResult({ pm: adapter.id, state: 'done', tail: st.tail.slice(-400) }, true);
      }
      if (st.state === 'failed') {
        return failResult(`dist-upgrade failed during the wait window — see "Distro upgrade status" for the log tail. ${st.tail.slice(-300)}`);
      }
      // Still running after the budget: NOT a failure — it keeps going under nohup.
      return okResult({ pm: adapter.id, state: 'running', note: 'Still running in the background (nohup). Re-check with "Distro upgrade status".', tail: st.tail.slice(-400) }, false);
    },
  },
  {
    id: 'packages.dist-upgrade-status.read',
    label: 'Distro upgrade status',
    description:
      'Read-only check of a previously launched dist-upgrade: running / done / failed plus the last log lines. Use it after "Distro upgrade (dist-upgrade)" reports that the run is still in progress.',
    module: 'Packages',
    riskLevel: 'read',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {},
    execute: async (ctx) => {
      const st = await pollDetached(ctx.backend, DIST_LOG, DIST_PID, 0); // single status read
      if (st.state === 'unknown') {
        return okResult({ state: 'none', note: 'No dist-upgrade has been launched on this host.' });
      }
      return okResult({ state: st.state, tail: st.tail.slice(-800) }, st.state !== 'running');
    },
  },
];
