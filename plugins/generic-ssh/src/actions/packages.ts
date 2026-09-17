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
 */

import { detectPackageManager, listUpgradablePackages, runPackageUpgrade } from '@unm/plugin-sdk';
import type { ActionDescriptor } from './types';
import { failResult, okResult, shq } from './types';

/** Conservative package-name charset — anything else is rejected before it touches a shell. */
function isSafePackageName(s: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9._:+@-]{0,127}$/.test(s);
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
      'Upgrades one package (input `package`) or ALL upgradable packages when omitted. Runs the host package manager non-interactively, then verifies by re-querying the upgradable list. DANGEROUS — a full upgrade can restart services; use per-package updates for surgical changes.',
    module: 'Packages',
    riskLevel: 'dangerous',
    deviceCount: 1,
    // Full OS upgrades are slow (hundreds of MB on a server) — generous budget.
    timeoutMs: 600_000,
    inputSchema: {
      package: { type: 'string', description: 'Package name to upgrade (e.g. "curl"). Omit/empty = upgrade ALL upgradable packages.' },
    },
    execute: async (ctx, input) => {
      const pkgRaw = typeof input['package'] === 'string' ? (input['package'] as string).trim() : '';
      const pkg = pkgRaw !== '' ? pkgRaw : undefined;
      if (pkg && !isSafePackageName(pkg)) {
        return failResult(`Invalid package name: ${shq(pkg)}`);
      }

      const res = await runPackageUpgrade(ctx.backend, pkg);
      if (!res.ok) {
        return failResult(
          `Package upgrade failed (${res.pm ?? 'unknown manager'}): ${(res.stderr || res.stdout).slice(-500) || 'no output'}`
        );
      }

      // Verify: the target must no longer be listed as upgradable. A full
      // upgrade verifies by re-detecting (list may still show a few stragglers —
      // we only fail when the SPECIFIC requested package is still pending).
      let verified = true;
      try {
        const remaining = await listUpgradablePackages(ctx.backend);
        if (pkg) {
          verified = !remaining.some((r) => r.name === pkg);
        } else {
          // Full upgrade: consider it verified when the manager reports nothing left.
          verified = remaining.length === 0;
        }
      } catch {
        verified = false; // verification query failed — don't claim success we can't prove
      }

      return okResult({ pm: res.pm, package: pkg ?? null, upgradedAll: pkg === undefined, verified });
    },
  },
];
