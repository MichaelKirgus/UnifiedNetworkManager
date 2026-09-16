/**
 * Config snapshots (= backups) — the rollback mechanism for plans.
 *
 * `snapshot.create` tars /etc (the system configuration tree) to a timestamped
 * file in $HOME/unm-backups (works for root AND non-root SSH users; unreadable
 * files are skipped, not fatal). The SDK's finalizePlan() auto-prepends one
 * best-effort snapshot.create per dirty device before any write plan runs.
 * `snapshot.restore` extracts it back over /etc — DANGEROUS (root required to
 * actually replace system config; a non-root restore fails with a clear error).
 */

import type { ActionDescriptor } from './types';
import { okResult, failResult, runCommands, shq } from './types';

const BACKUP_DIR = '$HOME/unm-backups';

export const SNAPSHOT_ACTIONS: ActionDescriptor[] = [
  {
    id: 'snapshot.create',
    label: 'Create config snapshot',
    description:
      'Tars /etc to ~/unm-backups/unm-<timestamp>.tar.gz (kept on disk, survives reboots). Auto-prepended by UNM before write plans as the rollback point. Keeps the 10 most recent.',
    module: 'Backup',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 120_000,
    inputSchema: {
      label: { type: 'string', description: 'Optional human-readable label stored alongside the snapshot.' },
    },
    execute: async (ctx, input) => {
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const file = `${BACKUP_DIR}/unm-${ts}.tar.gz`;
      const labelLine = typeof input.label === 'string' && input.label ? `echo ${shq(String(input.label).slice(0, 200))} > ${file}.label` : ': no-label';
      // --ignore-failed-read: a non-root user cannot read every file in /etc —
      // skip those instead of failing the whole snapshot.
      const r = await runCommands(ctx.backend, [
        `mkdir -p ${BACKUP_DIR}`,
        `tar czf ${file} --ignore-failed-read -C / etc 2>/dev/null || true`,
        `[ -s ${file} ] || { echo "snapshot is empty — no readable config"; exit 1; }`,
        labelLine,
        // Keep the 10 most recent snapshots.
        `ls -1t ${BACKUP_DIR}/unm-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f`,
      ], 120_000);
      if (!r.ok) return failResult(`Snapshot creation failed: ${(r.stderr || r.stdout).slice(0, 300)}`);
      const size = await ctx.backend.exec(`stat -c %s ${file} 2>/dev/null || echo 0`).catch(() => null);
      return okResult({ file, bytes: Number((size?.stdout ?? '0').trim()) || null });
    },
  },
  {
    id: 'snapshot.list',
    label: 'List config snapshots',
    description: 'Lists snapshots in ~/unm-backups with size + age.',
    module: 'Backup',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const r = await ctx.backend.exec(`ls -lh ${BACKUP_DIR}/unm-*.tar.gz 2>/dev/null || true`).catch(() => null);
      if (!r) return failResult('Could not list snapshots.');
      const files: string[] = [];
      for (const line of r.stdout.split('\n')) {
        const m = line.trim().match(/(\S+unm-[^ ]*\.tar\.gz)\s*$/);
        if (m) files.push(m[1]);
      }
      return okResult({ count: files.length, files });
    },
  },
  {
    id: 'snapshot.restore',
    label: 'Restore config snapshot',
    description:
      'Extracts a snapshot back over /etc. DANGEROUS — current configuration is replaced and services may need restarting. Requires root (or sudo) SSH access; a non-root restore fails with a clear error instead of partially writing.',
    module: 'Backup',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 120_000,
    inputSchema: {
      file: { type: 'string', required: true, description: 'Snapshot path (from snapshot.list), e.g. /root/unm-backups/unm-2026-09-16T10-00-00.tar.gz' },
    },
    execute: async (ctx, input) => {
      const file = String(input.file).trim();
      // Path confinement: must live inside a unm-backups dir and contain no traversal.
      if (!/unm-backups\/unm-[^\s]+\.tar\.gz$/.test(file) || file.includes('..')) {
        return failResult(`Invalid snapshot path — expected <home>/unm-backups/unm-<timestamp>.tar.gz.`);
      }
      // Root check FIRST — a non-root restore would half-write /etc and leave the box broken.
      const who = await ctx.backend.exec('id -u').catch(() => null);
      if (!who || (who.stdout ?? '').trim() !== '0') {
        return failResult('Restore requires root SSH access (the bound credential is not uid 0).');
      }
      const r = await runCommands(ctx.backend, [
        `[ -s ${shq(file)} ] || { echo "snapshot file missing"; exit 1; }`,
        `tar xzf ${shq(file)} -C / --ignore-failed-read 2>/dev/null || true`,
      ], 120_000);
      if (!r.ok) return failResult(`Restore failed: ${(r.stderr || r.stdout).slice(0, 300)}`);
      return okResult({ file, note: 'Configuration restored — restart affected services (or the system) to apply.' });
    },
  },
];
