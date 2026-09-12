/**
 * Config snapshots (= backups) — the rollback mechanism for plans.
 *
 * `snapshot.create` tars /etc/config to a timestamped file on the device's
 * overlay (survives reboots, unlike /tmp). The SDK's finalizePlan() auto-
 * prepends one best-effort snapshot.create per dirty device before any write
 * plan runs; `snapshot.restore` extracts it and reboots.
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands } from './helpers';

const BACKUP_DIR = '/root/unm-backups';

export const SNAPSHOT_ACTIONS: ActionDescriptor[] = [
  {
    id: 'snapshot.create',
    label: 'Create config snapshot',
    description: `Tars /etc/config to ${BACKUP_DIR}/<timestamp>.tar.gz (kept on the overlay). Auto-prepended by UNM before write plans as the rollback point.`,
    module: 'Backup',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {
      label: { type: 'string', description: 'Optional human-readable label stored alongside the snapshot.' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const file = `${BACKUP_DIR}/unm-${ts}.tar.gz`;
      const labelLine = typeof input.label === 'string' && input.label ? `echo '${String(input.label).replace(/'/g, '')}' > ${file}.label` : ': no-label';
      const r = await runCommands(ctx.backend.ssh!, [
        `mkdir -p ${BACKUP_DIR}`,
        `tar czf ${file} -C / etc/config`,
        labelLine,
        // Keep the 10 most recent snapshots.
        `ls -1t ${BACKUP_DIR}/unm-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f`,
      ]);
      if (!r.ok) return failResult(`Snapshot creation failed: ${r.stderr.slice(0, 300)}`);
      const size = await ctx.backend.ssh!.exec(`stat -c %s ${file} 2>/dev/null || echo 0`).catch(() => null);
      return okResult({ file, bytes: Number((size?.stdout ?? '0').trim()) || null });
    },
  },
  {
    id: 'snapshot.list',
    label: 'List config snapshots',
    description: `Lists snapshots in ${BACKUP_DIR} with size + age.`,
    module: 'Backup',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await ctx.backend.ssh!.exec(`ls -lh ${BACKUP_DIR}/unm-*.tar.gz 2>/dev/null || true`).catch(() => null);
      const files: string[] = [];
      for (const line of (r?.stdout ?? '').split('\n')) {
        const m = line.trim().match(/(\S+\.tar\.gz)\s*$/);
        if (m) files.push(m[1]);
      }
      return okResult({ count: files.length, files });
    },
  },
  {
    id: 'snapshot.restore',
    label: 'Restore config snapshot',
    description: `Extracts a snapshot over /etc/config and reboots. DANGEROUS — current configuration is replaced.`,
    module: 'Backup',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 90_000,
    inputSchema: {
      file: { type: 'string', required: true, description: `Snapshot filename (from snapshot.list), e.g. ${BACKUP_DIR}/unm-2026-09-12T10-00-00.tar.gz` },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const file = String(input.file);
      // Path confinement: must live inside the backup dir.
      if (!file.startsWith(`${BACKUP_DIR}/`) || file.includes('..')) {
        return failResult(`Invalid snapshot path — must be under ${BACKUP_DIR}.`);
      }
      const r = await runCommands(ctx.backend.ssh!, [
        `test -f ${file}`,
        // Safety: take a pre-restore snapshot of the CURRENT config first.
        `mkdir -p ${BACKUP_DIR}`,
        `tar czf ${BACKUP_DIR}/pre-restore-$(date +%s).tar.gz -C / etc/config`,
        `tar xzf ${file} -C /`,
      ]);
      if (!r.ok) return failResult(`Restore failed: ${r.stderr.slice(0, 300)}`);
      await ctx.backend.ssh!.exec('reboot', 5_000).catch(() => undefined);
      return okResult({ file, note: 'Configuration restored — device is rebooting.' });
    },
  },
];
