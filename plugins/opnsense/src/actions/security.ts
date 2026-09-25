/**
 * Security actions — explicit re-baselining of watched files.
 *
 * File-integrity findings are DELIBERATELY not auto-resolved: an attacker who
 * can edit /etc/master.passwd must not be able to make the finding disappear by
 * changing the file again (that would just re-baseline their own change). The
 * operator verifies the change is legitimate, then runs this action to accept
 * the new state as the baseline. It writes through the SAME plugin state store
 * the monitoring checks read from, so the next inventory poll sees the fresh
 * baseline and the finding clears. Requires a bound `ssh` slot (same gate as
 * the monitoring checks).
 */

import { hostFromAddress } from '@unm/plugin-sdk';
import type { ActionDescriptor } from './types';
import { DEFAULT_WATCHED_FILES } from '../security';
import { execViaSshSlot } from '../zfsSsh';
// The SAME shared store the monitoring path writes baselines through — bound to
// this instance's effective uuid (`<uuid>:<instanceId>`), so multi-instance
// deployments re-baseline only their own state. Never build a second store here:
// an action that wrote under a different plugin id would be invisible to (or
// clobber) the monitoring checks of another instance.
import { stateStore } from '../stateStore';

const STATE_NAMESPACE = 'file-integrity'; // must match security.ts

export const securityActions: ActionDescriptor[] = [
  {
    id: 'security.rebaseline',
    label: 'Re-baseline watched files',
    description:
      'Accepts the CURRENT content of the plugin\'s watched files as the new integrity baseline, clearing any open file-integrity findings for them. Use ONLY after you have verified a change is legitimate (e.g. you rotated /etc/master.passwd yourself). Requires a bound SSH credential slot. Without this action, a changed file keeps raising a critical finding on every poll.',
    module: 'Security',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {
      files: {
        type: 'array',
        items: { type: 'string' },
        required: false,
        description: 'Specific watched paths to re-baseline (e.g. ["/etc/ssh/sshd_config"]). Omit to re-baseline every file the plugin watches.',
      },
    },
    execute: async (ctx, input) => {
      const host = hostFromAddress(ctx.host) ?? ctx.host;

      // Re-hash exactly what monitoring hashes (sha256sum on Linux, sha256 on FreeBSD).
      const wanted: string[] = Array.isArray(input.files) && input.files.length > 0
        ? (input.files as unknown[]).map((f) => String(f)).filter((f) => f.startsWith('/'))
        : DEFAULT_WATCHED_FILES;

      const list = wanted.map((p) => `'${p.replace(/'/g, "'\\''")}'`).join(' ');
      const command = [
        'hashfile() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | cut -d\' \' -f1; else sha256 -h "$1" 2>/dev/null | awk \'{print $NF}\'; fi; }',
        `for f in ${list}; do [ -f "$f" ] && printf 'HASH %s %s\\n' "$(hashfile "$f")" "$f"; done`,
      ].join('\n');

      const r = await execViaSshSlot(host, ctx.credentials as Record<string, unknown>, command, {
        port: typeof ctx.extra?.['sshPort'] === 'number' ? (ctx.extra['sshPort'] as number) : undefined,
        timeoutMs: 20_000,
      }).catch(() => null);
      if (!r || r.code !== 0) return { success: false, error: 'Could not read the watched files over SSH — bind an `ssh` credential slot to this device.' };

      const baselines = await stateStore.list(STATE_NAMESPACE);
      const prefix = `${host}|`;
      let rebaselined = 0;
      const entries: { key: string; value: unknown }[] = [];
      for (const line of (r.stdout ?? '').split('\n')) {
        if (!line.startsWith('HASH ')) continue;
        const [hash, ...rest] = line.slice(5).trim().split(/\s+/);
        const path = rest.join(' ');
        if (!hash || !path) continue;
        // Only re-baseline files that are actually in the plugin's watched set —
        // never let an arbitrary path be written into the store.
        const isWatched = (baselines[`${prefix}${path}`] !== undefined);
        if (!isWatched) continue;
        entries.push({ key: `${prefix}${path}`, value: { hash } });
        rebaselined++;
      }

      if (rebaselined === 0) return { success: false, error: 'No watched files could be re-baselined (none of the requested paths are currently baselined on this host).' };
      await stateStore.put(entries.map((e) => ({ namespace: STATE_NAMESPACE, key: e.key, value: e.value, deviceId: ctx.deviceId ?? undefined })));

      return { success: true, applied: true, verified: true, details: { rebaselined, files: entries.map((e) => e.key.slice(prefix.length)) } };
    },
  },
];
