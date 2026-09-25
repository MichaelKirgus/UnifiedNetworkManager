/**
 * Security actions — explicit re-baselining of watched files.
 *
 * File-integrity findings are DELIBERATELY not auto-resolved: an attacker who
 * can edit /etc/passwd must not be able to make the finding disappear by
 * changing the file again (that would just re-baseline their own change). The
 * operator verifies the change is legitimate, then runs this action to accept
 * the new state as the baseline. It writes through the SAME plugin state store
 * the monitoring checks read from, so the next inventory poll sees the fresh
 * baseline and the finding clears.
 */

import type { ActionDescriptor } from './types';
import { okResult, failResult } from './types';
import { DEFAULT_WATCHED_FILES } from '../security';
// The SAME shared store the monitoring path writes baselines through — bound to
// this instance's effective uuid (`<uuid>:<instanceId>`), so multi-instance
// deployments re-baseline only their own state. Never build a second store here:
// an action that wrote under a different plugin id would be invisible to (or
// clobber) the monitoring checks of another instance.
import { stateStore } from '../stateStore';

const STATE_NAMESPACE = 'file-integrity'; // must match security.ts

export const SECURITY_ACTIONS: ActionDescriptor[] = [
  {
    id: 'security.rebaseline',
    label: 'Re-baseline watched files',
    description:
      'Accepts the CURRENT content of the plugin\'s watched files as the new integrity baseline, clearing any open file-integrity findings for them. Use ONLY after you have verified a change is legitimate (e.g. you edited /etc/ssh/sshd_config yourself). Without this action, a changed file keeps raising a critical finding on every poll.',
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
      const store = stateStore; // shared, instance-scoped — see import above
      const host = ctx.host;

      // Re-hash exactly what monitoring hashes (sha256sum), then write baselines.
      const wanted: string[] = Array.isArray(input.files) && input.files.length > 0
        ? (input.files as unknown[]).map((f) => String(f)).filter((f) => f.startsWith('/'))
        : DEFAULT_WATCHED_FILES;

      const list = wanted.map((p) => `'${p.replace(/'/g, "'\\''")}'`).join(' ');
      const r = await ctx.backend.exec(
        `for f in ${list}; do [ -f "$f" ] && printf 'HASH %s %s\\n' "$(sha256sum "$f" 2>/dev/null | cut -d\' \' -f1)" "$f"; done`,
        20_000,
      ).catch(() => null);
      if (!r || r.code !== 0) return failResult('Could not read the watched files (missing sha256sum or exec failed).');

      const baselines = await store.list(STATE_NAMESPACE);
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

      if (rebaselined === 0) return failResult('No watched files could be re-baselined (none of the requested paths are currently baselined on this host).');
      await store.put(entries.map((e) => ({ namespace: STATE_NAMESPACE, key: e.key, value: e.value, deviceId: ctx.deviceId ?? undefined })));

      return okResult({ rebaselined, files: entries.map((e) => e.key.slice(prefix.length)) }, true);
    },
  },
];
