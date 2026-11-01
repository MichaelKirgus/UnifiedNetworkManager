/**
 * Actions & Schedules — automation template catalog.
 *
 * Two sources, one list:
 *  - BUILT-IN templates owned by the API (below) — generic update-automation
 *    recipes that work with any plugin whose device_updates rows carry an apply
 *    path (intent actions use resolveFromTrigger='update', so no per-plugin
 *    action ids are hardcoded).
 *  - PLUGIN-advertised templates: plugins declare `automationTemplates[]` in
 *    /discover; discovery persists them on the plugin row and they are served
 *    here alongside the built-ins. Malformed entries (bad shape or a draft that
 *    fails validateAutomationDraft) are dropped at normalization time — a bad
 *    template must never poison the catalog.
 *
 * The webapp's Automations page offers each template as a starting point: it
 * opens the rule builder pre-filled with the draft (block ids regenerated), and
 * the user edits before saving via the normal POST /automations path — nothing
 * is created by picking a template.
 */

import { db } from '../db';
import * as schema from '../db/schema';
import { validateAutomationDraft } from './engine';
import type { AutomationDraft, ActionBlock, TriggerBlock } from './types';

/** One ready-made automation rule draft (same shape the SDK advertises). */
export interface AutomationTemplate {
  /** Stable template identity within its source. */
  id: string;
  /** Display name for the catalog. */
  name: string;
  /** Short human description of what the rule does and when it fires. */
  description?: string;
  /** AutomationDraft-shaped pre-fill (triggers + actions blocks). */
  draft: Record<string, unknown>;
}

/** A template as served to the webapp — source attribution added. */
export interface ServedTemplate extends AutomationTemplate {
  /** 'builtin' or the advertising plugin's id. */
  source: string;
  /** Display name of the source ('Built-in' for built-ins, else the plugin name). */
  sourceName: string;
}

/** Hard cap on advertised templates per plugin (abuse guard at normalization). */
const MAX_TEMPLATES_PER_PLUGIN = 50;

// ── Built-in templates ────────────────────────────────────────────────────────

export const BUILTIN_TEMPLATES: AutomationTemplate[] = [
  {
    id: 'builtin-auto-update-no-reboot-nightly',
    name: 'Auto-update apps without reboot (nightly window)',
    description:
      'When an app or container-image update appears that does NOT require a reboot, apply it automatically at the next 02:00 daily slot via its plugin apply action. Reboot-required updates are skipped and logged.',
    draft: {
      name: 'Auto-update apps without reboot (nightly window)',
      description: 'Deferred to 02:00 daily; skips reboot-required rows.',
      enabled: true,
      cooldownSec: 3600,
      triggers: [
        {
          id: 't-update',
          type: 'updateAvailable',
          condition: 'available',
          kinds: ['app', 'docker-image'],
          rebootRequired: false,
          defer: { schedule: { kind: 'dailyAt', time: '02:00' } },
        },
      ],
      actions: [
        {
          id: 'a-apply',
          type: 'intent',
          resolveFromTrigger: 'update',
          requireNoReboot: true,
          devices: {},
        },
        {
          id: 'a-note',
          type: 'notification',
          severity: 'info',
          titleTemplate: 'Update applied on {{device.name}}',
          messageTemplate: '{{update.kind}} "{{update.name}}" updated to {{update.latestVersion}} by automation.',
        },
      ],
    },
  },
  {
    id: 'builtin-notify-firmware-update',
    name: 'Notify on firmware update',
    description:
      'Send a warning notification as soon as a firmware update becomes available for any device. No automatic apply — the admin decides (firmware updates usually need a reboot).',
    draft: {
      name: 'Notify on firmware update',
      enabled: true,
      cooldownSec: 3600,
      triggers: [
        { id: 't-update', type: 'updateAvailable', condition: 'available', kinds: ['firmware'] },
      ],
      actions: [
        {
          id: 'a-note',
          type: 'notification',
          severity: 'warning',
          titleTemplate: 'Firmware update available on {{device.name}}',
          messageTemplate: '{{update.name}}: {{update.currentVersion}} → {{update.latestVersion}}. Apply it from the Updates page when ready (firmware updates usually need a reboot).',
        },
      ],
    },
  },
  {
    id: 'builtin-apply-no-reboot-immediately',
    name: 'Apply no-reboot updates immediately',
    description:
      'As soon as any update appears that does NOT require a reboot and has an apply path, run its plugin apply action right away (plan workflow — still 2FA-gated). Reboot-required rows are skipped.',
    draft: {
      name: 'Apply no-reboot updates immediately',
      enabled: true,
      cooldownSec: 600,
      triggers: [
        { id: 't-update', type: 'updateAvailable', condition: 'available', rebootRequired: false },
      ],
      actions: [
        {
          id: 'a-apply',
          type: 'intent',
          resolveFromTrigger: 'update',
          requireNoReboot: true,
          devices: {},
        },
      ],
    },
  },
];

// ── Normalization (defensive — plugin-supplied data) ─────────────────────────

/** True when `raw` looks like an AutomationDraft with non-empty block arrays. */
function isPlausibleDraft(raw: unknown): raw is Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
  const d = raw as Record<string, unknown>;
  return (
    typeof d.name === 'string' &&
    d.name.trim().length > 0 &&
    Array.isArray(d.triggers) &&
    d.triggers.length > 0 &&
    Array.isArray(d.actions) &&
    d.actions.length > 0
  );
}

/**
 * Defensively normalizes a raw `automationTemplates` array from /discover:
 * keeps only entries with a non-empty string id + name and a draft that passes
 * validateAutomationDraft; caps the list. Returns undefined when nothing
 * survives (so an empty/absent advertisement never wipes stored templates).
 */
export function normalizeAutomationTemplates(raw: unknown): AutomationTemplate[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out: AutomationTemplate[] = [];
  for (const item of raw.slice(0, MAX_TEMPLATES_PER_PLUGIN)) {
    if (!item || typeof item !== 'object') continue;
    const e = item as Record<string, unknown>;
    if (typeof e.id !== 'string' || e.id.trim() === '') continue;
    if (!isPlausibleDraft(e.draft)) continue;
    // The draft must pass the SAME validation a user-created rule passes —
    // otherwise creating from it would 400. Block ids are backfilled when missing
    // (the webapp regenerates them anyway on create).
    const triggers = (e.draft.triggers as TriggerBlock[]).map((t, i) => ({ ...t, id: typeof t.id === 'string' && t.id !== '' ? t.id : `t-${i}` }));
    const actions = (e.draft.actions as ActionBlock[]).map((a, i) => ({ ...a, id: typeof a.id === 'string' && a.id !== '' ? a.id : `a-${i}` }));
    const errors = validateAutomationDraft({ ...(e.draft as unknown as AutomationDraft), triggers, actions });
    if (errors.length > 0) {
      // eslint-disable-next-line no-console
      console.warn(`[automations] dropping invalid advertised template "${e.id}":`, errors.join('; '));
      continue;
    }
    const t: AutomationTemplate = { id: e.id.trim(), name: typeof e.name === 'string' && e.name.trim() !== '' ? e.name.trim() : e.id.trim(), draft: e.draft as Record<string, unknown> };
    if (typeof e.description === 'string' && e.description.trim() !== '') t.description = e.description.trim();
    out.push(t);
  }
  return out.length > 0 ? out : undefined;
}

// ── Catalog assembly ──────────────────────────────────────────────────────────

/**
 * The full template catalog: built-ins first, then plugin-advertised templates
 * (alphabetical by plugin name). Plugin rows with a stored list that fails to
 * parse contribute nothing.
 */
export async function listAutomationTemplates(): Promise<ServedTemplate[]> {
  const out: ServedTemplate[] = BUILTIN_TEMPLATES.map((t) => ({ ...t, source: 'builtin', sourceName: 'Built-in' }));

  const rows = await db.select({ id: schema.plugins.id, name: schema.plugins.name, automationTemplates: schema.plugins.automationTemplates }).from(schema.plugins);
  for (const row of rows) {
    if (!row.automationTemplates || typeof row.automationTemplates !== 'string') continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.automationTemplates);
    } catch {
      continue; // corrupt stored list — skip, never fail the catalog
    }
    const normalized = normalizeAutomationTemplates(parsed);
    if (!normalized) continue;
    for (const t of normalized) out.push({ ...t, source: row.id, sourceName: row.name });
  }

  // Built-ins stay first; plugin templates sort by source name then template name.
  const builtins = out.filter((t) => t.source === 'builtin');
  const advertised = out
    .filter((t) => t.source !== 'builtin')
    .sort((a, b) => a.sourceName.localeCompare(b.sourceName) || a.name.localeCompare(b.name));
  return [...builtins, ...advertised];
}
