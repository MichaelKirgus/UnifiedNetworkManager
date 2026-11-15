import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { DataTable, DataTableColumn } from './DataTable';
import { DialogShell } from './DialogShell';
import { ChipInput } from './ChipInput';
import { api, NotificationRule, NotificationRuleFilter, NotificationSeverity, NotificationSource } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Rules tab of the Notifications page — "when a notification matches this
 * filter, render these templates and deliver to these channels". The editor
 * offers severity/source checkboxes, tag/vendor/type chip inputs (suggestions
 * sourced from existing devices), regex fields with live compile validation,
 * and template textareas with token-insert buttons + a sample preview.
 */

const SEVERITIES: NotificationSeverity[] = ['info', 'warning', 'critical'];
const SOURCES: NotificationSource[] = ['system', 'device', 'plugin'];

/** Template tokens the API's renderTemplate understands (context.* is free-form). */
const TEMPLATE_TOKENS = [
  'notification.title',
  'notification.message',
  'notification.severity',
  'notification.source',
  'notification.status',
  'notification.createdAt',
  'notification.lastSeenAt',
  'notification.occurrences',
  'device.name',
  'device.address',
  'device.vendor',
  'device.tags',
  'device.types',
  'device.site',
  'device.status',
  'plugin.name',
] as const;

/** Sample values for the live preview (mirrors the API's "unknown tokens stay literal" behavior). */
const SAMPLE_VARS: Record<string, string> = {
  'notification.title': 'WAN link down',
  'notification.message': 'wan0 lost carrier since 12:03',
  'notification.severity': 'critical',
  'notification.source': 'device',
  'notification.status': 'open',
  'notification.createdAt': '2026-01-01T12:04:00Z',
  'notification.lastSeenAt': '2026-01-01T12:30:00Z',
  'notification.occurrences': '5',
  'device.name': 'OPNSENSE01',
  'device.address': '192.168.1.1',
  'device.vendor': 'opnsense',
  'device.tags': 'edge, wan',
  'device.types': 'router, firewall',
  'device.site': 'HQ',
  'device.status': 'down',
  'plugin.name': 'opnsense-plugin',
};

/** Client-side mirror of the API's renderTemplate (same regex + literal fallback). */
function previewTemplate(template: string): string {
  return template.replace(/\{\{([\w.]+)\}\}/g, (match, key: string) => SAMPLE_VARS[key] ?? match);
}

export function NotificationRulesTab() {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<NotificationRule | null>(null);
  const [creating, setCreating] = useState(false);

  const rulesQuery = useQuery({ queryKey: ['notificationRules'], queryFn: api.notificationRules });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['notificationRules'] });

  const deleteMut = useMutation({ mutationFn: (id: string) => api.deleteNotificationRule(id), onSuccess: invalidate });

  /** Compact one-line summary of a rule's filter for the table. */
  function filterSummary(f: NotificationRuleFilter): string {
    const parts: string[] = [];
    if (f.severities?.length) parts.push(`severity: ${f.severities.join('/')}`);
    if (f.sources?.length) parts.push(`source: ${f.sources.join('/')}`);
    if (f.deviceTags?.length) parts.push(`${f.deviceTags.length} tag(s)`);
    if (f.vendors?.length) parts.push(f.vendors.join(', '));
    if (f.deviceTypes?.length) parts.push(`type: ${f.deviceTypes.join('/')}`);
    if (f.titleRegex) parts.push('title ~ regex');
    if (f.messageRegex) parts.push('message ~ regex');
    return parts.length > 0 ? parts.join(' · ') : 'matches everything';
  }

  const columns: DataTableColumn<NotificationRule>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 220,
      render: (r) => <span className="text-sm font-medium text-foreground">{r.name}</span>,
    },
    {
      header: 'Filter',
      key: 'filter',
      width: 340,
      render: (r) => <span className="block truncate text-xs text-muted-foreground" title={filterSummary(r.filter)}>{filterSummary(r.filter)}</span>,
      exportValue: (r) => filterSummary(r.filter),
    },
    {
      header: 'Channels',
      key: 'channelIds',
      width: 200,
      render: (r) => (
        <span className="block truncate text-xs text-secondary" title={(r.channelNames ?? r.channelIds).join(', ')}>
          {(r.channelNames ?? []).length > 0 ? (r.channelNames as string[]).join(', ') : '—'}
        </span>
      ),
    },
    {
      header: 'Cooldown',
      key: 'cooldownSec',
      width: 100,
      render: (r) => <span className="text-xs text-muted-foreground">{r.cooldownSec}s</span>,
      sortAccessor: (r) => r.cooldownSec,
    },
    {
      header: 'Enabled',
      key: 'enabled',
      width: 90,
      render: (r) => (
        <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium', r.enabled ? 'bg-success text-success-fg' : 'bg-muted text-faint')}>
          {r.enabled ? 'yes' : 'no'}
        </span>
      ),
    },
    {
      header: '',
      key: 'actions',
      width: 90,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (r) => (
        <div className="flex items-center justify-end gap-1">
          {can('notifications:write') && (
            <>
              <button type="button" title="Edit rule" aria-label={`Edit ${r.name}`} onClick={() => setEditing(r)} className="rounded p-1.5 text-faint hover:bg-muted hover:text-secondary">
                <Pencil className="h-4 w-4" />
              </button>
              <button
                type="button"
                title="Delete rule"
                aria-label={`Delete ${r.name}`}
                onClick={() => {
                  if (window.confirm(`Delete rule "${r.name}"? Its delivery history is removed too.`)) deleteMut.mutate(r.id);
                }}
                className="rounded p-1.5 text-faint hover:bg-danger hover:text-danger-fg"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          Rules decide which notifications are delivered, to which channels, and what they say. An empty filter matches everything; the cooldown suppresses re-firing after each delivery.
        </p>
        {can('notifications:write') && (
          <button type="button" onClick={() => setCreating(true)} className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover">
            <Plus className="h-4 w-4" /> New rule
          </button>
        )}
      </div>

      <DataTable<NotificationRule>
        columns={columns}
        rows={rulesQuery.data ?? []}
        rowKey={(r) => r.id}
        storageKey="unm:notification-rules-table"
        searchPlaceholder="Search rules…"
        emptyMessage="No notification rules yet — create one to start delivering notifications."
      />

      {(creating || editing) && (
        <RuleDialog
          initial={editing ?? undefined}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

// ── Rule create/edit dialog ──────────────────────────────────────────────────

function RuleDialog({ initial, onClose }: { initial?: NotificationRule; onClose: () => void }) {
  const queryClient = useQueryClient();
  const channelsQuery = useQuery({ queryKey: ['notificationChannels'], queryFn: api.notificationChannels });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  const [name, setName] = useState(initial?.name ?? '');
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [cooldownSec, setCooldownSec] = useState<string>(String(initial?.cooldownSec ?? 300));
  const [severities, setSeverities] = useState<NotificationSeverity[]>(initial?.filter.severities ?? []);
  const [sources, setSources] = useState<NotificationSource[]>(initial?.filter.sources ?? []);
  const [deviceTags, setDeviceTags] = useState<string[]>(initial?.filter.deviceTags ?? []);
  const [vendors, setVendors] = useState<string[]>(initial?.filter.vendors ?? []);
  const [deviceTypes, setDeviceTypes] = useState<string[]>(initial?.filter.deviceTypes ?? []);
  const [titleRegex, setTitleRegex] = useState(initial?.filter.titleRegex ?? '');
  const [messageRegex, setMessageRegex] = useState(initial?.filter.messageRegex ?? '');
  const [channelIds, setChannelIds] = useState<string[]>(initial?.channelIds ?? []);
  const [titleTemplate, setTitleTemplate] = useState(initial?.titleTemplate ?? '{{notification.title}}');
  const [bodyTemplate, setBodyTemplate] = useState(initial?.bodyTemplate ?? '');

  // Suggestions sourced from existing devices (deduped, sorted).
  const { tagSuggestions, vendorSuggestions, typeSuggestions } = useMemo(() => {
    const tags = new Set<string>();
    const vendors = new Set<string>();
    const types = new Set<string>();
    for (const d of devicesQuery.data ?? []) {
      for (const t of d.tags) tags.add(t);
      if (d.vendor) vendors.add(d.vendor);
      for (const t of d.deviceTypes) types.add(t);
    }
    const sort = (s: Set<string>) => [...s].sort((a, b) => a.localeCompare(b));
    return { tagSuggestions: sort(tags), vendorSuggestions: sort(vendors), typeSuggestions: sort(types) };
  }, [devicesQuery.data]);

  function toggle<T>(list: T[], value: T): T[] {
    return list.includes(value) ? list.filter((x) => x !== value) : [...list, value];
  }

  // Live regex validation (same 'i' flag the API compiles with).
  const titleRegexError = useMemo(() => {
    if (!titleRegex.trim()) return null;
    try {
      new RegExp(titleRegex, 'i');
      return null;
    } catch (e) {
      return (e as Error).message;
    }
  }, [titleRegex]);
  const messageRegexError = useMemo(() => {
    if (!messageRegex.trim()) return null;
    try {
      new RegExp(messageRegex, 'i');
      return null;
    } catch (e) {
      return (e as Error).message;
    }
  }, [messageRegex]);

  const cooldownNum = Number(cooldownSec);
  const validCooldown = Number.isInteger(cooldownNum) && cooldownNum >= 0;
  const validName = name.trim().length > 0 && name.trim().length <= 200;
  const validTitleTemplate = titleTemplate.trim().length > 0;

  function insertToken(target: 'title' | 'body', token: string) {
    const t = `{{${token}}}`;
    if (target === 'title') setTitleTemplate((prev) => prev + t);
    else setBodyTemplate((prev) => prev + t);
  }

  const saveMut = useMutation({
    mutationFn: () => {
      const filter: NotificationRuleFilter = {};
      if (severities.length > 0) filter.severities = severities;
      if (sources.length > 0) filter.sources = sources;
      if (deviceTags.length > 0) filter.deviceTags = deviceTags;
      if (vendors.length > 0) filter.vendors = vendors;
      if (deviceTypes.length > 0) filter.deviceTypes = deviceTypes;
      if (titleRegex.trim()) filter.titleRegex = titleRegex.trim();
      if (messageRegex.trim()) filter.messageRegex = messageRegex.trim();

      const payload = {
        name: name.trim(),
        enabled,
        filter,
        channelIds,
        titleTemplate,
        bodyTemplate,
        cooldownSec: cooldownNum,
      };
      return initial ? api.updateNotificationRule(initial.id, payload) : api.createNotificationRule(payload);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['notificationRules'] });
      onClose();
    },
  });

  const channels = channelsQuery.data ?? [];

  return (
    <DialogShell
      tag="form"
      onSubmit={(e: React.FormEvent) => {
        e.preventDefault();
        saveMut.mutate();
      }}
      title={initial ? 'Edit rule' : 'New rule'}
      subtitle="Filter → templates → channels. An empty filter matches every notification."
      icon={<Plus className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-2xl"
      bodyMaxHeight="min(75vh, 720px)"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending || !validName || !validTitleTemplate || !validCooldown || !!titleRegexError || !!messageRegexError}
            className="rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {saveMut.isPending ? 'Saving…' : initial ? 'Save rule' : 'Create rule'}
          </button>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_120px]">
          <div>
            <label className="mb-1.5 block text-sm font-medium text-secondary">Name</label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Critical device alerts → ops email" className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium text-secondary">Cooldown (s)</label>
            <input type="number" min={0} value={cooldownSec} onChange={(e) => setCooldownSec(e.target.value)} className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" />
          </div>
        </div>

        {/* ── Filter ─────────────────────────────────────────────────────── */}
        <fieldset className="rounded-md border border-border p-3">
          <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-faint">Filter (all empty = match everything)</legend>
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3">
            {SEVERITIES.map((s) => (
              <label key={s} className="flex cursor-pointer items-center gap-2 text-sm capitalize text-secondary">
                <input type="checkbox" checked={severities.includes(s)} onChange={() => setSeverities((prev) => toggle(prev, s))} className="h-4 w-4 rounded border-border" />
                {s}
              </label>
            ))}
            {SOURCES.map((s) => (
              <label key={s} className="flex cursor-pointer items-center gap-2 text-sm capitalize text-secondary">
                <input type="checkbox" checked={sources.includes(s)} onChange={() => setSources((prev) => toggle(prev, s))} className="h-4 w-4 rounded border-border" />
                {s} source
              </label>
            ))}
          </div>
          <div className="mt-3 space-y-2.5">
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Device tags (any match — device notifications only)</label>
              <ChipInput values={deviceTags} onChange={setDeviceTags} suggestions={tagSuggestions} placeholder="Add a tag…" ariaLabel="Device tags" />
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Vendors (exact, case-insensitive)</label>
                <ChipInput values={vendors} onChange={setVendors} suggestions={vendorSuggestions} placeholder="Add a vendor…" ariaLabel="Vendors" />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Device types (any match)</label>
                <ChipInput values={deviceTypes} onChange={setDeviceTypes} suggestions={typeSuggestions} placeholder="Add a type…" ariaLabel="Device types" />
              </div>
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Title regex (case-insensitive)</label>
                <input type="text" value={titleRegex} onChange={(e) => setTitleRegex(e.target.value)} placeholder="e.g. ^.*link down$" className={clsx('w-full rounded-md border bg-background px-3 py-2 font-mono text-xs', titleRegexError ? 'border-danger' : 'border-border')} />
                {titleRegexError && <p className="mt-1 text-xs text-danger-fg">{titleRegexError}</p>}
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Message regex (case-insensitive)</label>
                <input type="text" value={messageRegex} onChange={(e) => setMessageRegex(e.target.value)} placeholder="e.g. carrier|timeout" className={clsx('w-full rounded-md border bg-background px-3 py-2 font-mono text-xs', messageRegexError ? 'border-danger' : 'border-border')} />
                {messageRegexError && <p className="mt-1 text-xs text-danger-fg">{messageRegexError}</p>}
              </div>
            </div>
          </div>
        </fieldset>

        {/* ── Templates ──────────────────────────────────────────────────── */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-secondary">Title template</label>
          <textarea value={titleTemplate} onChange={(e) => setTitleTemplate(e.target.value)} rows={2} placeholder="{{notification.title}}" className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs" />
          <div className="mt-1.5 flex flex-wrap gap-1">
            {TEMPLATE_TOKENS.map((t) => (
              <button key={t} type="button" onClick={() => insertToken('title', t)} title={`Insert {{${t}}}`} className="rounded-full border border-dashed border-border px-2 py-0.5 text-xs text-muted-foreground hover:border-focus-ring hover:bg-background hover:text-secondary">
                {t}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-secondary">Body template (empty = the raw notification message)</label>
          <textarea value={bodyTemplate} onChange={(e) => setBodyTemplate(e.target.value)} rows={4} placeholder={'{{device.name}}: {{notification.message}}\nSeverity: {{notification.severity}} · Occurrences: {{notification.occurrences}}'} className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs" />
          <div className="mt-1.5 flex flex-wrap gap-1">
            {TEMPLATE_TOKENS.map((t) => (
              <button key={t} type="button" onClick={() => insertToken('body', t)} title={`Insert {{${t}}}`} className="rounded-full border border-dashed border-border px-2 py-0.5 text-xs text-muted-foreground hover:border-focus-ring hover:bg-background hover:text-secondary">
                {t}
              </button>
            ))}
          </div>
        </div>

        {/* Live preview with sample values */}
        <div className="rounded-md border border-border bg-background p-3">
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-faint">Preview (sample data)</p>
          <p className="text-sm font-medium text-foreground">{previewTemplate(titleTemplate) || '—'}</p>
          {bodyTemplate.trim() !== '' && <pre className="mt-2 whitespace-pre-wrap font-mono text-xs text-secondary">{previewTemplate(bodyTemplate)}</pre>}
        </div>

        {/* ── Channel bindings ───────────────────────────────────────────── */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-secondary">Deliver to channels</label>
          {channels.length === 0 ? (
            <p className="text-xs text-faint">No channels exist yet — create one on the Channels tab first.</p>
          ) : (
            <div className="space-y-1.5 rounded-md border border-border p-3">
              {channels.map((c) => (
                <label key={c.id} className="flex cursor-pointer items-center gap-2 text-sm text-secondary">
                  <input type="checkbox" checked={channelIds.includes(c.id)} onChange={() => setChannelIds((prev) => toggle(prev, c.id))} className="h-4 w-4 rounded border-border" />
                  {c.name}
                  <span className="text-xs text-faint">({c.typeLabel ?? c.channelType})</span>
                </label>
              ))}
            </div>
          )}
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-sm text-secondary">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="h-4 w-4 rounded border-border" />
          Rule enabled (disabled rules never fire)
        </label>

        {saveMut.isError && (
          <p className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger-fg">
            {(saveMut.error as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'Save failed'}
          </p>
        )}
      </div>
    </DialogShell>
  );
}
