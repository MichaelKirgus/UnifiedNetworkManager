import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { KeyRound, Pencil, Plus, Send, Trash2 } from 'lucide-react';
import { DataTable, DataTableColumn } from './DataTable';
import { DialogShell } from './DialogShell';
import { api, NotificationChannel, NotificationChannelDescriptor, NotificationDelivery, Plugin, Secret } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/**
 * Channels tab of the Notifications page — configured delivery endpoints.
 * The channel form is rendered DYNAMICALLY from the sender plugin's declared
 * catalog (fields + accepted secret types), so a new channel type needs no
 * webapp change. Gated by `notifications:read` / `notifications:write`.
 */

/** Relative age ("42s ago", "3m ago") with an absolute fallback for old entries. */
function timeAgo(iso: string, fmtDate: (v: string) => string, fmtTime: (v: string) => string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${fmtDate(iso)} ${fmtTime(iso)}`;
}

export function NotificationChannelsTab() {
  const { formatDate, formatTime } = useTimeFormat();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<NotificationChannel | null>(null);
  const [creating, setCreating] = useState(false);

  const channelsQuery = useQuery({ queryKey: ['notificationChannels'], queryFn: api.notificationChannels });
  const deliveriesQuery = useQuery({ queryKey: ['notificationDeliveries', 'recent'], queryFn: () => api.notificationDeliveries({ limit: 50 }) });
  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['notificationChannels'] });
    void queryClient.invalidateQueries({ queryKey: ['notificationDeliveries'] });
  };

  const deleteMut = useMutation({ mutationFn: (id: string) => api.deleteNotificationChannel(id), onSuccess: invalidate });
  const testMut = useMutation({ mutationFn: (id: string) => api.testNotificationChannel(id), onSuccess: invalidate });

  const columns: DataTableColumn<NotificationChannel>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 220,
      render: (c) => <span className="text-sm font-medium text-foreground">{c.name}</span>,
    },
    {
      header: 'Type',
      key: 'channelType',
      width: 180,
      render: (c) => (
        <div className="min-w-0">
          <span className="text-sm text-secondary">{c.typeLabel ?? c.channelType}</span>
          {c.pluginName && <p className="truncate text-xs text-faint" title={c.pluginName}>{c.pluginName}</p>}
        </div>
      ),
    },
    {
      header: 'Owner',
      key: 'ownerId',
      width: 120,
      render: (c) =>
        c.ownerId ? (
          <span className="inline-flex rounded bg-accent-indigo/15 px-1.5 py-0.5 text-xs font-medium text-accent-indigo" title={`Personal channel of ${c.ownerName ?? 'unknown user'} — fan-out target for rule audiences`}>
            {c.ownerId === meQuery.data?.id ? 'you' : (c.ownerName ?? 'personal')}
          </span>
        ) : (
          <span className="text-xs text-faint">shared</span>
        ),
    },
    {
      header: 'Enabled',
      key: 'enabled',
      width: 90,
      render: (c) => (
        <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium', c.enabled ? 'bg-success text-success-fg' : 'bg-muted text-faint')}>
          {c.enabled ? 'yes' : 'no'}
        </span>
      ),
    },
    {
      header: 'Last delivery',
      key: 'lastDelivery',
      width: 200,
      render: (c) =>
        c.lastDelivery ? (
          <div className="flex items-center gap-1.5" title={c.lastDelivery.error ?? undefined}>
            <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium', c.lastDelivery.status === 'sent' ? 'bg-success text-success-fg' : 'bg-danger text-danger-fg')}>
              {c.lastDelivery.status}
            </span>
            <span className="text-xs text-muted-foreground">{timeAgo(c.lastDelivery.sentAt, formatDate, formatTime)}</span>
          </div>
        ) : (
          <span className="text-xs text-faint">never</span>
        ),
      sortAccessor: (c) => c.lastDelivery?.sentAt ?? '',
    },
    {
      header: 'Secret',
      key: 'secretId',
      width: 90,
      render: (c) =>
        c.secretId ? <KeyRound className="h-3.5 w-3.5 text-muted-foreground" aria-label="Has bound secret" /> : <span className="text-faint">—</span>,
    },
    {
      header: '',
      key: 'actions',
      width: 120,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (c) => (
        <div className="flex items-center justify-end gap-1">
          {can('notifications:write') && (
            <>
              <button
                type="button"
                title={testMut.isPending ? 'Sending…' : 'Send test message'}
                aria-label={`Test ${c.name}`}
                disabled={testMut.isPending}
                onClick={() => testMut.mutate(c.id)}
                className="rounded p-1.5 text-faint hover:bg-accent-indigo hover:text-accent-indigo-fg disabled:opacity-50"
              >
                <Send className="h-4 w-4" />
              </button>
              <button type="button" title="Edit channel" aria-label={`Edit ${c.name}`} onClick={() => setEditing(c)} className="rounded p-1.5 text-faint hover:bg-muted hover:text-secondary">
                <Pencil className="h-4 w-4" />
              </button>
              <button
                type="button"
                title="Delete channel"
                aria-label={`Delete ${c.name}`}
                onClick={() => {
                  if (window.confirm(`Delete channel "${c.name}"? Its delivery history is removed too.`)) deleteMut.mutate(c.id);
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

  const testError = testMut.isError ? (testMut.error as { response?: { data?: { error?: string } } })?.response?.data?.error : undefined;

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          Delivery endpoints for notification rules. Config fields are declared by the sender plugin; credentials come from bound secrets.
        </p>
        {can('notifications:write') && (
          <button type="button" onClick={() => setCreating(true)} className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover">
            <Plus className="h-4 w-4" /> New channel
          </button>
        )}
      </div>

      {testError && (
        <p className="mb-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger-fg">Test send failed: {testError}</p>
      )}

      <DataTable<NotificationChannel>
        columns={columns}
        rows={channelsQuery.data ?? []}
        rowKey={(c) => c.id}
        storageKey="unm:notification-channels-table"
        searchPlaceholder="Search channels…"
        emptyMessage="No notification channels yet — create one to deliver notifications."
      />

      <h3 className="mb-2 mt-6 text-sm font-semibold text-secondary">Recent deliveries</h3>
      <DataTable<NotificationDelivery>
        columns={DELIVERY_COLUMNS}
        rows={deliveriesQuery.data ?? []}
        rowKey={(d) => d.id}
        storageKey="unm:notification-deliveries-table"
        searchPlaceholder="Search deliveries…"
        emptyMessage="No delivery attempts recorded yet."
      />

      {(creating || editing) && (
        <ChannelDialog
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

const DELIVERY_COLUMNS: DataTableColumn<NotificationDelivery>[] = [
  {
    header: 'When',
    key: 'sentAt',
    width: 160,
    render: (d) => <span className="text-xs text-muted-foreground">{new Date(d.sentAt).toLocaleString()}</span>,
    sortAccessor: (d) => d.sentAt,
  },
  { header: 'Channel', key: 'channelName', width: 180, render: (d) => <span className="text-sm text-secondary">{d.channelName ?? d.channelId}</span> },
  { header: 'Type', key: 'channelType', width: 120, render: (d) => <span className="text-xs text-muted-foreground">{d.channelType ?? '—'}</span> },
  { header: 'Rule', key: 'ruleName', width: 180, render: (d) => <span className="text-xs text-secondary">{d.ruleName ?? (d.notificationId ? 'test send' : '—')}</span> },
  {
    header: 'Status',
    key: 'status',
    width: 90,
    render: (d) => (
      <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium', d.status === 'sent' ? 'bg-success text-success-fg' : 'bg-danger text-danger-fg')}>
        {d.status}
      </span>
    ),
  },
  { header: 'Error', key: 'error', width: 320, render: (d) => <span className="block truncate text-xs text-muted-foreground" title={d.error ?? undefined}>{d.error ?? ''}</span> },
];

// ── Channel create/edit dialog (dynamic form from the plugin catalog) ────────

function ChannelDialog({ initial, onClose }: { initial?: NotificationChannel; onClose: () => void }) {
  const queryClient = useQueryClient();
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const secretsQuery = useQuery({ queryKey: ['secrets'], queryFn: api.secrets });
  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me });

  // Sender plugins = capability + a non-empty channel catalog.
  const senderPlugins = useMemo(
    () => (pluginsQuery.data ?? []).filter((p) => p.capabilities?.includes('notificationSender') && (p.notificationChannels?.length ?? 0) > 0),
    [pluginsQuery.data]
  );

  const [name, setName] = useState(initial?.name ?? '');
  const [pluginId, setPluginId] = useState(initial?.pluginId ?? senderPlugins[0]?.id ?? '');
  const [channelType, setChannelType] = useState(initial?.channelType ?? '');
  const [config, setConfig] = useState<Record<string, unknown>>(initial?.config ?? {});
  const [secretId, setSecretId] = useState<string>(initial?.secretId ?? '');
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  // Personal channel (create only — ownership is immutable after creation).
  const [personal, setPersonal] = useState(false);

  // When the dialog opens with no initial channelType (create), pick the first
  // catalog entry of the default plugin once plugins have loaded.
  const selectedPlugin: Plugin | undefined = senderPlugins.find((p) => p.id === pluginId);
  const descriptor: NotificationChannelDescriptor | undefined = useMemo(
    () => selectedPlugin?.notificationChannels?.find((c) => c.type === channelType),
    [selectedPlugin, channelType]
  );

  // Effective type — for create with no explicit choice yet, fall back to the
  // plugin's first catalog entry so the form renders immediately.
  const effectiveDescriptor = descriptor ?? selectedPlugin?.notificationChannels?.[0];
  const effectiveType = effectiveDescriptor?.type ?? '';

  function pickPlugin(id: string) {
    setPluginId(id);
    const p = senderPlugins.find((x) => x.id === id);
    setChannelType(p?.notificationChannels?.[0]?.type ?? '');
    setConfig({});
    setSecretId('');
  }

  function pickType(type: string) {
    setChannelType(type);
    // Keep only config keys the new descriptor still declares.
    const fields = selectedPlugin?.notificationChannels?.find((c) => c.type === type)?.fields ?? [];
    setConfig((prev) => Object.fromEntries(Object.entries(prev).filter(([k]) => fields.some((f) => f.name === k))));
  }

  function setField(field: string, value: unknown) {
    setConfig((prev) => ({ ...prev, [field]: value }));
  }

  const saveMut = useMutation({
    mutationFn: () => {
      const payload = {
        name: name.trim(),
        pluginId,
        channelType: effectiveType,
        enabled,
        config,
        secretId: secretId || null,
        // Personal channels belong to the caller (the API enforces this).
        ...(initial ? {} : personal && meQuery.data ? { ownerId: meQuery.data.id } : {}),
      };
      return initial ? api.updateNotificationChannel(initial.id, payload) : api.createNotificationChannel(payload);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['notificationChannels'] });
      onClose();
    },
  });

  const secrets = (secretsQuery.data ?? []) as Secret[];
  // Accepted secret types — empty list means "no restriction".
  const acceptedTypes = effectiveDescriptor?.secretTypes ?? [];
  const eligibleSecrets = acceptedTypes.length > 0 ? secrets.filter((s) => acceptedTypes.includes(s.type)) : secrets;

  const validName = name.trim().length > 0 && name.trim().length <= 200;
  const missingRequired = (effectiveDescriptor?.fields ?? []).filter(
    (f) => f.required && (config[f.name] === undefined || config[f.name] === null || String(config[f.name]).trim() === '')
  );

  return (
    <DialogShell
      tag="form"
      onSubmit={(e: React.FormEvent) => {
        e.preventDefault();
        saveMut.mutate();
      }}
      title={initial ? 'Edit channel' : 'New channel'}
      subtitle={effectiveDescriptor?.description}
      icon={<Send className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-xl"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending || !validName || missingRequired.length > 0 || senderPlugins.length === 0}
            className="rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {saveMut.isPending ? 'Saving…' : initial ? 'Save channel' : 'Create channel'}
          </button>
        </div>
      }
    >
      {senderPlugins.length === 0 && (
        <p className="mb-3 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-secondary">
          No online plugin advertises the notificationSender capability. Start a sender plugin (e.g. Basic Notification Plugin) first.
        </p>
      )}

      <div className="space-y-4">
        <div>
          <label className="mb-1.5 block text-sm font-medium text-secondary">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Ops team email, PagerDuty webhook, …"
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="mb-1.5 block text-sm font-medium text-secondary">Sender plugin</label>
            <select value={pluginId} onChange={(e) => pickPlugin(e.target.value)} className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" disabled={senderPlugins.length === 0}>
              {senderPlugins.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium text-secondary">Channel type</label>
            <select value={effectiveType} onChange={(e) => pickType(e.target.value)} className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" disabled={!selectedPlugin}>
              {(selectedPlugin?.notificationChannels ?? []).map((c) => (
                <option key={c.type} value={c.type}>{c.label}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Dynamic config fields from the plugin's catalog */}
        {effectiveDescriptor && effectiveDescriptor.fields.length > 0 && (
          <div className="space-y-3 rounded-md border border-border p-3">
            {(effectiveDescriptor?.fields ?? []).map((f) => (
              <div key={f.name}>
                <label className="mb-1.5 block text-sm font-medium text-secondary">
                  {f.label}
                  {f.required && <span className="ml-0.5 text-danger-fg">*</span>}
                </label>
                {f.input === 'select' ? (
                  <select value={String(config[f.name] ?? '')} onChange={(e) => setField(f.name, e.target.value)} className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm">
                    {(f.options ?? []).map((o) => (
                      <option key={o} value={o}>{o}</option>
                    ))}
                  </select>
                ) : f.input === 'boolean' ? (
                  <label className="flex cursor-pointer items-center gap-2 text-sm text-secondary">
                    <input type="checkbox" checked={Boolean(config[f.name])} onChange={(e) => setField(f.name, e.target.checked)} className="h-4 w-4 rounded border-border" />
                    Enabled
                  </label>
                ) : (
                  <input
                    type={f.input === 'number' ? 'number' : 'text'}
                    value={String(config[f.name] ?? '')}
                    onChange={(e) => setField(f.name, f.input === 'number' ? (e.target.value === '' ? '' : Number(e.target.value)) : e.target.value)}
                    placeholder={f.placeholder}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                )}
              </div>
            ))}
          </div>
        )}

        {/* Bound secret (credentials) — filtered by the descriptor's accepted types */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-secondary">Credentials (secret)</label>
          {acceptedTypes.length > 0 ? (
            <>
              <select value={secretId} onChange={(e) => setSecretId(e.target.value)} className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm">
                <option value="">None</option>
                {eligibleSecrets.map((s) => (
                  <option key={s.id} value={s.id}>{s.label} ({s.type})</option>
                ))}
              </select>
              {eligibleSecrets.length === 0 && (
                <p className="mt-1 text-xs text-faint">No secrets of type {acceptedTypes.join(' / ')} exist yet — create one on the Secrets page first.</p>
              )}
            </>
          ) : (
            <p className="text-xs text-faint">This channel type needs no credentials.</p>
          )}
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-sm text-secondary">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="h-4 w-4 rounded border-border" />
          Channel enabled (disabled channels are skipped by rules)
        </label>

        {initial?.ownerId ? (
          <p className="rounded-md border border-border bg-background px-3 py-2 text-xs text-muted-foreground">
            Personal channel of <span className="font-medium text-secondary">{initial.ownerName ?? 'unknown user'}</span> — ownership cannot be changed.
          </p>
        ) : (
          !initial && (
            <div>
              <label className="flex cursor-pointer items-center gap-2 text-sm text-secondary">
                <input type="checkbox" checked={personal} onChange={(e) => setPersonal(e.target.checked)} className="h-4 w-4 rounded border-border" />
                Personal channel (only you can see/manage it)
              </label>
              <p className="mt-1 text-xs text-faint">Personal channels are the fan-out targets of rule audiences — e.g. "critical alerts → every admin's own Telegram chat".</p>
            </div>
          )
        )}

        {missingRequired.length > 0 && (
          <p className="text-xs text-danger-fg">Missing required fields: {missingRequired.map((f) => f.label).join(', ')}</p>
        )}
        {saveMut.isError && (
          <p className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger-fg">
            {(saveMut.error as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'Save failed'}
          </p>
        )}
      </div>
    </DialogShell>
  );
}
