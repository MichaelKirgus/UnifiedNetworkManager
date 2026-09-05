import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { BellRing, CheckCheck, Info, OctagonX, Settings2, TriangleAlert, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, Notification, NotificationSeverity, NotificationSource } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Full notification center — every row (all statuses) with filters: status,
 * severity, source, device + search. Includes the personal visibility-settings
 * panel (which severities from which sources show up in the bell). Gated by
 * `notifications:read`; the settings panel needs `notifications:write`.
 */

const SEVERITY_ICON: Record<NotificationSeverity, typeof Info> = {
  info: Info,
  warning: TriangleAlert,
  critical: OctagonX,
};

const SEVERITY_STYLES: Record<NotificationSeverity, string> = {
  info: 'bg-info text-info-fg',
  warning: 'bg-warning text-warning-fg',
  critical: 'bg-danger text-danger-fg',
};

const SOURCE_STYLES: Record<NotificationSource, string> = {
  system: 'bg-muted text-secondary',
  device: 'bg-indigo-100 text-indigo-700',
  plugin: 'bg-purple-100 text-purple-700',
};

const STATUS_STYLES: Record<Notification['status'], string> = {
  open: 'bg-success text-success-fg',
  acknowledged: 'bg-muted text-secondary',
  resolved: 'bg-teal-100 text-teal-700',
  closed: 'bg-muted text-faint',
};

const SEVERITIES: NotificationSeverity[] = ['info', 'warning', 'critical'];
const SOURCES: NotificationSource[] = ['system', 'device', 'plugin'];
const STATUSES: Array<{ value: string; label: string }> = [
  { value: '', label: 'Open + seen' },
  { value: 'open', label: 'Open only' },
  { value: 'acknowledged', label: 'Seen (acknowledged)' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'closed', label: 'Closed' },
  { value: 'open,acknowledged,resolved,closed', label: 'All' },
];

function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  const d = new Date(iso);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}

export default function Notifications() {
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [search, setSearch] = useState('');
  const [showSettings, setShowSettings] = useState(false);

  const queryClient = useQueryClient();
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const devices = useMemo(
    () => (devicesQuery.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)),
    [devicesQuery.data]
  );

  // Full history — `all=true` ignores personal visibility prefs so the page is
  // the complete audit view; the bell/panel apply the user's filters.
  const listQuery = useQuery({
    queryKey: ['notifications', 'page', status, severity, source, deviceId, search],
    queryFn: () =>
      api.notifications({
        status: status || undefined,
        severity: severity || undefined,
        source: source || undefined,
        deviceId: deviceId || undefined,
        search: search.trim() || undefined,
        all: true,
        limit: 500,
      }),
    refetchInterval: 30_000,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['notifications'] });
    void queryClient.invalidateQueries({ queryKey: ['notificationCount'] });
  };

  const ackMut = useMutation({ mutationFn: (ids: string[]) => api.acknowledgeNotifications(ids), onSuccess: invalidate });
  const closeMut = useMutation({ mutationFn: (ids: string[]) => api.closeNotifications(ids), onSuccess: invalidate });
  const resolveMut = useMutation({ mutationFn: (id: string) => api.resolveNotification(id), onSuccess: invalidate });

  const columns: DataTableColumn<Notification>[] = [
    {
      header: 'Severity',
      key: 'severity',
      width: 110,
      render: (n) => {
        const Icon = SEVERITY_ICON[n.severity];
        return (
          <span className={clsx('inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium uppercase', SEVERITY_STYLES[n.severity])}>
            <Icon className="h-3 w-3" /> {n.severity}
          </span>
        );
      },
      sortAccessor: (n) => n.severity,
    },
    {
      header: 'Source',
      key: 'source',
      width: 100,
      render: (n) => (
        <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium', SOURCE_STYLES[n.source])}>{n.source}</span>
      ),
    },
    {
      header: 'Notification',
      key: 'title',
      width: 420,
      render: (n) => (
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-foreground" title={n.title}>
            {n.title}
          </p>
          {n.message && <p className="mt-0.5 truncate text-xs text-muted-foreground" title={n.message}>{n.message}</p>}
        </div>
      ),
      exportValue: (n) => `${n.title} ${n.message}`.trim(),
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 160,
      render: (n) =>
        n.deviceId && n.deviceName ? (
          <a href={`/devices/${n.deviceId}`} title={`Open ${n.deviceName}`} className="inline-flex max-w-[240px] items-center rounded border border-border bg-card px-1.5 py-1 text-xs font-medium text-secondary hover:bg-background">
            <span className="truncate">{n.deviceName}</span>
          </a>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Plugin',
      key: 'pluginName',
      width: 160,
      render: (n) => (n.pluginName ? <span className="text-xs text-muted-foreground">{n.pluginName}</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Status',
      key: 'status',
      width: 120,
      render: (n) => (
        <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium capitalize', STATUS_STYLES[n.status])}>{n.status}</span>
      ),
    },
    {
      header: 'Seen',
      key: 'lastSeenAt',
      width: 130,
      render: (n) => <span className="text-xs text-muted-foreground">{timeAgo(n.lastSeenAt)}</span>,
      sortAccessor: (n) => n.lastSeenAt,
    },
    {
      header: '×',
      key: 'occurrences',
      width: 60,
      sortable: false,
      filterable: false,
      render: (n) => (n.occurrences > 1 ? <span className="text-xs font-medium text-muted-foreground">{n.occurrences}</span> : null),
    },
    {
      header: '',
      key: 'actions',
      width: 120,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (n) => (
        <div className="flex items-center justify-end gap-1">
          {n.status === 'open' && (
            <button
              type="button"
              title="Mark as seen"
              aria-label="Mark as seen"
              onClick={() => ackMut.mutate([n.id])}
              className="rounded p-1.5 text-faint hover:bg-muted hover:text-secondary"
            >
              <CheckCheck className="h-4 w-4" />
            </button>
          )}
          {(n.status === 'open' || n.status === 'acknowledged') && (
            <>
              <button
                type="button"
                title="Resolve (condition fixed)"
                aria-label="Resolve notification"
                onClick={() => resolveMut.mutate(n.id)}
                className="rounded p-1.5 text-faint hover:bg-success hover:text-emerald-600"
              >
                <X className="h-4 w-4" />
              </button>
              <button
                type="button"
                title="Close (dismiss from view)"
                aria-label="Close notification"
                onClick={() => closeMut.mutate([n.id])}
                className="rounded p-1.5 text-faint hover:bg-danger hover:text-danger-fg"
              >
                <BellRing className="h-4 w-4 rotate-12" />
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <Layout
      title="Notifications"
      actions={
        can('notifications:write') && (
          <button
            type="button"
            onClick={() => setShowSettings((v) => !v)}
            className={clsx(
              'flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm font-medium',
              showSettings
                ? 'border-slate-800 bg-primary text-white'
                : 'border-border bg-card text-secondary hover:bg-muted'
            )}
          >
            <Settings2 className="h-4 w-4" /> Visibility settings
          </button>
        )
      }
    >

        {showSettings && can('notifications:write') && (
          <VisibilitySettings onDone={() => setShowSettings(false)} />
        )}

        {/* Filter bar */}
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <select value={status} onChange={(e) => setStatus(e.target.value)} className="rounded-md border border-border bg-card px-2 py-1.5 text-sm">
            {STATUSES.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="rounded-md border border-border bg-card px-2 py-1.5 text-sm">
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={source} onChange={(e) => setSource(e.target.value)} className="rounded-md border border-border bg-card px-2 py-1.5 text-sm">
            <option value="">All sources</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)} className="rounded-md border border-border bg-card px-2 py-1.5 text-sm">
            <option value="">All devices</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title or message…"
            className="w-64 rounded-md border border-border bg-card px-2 py-1.5 text-sm"
          />
        </div>

        <DataTable<Notification>
          columns={columns}
          rows={listQuery.data ?? []}
          rowKey={(n) => n.id}
          storageKey="unm:notifications-table"
          searchPlaceholder="Search notifications…"
          emptyMessage="No notifications match the current filters."
        />
    </Layout>
  );
}

/** Personal visibility settings — which severities from each source show up in the bell. */
function VisibilitySettings({ onDone }: { onDone: () => void }) {
  const queryClient = useQueryClient();
  const prefsQuery = useQuery({ queryKey: ['notificationPrefs'], queryFn: api.notificationPrefs });

  const saveMut = useMutation({
    mutationFn: (visibility: Record<string, NotificationSeverity[]>) => api.setNotificationPrefs(visibility),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['notificationPrefs'] });
      void queryClient.invalidateQueries({ queryKey: ['notifications'] });
      void queryClient.invalidateQueries({ queryKey: ['notificationCount'] });
      onDone();
    },
  });

  const [draft, setDraft] = useState<Record<string, NotificationSeverity[]> | null>(null);
  const visibility = draft ?? prefsQuery.data?.visibility ?? { system: SEVERITIES, device: SEVERITIES, plugin: SEVERITIES };

  function toggle(source: string, sev: NotificationSeverity) {
    setDraft((prev) => {
      const cur = prev ?? visibility;
      const list = [...(cur[source] ?? [])];
      const i = list.indexOf(sev);
      if (i >= 0) list.splice(i, 1);
      else list.push(sev);
      return { ...cur, [source]: list };
    });
  }

  return (
    <div className="mb-4 rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold text-foreground">Visibility settings</h2>
      <p className="mt-1 text-xs text-muted-foreground">
        Controls which notifications appear in the bell badge and dropdown panel. The full history on this page is never filtered by these settings.
      </p>
      <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {SOURCES.map((source) => (
          <div key={source} className="rounded-md border border-border p-3">
            <span className={clsx('inline-flex rounded px-1.5 py-0.5 text-xs font-medium capitalize', SOURCE_STYLES[source])}>{source}</span>
            <div className="mt-2 flex flex-col gap-1.5">
              {SEVERITIES.map((sev) => (
                <label key={sev} className="flex cursor-pointer items-center gap-2 text-sm text-secondary">
                  <input
                    type="checkbox"
                    checked={(visibility[source] ?? []).includes(sev)}
                    onChange={() => toggle(source, sev)}
                    className="h-4 w-4 rounded border-border"
                  />
                  {sev}
                </label>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-2">
        <button
          type="button"
          onClick={() => saveMut.mutate(visibility)}
          disabled={saveMut.isPending || !draft}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
        >
          {saveMut.isPending ? 'Saving…' : 'Save settings'}
        </button>
        {draft && (
          <button type="button" onClick={() => setDraft(null)} className="rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground hover:bg-muted">
            Reset
          </button>
        )}
        {saveMut.isSuccess && !draft && <span className="text-xs text-emerald-600">Saved.</span>}
      </div>
    </div>
  );
}
