import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Play, RotateCw, Square } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { StatusBadge } from '../components/StatusBadge';
import { ReauthDialog } from '../components/ReauthDialog';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, ServiceRow } from '../api/client';

/** Small colored pill for the init system / service framework. */
const TYPE_STYLES: Record<string, string> = {
  systemd: 'bg-accent-indigo text-accent-indigo-fg',
  openrc: 'bg-accent-teal text-accent-teal-fg',
  runit: 'bg-accent-purple text-accent-purple-fg',
  sysvinit: 'bg-warning text-warning-fg',
  'freebsd-rc': 'bg-info text-info-fg',
  truenas: 'bg-success text-success-fg',
  openwrt: 'bg-accent-sky text-accent-sky-fg',
};

function TypeBadge({ type }: { type: string }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${TYPE_STYLES[type] ?? 'bg-muted text-secondary'}`}>
      {type}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the Containers / VMs pages)
// ---------------------------------------------------------------------------

/** Creates a plan for ONE plugin. In Execute mode it is also executed in the
 * background; in Plan mode it is saved WITHOUT executing and only its id is
 * returned — callers surface a "saved" notice instead of tracking execution.
 * Throws on failure — callers catch ApiError 401 to offer two-factor revalidation. */
async function createAndExecutePlan(
  pluginId: string,
  actionId: string,
  steps: Array<{ deviceId: string; input: Record<string, unknown> }>,
  mode: ExecutionMode,
): Promise<string> {
  const first = steps[0];
  const create = async () => {
    const plan = await api.createPlan({
      pluginId,
      intentActionId: actionId,
      inputs: first.input,
      devices: [{ deviceId: first.deviceId }],
    });
    if (steps.length > 1) {
      await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId, input: s.input })));
    }
    return plan;
  };
  return runAction(create, (id) => api.executePlan(id), mode);
}

export default function Services() {
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const queryClient = useQueryClient();
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';

  // The API polls plugins every ~30 s and upserts these rows — refresh at the
  // same cadence so the view tracks live service state.
  const servicesQuery = useQuery({
    queryKey: ['services'],
    queryFn: () => api.services(),
    refetchInterval: 30_000,
  });

  const rows = useMemo(() => {
    const all = servicesQuery.data ?? [];
    return all.filter(
      (r) => (!typeFilter || r.type === typeFilter) && (!statusFilter || r.status === statusFilter)
    );
  }, [servicesQuery.data, typeFilter, statusFilter]);

  // Distinct init systems present in the data — drives the filter options.
  const types = useMemo(
    () => Array.from(new Set((servicesQuery.data ?? []).map((r) => r.type))).sort(),
    [servicesQuery.data]
  );

  // --- Action catalogs (drives the per-row Actions column GENERICALLY) --------
  // A button only renders when the row's plugin advertises that action id, so
  // any future service-capable plugin gets the same column for free. Catalogs
  // are fetched for every distinct plugin present in the current rows.
  const catalogPluginIds = useMemo(
    () => Array.from(new Set((servicesQuery.data ?? []).map((r) => r.pluginId))),
    [servicesQuery.data],
  );
  const catalogsQuery = useQuery({
    queryKey: ['pluginActionCatalogs', 'services', catalogPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        catalogPluginIds.map(async (pluginId) => [pluginId, (await api.pluginActions(pluginId)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: catalogPluginIds.length > 0,
  });

  /** True when the plugin's advertised action catalog contains `actionId`. */
  function hasAction(pluginId: string, actionId: string): boolean {
    const actions = catalogsQuery.data?.[pluginId];
    return Array.isArray(actions) && actions.some((a) => a.id === actionId);
  }

  // --- Action feedback + plan tracking ---------------------------------------
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
  // Plans kicked off in Execute mode — polled until they settle so the touched
  // device force-refreshes and the row's status badge catches up.
  const [pendingPlans, setPendingPlans] = useState<Record<string, { deviceIds: string[]; names: string[] }>>({});
  const pendingRef = useRef(pendingPlans);
  useEffect(() => { pendingRef.current = pendingPlans; }, [pendingPlans]);

  function trackPlan(planId: string, deviceIds: string[], names: string[]) {
    setPendingPlans((prev) => ({ ...prev, [planId]: { deviceIds, names } }));
  }

  useEffect(() => {
    if (Object.keys(pendingPlans).length === 0) return;
    const timer = setInterval(async () => {
      for (const [planId, entry] of Object.entries(pendingRef.current)) {
        let p;
        try {
          p = await api.getPlan(planId);
        } catch { continue; } // transient API error — keep waiting
        if (!['succeeded', 'failed', 'cancelled'].includes(p.status)) continue;
        setPendingPlans((prev) => {
          const next = { ...prev };
          delete next[planId];
          return next;
        });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['services'] });
        if (p.status !== 'succeeded') {
          const what = entry.names[0] ?? entry.deviceIds.join(', ');
          setNotice({ kind: 'error', text: `A plan for ${what} finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  /** One-click per-service action — runs a single-step plan through the standard
   * workflow (2FA-gated) and tracks it so the row auto-refreshes when execution
   * settles. Same 401 → reauth flow as the Containers page. */
  async function runService(row: ServiceRow, actionId: string, label: string) {
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { name: row.name } }], mode);
      if (isPlanMode) {
        setNotice({ kind: 'ok', text: `${label} ${row.name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [row.deviceId], [row.name]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `${label} — ${row.name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  const columns: DataTableColumn<ServiceRow>[] = [
    {
      header: 'Service',
      key: 'name',
      width: 240,
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-foreground">{row.name}</span>
          {row.description && row.description.trim() !== '' && (
            <span className="text-xs text-faint">{row.description}</span>
          )}
        </div>
      ),
    },
    {
      header: 'Init system',
      key: 'type',
      width: 120,
      render: (row) => <TypeBadge type={row.type} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={[]}
        />
      ),
    },
    {
      header: 'Status',
      key: 'status',
      width: 110,
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      // Boot persistence — null when the vendor doesn't expose it.
      header: 'Enabled',
      key: 'enabled',
      width: 90,
      exportValue: (row) => (row.enabled === null || row.enabled === undefined ? '' : row.enabled ? 'yes' : 'no'),
      render: (row) => {
        if (row.enabled === null || row.enabled === undefined) return <span className="text-faint">—</span>;
        return row.enabled ? (
          <span className="font-mono text-xs text-success-fg">yes</span>
        ) : (
          <span className="font-mono text-xs text-secondary">no</span>
        );
      },
    },
    {
      header: 'PID',
      key: 'pid',
      width: 80,
      sortAccessor: (row) => row.pid ?? -1,
      render: (row) =>
        row.pid !== null && row.pid !== undefined ? (
          <span className="font-mono text-xs">{row.pid}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      // Per-service lifecycle — rendered ONLY when the row's plugin advertises
      // the matching action id (catalog-driven, generic across plugins).
      header: 'Actions',
      key: 'actions',
      width: 120,
      render: (row) => <ServiceRowActions row={row} hasAction={hasAction} readOnly={isReadOnly} onRun={runService} />,
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      hiddenByDefault: true,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => <span className="font-mono text-xs">{new Date(row.collectedAt).toLocaleString()}</span>,
    },
  ];

  return (
    <Layout title="Services">
      {servicesQuery.isLoading && <p className="text-sm text-muted-foreground">Loading services...</p>}
      {servicesQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load services: {(servicesQuery.error as Error).message}</p>
      )}
      {servicesQuery.data && (
        <>
          {/* Client-side filters — the API returns every row; filtering here keeps
              one round-trip and instant toggles. */}
          <div className="mb-3 flex items-center gap-4">
            <label className="flex items-center gap-2 text-sm text-secondary">
              Init system
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="rounded border border-border bg-background px-2 py-1 text-sm"
              >
                <option value="">All</option>
                {types.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 text-sm text-secondary">
              Status
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded border border-border bg-background px-2 py-1 text-sm"
              >
                <option value="">All</option>
                <option value="running">Running</option>
                <option value="stopped">Stopped</option>
                <option value="failed">Failed</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>
          </div>

          {notice && (
            <div
              className={clsx(
                'mb-3 rounded-md border px-3 py-2 text-sm',
                notice.kind === 'ok' && 'border-success-border bg-success text-success-fg',
                notice.kind === 'info' && 'border-info-border bg-info text-info-fg',
                notice.kind === 'error' && 'border-danger-border bg-danger text-danger-fg',
              )}
            >
              {notice.text}
            </div>
          )}

          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}|${row.type}`}
            storageKey="services"
            autoRefresh={{ intervalMs: 30_000, queries: [servicesQuery] }}
            searchPlaceholder="Search services…"
            emptyMessage={
              rows.length === 0 && (servicesQuery.data?.length ?? 0) > 0
                ? 'No services match the current filters.'
                : 'No services collected yet — assign a plugin that reports services (OPNsense, TrueNAS or generic SSH) to a device and wait for the next poll.'
            }
          />
        </>
      )}

      {/* In-session 2FA revalidation (plan create/execute returned 401). */}
      {reauth && (
        <ReauthDialog
          contextLabel={reauth.label}
          onClose={() => setReauth(null)}
          onSuccess={async () => {
            const retry = reauth.retry;
            setReauth(null);
            await retry();
          }}
        />
      )}
    </Layout>
  );
}

/** Per-service lifecycle buttons for one row. Availability is GENERIC: a button
 * only renders when the owning plugin advertises the matching action id (TrueNAS,
 * OPNsense, generic SSH and OpenWRT all do). Eligibility follows the current
 * status — start/stop are disabled in their already-applied state; restart is
 * always offered. Read-Only mode disables every button with a clear tooltip. */
function ServiceRowActions({
  row,
  hasAction,
  readOnly,
  onRun,
}: {
  row: ServiceRow;
  hasAction: (pluginId: string, actionId: string) => boolean;
  readOnly: boolean;
  onRun: (row: ServiceRow, actionId: string, label: string) => void;
}) {
  const running = row.status === 'running';
  const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean }[] = [
    { id: 'services.start', label: 'Start', icon: <Play size={13} />, available: hasAction(row.pluginId, 'services.start'), eligible: !running },
    { id: 'services.stop', label: 'Stop', icon: <Square size={12} />, available: hasAction(row.pluginId, 'services.stop'), eligible: running || row.status === 'failed', danger: true },
    { id: 'services.restart', label: 'Restart', icon: <RotateCw size={13} />, available: hasAction(row.pluginId, 'services.restart'), eligible: true },
  ];
  const anyAvailable = actions.some((a) => a.available);
  if (!anyAvailable) return <span className="text-faint">—</span>;
  return (
    <div className="flex items-center gap-0.5">
      {actions.map((a) => {
        if (!a.available) return null;
        const enabled = a.eligible && !readOnly;
        const title = readOnly
          ? 'Read-only mode — switch to Plan or Execute to make changes'
          : !a.eligible
            ? `Not applicable in state ${row.status}`
            : `${a.label} ${row.name}`;
        return (
          <button
            key={a.id}
            type="button"
            aria-label={`${a.label} ${row.name}`}
            title={title}
            disabled={!enabled}
            onClick={() => onRun(row, a.id, a.label)}
            className={clsx(
              'rounded-md p-1 hover:bg-muted',
              a.danger ? 'text-danger-fg hover:text-danger-fg' : 'text-secondary hover:text-foreground',
              !enabled && 'cursor-not-allowed opacity-30',
            )}
          >
            {a.icon}
          </button>
        );
      })}
    </div>
  );
}
