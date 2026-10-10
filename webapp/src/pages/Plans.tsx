import { FormEvent, ReactNode, useMemo, useState } from 'react';
import clsx from 'clsx';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { CalendarClock, Play, Plus, RotateCcw, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableBulkAction, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { SchemaForm, validateSchema, defaultValues } from '../components/SchemaForm';
import { ReauthDialog } from '../components/ReauthDialog';
import { ScheduleDialog } from '../components/ScheduleDialog';
import { api, ApiError, CatalogEntry, Device, Plan } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/** True when the user lacks a 2FA-completed session (server returns this on execute/create). */
function isTwoFactorError(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401;
}

export default function Plans() {
  const [mode, setMode] = useState<'list' | 'create'>('list');

  // Creating plans needs configs:apply (+2FA server-side); viewing only plans:read.
  if (mode === 'create') {
    return <CreatePlan onDone={() => setMode('list')} onCancel={() => setMode('list')} />;
  }
  return <PlansList onCreate={can('configs:apply') ? () => setMode('create') : undefined} />;
}

/** Id prefix marking a plan's synthetic payload child row (see PlansList expandable). */
const PAYLOAD_CHILD_PREFIX = '__payload__:';

function PlansList({ onCreate }: { onCreate?: () => void }) {
  const { formatDateTime } = useTimeFormat();
  // '—' when absent — the central formatter already renders null/invalid as '—'.
  const fmtTime = (iso?: string | null) => formatDateTime(iso);
  const plansQuery = useQuery({ queryKey: ['plans'], queryFn: api.plans, refetchInterval: 10_000 });
  // Plugin names for the table — only fetched when allowed (API gates on plugins:read).
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, enabled: can('plugins:read') });

  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;
  const canApply = can('configs:apply');

  // Retry duplicates the plan and executes the copy — 2FA-gated server-side,
  // so a 401 opens the in-session revalidation dialog before retrying.
  const [reauth, setReauth] = useState<{ label: string; retry: () => Promise<void> } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Schedule dialog — single plan (row button) or a bulk selection.
  const [scheduleTarget, setScheduleTarget] = useState<{ plans: Plan[]; label?: string } | null>(null);

  async function handleRetry(plan: Plan) {
    const attempt = async () => {
      const fresh = await api.retryPlan(plan.id);
      window.location.href = `/plans/${fresh.id}`;
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Retry ${plan.intentActionId}`, retry: attempt });
      else setNotice(`Retry failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // Execute a saved (never-run) plan directly from the list — the follow-up to
  // the top-bar Plan mode, where actions were saved without executing.
  async function handleExecute(plan: Plan) {
    const attempt = async () => {
      await api.executePlan(plan.id);
      window.location.href = `/plans/${plan.id}`;
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Execute ${plan.intentActionId}`, retry: attempt });
      else setNotice(`Execute failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // --- Bulk actions (selection bar) -----------------------------------------

  /** Plans that can be executed right now (draft/ready). */
  const executable = (rows: Plan[]) => rows.filter((r) => ['draft', 'ready'].includes(r.status));
  /** Plans that can be scheduled (saved or finished — never executing; unverified re-runs re-check the outcome). */
  const schedulable = (rows: Plan[]) => rows.filter((r) => r.status !== 'executing');

  async function bulkExecute(rows: Plan[]) {
    const targets = executable(rows);
    if (targets.length === 0) {
      setNotice('None of the selected plans can be executed right now (only draft/ready plans).');
      return;
    }
    const attempt = async () => {
      let ok = 0;
      for (const p of targets) {
        await api.executePlan(p.id);
        ok += 1;
      }
      setNotice(`Execution started for ${ok} plan${ok === 1 ? '' : 's'}.`);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Execute ${targets.length} plans`, retry: attempt });
      else setNotice(`Bulk execute failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async function bulkUnschedule(rows: Plan[]) {
    const targets = rows.filter((r) => r.status === 'scheduled');
    if (targets.length === 0) {
      setNotice('None of the selected plans are scheduled.');
      return;
    }
    try {
      let ok = 0;
      for (const p of targets) {
        await api.unschedulePlan(p.id);
        ok += 1;
      }
      setNotice(`Schedule removed from ${ok} plan${ok === 1 ? '' : 's'}.`);
    } catch (err) {
      setNotice(`Unschedule failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async function bulkDelete(rows: Plan[]) {
    const targets = rows.filter((r) => r.status !== 'executing');
    if (targets.length === 0) {
      setNotice('None of the selected plans can be deleted (cancel executing plans first).');
      return;
    }
    try {
      let ok = 0;
      for (const p of targets) {
        await api.deletePlan(p.id);
        ok += 1;
      }
      setNotice(`Deleted ${ok} plan${ok === 1 ? '' : 's'}.`);
    } catch (err) {
      setNotice(`Bulk delete failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const bulkActions: DataTableBulkAction<Plan>[] = [
    {
      label: 'Execute',
      confirm: (n) => `Execute the selected draft/ready plans now? (${n} selected — only startable ones are affected)`,
      onClick: (rows) => void bulkExecute(rows),
    },
    {
      label: 'Schedule…',
      confirm: (n) => `Pick a due time for the selected plans. (${n} selected — executing plans are ignored)`,
      onClick: (rows) => setScheduleTarget({ plans: schedulable(rows) }),
    },
    {
      label: 'Unschedule',
      confirm: (n) => `Remove the schedule from the selected scheduled plans? They return to their previous state. (${n} selected)`,
      onClick: (rows) => void bulkUnschedule(rows),
    },
    {
      label: 'Delete',
      confirm: (n) => `Permanently delete the selected plans and their provisioned secrets? (${n} selected — executing plans are ignored)`,
      onClick: (rows) => void bulkDelete(rows),
    },
  ];

  const columns: DataTableColumn<Plan>[] = [
    {
      header: 'Intent',
      key: 'intentActionId',
      render: (row) => (
        <Link to={`/plans/${row.id}`} className="font-medium text-foreground hover:text-primary" title={`Open plan ${row.id.slice(0, 8)}…`}>
          {row.intentActionId}
        </Link>
      ),
    },
    { header: 'Plugin', key: 'pluginId', render: (row) => <span className="text-secondary">{pluginName(row.pluginId)}</span> },
    {
      header: 'Steps',
      key: 'stepCount',
      sortable: false,
      render: (row) => (
        <span className="tabular-nums text-secondary">
          {row.stepsDone ?? 0}/{row.stepCount ?? 0}
        </span>
      ),
    },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Scheduled',
      key: 'scheduledAt',
      sortable: false,
      filterable: false,
      width: 210,
      exportValue: (row) => row.scheduledAt ?? '',
      render: (row) =>
        row.status === 'scheduled' && row.scheduledAt ? (
          <span className="flex items-center gap-1.5 text-xs" title={`Policy: ${row.schedulePolicy === 'skip' ? 'skip if UNM/plugin is down when due' : 'retry as soon as possible if down when due'}`}>
            <CalendarClock className="h-3.5 w-3.5 shrink-0 text-primary" />
            <span>{fmtTime(row.scheduledAt)}</span>
            <span className={clsx('rounded border px-1 py-px text-[10px] font-medium', row.schedulePolicy === 'skip' ? 'border-warning-border bg-warning text-warning-fg' : 'border-info-border bg-info text-info-fg')}>
              {row.schedulePolicy === 'skip' ? 'skip if down' : 'retry if down'}
            </span>
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Error',
      key: 'error',
      sortable: false,
      filterable: false,
      width: 260,
      exportValue: (row) => row.error ?? '',
      render: (row) =>
        row.error ? (
          <span className="block max-w-[300px] truncate text-danger-fg" title={row.error}>
            {row.error}
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Created by',
      key: 'createdByName',
      render: (row) => <span className="text-secondary">{row.createdByName ?? row.createdBy}</span>,
    },
    {
      header: 'Executed by',
      key: 'executedByName',
      render: (row) => (
        <span className={row.executedByName ? 'text-secondary' : 'text-faint'}>{row.executedByName ?? '—'}</span>
      ),
    },
    {
      header: 'Created',
      key: 'createdAt',
      sortAccessor: (row) => new Date(row.createdAt).getTime(),
      render: (row) => fmtTime(row.createdAt),
    },
    {
      header: 'Started',
      key: 'startedAt',
      sortAccessor: (row) => (row.startedAt ? new Date(row.startedAt).getTime() : 0),
      render: (row) => (
        row.startedAt ? fmtTime(row.startedAt) : <span className="text-faint">{['draft', 'ready'].includes(row.status) ? 'queued' : '—'}</span>
      ),
    },
    {
      header: 'Finished',
      key: 'finishedAt',
      sortAccessor: (row) => (row.finishedAt ? new Date(row.finishedAt).getTime() : 0),
      render: (row) => fmtTime(row.finishedAt),
    },
    {
      header: 'Actions',
      key: 'actions',
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      width: 150,
      render: (row) => {
        if (!canApply || row.status === 'executing') return null;
        const neverRun = ['draft', 'ready'].includes(row.status);
        // Icon-only action buttons — same design language as Storage/VMs/Containers.
        const actions: { id: string; label: string; icon: ReactNode; danger?: boolean }[] = [];
        if (neverRun) actions.push({ id: 'execute', label: `Execute ${row.intentActionId} now`, icon: <Play size={14} /> });
        actions.push({
          id: row.status === 'scheduled' ? 'reschedule' : 'schedule',
          label: row.status === 'scheduled' ? `Change the schedule for ${row.intentActionId}` : `Schedule ${row.intentActionId} to run later`,
          icon: <CalendarClock size={14} />,
        });
        if (row.status === 'scheduled') actions.push({ id: 'unschedule', label: `Remove the schedule from ${row.intentActionId}`, icon: <X size={14} /> });
        actions.push({ id: 'retry', label: `Retry ${row.intentActionId} — duplicates this plan and executes the copy`, icon: <RotateCcw size={14} /> });
        actions.push({ id: 'delete', label: `Delete ${row.intentActionId}`, icon: <Trash2 size={13} />, danger: true });

        return (
          <div className="flex items-center gap-0.5">
            {actions.map((a) => (
              <button
                key={a.id}
                type="button"
                aria-label={a.label}
                title={a.label}
                onClick={() => {
                  if (a.id === 'execute') void handleExecute(row);
                  else if (a.id === 'schedule' || a.id === 'reschedule') setScheduleTarget({ plans: [row] });
                  else if (a.id === 'unschedule') void bulkUnschedule([row]);
                  else if (a.id === 'retry') void handleRetry(row);
                  else if (a.id === 'delete') {
                    const msg = `Permanently delete this plan and its provisioned secrets? This cannot be undone.`;
                    if (!window.confirm(msg)) return;
                    void bulkDelete([row]);
                  }
                }}
                className={clsx(
                  'rounded-md p-1.5 hover:bg-muted',
                  a.danger ? 'text-danger-fg hover:text-danger-fg' : 'text-secondary hover:text-foreground',
                )}
              >
                {a.icon}
              </button>
            ))}
          </div>
        );
      },
    },
  ];

  return (
    <Layout
      title="Plans"
      actions={
        onCreate && (
          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
            onClick={onCreate}
          >
            <Plus className="h-4 w-4" /> New Plan
          </button>
        )
      }
    >

      {plansQuery.isLoading && <p className="text-sm text-muted-foreground">Loading plans…</p>}
      {plansQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load plans: {(plansQuery.error as Error).message}</p>
      )}
      {notice && (
        <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
          {notice}{' '}
          <button onClick={() => setNotice(null)} className="font-medium underline">Dismiss</button>
        </div>
      )}
      {plansQuery.data && (
        <DataTable
          columns={columns}
          rows={plansQuery.data.map((p) => ({ ...p, intentActionId: p.intentActionId }))}
          rowKey={(row) => row.id}
          storageKey="plans"
          selectable={canApply}
          bulkActions={bulkActions}
          autoRefresh={{ intervalMs: 10_000, queries: [plansQuery] }}
          emptyMessage="No plans yet. Create one to roll out a multi-device change (e.g. a WireGuard tunnel)."
          expandable={{
            // Every plan is expandable — the payload (intent inputs + per-step
            // payloads) must always be visible, for past and future executions.
            // The child is a sentinel COPY of the row (synthetic id): search/
            // filter match it exactly like its parent (no new surface), and the
            // prefix marks it as leaf so DataTable's subtree walk terminates.
            childrenOf: (row) =>
              String(row.id).startsWith(PAYLOAD_CHILD_PREFIX) ? [] : [{ ...row, id: PAYLOAD_CHILD_PREFIX + row.id }],
            renderChild: (_child, parent, ctx) => <PlanPayloadRow plan={parent} ctx={ctx} />,
          }}
        />
      )}

      {scheduleTarget && scheduleTarget.plans.length > 0 && (
        <ScheduleDialog
          plans={scheduleTarget.plans}
          onClose={() => setScheduleTarget(null)}
          onSaved={(n) => {
            setNotice(`Scheduled ${n} plan${n === 1 ? '' : 's'} — the scheduler will run them at their due time.`);
            void plansQuery.refetch();
          }}
        />
      )}

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

/**
 * Expanded row under a plan: the full payload of what was / will be executed —
 * the raw intent inputs plus every step's action, target device and input.
 * Step payloads are loaded lazily (the list endpoint omits them).
 */
function PlanPayloadRow({ plan, ctx }: { plan: Plan; ctx: ExpandChildContext }) {
  const detailQuery = useQuery({ queryKey: ['plan', plan.id], queryFn: () => api.getPlan(plan.id) });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, enabled: can('plugins:read') });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices, enabled: can('devices:read') });

  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;
  const deviceName = (id: string) => devicesQuery.data?.find((d) => d.id === id)?.name ?? id;

  // One full-width cell spanning every column — the payload (intent inputs +
  // per-step payloads) is wide JSON that must not be squeezed into a single
  // narrow table column. colSpan covers all visible data columns PLUS the two
  // leading cells DataTable always renders on expandable+selectable tables:
  // the chevron column (+1, always present here since renderChild only runs for
  // expandable rows) and the checkbox column (only when selectable).
  const colSpan = ctx.columns.length + (ctx.selectable ? 1 : 0) + 1;

  return (
    <tr className="bg-background/70">
      <td colSpan={colSpan} className="px-4 py-2 text-secondary">
        <div className="space-y-3 py-1">
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-faint">Intent inputs</p>
            <pre className="max-h-48 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-code-fg">
              {Object.keys(plan.intentInputs ?? {}).length > 0
                ? JSON.stringify(plan.intentInputs, null, 2)
                : '{}'}
            </pre>
          </div>
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-faint">Step payloads</p>
            {detailQuery.isLoading && <p className="text-xs text-faint">Loading steps…</p>}
            {!detailQuery.isLoading && (detailQuery.data?.steps ?? []).length === 0 && (
              <p className="text-xs text-faint">No steps.</p>
            )}
            <div className="space-y-2">
              {(detailQuery.data?.steps ?? []).map((s) => (
                <details key={s.id} className="rounded border border-border bg-card px-2.5 py-1.5">
                  <summary className="cursor-pointer text-xs font-medium text-secondary hover:text-foreground">
                    #{s.stepIndex} · {s.actionId}
                    <span className="ml-2 text-faint">{deviceName(s.deviceId)} ({pluginName(plan.pluginId)})</span>
                    <StatusBadge status={s.status} />
                  </summary>
                  <pre className="mt-1.5 max-h-40 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-code-fg">
                    {JSON.stringify(s.input ?? {}, null, 2)}
                  </pre>
                </details>
              ))}
            </div>
          </div>
        </div>
      </td>
    </tr>
  );
}

function CreatePlan({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // Only plugins that advertise an action catalog can seed a plan.
  const [pluginId, setPluginId] = useState('');
  const actionsQuery = useQuery({
    queryKey: ['pluginActions', pluginId],
    queryFn: () => api.pluginActions(pluginId),
    enabled: Boolean(pluginId),
  });

  const catalog: CatalogEntry[] = useMemo(() => actionsQuery.data?.actions ?? [], [actionsQuery.data]);
  // Multi-device intents first (the headline use case), then single-device fan-outs.
  const intents = useMemo(
    () => [...catalog].sort((a, b) => Number(typeof b.deviceCount === 'number' && b.deviceCount > 1) - Number(typeof a.deviceCount === 'number' && a.deviceCount > 1)),
    [catalog]
  );

  const [intentId, setIntentId] = useState('');
  const intent: CatalogEntry | undefined = intents.find((c) => c.id === intentId);
  const requiredDevices = typeof intent?.deviceCount === 'number' ? intent.deviceCount : null;

  const [inputs, setInputs] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  // Optional per-plan retry override (empty = inherit the global defaults).
  const [retryMax, setRetryMax] = useState('');
  const [retryWaitS, setRetryWaitS] = useState('');

  // Devices that have THIS plugin assigned (the plan can only target those).
  const eligibleDevices: Device[] = useMemo(() => {
    if (!pluginId) return [];
    return (devicesQuery.data ?? []).filter((d) => d.plugins?.some((p) => p.pluginId === pluginId));
  }, [devicesQuery.data, pluginId]);

  function handleIntentChange(id: string) {
    setIntentId(id);
    const entry = catalog.find((c) => c.id === id);
    setInputs(entry?.inputSchema ? defaultValues(entry.inputSchema) : {});
    setFieldErrors({});
  }

  const createPlan = useMutation({
    mutationFn: () => {
      const retryPolicy: Record<string, number> = {};
      if (retryMax.trim() !== '') retryPolicy.maxAttempts = Number(retryMax);
      if (retryWaitS.trim() !== '') retryPolicy.waitMs = Math.round(Number(retryWaitS) * 1000);
      return api.createPlan({
        pluginId,
        intentActionId: intentId,
        inputs,
        devices: selectedDeviceIds.map((deviceId) => ({ deviceId })),
        ...(Object.keys(retryPolicy).length > 0 ? { retryPolicy } : {}),
      });
    },
    onSuccess: (plan) => {
      window.location.href = `/plans/${plan.id}`;
    },
    onError: (err: unknown) => setFormError(describeError(err)),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!pluginId || !intentId) return;
    const errors = intent?.inputSchema ? validateSchema(intent.inputSchema, inputs) : {};
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    if (requiredDevices !== null && selectedDeviceIds.length !== requiredDevices) {
      setFormError(`This intent requires exactly ${requiredDevices} devices — select ${selectedDeviceIds.length}.`);
      return;
    }
    if (selectedDeviceIds.length === 0) {
      setFormError('Select at least one device.');
      return;
    }
    createPlan.mutate();
  }

  const plugins = pluginsQuery.data ?? [];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-foreground">New Plan</h1>
        <button
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted"
          onClick={onCancel}
        >
          <X className="h-4 w-4" /> Cancel
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {formError && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
        )}

        {/* Step 1: plugin + intent */}
        <section className="grid grid-cols-1 gap-4 rounded-md border border-border bg-card p-4 shadow-sm sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Plugin</label>
            <select
              required
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={pluginId}
              onChange={(e) => {
                setPluginId(e.target.value);
                setIntentId('');
                setSelectedDeviceIds([]);
                setInputs({});
              }}
            >
              <option value="" disabled>Select a plugin</option>
              {plugins.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Intent</label>
            <select
              required
              disabled={!pluginId || intents.length === 0}
              className="w-full rounded-md border border-border px-3 py-2 text-sm disabled:opacity-50"
              value={intentId}
              onChange={(e) => handleIntentChange(e.target.value)}
            >
              <option value="" disabled>
                {pluginId ? (intents.length === 0 ? 'No actions advertised' : 'Select an intent') : 'Pick a plugin first'}
              </option>
              {intents.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}{typeof c.deviceCount === 'number' && c.deviceCount > 1 ? ` (${c.deviceCount} devices)` : ''}
                </option>
              ))}
            </select>
          </div>
          {intent?.description && (
            <p className="col-span-full text-xs text-muted-foreground">{intent.description}</p>
          )}
        </section>

        {/* Step 2: intent inputs */}
        {intent && (
          <section className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h2 className="mb-2 text-sm font-semibold text-foreground">Intent settings</h2>
            <SchemaForm schema={intent.inputSchema ?? {}} values={inputs} onChange={(v) => { setInputs(v); setFieldErrors({}); }} fieldErrors={fieldErrors} />
          </section>
        )}

        {/* Step 3: devices */}
        {pluginId && (
          <section className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h2 className="mb-1 text-sm font-semibold text-foreground">
              Devices{requiredDevices !== null ? ` — select exactly ${requiredDevices}` : ''}
            </h2>
            {eligibleDevices.length === 0 ? (
              <p className="text-sm text-muted-foreground">No devices have this plugin assigned.</p>
            ) : (
              <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {eligibleDevices.map((d) => (
                  <label key={d.id} className="flex cursor-pointer items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-background">
                    <input
                      type="checkbox"
                      checked={selectedDeviceIds.includes(d.id)}
                      onChange={(e) =>
                        setSelectedDeviceIds((prev) => (e.target.checked ? [...prev, d.id] : prev.filter((x) => x !== d.id)))
                      }
                      className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring"
                    />
                    <span className="flex-1 truncate">{d.name}</span>
                    <span className="font-mono text-xs text-faint">{d.managementAddress}</span>
                  </label>
                ))}
              </div>
            )}
          </section>
        )}

        {/* Step 4: optional retry override */}
        <section className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="mb-1 text-sm font-semibold text-foreground">Retry policy (optional)</h2>
          <p className="text-xs text-muted-foreground">
            Failed steps are retried only when the failure is transient (the plugin reports it as retryable, or the dispatch timed out / could not
            reach the plugin). Leave empty to use the global defaults — or set max attempts to 0 to disable retries for this plan.
          </p>
          <div className="mt-2 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="mb-1 block font-medium text-secondary">Max attempts per step</span>
              <input
                type="number" min={0} max={10}
                value={retryMax}
                onChange={(e) => setRetryMax(e.target.value)}
                placeholder="inherit global default"
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block font-medium text-secondary">Wait between attempts (seconds)</span>
              <input
                type="number" min={1} max={3600}
                value={retryWaitS}
                onChange={(e) => setRetryWaitS(e.target.value)}
                placeholder="inherit global default"
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
              />
            </label>
          </div>
        </section>

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={createPlan.isPending || !pluginId || !intentId || selectedDeviceIds.length === 0}
            className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {createPlan.isPending ? 'Creating…' : 'Create Plan'}
          </button>
          <span className="text-xs text-faint">Provisioned secrets (keys, PSKs, certs) are generated at creation time.</span>
        </div>
      </form>
    </Layout>
  );
}

function describeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return isTwoFactorError(err) ? `${msg} — sign in again to complete two-factor authentication.` : msg;
}
