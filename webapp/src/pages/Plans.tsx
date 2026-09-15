import { FormEvent, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Play, Plus, RotateCcw, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { SchemaForm, validateSchema, defaultValues } from '../components/SchemaForm';
import { ReauthDialog } from '../components/ReauthDialog';
import { api, ApiError, CatalogEntry, Device, Plan } from '../api/client';
import { can } from '../auth/permissions';

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

/** Formats an ISO timestamp for the timing columns; '—' when absent. */
function fmtTime(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—';
}

/** Id prefix marking a plan's synthetic payload child row (see PlansList expandable). */
const PAYLOAD_CHILD_PREFIX = '__payload__:';

function PlansList({ onCreate }: { onCreate?: () => void }) {
  const plansQuery = useQuery({ queryKey: ['plans'], queryFn: api.plans, refetchInterval: 10_000 });
  // Plugin names for the table — only fetched when allowed (API gates on plugins:read).
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, enabled: can('plugins:read') });

  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;
  const canApply = can('configs:apply');

  // Retry duplicates the plan and executes the copy — 2FA-gated server-side,
  // so a 401 opens the in-session revalidation dialog before retrying.
  const [reauth, setReauth] = useState<{ label: string; retry: () => Promise<void> } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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
        return (
          <div className="flex items-center gap-1">
            {neverRun && (
              <button
                onClick={() => handleExecute(row)}
                title="Execute this saved plan now"
                aria-label={`Execute ${row.intentActionId}`}
                className="flex items-center gap-1 rounded border border-success-border bg-success px-2 py-1 text-xs font-medium text-success-fg hover:opacity-90"
              >
                <Play className="h-3.5 w-3.5" /> Execute
              </button>
            )}
            <button
              onClick={() => handleRetry(row)}
              title="Retry — duplicates this plan (same payload + secrets) and executes the copy"
              aria-label={`Retry ${row.intentActionId}`}
              className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted disabled:opacity-50"
            >
              <RotateCcw className="h-3.5 w-3.5" /> Retry
            </button>
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
            className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover"
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

  // Anchor the payload in the Intent column when visible, else the first
  // visible column — hiding a column must never hide the payload.
  const anchorIdx = Math.max(0, ctx.columns.findIndex((c) => c.key === 'intentActionId'));

  return (
    <tr className="bg-background/70">
      {ctx.columns.map((col, i) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
          {i === anchorIdx ? (
            <div className="space-y-3 py-1">
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-faint">Intent inputs</p>
                <pre className="max-h-48 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-slate-100">
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
                      <pre className="mt-1.5 max-h-40 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-slate-100">
                        {JSON.stringify(s.input ?? {}, null, 2)}
                      </pre>
                    </details>
                  ))}
                </div>
              </div>
            </div>
          ) : null}
        </td>
      ))}
    </tr>
  );
}

function CreatePlan({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // Only plugins that advertise an action catalog can seed a plan.
  const [pluginId, setPluginId] = useState('');
  const actionsQuery = useQuery({
    queryKey: ['plugin-actions', pluginId],
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
    mutationFn: () =>
      api.createPlan({
        pluginId,
        intentActionId: intentId,
        inputs,
        devices: selectedDeviceIds.map((deviceId) => ({ deviceId })),
      }),
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
                      className="h-4 w-4 rounded border-border text-foreground focus:ring-slate-400"
                    />
                    <span className="flex-1 truncate">{d.name}</span>
                    <span className="font-mono text-xs text-faint">{d.managementAddress}</span>
                  </label>
                ))}
              </div>
            )}
          </section>
        )}

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
