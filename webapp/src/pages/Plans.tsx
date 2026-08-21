import { FormEvent, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Plus, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { SchemaForm, validateSchema, defaultValues } from '../components/SchemaForm';
import { api, ApiError, CatalogEntry, Device, Plan } from '../api/client';

/** True when the user lacks a 2FA-completed session (server returns this on execute/create). */
function isTwoFactorError(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401;
}

export default function Plans() {
  const [mode, setMode] = useState<'list' | 'create'>('list');

  if (mode === 'create') {
    return <CreatePlan onDone={() => setMode('list')} onCancel={() => setMode('list')} />;
  }
  return <PlansList onCreate={() => setMode('create')} />;
}

function PlansList({ onCreate }: { onCreate: () => void }) {
  const plansQuery = useQuery({ queryKey: ['plans'], queryFn: api.plans, refetchInterval: 10_000 });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });

  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;

  const columns: DataTableColumn<Plan>[] = [
    { header: 'Intent', key: 'intentActionId' },
    { header: 'Plugin', key: 'pluginId', render: (row) => <span className="text-slate-600">{pluginName(row.pluginId)}</span> },
    {
      header: 'Steps',
      key: 'stepCount',
      sortable: false,
      render: (row) => (
        <span className="tabular-nums text-slate-600">
          {row.stepsDone ?? 0}/{row.stepCount ?? 0}
        </span>
      ),
    },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Created',
      key: 'createdAt',
      sortAccessor: (row) => new Date(row.createdAt).getTime(),
      render: (row) => new Date(row.createdAt).toLocaleString(),
    },
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Plans</h1>
        <button
          className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
          onClick={onCreate}
        >
          <Plus className="h-4 w-4" /> New Plan
        </button>
      </div>

      {plansQuery.isLoading && <p className="text-sm text-slate-500">Loading plans…</p>}
      {plansQuery.isError && (
        <p className="text-sm text-red-600">Failed to load plans: {(plansQuery.error as Error).message}</p>
      )}
      {plansQuery.data && (
        <DataTable
          columns={columns}
          rows={plansQuery.data.map((p) => ({ ...p, intentActionId: p.intentActionId }))}
          rowKey={(row) => row.id}
          storageKey="plans"
          emptyMessage="No plans yet. Create one to roll out a multi-device change (e.g. a WireGuard tunnel)."
        />
      )}
    </Layout>
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
        <h1 className="text-xl font-bold text-slate-900">New Plan</h1>
        <button
          className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
          onClick={onCancel}
        >
          <X className="h-4 w-4" /> Cancel
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {formError && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
        )}

        {/* Step 1: plugin + intent */}
        <section className="grid grid-cols-1 gap-4 rounded-md border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Plugin</label>
            <select
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
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
            <label className="mb-1 block text-sm font-medium text-slate-700">Intent</label>
            <select
              required
              disabled={!pluginId || intents.length === 0}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
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
            <p className="col-span-full text-xs text-slate-500">{intent.description}</p>
          )}
        </section>

        {/* Step 2: intent inputs */}
        {intent && (
          <section className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
            <h2 className="mb-2 text-sm font-semibold text-slate-800">Intent settings</h2>
            <SchemaForm schema={intent.inputSchema ?? {}} values={inputs} onChange={(v) => { setInputs(v); setFieldErrors({}); }} fieldErrors={fieldErrors} />
          </section>
        )}

        {/* Step 3: devices */}
        {pluginId && (
          <section className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
            <h2 className="mb-1 text-sm font-semibold text-slate-800">
              Devices{requiredDevices !== null ? ` — select exactly ${requiredDevices}` : ''}
            </h2>
            {eligibleDevices.length === 0 ? (
              <p className="text-sm text-slate-500">No devices have this plugin assigned.</p>
            ) : (
              <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {eligibleDevices.map((d) => (
                  <label key={d.id} className="flex cursor-pointer items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm hover:bg-slate-50">
                    <input
                      type="checkbox"
                      checked={selectedDeviceIds.includes(d.id)}
                      onChange={(e) =>
                        setSelectedDeviceIds((prev) => (e.target.checked ? [...prev, d.id] : prev.filter((x) => x !== d.id)))
                      }
                      className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
                    />
                    <span className="flex-1 truncate">{d.name}</span>
                    <span className="font-mono text-xs text-slate-400">{d.managementAddress}</span>
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
            className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
          >
            {createPlan.isPending ? 'Creating…' : 'Create Plan'}
          </button>
          <span className="text-xs text-slate-400">Provisioned secrets (keys, PSKs, certs) are generated at creation time.</span>
        </div>
      </form>
    </Layout>
  );
}

function describeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return isTwoFactorError(err) ? `${msg} — sign in again to complete two-factor authentication.` : msg;
}
