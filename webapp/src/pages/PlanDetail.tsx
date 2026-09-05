import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import clsx from 'clsx';
import {
  ArrowDown,
  ArrowUp,
  ChevronRight,
  Play,
  Plus,
  RefreshCw,
  Square,
  Trash2,
  X,
} from 'lucide-react';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { SchemaForm, validateSchema, defaultValues } from '../components/SchemaForm';
import { api, ApiError, CatalogEntry, Device, PlanDetail as PlanDetailType, PlanStep } from '../api/client';
import { can } from '../auth/permissions';

export default function PlanDetail() {
  const { id = '' } = useParams();
  // Viewing needs plans:read (route guard); every mutation below needs configs:apply.
  const canApply = can('configs:apply');
  const planQuery = useQuery({
    queryKey: ['plan', id],
    queryFn: () => api.getPlan(id),
    refetchInterval: (query) => {
      // Poll faster while the plan is executing, otherwise settle to 15s.
      return query.state.data?.status === 'executing' ? 3_000 : 15_000;
    },
  });

  // Reference data — only fetched when the user may actually use it (the API
  // gates these on plugins:read / devices:read).
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, enabled: can('plugins:read') });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices, enabled: can('devices:read') });
  const plan: PlanDetailType | undefined = planQuery.data;

  // Action catalog for labels + the step editor (single-device actions only).
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const parentActionsQuery = useQuery({
    queryKey: ['plugin-actions', plan?.pluginId ?? ''],
    queryFn: () => api.pluginActions(plan!.pluginId),
    enabled: Boolean(plan?.pluginId) && can('plugins:read'),
  });
  useEffect(() => {
    if (parentActionsQuery.data) setCatalog(parentActionsQuery.data.actions);
  }, [parentActionsQuery.data]);

  const pluginName = pluginsQuery.data?.find((p) => p.id === plan?.pluginId)?.name ?? '—';
  const deviceName = (deviceId: string) => devicesQuery.data?.find((d) => d.id === deviceId)?.name ?? deviceId;
  const actionLabel = (actionId: string) => catalog.find((c) => c.id === actionId)?.label ?? actionId;

  const editable = plan ? ['draft', 'ready'].includes(plan.status) : false;

  const executeMutation = useMutation({
    mutationFn: () => api.executePlan(id),
    onSuccess: () => planQuery.refetch(),
  });
  const cancelMutation = useMutation({
    mutationFn: () => api.cancelPlan(id),
    onSuccess: () => planQuery.refetch(),
  });
  const deleteMutation = useMutation({
    mutationFn: () => api.deletePlan(id),
    onSuccess: () => {
      window.location.href = '/plans';
    },
  });

  if (planQuery.isLoading) return <Layout><p className="text-sm text-muted-foreground">Loading plan…</p></Layout>;
  if (planQuery.isError || !plan) {
    return (
      <Layout>
        <p className="text-sm text-danger-fg">Failed to load plan: {(planQuery.error as Error)?.message ?? 'not found'}</p>
        <Link to="/plans" className="mt-2 inline-block text-sm text-muted-foreground hover:text-secondary">← Back to plans</Link>
      </Layout>
    );
  }

  const steps = plan.steps ?? [];
  const doneCount = steps.filter((s) => s.status === 'succeeded').length;

  return (
    <Layout
      title={
        <span className="flex items-center gap-2">
          {plan.intentActionId}
          <StatusBadge status={plan.status} />
        </span>
      }
      actions={
        <div className="flex items-center gap-2">
          {canApply && editable && (
            <button onClick={() => executeMutation.mutate()} disabled={executeMutation.isPending || steps.length === 0}
              className="flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-50">
              <Play className="h-4 w-4" /> Execute
            </button>
          )}
          {canApply && plan.status === 'executing' && (
            <button onClick={() => cancelMutation.mutate()} disabled={cancelMutation.isPending}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50">
              <Square className="h-4 w-4" /> Cancel
            </button>
          )}
          {canApply && plan.status !== 'executing' && (
            <button onClick={() => { if (window.confirm('Delete this plan and its provisioned secrets?')) deleteMutation.mutate(); }}
              disabled={deleteMutation.isPending}
              className="flex items-center gap-1.5 rounded-md border border-danger-border px-3 py-1.5 text-sm font-medium text-danger-fg hover:bg-danger disabled:opacity-50">
              <Trash2 className="h-4 w-4" /> Delete
            </button>
          )}
        </div>
      }
    >
      <Link to="/plans" className="mb-3 inline-block text-xs text-faint hover:text-secondary">← Plans</Link>

      {(executeMutation.error || cancelMutation.error) && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
          {describeError(executeMutation.error ?? cancelMutation.error)}
        </div>
      )}

      {/* Provisioned secrets */}
      {plan.provisionedSecrets.length > 0 && (
        <section className="mb-5 rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="mb-2 text-sm font-semibold text-foreground">Provisioned secrets</h2>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {plan.provisionedSecrets.map((ps) => (
              <SecretCard key={ps.ref} planId={plan.id} refName={ps.ref} label={ps.label ?? ps.type ?? ps.ref} type={ps.type ?? '—'} secretId={ps.secretId} onRegenerated={() => planQuery.refetch()} />
            ))}
          </div>
        </section>
      )}

      {/* Steps */}
      <section className="rounded-md border border-border bg-card shadow-sm">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold text-foreground">Steps</h2>
          {canApply && editable && (
            <AddStepButton plan={plan} onAdded={() => planQuery.refetch()} />
          )}
        </div>
        <ol className="divide-y divide-border">
          {steps.map((step, i) => (
            <StepRow key={step.id} step={step} position={i} total={steps.length} editable={canApply && editable}
              deviceName={deviceName(step.deviceId)} actionLabel={actionLabel(step.actionId)}
              onMutated={() => planQuery.refetch()} />
          ))}
        </ol>
      </section>

      {plan.error && (
        <div className="mt-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{plan.error}</div>
      )}
    </Layout>
  );
}

// --- Provisioned secret card --------------------------------------------------

function SecretCard({ planId, refName, label, type, secretId, onRegenerated }: {
  planId: string; refName: string; label: string; type: string; secretId: string; onRegenerated: () => void;
}) {
  const regenerate = useMutation({
    mutationFn: () => api.regeneratePlanSecret(planId, refName),
    onSuccess: onRegenerated,
  });
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border border-border bg-background/60 px-3 py-2">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-foreground" title={label}>{label}</p>
        <p className="font-mono text-xs text-faint">{type} · {secretId.slice(0, 8)}…</p>
      </div>
      {can('secrets:write') && (
        <button onClick={() => regenerate.mutate()} disabled={regenerate.isPending} title={`Re-roll ${refName} (same id preserved)`} aria-label="Regenerate secret"
          className="rounded p-1.5 text-faint hover:bg-card hover:text-secondary disabled:opacity-50">
          <RefreshCw className={clsx('h-4 w-4', regenerate.isPending && 'animate-spin')} />
        </button>
      )}
    </div>
  );
}

// --- Step row ------------------------------------------------------------------

function StepRow({ step, position, total, editable, deviceName, actionLabel, onMutated }: {
  step: PlanStep; position: number; total: number; editable: boolean;
  deviceName: string; actionLabel: string; onMutated: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);

  const moveMutation = useMutation({
    mutationFn: (to: number) => api.reorderPlanSteps(step.planId, position, to),
    onSuccess: onMutated,
  });
  const removeMutation = useMutation({
    mutationFn: () => api.removePlanStep(step.planId, step.id),
    onSuccess: onMutated,
  });

  return (
    <li className="px-4 py-3">
      <div className="flex items-center gap-3">
        <button onClick={() => setExpanded((v) => !v)} aria-label={expanded ? 'Collapse step' : 'Expand step'}
          className="rounded p-0.5 text-faint hover:bg-muted hover:text-secondary">
          <ChevronRight className={clsx('h-4 w-4 transition-transform', expanded && 'rotate-90')} />
        </button>
        <span className="w-8 shrink-0 text-right font-mono text-xs text-faint">#{step.stepIndex}</span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-foreground">{actionLabel}</p>
          <p className="text-xs text-muted-foreground">
            {deviceName}
            {step.bestEffort && <span className="ml-2 rounded bg-warning px-1.5 py-0.5 text-[10px] font-medium text-warning-fg">best effort</span>}
          </p>
        </div>
        {(step.dependsOn?.length ?? 0) > 0 && (
          <span className="hidden shrink-0 rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground sm:inline">
            after {step.dependsOn!.map((d) => `#${d}`).join(', ')}
          </span>
        )}
        <StatusBadge status={step.status} />
        {editable && (
          <div className="flex shrink-0 items-center gap-0.5">
            <button onClick={() => moveMutation.mutate(position - 1)} disabled={position === 0 || moveMutation.isPending} title="Move up" aria-label="Move step up"
              className="rounded p-1 text-faint hover:bg-muted hover:text-secondary disabled:opacity-30">
              <ArrowUp className="h-3.5 w-3.5" />
            </button>
            <button onClick={() => moveMutation.mutate(position + 1)} disabled={position === total - 1 || moveMutation.isPending} title="Move down" aria-label="Move step down"
              className="rounded p-1 text-faint hover:bg-muted hover:text-secondary disabled:opacity-30">
              <ArrowDown className="h-3.5 w-3.5" />
            </button>
            <button onClick={() => setEditing(true)} title="Edit step" aria-label="Edit step"
              className="rounded p-1 text-faint hover:bg-muted hover:text-secondary">✎</button>
            <button onClick={() => { if (window.confirm('Remove this step?')) removeMutation.mutate(); }} title="Remove step" aria-label="Remove step"
              className="rounded p-1 text-faint hover:bg-danger hover:text-danger-fg">
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {expanded && (
        <div className="ml-11 mt-2 space-y-2 text-xs">
          {(step.secretRefs?.length ?? 0) > 0 && (
            <p className="text-muted-foreground">Secrets: {step.secretRefs!.join(', ')}</p>
          )}
          <details open={Boolean(step.result)}>
            <summary className="cursor-pointer text-faint hover:text-secondary">Result</summary>
            {step.result ? (
              <pre className="mt-1 max-h-64 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-slate-100">
                {JSON.stringify(step.result, null, 2)}
              </pre>
            ) : (
              <p className="mt-1 text-faint">No result yet.</p>
            )}
          </details>
        </div>
      )}

      {editing && (
        <StepEditor step={step} planId={step.planId} onSaved={() => { setEditing(false); onMutated(); }} onClose={() => setEditing(false)} />
      )}
    </li>
  );
}

// --- Step editor ----------------------------------------------------------------

function StepEditor({ step, planId, onSaved, onClose }: {
  step: PlanStep; planId: string; onSaved: () => void; onClose: () => void;
}) {
  const [actionId, setActionId] = useState(step.actionId);
  const [input, setInput] = useState<Record<string, unknown>>(step.input ?? {});
  const [secretRefs, setSecretRefs] = useState<string[]>(step.secretRefs ?? []);
  const [dependsOn, setDependsOn] = useState<number[]>(step.dependsOn ?? []);
  const [bestEffort, setBestEffort] = useState(Boolean(step.bestEffort));
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  // Plan context (provisioned secrets + other steps) and the plugin's action
  // catalog, fetched locally so this modal is self-contained.
  const catalogQuery = useQuery({ queryKey: ['plan-editor-catalog', planId], queryFn: () => api.getPlan(planId) });
  const actionsQuery = useCatalogByPlanId(planId);

  const saveMutation = useMutation({
    mutationFn: () =>
      api.updatePlanStep(planId, step.id, { actionId, input, secretRefs, dependsOn, bestEffort }),
    onSuccess: onSaved,
    onError: (err) => setError(describeError(err)),
  });


  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-primary/40 p-4" onClick={onClose}>
      <div className="max-h-[85vh] w-full max-w-lg overflow-auto rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="text-sm font-semibold text-foreground">Edit step #{step.stepIndex}</h3>
          <button onClick={onClose} aria-label="Close" className="rounded p-1 text-faint hover:bg-muted"><X className="h-4 w-4" /></button>
        </div>

        <div className="space-y-4 px-4 py-3">
          {error && <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{error}</div>}

          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Action</label>
            <select value={actionId} onChange={(e) => { setActionId(e.target.value); setInput({}); }}
              className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm">
              {(actionsQuery.data ?? []).map((c) => (
                <option key={c.id} value={c.id}>{c.label}</option>
              ))}
            </select>
          </div>

          {(() => {
            const entry = (actionsQuery.data ?? []).find((c) => c.id === actionId);
            return entry?.inputSchema ? (
              <SchemaForm schema={entry.inputSchema} values={input} onChange={(v) => { setInput(v); setFieldErrors({}); }} fieldErrors={fieldErrors} />
            ) : null;
          })()}

          {(catalogQuery.data?.provisionedSecrets.length ?? 0) > 0 && (
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Provisioned secrets</label>
              <div className="space-y-1">
                {catalogQuery.data!.provisionedSecrets.map((ps) => (
                  <label key={ps.ref} className="flex items-center gap-2 text-sm text-secondary">
                    <input type="checkbox" checked={secretRefs.includes(ps.ref)}
                      onChange={(e) => setSecretRefs((prev) => e.target.checked ? [...prev, ps.ref] : prev.filter((r) => r !== ps.ref))}
                      className="h-4 w-4 rounded border-border text-foreground focus:ring-slate-400" />
                    <span>{ps.label ?? ps.ref}</span>
                    <span className="font-mono text-xs text-faint">({ps.type})</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {(catalogQuery.data?.steps.length ?? 0) > 1 && (
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Runs after</label>
              <div className="space-y-1">
                {catalogQuery.data!.steps.filter((s) => s.id !== step.id).map((s) => (
                  <label key={s.id} className="flex items-center gap-2 text-sm text-secondary">
                    <input type="checkbox" checked={dependsOn.includes(s.stepIndex)}
                      onChange={(e) => setDependsOn((prev) => e.target.checked ? [...prev, s.stepIndex] : prev.filter((d) => d !== s.stepIndex))}
                      className="h-4 w-4 rounded border-border text-foreground focus:ring-slate-400" />
                    <span>Step #{s.stepIndex}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <label className="flex items-center gap-2 text-sm text-secondary">
            <input type="checkbox" checked={bestEffort} onChange={(e) => setBestEffort(e.target.checked)}
              className="h-4 w-4 rounded border-border text-foreground focus:ring-slate-400" />
            Best effort (failure does not abort the plan)
          </label>

          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">Cancel</button>
            <button
              onClick={() => {
                const entry = (actionsQuery.data ?? []).find((c) => c.id === actionId);
                if (entry?.inputSchema) {
                  const errors = validateSchema(entry.inputSchema, input);
                  if (Object.keys(errors).length > 0) { setFieldErrors(errors); return; }
                }
                saveMutation.mutate();
              }}
              disabled={saveMutation.isPending}
              className="rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50">
              {saveMutation.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Loads a plan's plugin action catalog, filtered to single-device actions (the only valid step targets). */
function useCatalogByPlanId(planId: string) {
  const [pluginId, setPluginId] = useState<string | null>(null);
  const planRefQuery = useQuery({
    queryKey: ['plan-plugin-id', planId],
    queryFn: async () => (await api.getPlan(planId)).pluginId,
    enabled: Boolean(planId),
  });
  useEffect(() => {
    if (planRefQuery.data) setPluginId(planRefQuery.data);
  }, [planRefQuery.data]);
  const actionsQuery = useQuery({
    queryKey: ['plugin-actions', pluginId ?? ''],
    queryFn: () => api.pluginActions(pluginId!),
    enabled: Boolean(pluginId),
  });
  return { data: (actionsQuery.data?.actions ?? []).filter((c) => c.deviceCount === 1) };
}

// --- Add step --------------------------------------------------------------------

function AddStepButton({ plan, onAdded }: { plan: PlanDetailType; onAdded: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button onClick={() => setOpen(true)} className="flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-secondary hover:bg-muted">
        <Plus className="h-3.5 w-3.5" /> Add step
      </button>
      {open && (
        <AddStepModal plan={plan} onDone={() => { setOpen(false); onAdded(); }} onClose={() => setOpen(false)} />
      )}
    </>
  );
}

function AddStepModal({ plan, onDone, onClose }: { plan: PlanDetailType; onDone: () => void; onClose: () => void }) {
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const [deviceId, setDeviceId] = useState('');
  const [actionId, setActionId] = useState('');
  const [input, setInput] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const actionsQuery = useCatalogByPlanId(plan.id);
  const eligibleDevices: Device[] = useMemo(
    () => (devicesQuery.data ?? []).filter((d) => d.plugins?.some((p) => p.pluginId === plan.pluginId)),
    [devicesQuery.data, plan.pluginId]
  );

  const addMutation = useMutation({
    mutationFn: () => api.addPlanStep(plan.id, { deviceId, actionId, input }),
    onSuccess: onDone,
    onError: (err) => setError(describeError(err)),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-primary/40 p-4" onClick={onClose}>
      <div className="max-h-[85vh] w-full max-w-lg overflow-auto rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h3 className="text-sm font-semibold text-foreground">Add step</h3>
          <button onClick={onClose} aria-label="Close" className="rounded p-1 text-faint hover:bg-muted"><X className="h-4 w-4" /></button>
        </div>
        <div className="space-y-4 px-4 py-3">
          {error && <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{error}</div>}

          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Device</label>
            <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)} className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm">
              <option value="" disabled>Select a device</option>
              {eligibleDevices.map((d) => (
                <option key={d.id} value={d.id}>{d.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Action</label>
            <select value={actionId} onChange={(e) => { setActionId(e.target.value); setInput({}); }} className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm">
              <option value="" disabled>Select an action</option>
              {(actionsQuery.data ?? []).map((c) => (
                <option key={c.id} value={c.id}>{c.label}</option>
              ))}
            </select>
          </div>

          {(() => {
            const entry = (actionsQuery.data ?? []).find((c) => c.id === actionId);
            return entry?.inputSchema ? (
              <SchemaForm schema={entry.inputSchema} values={input} onChange={(v) => { setInput(v); setFieldErrors({}); }} fieldErrors={fieldErrors} />
            ) : null;
          })()}

          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">Cancel</button>
            <button
              onClick={() => {
                const entry = (actionsQuery.data ?? []).find((c) => c.id === actionId);
                if (!deviceId || !actionId) return;
                if (entry?.inputSchema) {
                  const errors = validateSchema(entry.inputSchema, input);
                  if (Object.keys(errors).length > 0) { setFieldErrors(errors); return; }
                }
                addMutation.mutate();
              }}
              disabled={addMutation.isPending || !deviceId || !actionId}
              className="rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50">
              {addMutation.isPending ? 'Adding…' : 'Add Step'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function describeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return err instanceof ApiError && err.status === 401 ? `${msg} — sign in again to complete two-factor authentication.` : msg;
}
