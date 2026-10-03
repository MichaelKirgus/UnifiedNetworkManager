import React, { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import clsx from 'clsx';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  ClipboardList,
  HelpCircle,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Square,
  Trash2,
  X,
} from 'lucide-react';
import { DialogShell } from '../components/DialogShell';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { SchemaForm, validateSchema, defaultValues } from '../components/SchemaForm';
import { ReauthDialog } from '../components/ReauthDialog';
import { ScheduleDialog } from '../components/ScheduleDialog';
import { api, ApiError, CatalogEntry, Device, PlanDetail as PlanDetailType, PlanStep } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/** Statuses from which a plan can be (re-)scheduled — saved, already scheduled, or finished. */
const SCHEDULABLE_STATUSES = ['draft', 'ready', 'scheduled', 'succeeded', 'unverified', 'failed', 'cancelled', 'skipped'];

export default function PlanDetail() {
  const { formatDateTime, zone } = useTimeFormat();
  /** '—' when absent — the central formatter already renders null/invalid as '—'. */
  const fmtTime = (iso?: string | null) => formatDateTime(iso);
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

  // Retry duplicates the plan (same payload + provisioned secrets) and executes
  // the copy — 2FA-gated server-side, so a 401 opens in-session revalidation.
  const [reauth, setReauth] = useState<{ label: string; retry: () => Promise<void> } | null>(null);
  const [retryError, setRetryError] = useState<string | null>(null);
  // Schedule dialog (relative/absolute due time + down-policy).
  const [showSchedule, setShowSchedule] = useState(false);
  async function handleRetry() {
    setRetryError(null);
    const attempt = async () => {
      const fresh = await api.retryPlan(id);
      window.location.href = `/plans/${fresh.id}`;
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Retry ${plan?.intentActionId ?? 'plan'}`, retry: attempt });
      else setRetryError(describeError(err));
    }
  }

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
  const unscheduleMutation = useMutation({
    mutationFn: () => api.unschedulePlan(id),
    onSuccess: () => planQuery.refetch(),
  });

  // Per-plan retry policy — the global defaults (Settings → Execution) are the
  // baseline; this card overrides them for THIS plan only. Only transient
  // failures (plugin reports retryable, or dispatch timeout/unreachable) retry.
  const settingsQuery = useQuery({ queryKey: ['settings'], queryFn: api.listSettings });
  const globalRetryMax = Number(settingsQuery.data?.settings.find((s) => s.key === 'planStepRetryMaxAttempts')?.value ?? 2);
  const globalRetryWaitMs = Number(settingsQuery.data?.settings.find((s) => s.key === 'planStepRetryWaitMs')?.value ?? 15_000);
  const [retryMax, setRetryMax] = useState<string | null>(null); // null = inherit
  const [retryWaitS, setRetryWaitS] = useState<string | null>(null); // seconds; null = inherit
  useEffect(() => {
    if (!plan) return;
    setRetryMax(plan.retryPolicy?.maxAttempts !== undefined ? String(plan.retryPolicy.maxAttempts) : null);
    setRetryWaitS(plan.retryPolicy?.waitMs !== undefined ? String(Math.round(plan.retryPolicy.waitMs / 1000)) : null);
  }, [plan?.id, plan?.retryPolicy]);
  const retryMutation = useMutation({
    mutationFn: () => {
      const policy: Record<string, number> = {};
      if (retryMax !== null && retryMax.trim() !== '') policy.maxAttempts = Number(retryMax);
      if (retryWaitS !== null && retryWaitS.trim() !== '') policy.waitMs = Math.round(Number(retryWaitS) * 1000);
      return api.updatePlan(id, { retryPolicy: Object.keys(policy).length > 0 ? policy : null });
    },
    onSuccess: () => planQuery.refetch(),
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
            <button type="button" onClick={() => executeMutation.mutate()} disabled={executeMutation.isPending || steps.length === 0}
              className="inline-flex items-center gap-2 rounded-md bg-success-solid px-3 py-1.5 text-sm font-medium text-white hover:bg-success-solid-hover disabled:opacity-50">
              <Play className="h-4 w-4" /> Execute
            </button>
          )}
          {canApply && plan.status !== 'executing' && SCHEDULABLE_STATUSES.includes(plan.status) && (
            <button onClick={() => setShowSchedule(true)}
              title={plan.status === 'scheduled' ? 'Change the schedule for this plan' : 'Schedule this plan to run later (relative or absolute time)'}
              className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
              <CalendarClock className="h-4 w-4" /> {plan.status === 'scheduled' ? 'Reschedule' : 'Schedule'}
            </button>
          )}
          {canApply && plan.status === 'scheduled' && (
            <button onClick={() => unscheduleMutation.mutate()} disabled={unscheduleMutation.isPending}
              title="Remove the schedule — the plan returns to its previous state"
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50">
              <X className="h-4 w-4" /> Unschedule
            </button>
          )}
          {canApply && plan.status !== 'executing' && (
            <button onClick={handleRetry} title="Duplicates this plan (same payload + secrets) and executes the copy"
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
              <RotateCcw className="h-4 w-4" /> Retry
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

      {(executeMutation.error || cancelMutation.error || unscheduleMutation.error) && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
          {describeError(executeMutation.error ?? cancelMutation.error ?? unscheduleMutation.error)}
        </div>
      )}
      {retryError && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{retryError}</div>
      )}

      {/* Saved via the top-bar Plan mode (or created without executing) — never
          run yet. The Execute button in the header runs it; Schedule defers it. */}
      {editable && !plan.startedAt && plan.status !== 'scheduled' && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-info-border bg-info px-3 py-2 text-sm text-info-fg">
          <ClipboardList className="mt-0.5 h-4 w-4 shrink-0" />
          This plan is saved but has NOT been executed yet. Use “Execute” to run it now — or use “Schedule” to run it later
          (relative or absolute time).
        </div>
      )}
      {/* Scheduled — show the due time + what happens if UNM/plugin is down then. */}
      {plan.status === 'scheduled' && plan.scheduledAt && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-primary/40 bg-primary/10 px-3 py-2 text-sm">
          <CalendarClock className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
          <span>
            Scheduled to run at <strong>{fmtTime(plan.scheduledAt)}</strong> ({zone}).
            {plan.schedulePolicy === 'skip'
              ? ' If UNM or the plugin is down when it is due, the plan will be marked “skipped”.'
              : ' If UNM or the plugin is down when it is due, it will retry as soon as possible (with backoff).'}
          </span>
        </div>
      )}
      {/* Skipped — a due schedule was skipped per policy. */}
      {plan.status === 'skipped' && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-sm text-warning-fg">
          <X className="mt-0.5 h-4 w-4 shrink-0" />
          This plan was skipped{plan.error ? `: ${plan.error}` : '.'} You can re-schedule it or retry it.
        </div>
      )}
      {/* Unverified — applied without error, but the device state could not be confirmed. */}
      {plan.status === 'unverified' && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-sm text-warning-fg">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            This plan was applied without errors, but UNM could not verify the resulting device state (see the per-step “unverified” chips below).{' '}
            Check the affected devices manually — or retry to re-apply and re-check.
          </span>
        </div>
      )}

      {/* Retry policy — per-plan override of the global defaults (Settings → Execution). */}
      <section className="mb-5 rounded-md border border-border bg-card p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">Retry policy</h2>
          {canApply && editable && (
            retryMutation.isPending ? (
              <span className="text-xs text-faint">Saving…</span>
            ) : (
              <button
                onClick={() => retryMutation.mutate()}
                disabled={retryMax === null && retryWaitS === null}
                title={retryMax === null && retryWaitS === null ? 'Nothing to change — the plan uses the global defaults' : 'Save this plan’s retry policy'}
                className="rounded-md bg-primary px-3 py-1 text-xs font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
              >
                Save
              </button>
            )
          )}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Failed steps are re-dispatched only when the failure is TRANSIENT — the plugin reports it as retryable (appliance not ready, service still
          starting, …) or the dispatch itself timed out / could not reach the plugin. Hard failures fail this plan immediately.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="mb-1 block font-medium text-secondary">Max attempts per step</span>
            <input
              type="number" min={0} max={10}
              value={retryMax ?? ''}
              disabled={!canApply || !editable}
              onChange={(e) => setRetryMax(e.target.value)}
              placeholder={`inherit (${globalRetryMax})`}
              className="w-full rounded-md border border-border px-3 py-2 text-sm disabled:opacity-50"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium text-secondary">Wait between attempts (seconds)</span>
            <input
              type="number" min={1} max={3600}
              value={retryWaitS ?? ''}
              disabled={!canApply || !editable}
              onChange={(e) => setRetryWaitS(e.target.value)}
              placeholder={`inherit (${Math.round(globalRetryWaitMs / 1000)})`}
              className="w-full rounded-md border border-border px-3 py-2 text-sm disabled:opacity-50"
            />
          </label>
        </div>
        <p className="mt-2 text-xs text-faint">
          Leave a field empty to inherit the global default. A plugin can suggest a longer wait per failure (e.g. minutes for an update to settle) —
          that hint wins over this value for that attempt.
        </p>
      </section>

      {/* Who + when — attribution and execution timing for the current run. */}
      <section className="mb-5 grid grid-cols-2 gap-x-6 gap-y-3 rounded-md border border-border bg-card p-4 text-sm shadow-sm sm:grid-cols-3 lg:grid-cols-6">
        <Meta label="Created by" value={plan.createdByName ?? plan.createdBy} />
        <Meta label="Executed by" value={plan.executedByName ?? '—'} muted={!plan.executedByName} />
        <Meta label="Created" value={fmtTime(plan.createdAt)} />
        <Meta
          label="Started"
          value={plan.startedAt ? fmtTime(plan.startedAt) : ['draft', 'ready'].includes(plan.status) ? 'queued' : '—'}
          muted={!plan.startedAt}
        />
        <Meta label="Finished" value={fmtTime(plan.finishedAt)} muted={!plan.finishedAt} />
        {plan.status === 'scheduled' && plan.scheduledAt ? (
          <Meta
            label="Scheduled"
            value={
              <span className="flex items-center gap-1">
                <CalendarClock className="h-3.5 w-3.5 text-primary" />
                {fmtTime(plan.scheduledAt)}
              </span>
            }
          />
        ) : null}
        {plan.retriedFrom && (
          <Meta
            label="Retried from"
            value={
              <Link to={`/plans/${plan.retriedFrom}`} className="text-primary hover:underline">
                view original
              </Link>
            }
          />
        )}
      </section>

      {/* Payload — the raw intent inputs behind every execution of this plan. */}
      <section className="mb-5 rounded-md border border-border bg-card p-4 shadow-sm">
        <h2 className="mb-2 text-sm font-semibold text-foreground">Payload — intent inputs</h2>
        <pre className="max-h-64 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-code-fg">
          {Object.keys(plan.intentInputs ?? {}).length > 0 ? JSON.stringify(plan.intentInputs, null, 2) : '{}'}
        </pre>
      </section>

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

      {/* Generic error bar — skipped/unverified have their own banners that already show the message. */}
      {plan.error && plan.status !== 'skipped' && plan.status !== 'unverified' && (
        <div className="mt-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{plan.error}</div>
      )}

      {showSchedule && (
        <ScheduleDialog
          plan={plan}
          onClose={() => setShowSchedule(false)}
          onSaved={() => void planQuery.refetch()}
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

// --- Small helpers -------------------------------------------------------------

/** One label/value cell of the plan metadata grid. */
function Meta({ label, value, muted }: { label: string; value: React.ReactNode; muted?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-faint">{label}</p>
      <p className={muted ? 'truncate text-secondary' : 'truncate text-foreground'} title={typeof value === 'string' ? value : undefined}>
        {value}
      </p>
    </div>
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
        {/* Verification chip — the plugin re-read device state post-apply and
            reports it via ActionResult.verified; a succeeded write step without
            that flag was acknowledged but not confirmed. */}
        {step.status === 'succeeded' && !step.bestEffort && (
          (step.result?.['result'] as Record<string, unknown> | undefined)?.['verified'] === true ? (
            <span className="inline-flex items-center gap-1 rounded bg-success/15 px-1.5 py-0.5 text-[10px] font-medium text-success-fg" title="The plugin re-read the device state and confirmed the change.">
              <CheckCircle2 className="h-3 w-3" /> verified
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded bg-warning/15 px-1.5 py-0.5 text-[10px] font-medium text-warning-fg" title="The device acknowledged the change, but UNM could not confirm the resulting state.">
              <HelpCircle className="h-3 w-3" /> unverified
            </span>
          )
        )}
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
              <pre className="mt-1 max-h-64 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-code-fg">
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
    <DialogShell
      title={`Edit step #${step.stepIndex}`}
      onClose={onClose}
      maxWidth="max-w-lg"
      bodyMaxHeight="85vh"
      footer={
        <div className="flex justify-end gap-2">
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
      }
    >
        <div className="space-y-4">
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
                      className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring" />
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
                      className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring" />
                    <span>Step #{s.stepIndex}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <label className="flex items-center gap-2 text-sm text-secondary">
            <input type="checkbox" checked={bestEffort} onChange={(e) => setBestEffort(e.target.checked)}
              className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring" />
            Best effort (failure does not abort the plan)
          </label>
        </div>
    </DialogShell>
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
    <DialogShell
      title="Add step"
      onClose={onClose}
      maxWidth="max-w-lg"
      bodyMaxHeight="85vh"
      footer={
        <div className="flex justify-end gap-2">
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
      }
    >
        <div className="space-y-4">
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
        </div>
    </DialogShell>
  );
}

function describeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return err instanceof ApiError && err.status === 401 ? `${msg} — sign in again to complete two-factor authentication.` : msg;
}
