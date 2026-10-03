import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, CheckCircle2, EyeOff } from 'lucide-react';
import clsx from 'clsx';
import { SchemaForm, validateSchema, defaultValues } from './SchemaForm';
import { DialogShell } from './DialogShell';
import { api, ApiError, CatalogEntry } from '../api/client';
import { runAction, savedPlanIdOf, useExecutionMode } from '../executionMode';

/**
 * ActionDialog — the bridge between the device Config page and the plan
 * workflow. Renders a catalog action's inputSchema (seeded with the state
 * document's prefill values) in the standard modal pattern; on submit it
 * creates a 1-step plan for this device AND executes it immediately, then
 * navigates to the plan detail (which polls while executing). Every change —
 * including "dangerous" ones — flows through POST /plans + execute, so the
 * existing 2FA gate (configs:apply) and audit trail apply uniformly.
 */

interface ActionDialogProps {
  deviceId: string;
  pluginId: string;
  entry: CatalogEntry;
  /** Pre-filled input values from the state document's action ref. */
  prefill?: Record<string, unknown>;
  onClose: () => void;
}

export function ActionDialog({ deviceId, pluginId, entry, prefill, onClose }: ActionDialogProps) {
  const navigate = useNavigate();
  const { mode } = useExecutionMode();
  const [values, setValues] = useState<Record<string, unknown>>(() => ({
    ...defaultValues(entry.inputSchema ?? {}),
    ...(prefill ?? {}),
  }));
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  // Set when the plan was created in Plan mode (not executed) — the dialog
  // switches to a saved-state panel instead of navigating.
  const [savedPlanId, setSavedPlanId] = useState<string | null>(null);

  const dangerous = entry.riskLevel === 'dangerous';
  const isPlanMode = mode === 'plan';
  // Read-Only: nothing can be executed or saved — the submit control is disabled.
  const isReadOnly = mode === 'readonly';
  // In Plan mode nothing runs — the danger icon/wording only apply to Execute.
  const submitLabel = pending ? (isPlanMode ? 'Saving…' : 'Executing…') : isPlanMode ? 'Save as plan' : 'Execute now';

  async function handleSubmit() {
    if (isReadOnly) return; // Read-Only — the button is disabled; this is a safety net.
    const errors = validateSchema(entry.inputSchema ?? {}, values);
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    // Dangerous actions get an explicit second confirmation in the browser.
    if (dangerous && !window.confirm(`"${entry.label}" is a DANGEROUS action and may disrupt this device. Continue?`)) {
      return;
    }
    setPending(true);
    setSubmitError(null);
    try {
      // 1-step plan for THIS device. In Execute mode it runs immediately — the
      // executor dispatches to the plugin's /config with fresh credentials +
      // settings; in Plan mode it is saved (draft/ready) and NOT executed.
      const create = () =>
        api.createPlan({
          pluginId,
          intentActionId: entry.id,
          inputs: values,
          devices: [{ deviceId }],
        });
      if (mode === 'plan') {
        const plan = await create();
        setSavedPlanId(plan.id);
        return;
      }
      const planId = await runAction(create, (id) => api.executePlan(id), mode);
      navigate(`/plans/${planId}`);
    } catch (err) {
      const savedId = savedPlanIdOf(err);
      if (err instanceof ApiError && err.status === 401) {
        setSubmitError('Two-factor authentication required — sign in again and retry.');
      } else {
        let msg = err instanceof Error ? err.message : String(err);
        if (savedId) msg += ` The plan was saved (${savedId}) and can be executed from the Plans center.`;
        setSubmitError(msg);
      }
      setPending(false);
    }
  }

  // Plan mode: the plan was created but not executed — offer to open it in
  // the Plans center (where it can be run later or scheduled).
  if (savedPlanId) {
    return (
      <DialogShell
        title={entry.label}
        onClose={onClose}
        footer={
          <div className="flex items-center justify-end gap-2">
            <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background">
              Close
            </button>
            <button type="button" onClick={() => navigate(`/plans/${savedPlanId}`)} className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
              Open in Plans
            </button>
          </div>
        }
      >
        <div className="space-y-3">
          <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Plan saved — it was NOT executed. Open the Plans center to run it later (or schedule it).
          </div>
          <p className="text-xs text-faint">Plan ID: {savedPlanId}</p>
        </div>
      </DialogShell>
    );
  }

  return (
    <DialogShell title={entry.label} subtitle={entry.description || undefined} onClose={onClose}>
      <div>
          {isReadOnly && (
            <div className="mb-3 flex items-start gap-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
              <EyeOff className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              Read-only mode is active — this action cannot be executed or saved. Switch to Plan or Execute in the top bar.
            </div>
          )}

          {dangerous && (
            <div className="mb-3 flex items-start gap-2 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              Dangerous action — this may disrupt traffic or services on the device. It runs as a plan step and is
              recorded in the audit trail.
            </div>
          )}

          {Object.keys(entry.inputSchema ?? {}).length > 0 ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSubmit();
              }}
              className="space-y-3"
            >
              <SchemaForm schema={entry.inputSchema ?? {}} values={values} onChange={setValues} fieldErrors={fieldErrors} />
              {submitError && (
                <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{submitError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={pending}
                  className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={pending || isReadOnly}
                  title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    dangerous && !isPlanMode ? 'bg-danger-solid hover:bg-danger-solid-hover' : 'bg-primary hover:bg-primary-hover'
                  )}
                >
                  {dangerous && !isPlanMode && !pending ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5" /> {submitLabel}
                    </>
                  ) : (
                    submitLabel
                  )}
                </button>
              </div>
            </form>
          ) : (
            // Actions without an input schema (e.g. system.reboot) — direct confirm.
            <div className="space-y-3">
              {submitError && (
                <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{submitError}</div>
              )}
              <p className="text-sm text-secondary">
                {isPlanMode
                  ? 'This action takes no input. It will be saved as a plan step without executing.'
                  : 'This action takes no input. It will run immediately as a plan step.'}
              </p>
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={pending}
                  className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={pending || isReadOnly}
                  title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    dangerous && !isPlanMode ? 'bg-danger-solid hover:bg-danger-solid-hover' : 'bg-primary hover:bg-primary-hover'
                  )}
                >
                  {dangerous && !isPlanMode && !pending ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5" /> {submitLabel}
                    </>
                  ) : (
                    submitLabel
                  )}
                </button>
              </div>
            </div>
          )}
      </div>
    </DialogShell>
  );
}
