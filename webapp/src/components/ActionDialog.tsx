import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, X } from 'lucide-react';
import clsx from 'clsx';
import { SchemaForm, validateSchema, defaultValues } from './SchemaForm';
import { api, ApiError, CatalogEntry } from '../api/client';

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
  const [values, setValues] = useState<Record<string, unknown>>(() => ({
    ...defaultValues(entry.inputSchema ?? {}),
    ...(prefill ?? {}),
  }));
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const dangerous = entry.riskLevel === 'dangerous';

  async function handleSubmit() {
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
      // 1-step plan for THIS device, then execute immediately — the executor
      // dispatches to the plugin's /config with fresh credentials + settings.
      const plan = await api.createPlan({
        pluginId,
        intentActionId: entry.id,
        inputs: values,
        devices: [{ deviceId }],
      });
      await api.executePlan(plan.id);
      navigate(`/plans/${plan.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setSubmitError('Two-factor authentication required — sign in again and retry.');
      } else {
        setSubmitError(err instanceof Error ? err.message : String(err));
      }
      setPending(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-6"
      onClick={onClose}
    >
      <div
        className="mt-10 w-full max-w-lg rounded-md border border-slate-200 bg-white shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-slate-900">{entry.label}</h2>
            {entry.description && <p className="mt-0.5 text-xs text-slate-500">{entry.description}</p>}
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="p-4">
          {dangerous && (
            <div className="mb-3 flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
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
                <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">{submitError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={pending}
                  className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={pending}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    dangerous ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-900 hover:bg-slate-700'
                  )}
                >
                  {pending ? (
                    <>Executing…</>
                  ) : dangerous ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5" /> Execute now
                    </>
                  ) : (
                    'Execute now'
                  )}
                </button>
              </div>
            </form>
          ) : (
            // Actions without an input schema (e.g. system.reboot) — direct confirm.
            <div className="space-y-3">
              {submitError && (
                <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">{submitError}</div>
              )}
              <p className="text-sm text-slate-600">This action takes no input. It will run immediately as a plan step.</p>
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={pending}
                  className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={pending}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    dangerous ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-900 hover:bg-slate-700'
                  )}
                >
                  {pending ? (
                    <>Executing…</>
                  ) : dangerous ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5" /> Execute now
                    </>
                  ) : (
                    'Execute now'
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
