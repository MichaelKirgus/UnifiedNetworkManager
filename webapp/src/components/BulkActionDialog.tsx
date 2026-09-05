import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, X } from 'lucide-react';
import clsx from 'clsx';
import { SchemaForm, validateSchema, defaultValues } from './SchemaForm';
import { api, ApiError, CatalogEntry, InputSchema, StateItem } from '../api/client';

/**
 * BulkActionDialog — applies ONE catalog action to MANY ports of the same
 * device (selected on a VirtualSwitch). The dialog shows only the fields that
 * are IDENTICAL across all selected items' prefills; per-item values (e.g. the
 * port number) stay hidden and are merged back in at submit time. On submit it
 * creates a plan for the first item, appends one step per remaining item
 * (each validated server-side against the action's inputSchema), then executes
 * — so 2FA + configs:apply + audit trail apply exactly like single actions.
 */

interface BulkActionDialogProps {
  deviceId: string;
  pluginId: string;
  entry: CatalogEntry;
  /** The selected items, in panel order. Each carries the action's prefill for that port. */
  items: StateItem[];
  onClose: () => void;
}

/** Splits schema fields into hidden (per-item, differ across prefills), shared
 *  (identical prefill — shown editable, seeded) and the rest (user-filled). */
function splitFields(
  schema: InputSchema,
  prefills: Record<string, unknown>[]
): { hiddenKeys: Set<string>; sharedValues: Record<string, unknown> } {
  const hidden = new Set<string>();
  const shared: Record<string, unknown> = {};
  for (const k of Object.keys(schema)) {
    const first = prefills[0]?.[k];
    if (first === undefined) continue; // not prefilled anywhere → user fills it in the form
    const sameForAll = prefills.every((p) => JSON.stringify(p[k]) === JSON.stringify(first));
    if (sameForAll) shared[k] = first;
    else hidden.add(k);
  }
  return { hiddenKeys: hidden, sharedValues: shared };
}

export function BulkActionDialog({ deviceId, pluginId, entry, items, onClose }: BulkActionDialogProps) {
  const navigate = useNavigate();
  const schema: InputSchema = entry.inputSchema ?? {};

  // Per-item prefills for THIS action (the state document carries one ref per item).
  const prefills = useMemo(
    () => items.map((i) => i.actions?.find((a) => a.actionId === entry.id)?.prefill ?? {}),
    [items, entry.id]
  );

  // Hidden fields (per-item values like the port number) are merged back in at
  // submit; only shared + user-filled fields render in the form.
  const { hiddenKeys, sharedValues } = useMemo(() => splitFields(schema, prefills), [schema, prefills]);

  // The schema actually rendered — per-item fields stay out of the form (they
  // would be ignored at submit and confuse the user).
  const visibleSchema = useMemo(
    () => Object.fromEntries(Object.entries(schema).filter(([k]) => !hiddenKeys.has(k))),
    [schema, hiddenKeys]
  );

  // Form values: schema defaults + the shared prefill values.
  const initialValues = useMemo(() => {
    const v = defaultValues(visibleSchema);
    return { ...v, ...sharedValues };
  }, [visibleSchema, sharedValues]);

  const [values, setValues] = useState<Record<string, unknown>>(initialValues);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const dangerous = entry.riskLevel === 'dangerous';
  const count = items.length;

  async function handleSubmit() {
    // Validate the merged input against the full schema (per-item fields are
    // already valid — they came from the plugin's own prefills).
    const errors = validateSchema(schema, { ...prefills[0], ...values });
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    if (dangerous && !window.confirm(`"${entry.label}" is a DANGEROUS action and will be applied to ${count} ports. Continue?`)) {
      return;
    }
    setPending(true);
    setSubmitError(null);
    try {
      // Step 1: create the plan with the first item's full input (the plugin's
      // /plan endpoint validates it and may prepend a best-effort backup step).
      const firstInput = { ...prefills[0], ...values };
      const plan = await api.createPlan({
        pluginId,
        intentActionId: entry.id,
        inputs: firstInput,
        devices: [{ deviceId }],
      });
      // Steps 2..n: append one step per remaining item (server-side validated).
      for (let i = 1; i < count; i++) {
        await api.addPlanStep(plan.id, {
          deviceId,
          actionId: entry.id,
          input: { ...prefills[i], ...values },
        });
      }
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
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-10 w-full max-w-lg rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">{entry.label}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Applied to {count} port{count === 1 ? '' : 's'} — one plan step per port, executed in order.
            </p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="p-4">
          {dangerous && (
            <div className="mb-3 flex items-start gap-2 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              Dangerous action — this may disrupt traffic on the selected ports. It runs as plan steps and is recorded in
              the audit trail.
            </div>
          )}

          {Object.keys(visibleSchema).length > 0 ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSubmit();
              }}
              className="space-y-3"
            >
              <SchemaForm schema={visibleSchema} values={values} onChange={setValues} fieldErrors={fieldErrors} />
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
                  disabled={pending}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    dangerous ? 'bg-red-600 hover:bg-red-700' : 'bg-primary hover:bg-primary-hover'
                  )}
                >
                  {pending ? (
                    <>Executing…</>
                  ) : dangerous ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5" /> Execute on {count} ports
                    </>
                  ) : (
                    `Execute on ${count} port${count === 1 ? '' : 's'}`
                  )}
                </button>
              </div>
            </form>
          ) : (
            // No shared fields — the action is fully determined by the per-port prefills.
            <div className="space-y-3">
              {submitError && (
                <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{submitError}</div>
              )}
              <p className="text-sm text-secondary">
                This action takes no shared input — it will run on all {count} selected ports as plan steps.
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
                  disabled={pending}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    dangerous ? 'bg-red-600 hover:bg-red-700' : 'bg-primary hover:bg-primary-hover'
                  )}
                >
                  {pending ? (
                    <>Executing…</>
                  ) : dangerous ? (
                    <>
                      <AlertTriangle className="h-3.5 w-3.5" /> Execute on {count} ports
                    </>
                  ) : (
                    `Execute on ${count} port${count === 1 ? '' : 's'}`
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
