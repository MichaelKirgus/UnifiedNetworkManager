import { FormEvent, forwardRef, useEffect, useMemo, useImperativeHandle, useState } from 'react';
import clsx from 'clsx';
import { RotateCcw, Save } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, PluginOptionDescriptor, StringOption, IntegerOption } from '../api/client';

/** Imperative handle so a parent with ONE central Save button can trigger this
 * form's validating save (or reset) programmatically. */
export interface OptionFormHandle {
  /** Validates + persists the current values; resolves true on success. */
  save: () => Promise<boolean>;
  /** Resets to inherited/global defaults (no confirm — parent owns UX). */
  reset: () => Promise<void>;
}

interface OptionFormProps {
  pluginId: string;
  /**
   * When set, the form edits THIS DEVICE's overrides for the plugin (which
   * inherit from the global settings). Omit to edit the global settings.
   */
  deviceId?: string;
  /** Called after a successful save/reset so the parent can refresh if needed. */
  onSaved?: () => void;
  /**
   * When true, renders as a plain div (no <form> wrapper) with no footer
   * buttons — safe to nest inside another form. The parent is responsible
   * for submission; this component only manages field state + validation.
   */
  compact?: boolean;
  /**
   * Hides the Save/Reset footer even in (non-compact) mode, so a parent can
   * own a single central submit button for several nested forms at once.
   * Implies `compact` rendering semantics (no <form> wrapper).
   */
  hideFooter?: boolean;
  /** Reports whether the form's values differ from the loaded effective values. */
  onDirtyChange?: (dirty: boolean) => void;
}

/** Mirrors the API's validateOptionValue for instant client-side feedback. */
function validateLocal(descriptor: PluginOptionDescriptor, value: unknown): string | null {
  switch (descriptor.type) {
    case 'string': {
      if (typeof value !== 'string') return 'Required';
      const s = descriptor as StringOption;
      if (Array.isArray(s.enumOptions) && s.enumOptions.length > 0 && !s.enumOptions.includes(value)) {
        return `Must be one of: ${s.enumOptions.join(', ')}`;
      }
      if (s.minLength !== undefined && value.length < s.minLength) return `At least ${s.minLength} characters`;
      if (s.maxLength !== undefined && value.length > s.maxLength) return `At most ${s.maxLength} characters`;
      if (s.pattern) {
        try {
          if (!new RegExp(s.pattern).test(value)) return 'Does not match the required pattern';
        } catch {
          /* ignore malformed regex */
        }
      }
      return null;
    }
    case 'integer': {
      // null/undefined = "unset" (falls back to default) — allowed.
      if (value === null || value === undefined) return null;
      if (typeof value !== 'number' || !Number.isInteger(value)) return 'Must be a whole number';
      const s = descriptor as IntegerOption;
      if (s.min !== undefined && value < s.min) return `Must be >= ${s.min}`;
      if (s.max !== undefined && value > s.max) return `Must be <= ${s.max}`;
      return null;
    }
    case 'boolean': {
      if (typeof value !== 'boolean') return 'Required';
      return null;
    }
    default:
      return null;
  }
}

/** Renders the input for one option descriptor — shared by the bare (div) and
 * form layouts. String options with a closed `enumOptions` list render as a
 * combobox (select); everything else keeps its plain input. */
function OptionControl({ opt, value, error, onChange }: {
  opt: PluginOptionDescriptor;
  value: unknown;
  error?: string;
  onChange: (value: unknown) => void;
}) {
  const id = `opt-${opt.key}`;
  if (opt.type === 'boolean') {
    return (
      <div className="flex items-center gap-2">
        <input id={id} type="checkbox" checked={value === true}
          onChange={(e) => onChange(e.target.checked)}
          className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring" />
        <span className="text-sm text-muted-foreground">{value === true ? 'Enabled' : 'Disabled'}</span>
      </div>
    );
  }
  if (opt.type === 'integer') {
    return (
      <input id={id} type="number" step={1} inputMode="numeric"
        value={value === null || value === undefined ? '' : String(value)}
        placeholder={opt.default !== undefined ? `default: ${String(opt.default)}` : 'optional'}
        onChange={(e) => { const raw = e.target.value; onChange(raw === '' ? null : Number(raw)); }}
        className={clsx('w-full rounded-md border px-3 py-2 text-sm', error ? 'border-danger-border' : 'border-border')} />
    );
  }
  // String option: combobox when the descriptor declares a closed value set.
  const s = opt as StringOption;
  if (Array.isArray(s.enumOptions) && s.enumOptions.length > 0) {
    return (
      <select id={id} value={(value as string | undefined) ?? ''}
        onChange={(e) => onChange(e.target.value)}
        className={clsx('w-full rounded-md border px-3 py-2 text-sm', error ? 'border-danger-border' : 'border-border')}>
        {s.enumOptions.map((v) => (
          <option key={v} value={v}>{v}</option>
        ))}
      </select>
    );
  }
  return (
    <input id={id} type="text"
      value={(value as string | undefined) ?? ''}
      placeholder={opt.default !== undefined ? `default: ${String(opt.default)}` : 'optional'}
      onChange={(e) => onChange(e.target.value)}
      className={clsx('w-full rounded-md border px-3 py-2 text-sm', error ? 'border-danger-border' : 'border-border')} />
  );
}

export const OptionForm = forwardRef<OptionFormHandle, OptionFormProps>(function OptionForm(
  { pluginId, deviceId, onSaved, compact = false, hideFooter = false, onDirtyChange },
  ref
) {
  const scoped = Boolean(deviceId);
  // `hideFooter` reuses the compact (div-based) rendering so it can be nested
  // inside a parent form — only the footer buttons are additionally hidden.
  const bare = compact || hideFooter;
  const optionsQuery = useQuery({
    queryKey: scoped ? ['devicePluginOptions', deviceId, pluginId] : ['pluginOptions', pluginId],
    queryFn: () => (scoped ? api.devicePluginOptions(deviceId!, pluginId) : api.pluginOptions(pluginId)),
  });

  const [values, setValues] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  // Initialize the form from effective values once loaded.
  useEffect(() => {
    if (optionsQuery.data) {
      setValues(optionsQuery.data.effectiveValues ?? {});
      setFieldErrors({});
    }
  }, [optionsQuery.data]);

  // Dirty tracking: compare current field values against the loaded effective
  // values so a parent can badge collapsed sections that hold unsaved edits.
  const dirty = useMemo(() => {
    if (!optionsQuery.data) return false;
    const base = optionsQuery.data.effectiveValues ?? {};
    for (const opt of optionsQuery.data.options ?? []) {
      if (JSON.stringify(values[opt.key] ?? null) !== JSON.stringify(base[opt.key] ?? null)) return true;
    }
    return false;
  }, [values, optionsQuery.data]);
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  const options = useMemo(() => optionsQuery.data?.options ?? [], [optionsQuery.data]);

  function setValue(key: string, value: unknown) {
    setValues((v) => ({ ...v, [key]: value }));
    // Clear any prior error for this field as the user corrects it.
    setFieldErrors((e) => {
      if (!(key in e)) return e;
      const next = { ...e };
      delete next[key];
      return next;
    });
  }

  function validateAll(): Record<string, string> {
    const errors: Record<string, string> = {};
    for (const opt of options) {
      const problem = validateLocal(opt, values[opt.key]);
      if (problem) errors[opt.key] = problem;
    }
    return errors;
  }

  /** Build the payload: omit unset integers so they fall back to defaults. */
  function buildPayload(): Record<string, unknown> {
    const payload: Record<string, unknown> = {};
    for (const opt of options) {
      const v = values[opt.key];
      if (opt.type === 'integer' && (v === null || v === undefined)) continue;
      payload[opt.key] = v;
    }
    return payload;
  }

  /** Validates + persists current values. Returns true on success, false when
   * validation failed (field errors are surfaced in place). */
  async function saveCore(): Promise<boolean> {
    const errors = validateAll();
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return false;
    }
    setSaving(true);
    try {
      if (scoped) {
        await api.saveDevicePluginSettings(deviceId!, pluginId, buildPayload());
      } else {
        await api.savePluginSettings(pluginId, buildPayload());
      }
      setSavedAt(Date.now());
      onSaved?.();
      return true;
    } catch (err) {
      if (err instanceof ApiError && err.fieldErrors) {
        setFieldErrors(err.fieldErrors);
      } else {
        // Surface a generic failure without clobbering per-field state.
        setFieldErrors({ __form__: (err as Error).message });
      }
      return false;
    } finally {
      setSaving(false);
    }
  }

  /** Resets to inherited/global defaults and reloads the effective values. */
  async function resetCore(): Promise<void> {
    setSaving(true);
    try {
      const view = scoped
        ? await api.resetDevicePluginSettings(deviceId!, pluginId)
        : await api.resetPluginSettings(pluginId);
      setValues(view.effectiveValues ?? {});
      setFieldErrors({});
      setSavedAt(Date.now());
      onSaved?.();
    } catch (err) {
      setFieldErrors({ __form__: (err as Error).message });
    } finally {
      setSaving(false);
    }
  }

  // Expose save/reset so a parent's single central Save button can drive this
  // form without its own footer buttons. No dep array on purpose — the handle
  // must always wrap the FRESH closures (values/options change every render).
  useImperativeHandle(ref, () => ({ save: saveCore, reset: resetCore }));

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    await saveCore();
  }

  async function handleReset() {
    const message = scoped
      ? 'Reset this device\'s overrides? The options will fall back to the global settings (or their defaults).'
      : 'Reset all settings for this plugin to their defaults?';
    if (!window.confirm(message)) return;
    await resetCore();
  }

  if (optionsQuery.isLoading) {
    return <p className="px-1 py-2 text-sm text-muted-foreground">Loading options…</p>;
  }
  if (optionsQuery.isError) {
    return <p className="px-1 py-2 text-sm text-danger-fg">Failed to load options: {(optionsQuery.error as Error).message}</p>;
  }

  const formError = fieldErrors.__form__;

  // Compact / footer-less mode: render as a div (no form wrapper, no footer)
  // so it can be safely nested inside another form. Parent handles submission.
  if (bare) {
    return (
      <div>
        {options.length === 0 ? (
          <p className="px-1 py-2 text-sm text-muted-foreground">This plugin does not declare any configurable options.</p>
        ) : (
          <div className="space-y-4 px-1 py-2">
            {options.map((opt) => {
              const error = fieldErrors[opt.key];
              return (
                <div key={opt.key}>
                  <label className="mb-1 flex items-center gap-2 text-sm font-medium text-secondary" htmlFor={`opt-${opt.key}`}>
                    {opt.label}
                    {opt.docsUrl && (
                      <a href={opt.docsUrl} target="_blank" rel="noreferrer noopener"
                        className="text-xs font-normal text-faint hover:text-secondary hover:underline">More info ↗</a>
                    )}
                  </label>
                  <OptionControl opt={opt} value={values[opt.key]} error={error} onChange={(v) => setValue(opt.key, v)} />
                  {opt.description && <p className="mt-1 text-xs text-muted-foreground">{opt.description}</p>}
                  {error && <p className="mt-1 text-xs text-danger-fg">{error}</p>}
                </div>
              );
            })}
          </div>
        )}
        {formError && (
          <div className="mx-1 mt-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
        )}
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      {options.length === 0 ? (
        <p className="px-1 py-2 text-sm text-muted-foreground">This plugin does not declare any configurable options.</p>
      ) : (
        <div className="space-y-4 px-1 py-2">
          {options.map((opt) => {
            const error = fieldErrors[opt.key];
            return (
              <div key={opt.key}>
                <label className="mb-1 flex items-center gap-2 text-sm font-medium text-secondary" htmlFor={`opt-${opt.key}`}>
                  {opt.label}
                  {opt.docsUrl && (
                    <a
                      href={opt.docsUrl}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-xs font-normal text-faint hover:text-secondary hover:underline"
                    >
                      More info ↗
                    </a>
                  )}
                </label>

                <OptionControl opt={opt} value={values[opt.key]} error={error} onChange={(v) => setValue(opt.key, v)} />

                {opt.description && <p className="mt-1 text-xs text-muted-foreground">{opt.description}</p>}
                {error && <p className="mt-1 text-xs text-danger-fg">{error}</p>}
              </div>
            );
          })}
        </div>
      )}

      {formError && (
        <div className="mx-1 mt-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
      )}
      {savedAt && !formError && options.length > 0 && (
        <p className="mx-1 mt-3 text-xs font-medium text-success-fg">Saved.</p>
      )}

      {options.length > 0 && (
        <div className="mt-4 flex items-center justify-end gap-2 border-t border-border px-1 pt-3">
          <button
            type="button"
            onClick={handleReset}
            disabled={saving}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-50"
          >
            <RotateCcw className="h-4 w-4" />
            {scoped ? 'Reset to inherited' : 'Reset to defaults'}
          </button>
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            <Save className="h-4 w-4" />
            {saving ? 'Saving…' : 'Save settings'}
          </button>
        </div>
      )}
    </form>
  );
});
