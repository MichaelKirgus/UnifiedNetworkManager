import { FormEvent, useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import { RotateCcw, Save } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, PluginOptionDescriptor, StringOption, IntegerOption } from '../api/client';

interface OptionFormProps {
  pluginId: string;
  /** Called after a successful save/reset so the parent can refresh if needed. */
  onSaved?: () => void;
}

/** Mirrors the API's validateOptionValue for instant client-side feedback. */
function validateLocal(descriptor: PluginOptionDescriptor, value: unknown): string | null {
  switch (descriptor.type) {
    case 'string': {
      if (typeof value !== 'string') return 'Required';
      const s = descriptor as StringOption;
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

export function OptionForm({ pluginId, onSaved }: OptionFormProps) {
  const optionsQuery = useQuery({ queryKey: ['plugin-options', pluginId], queryFn: () => api.pluginOptions(pluginId) });

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

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const errors = validateAll();
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    setSaving(true);
    try {
      await api.savePluginSettings(pluginId, buildPayload());
      setSavedAt(Date.now());
      onSaved?.();
    } catch (err) {
      if (err instanceof ApiError && err.fieldErrors) {
        setFieldErrors(err.fieldErrors);
      } else {
        // Surface a generic failure without clobbering per-field state.
        setFieldErrors({ __form__: (err as Error).message });
      }
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    if (!window.confirm('Reset all settings for this plugin to their defaults?')) return;
    setSaving(true);
    try {
      const view = await api.resetPluginSettings(pluginId);
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

  if (optionsQuery.isLoading) {
    return <p className="px-1 py-2 text-sm text-slate-500">Loading options…</p>;
  }
  if (optionsQuery.isError) {
    return <p className="px-1 py-2 text-sm text-red-600">Failed to load options: {(optionsQuery.error as Error).message}</p>;
  }

  const formError = fieldErrors.__form__;

  return (
    <form onSubmit={handleSubmit} noValidate>
      {options.length === 0 ? (
        <p className="px-1 py-2 text-sm text-slate-500">This plugin does not declare any configurable options.</p>
      ) : (
        <div className="space-y-4 px-1 py-2">
          {options.map((opt) => {
            const error = fieldErrors[opt.key];
            return (
              <div key={opt.key}>
                <label className="mb-1 flex items-center gap-2 text-sm font-medium text-slate-700" htmlFor={`opt-${opt.key}`}>
                  {opt.label}
                  {opt.docsUrl && (
                    <a
                      href={opt.docsUrl}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-xs font-normal text-slate-400 hover:text-slate-600 hover:underline"
                    >
                      More info ↗
                    </a>
                  )}
                </label>

                {opt.type === 'boolean' ? (
                  <div className="flex items-center gap-2">
                    <input
                      id={`opt-${opt.key}`}
                      type="checkbox"
                      checked={values[opt.key] === true}
                      onChange={(e) => setValue(opt.key, e.target.checked)}
                      className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
                    />
                    <span className="text-sm text-slate-500">{values[opt.key] === true ? 'Enabled' : 'Disabled'}</span>
                  </div>
                ) : opt.type === 'integer' ? (
                  <input
                    id={`opt-${opt.key}`}
                    type="number"
                    step={1}
                    inputMode="numeric"
                    value={values[opt.key] === null || values[opt.key] === undefined ? '' : String(values[opt.key])}
                    placeholder={opt.default !== undefined ? `default: ${String(opt.default)}` : 'optional'}
                    onChange={(e) => {
                      const raw = e.target.value;
                      setValue(opt.key, raw === '' ? null : Number(raw));
                    }}
                    className={clsx(
                      'w-full rounded-md border px-3 py-2 text-sm',
                      error ? 'border-red-400' : 'border-slate-300'
                    )}
                  />
                ) : (
                  <input
                    id={`opt-${opt.key}`}
                    type="text"
                    value={(values[opt.key] as string | undefined) ?? ''}
                    placeholder={opt.default !== undefined ? `default: ${String(opt.default)}` : 'optional'}
                    onChange={(e) => setValue(opt.key, e.target.value)}
                    className={clsx(
                      'w-full rounded-md border px-3 py-2 text-sm',
                      error ? 'border-red-400' : 'border-slate-300'
                    )}
                  />
                )}

                {opt.description && <p className="mt-1 text-xs text-slate-500">{opt.description}</p>}
                {error && <p className="mt-1 text-xs text-red-600">{error}</p>}
              </div>
            );
          })}
        </div>
      )}

      {formError && (
        <div className="mx-1 mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
      )}
      {savedAt && !formError && options.length > 0 && (
        <p className="mx-1 mt-3 text-xs font-medium text-green-600">Saved.</p>
      )}

      {options.length > 0 && (
        <div className="mt-4 flex items-center justify-end gap-2 border-t border-slate-200 px-1 pt-3">
          <button
            type="button"
            onClick={handleReset}
            disabled={saving}
            className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-50"
          >
            <RotateCcw className="h-4 w-4" />
            Reset to defaults
          </button>
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-1.5 rounded-md bg-slate-900 px-4 py-1.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
          >
            <Save className="h-4 w-4" />
            {saving ? 'Saving…' : 'Save settings'}
          </button>
        </div>
      )}
    </form>
  );
}
