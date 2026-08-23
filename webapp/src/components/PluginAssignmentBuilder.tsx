import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { Plus, X } from 'lucide-react';
import { api, DevicePluginAssignmentInput, Plugin, Secret } from '../api/client';

interface RowState {
  pluginId: string;
  secretId: string;
  isPrimary: boolean;
}

const emptyRow = (): RowState => ({ pluginId: '', secretId: '', isPrimary: false });

/**
 * Multi-plugin assignment builder. Each row binds one plugin to a device with
 * its own credential source (filtered by the plugin's required secret type)
 * and an optional primary flag — exactly one row may be primary, but ONLY if
 * the user explicitly marks it; adding plugins never auto-promotes them.
 */
export function PluginAssignmentBuilder({
  plugins,
  secrets,
  initial = [],
  excludedPluginIds = [],
  onSubmit,
  submitLabel = 'Save',
  busy = false,
  onRowsChange,
}: {
  plugins: Plugin[];
  secrets: Secret[];
  /** Existing assignments to prefill (e.g. when adding more to a device). */
  initial?: DevicePluginAssignmentInput[];
  /** Plugins already assigned elsewhere — hidden from the options list. */
  excludedPluginIds?: string[];
  onSubmit: (assignments: DevicePluginAssignmentInput[]) => void;
  submitLabel?: string;
  busy?: boolean;
  /** Reports the currently selected plugin ids as rows change (incl. initial).
   * Lets the parent derive vendor-specific form fields (e.g. model catalogs)
   * from exactly the plugins assigned to this device. */
  onRowsChange?: (pluginIds: string[]) => void;
}) {
  const availablePlugins = useMemo(
    () => plugins.filter((p) => !excludedPluginIds.includes(p.id)),
    [plugins, excludedPluginIds]
  );
  const [rows, setRows] = useState<RowState[]>(() =>
    initial.length > 0 ? initial.map((a) => ({ pluginId: a.pluginId, secretId: a.secretId ?? '', isPrimary: a.isPrimary === true })) : [emptyRow()]
  );

  // Required secret type per chosen plugin (drives the credentials dropdown).
  const [requiredTypes, setRequiredTypes] = useState<Record<string, string | null>>({});
  useEffect(() => {
    const ids = Array.from(new Set(rows.map((r) => r.pluginId).filter(Boolean)));
    let cancelled = false;
    Promise.all(
      ids.map(async (id) => {
        try {
          return [id, (await api.requiredSecretType(id)).requiredSecretType] as const;
        } catch {
          return [id, null] as const;
        }
      })
    ).then((entries) => {
      if (!cancelled) setRequiredTypes(Object.fromEntries(entries));
    });
    return () => {
      cancelled = true;
    };
  }, [rows]);

  function compatibleSecrets(pluginId: string): Secret[] {
    const required = pluginId ? requiredTypes[pluginId] : undefined;
    if (!required) return secrets;
    return secrets.filter((s) => s.type === required);
  }

  function updateRow(index: number, patch: Partial<RowState>) {
    setRows((rs) => rs.map((r, i) => (i === index ? { ...r, ...patch } : r)));
  }

  /** Exactly one primary: picking a row demotes the others. */
  function makePrimary(index: number) {
    setRows((rs) => rs.map((r, i) => ({ ...r, isPrimary: i === index ? true : false })));
  }

  const usedPluginIds = useMemo(
    () => new Set(rows.map((r) => r.pluginId).filter(Boolean)),
    [rows]
  );

  // Report the selected plugin ids to the parent (initial rows included) so it
  // can derive vendor-specific fields — e.g. model catalogs — from exactly the
  // plugins assigned here. The callback is kept in a ref: only `rows` should
  // retrigger this, not a new closure on every parent render.
  const onRowsChangeRef = useRef(onRowsChange);
  onRowsChangeRef.current = onRowsChange;
  useEffect(() => {
    onRowsChangeRef.current?.(Array.from(new Set(rows.map((r) => r.pluginId).filter(Boolean))));
  }, [rows]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const valid = rows.filter((r) => r.pluginId);
    if (valid.length === 0) return;
    // Primary is only set when the user explicitly marked a row — adding
    // plugins must never silently steal primary from an existing one.
    onSubmit(
      valid.map((r) => ({
        pluginId: r.pluginId,
        secretId: r.secretId || null,
        isPrimary: r.isPrimary,
      }))
    );
  }

  return (
    <form onSubmit={handleSubmit} noValidate>
      <div className="space-y-3">
      {rows.map((row, index) => {
        const required = row.pluginId ? requiredTypes[row.pluginId] : undefined;
        return (
          <div key={index} className="grid grid-cols-1 gap-2 rounded-md border border-slate-200 bg-slate-50 p-3 sm:grid-cols-[1fr_1fr_auto_auto]">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">Plugin</label>
              <select
                required
                className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm"
                value={row.pluginId}
                onChange={(e) => updateRow(index, { pluginId: e.target.value, secretId: '' })}
              >
                <option value="" disabled>
                  Select a plugin
                </option>
                {availablePlugins.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.version})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">
                Credentials{required ? ` (${required})` : ''}
              </label>
              <select
                className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm"
                value={row.secretId}
                onChange={(e) => updateRow(index, { secretId: e.target.value })}
              >
                <option value="">No credentials</option>
                {(compatibleSecrets(row.pluginId) ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label || s.id} [{s.type}]
                  </option>
                ))}
              </select>
            </div>
            <label className="flex items-center gap-1.5 self-end pb-1 text-sm text-slate-600">
              <input
                type="radio"
                name="primary-plugin"
                checked={row.isPrimary}
                onChange={() => makePrimary(index)}
                className="h-4 w-4 border-slate-300 text-slate-900 focus:ring-slate-400"
              />
              Primary
            </label>
            <div className="self-end pb-1">
              {rows.length > 1 && (
                <button
                  type="button"
                  aria-label={`Remove plugin row ${index + 1}`}
                  title="Remove this plugin"
                  onClick={() => setRows((rs) => rs.filter((_, i) => i !== index))}
                  className="rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
        );
      })}

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setRows((rs) => [...rs, emptyRow()])}
          disabled={availablePlugins.length === 0 || usedPluginIds.size >= availablePlugins.length}
          className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-40"
        >
          <Plus className="h-4 w-4" />
          Add plugin
        </button>
        <button
          type="submit"
          disabled={busy}
          className="flex items-center gap-1.5 rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
        >
          {busy ? 'Saving…' : submitLabel}
        </button>
      </div>
      </div>
    </form>
  );
}
