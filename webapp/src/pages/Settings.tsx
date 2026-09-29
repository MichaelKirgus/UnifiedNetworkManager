import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, SettingView } from '../api/client';
import { can } from '../auth/permissions';
import { ChevronDown, ChevronRight, RotateCcw, Save, Settings2, X } from 'lucide-react';

/** Compact duration for ms values ("30 s" / "15 min" / "2 h"). */
function fmtMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  return `${Math.round(m / 60)} h`;
}

/** Compact duration for seconds values ("1 h" / "30 min"). */
function fmtSeconds(s: number): string {
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h`;
  return `${Math.round(h / 24)} d`;
}

/** Human-friendly rendering of a setting value given its unit hint. */
function fmtValue(v: number | string | boolean, unit?: string | null): string {
  if (typeof v === 'boolean') return v ? 'on' : 'off';
  if (typeof v === 'string') return v;
  switch (unit) {
    case 'ms':
      return fmtMs(v);
    case 's':
      return fmtSeconds(v);
    case 'days':
      return `${v} d`;
    case '%':
      return `${v}%`;
    default:
      return String(v);
  }
}

/**
 * Extracts the option list from an enum-style pattern like `^(warn|block)$`.
 * Returns null for free-form strings (no such pattern) — those keep a text input.
 */
function enumOptions(pattern?: string | null): string[] | null {
  if (!pattern) return null;
  const m = pattern.match(/^\^?\(([^()]+)\)\$$/);
  if (!m) return null;
  const opts = m[1].split('|').map((s) => s.trim()).filter(Boolean);
  return opts.length >= 2 ? opts : null;
}

const CATEGORY_STYLES: Record<string, string> = {
  Telemetry: 'bg-info text-info-fg',
  Retention: 'bg-warning text-warning-fg',
  Security: 'bg-danger text-danger-fg',
  Execution: 'bg-success text-success-fg',
  Discovery: 'bg-muted text-secondary',
};

/** Inline editor for one expanded setting — owns its own draft state. */
function SettingEditor({
  setting,
  canWrite,
  saving,
  onSave,
}: {
  setting: SettingView;
  canWrite: boolean;
  saving: boolean;
  onSave: (value: number | string | boolean) => void;
}) {
  const [draft, setDraft] = useState<string>(String(setting.value));

  if (!canWrite) {
    return <span className="text-xs text-faint">Read-only — requires system:write to change this setting.</span>;
  }

  const isInt = setting.type === 'integer';
  const opts = enumOptions(setting.pattern); // enum-style string settings render as a dropdown
  const parsed = Number(draft);
  const dirty = draft !== String(setting.value);
  const invalid = isInt && (!Number.isFinite(parsed) || (setting.min != null && parsed < setting.min) || (setting.max != null && parsed > setting.max));

  return (
    <div className="flex flex-wrap items-center gap-2">
      {isInt ? (
        <input
          type="number"
          value={draft}
          min={setting.min ?? undefined}
          max={setting.max ?? undefined}
          step={setting.unit === 'ms' ? 1000 : setting.unit === 's' ? 60 : 1}
          disabled={saving || invalid}
          onChange={(e) => setDraft(e.target.value)}
          className="w-40 rounded-md border border-border bg-card px-3 py-1.5 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
        />
      ) : opts ? (
        <select
          value={draft}
          disabled={saving || invalid}
          onChange={(e) => setDraft(e.target.value)}
          className="w-48 rounded-md border border-border bg-card px-3 py-1.5 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
        >
          {opts.map((o) => (<option key={o} value={o}>{o}</option>))}
        </select>
      ) : (
        <input
          type="text"
          value={draft}
          disabled={saving || invalid}
          onChange={(e) => setDraft(e.target.value)}
          className="w-64 rounded-md border border-border bg-card px-3 py-1.5 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
        />
      )}
      {setting.unit && <span className="text-xs text-faint">{setting.unit}</span>}
      {(dirty || invalid) && (
        <>
          <button
            type="button"
            onClick={() => onSave(isInt ? parsed : draft)}
            disabled={saving || invalid}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            <Save className="h-4 w-4" />
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            type="button"
            onClick={() => setDraft(String(setting.value))}
            disabled={saving}
            className="inline-flex items-center gap-1 rounded-md border border-border px-3 py-1.5 text-sm text-secondary hover:bg-muted disabled:opacity-50"
          >
            <X className="h-4 w-4" />
            Cancel
          </button>
        </>
      )}
      {invalid && (
        <span className="text-xs text-danger-fg">
          Must be a number{setting.min != null ? ` ≥ ${fmtValue(setting.min, setting.unit)}` : ''}{setting.max != null ? ` ≤ ${fmtValue(setting.max, setting.unit)}` : ''}
        </span>
      )}
    </div>
  );
}

/**
 * Central system settings page. Lists every app-wide knob (retention windows,
 * session/timeout behaviour, worker cadence, execution budgets) in a table; each
 * row expands to show its help text + an inline editor, and carries a per-row
 * Reset button that reverts the value to its default. Gated by system:read /
 * system:write (the server enforces both).
 */
export default function Settings() {
  const queryClient = useQueryClient();
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: api.listSettings,
  });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['settings'] });

  const updateMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: number | string | boolean }) => api.updateSetting(key, value),
    onSuccess: invalidate,
  });
  const resetMutation = useMutation({
    mutationFn: (key: string) => api.resetSetting(key),
    onSuccess: invalidate,
  });

  const canWrite = can('system:write');
  const settings = settingsQuery.data?.settings ?? [];

  const toggle = (key: string) =>
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const columns: DataTableColumn<SettingView>[] = [
    {
      header: 'Setting',
      key: 'label',
      width: 280,
      render: (row) => {
        const expanded = expandedKeys.has(row.key);
        return (
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => toggle(row.key)}
              aria-expanded={expanded}
              title={expanded ? 'Collapse' : 'Show details'}
              className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-faint hover:bg-muted hover:text-secondary"
            >
              {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
            </button>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 text-sm font-medium text-foreground">
                {row.label}
                {row.isModified && (
                  <span title="Modified from default" className="h-1.5 w-1.5 shrink-0 rounded-full bg-warning" />
                )}
              </div>
              <div className="truncate font-mono text-[11px] text-faint">{row.key}</div>
            </div>
          </div>
        );
      },
    },
    {
      header: 'Category',
      key: 'category',
      width: 120,
      render: (row) => (
        <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${CATEGORY_STYLES[row.category] ?? 'bg-muted text-secondary'}`}>
          {row.category}
        </span>
      ),
    },
    { header: 'Type', key: 'type', width: 90, render: (row) => <span className="font-mono text-xs">{row.type}</span> },
    {
      header: 'Value',
      key: 'value',
      width: 140,
      sortAccessor: (row) => String(row.value),
      render: (row) => (
        <span className="font-mono text-sm">
          {fmtValue(row.value, row.unit)}
          {row.isModified && <span className="ml-1.5 rounded bg-warning px-1 py-0.5 text-[10px] font-semibold text-warning-fg">modified</span>}
        </span>
      ),
    },
    {
      header: 'Default',
      key: 'defaultValue',
      width: 140,
      render: (row) => <span className="font-mono text-sm text-muted-foreground">{fmtValue(row.defaultValue, row.unit)}</span>,
    },
    {
      header: 'Actions',
      key: '__actions',
      width: 120,
      excludeFromExport: true,
      render: (row) =>
        canWrite ? (
          <button
            type="button"
            onClick={() => resetMutation.mutate(row.key)}
            disabled={!row.isModified || resetMutation.isPending}
            title={row.isModified ? 'Reset to default' : 'Already at default'}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-secondary hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Reset
          </button>
        ) : (
          <span className="text-xs text-faint">—</span>
        ),
    },
  ];

  return (
    <Layout
      title="Settings"
      actions={
        !canWrite && (
          <span className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground">read-only — requires system:write</span>
        )
      }
    >
      <div className="space-y-4">
        <section className="rounded-md border border-border bg-card shadow-sm">
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <Settings2 className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold text-foreground">System settings</h2>
            <span className="ml-auto text-xs text-faint">app-wide behaviour — not plugin or device specific · changes apply live, no restart</span>
          </div>
          <DataTable<SettingView>
            columns={columns}
            rows={settings}
            rowKey={(row) => row.key}
            storageKey="unm:table:settings"
            searchPlaceholder="Search settings…"
            emptyMessage="No settings available"
            renderRowDetail={(row) => {
              if (!expandedKeys.has(row.key)) return null;
              const saving = updateMutation.isPending && updateMutation.variables?.key === row.key;
              return (
                <div className="space-y-3 py-1">
                  <p className="max-w-3xl text-xs leading-relaxed text-secondary">{row.help}</p>
                  <SettingEditor
                    key={row.key}
                    setting={row}
                    canWrite={canWrite}
                    saving={saving}
                    onSave={(value) => updateMutation.mutate({ key: row.key, value })}
                  />
                </div>
              );
            }}
          />
        </section>
      </div>
    </Layout>
  );
}
