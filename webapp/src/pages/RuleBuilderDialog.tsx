import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Plus, Trash2, Workflow } from 'lucide-react';
import {
  api, ApiError, Automation, AutomationActionBlock, AutomationDraft, AutomationNotificationSeverity, AutomationTriggerBlock,
  AUTOMATION_NOTIFICATION_SEVERITIES, BACKUP_PRESETS, CatalogEntry, DEVICE_STATUSES, DeviceStatusValue, InputSchema, LOG_LEVELS, LogLevel,
  METRIC_COMPARATORS, MetricComparator, Plugin, Site,
} from '../api/client';
import { DialogShell } from '../components/DialogShell';
import { defaultValues, SchemaForm, validateSchema } from '../components/SchemaForm';
import { useTimeFormat } from '../utils/time';

/** Stable-enough id for trigger/action blocks (the engine only needs uniqueness within a rule). */
function newId(prefix: string): string {
  try { return `${prefix}-${crypto.randomUUID()}`; } catch { return `${prefix}-${Math.random().toString(36).slice(2, 10)}`; }
}

/** {{…}} tokens available in webhook/notification templates (see engine renderTemplate). */
const TEMPLATE_TOKENS = '{{automation.name}}, {{trigger.type}}, {{run.at}}, {{device.name}}, {{device.address}}, {{metric.key}}, {{metric.value}}, {{log.message}}';

// ── Block factories ───────────────────────────────────────────────────────────

function newScheduleTrigger(): AutomationTriggerBlock {
  return { id: newId('t'), type: 'schedule', schedule: { kind: 'interval', everyMinutes: 5 } };
}
function newMetricTrigger(): AutomationTriggerBlock {
  return { id: newId('t'), type: 'metric', metricKey: '', mode: 'compare', comparator: '>=', value: '' };
}
function newLogTrigger(): AutomationTriggerBlock {
  return { id: newId('t'), type: 'log', source: 'plugin', pattern: '' };
}
function newDeviceStatusTrigger(): AutomationTriggerBlock {
  return { id: newId('t'), type: 'deviceStatus', toStatuses: ['offline'] };
}

function newIntentAction(): AutomationActionBlock {
  return { id: newId('a'), type: 'intent', pluginId: '', actionId: '', devices: { deviceIds: [] }, input: {} };
}
function newWebhookAction(): AutomationActionBlock {
  return { id: newId('a'), type: 'webhook', url: '', method: 'POST' };
}
function newNotificationAction(): AutomationActionBlock {
  return {
    id: newId('a'), type: 'notification', severity: 'warning',
    titleTemplate: '{{automation.name}} fired ({{trigger.type}})',
    messageTemplate: 'Triggered by {{trigger.type}} at {{run.at}}.',
  };
}
function newInternalAction(): AutomationActionBlock {
  return { id: newId('a'), type: 'internal', kind: 'backup', preset: 'config' };
}

// ── Client-side draft validation (mirrors the API's validateAutomationDraft) ──

function validateDraft(draft: AutomationDraft): string[] {
  const errors: string[] = [];
  if (!draft.name.trim()) errors.push('Name is required');
  else if (draft.name.length > 200) errors.push('Name must be at most 200 characters');
  if (draft.cooldownSec !== undefined && (!Number.isInteger(draft.cooldownSec) || draft.cooldownSec < 0)) {
    errors.push('Cooldown must be a non-negative integer (seconds)');
  }
  if (draft.triggers.length === 0) errors.push('Add at least one trigger');
  for (const [i, t] of draft.triggers.entries()) {
    const where = `Trigger ${i + 1}`;
    switch (t.type) {
      case 'schedule': {
        const s = t.schedule;
        if (s.kind === 'cron' && !s.expr.trim()) errors.push(`${where}: cron expression is required`);
        else if (s.kind === 'interval' && (!Number.isInteger(s.everyMinutes) || s.everyMinutes < 1)) errors.push(`${where}: interval must be an integer ≥ 1 minute`);
        else if (s.kind === 'dailyAt' && !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time)) errors.push(`${where}: time must be HH:MM (24h)`);
        break;
      }
      case 'metric': {
        if (!t.metricKey.trim()) errors.push(`${where}: metric key is required`);
        if (t.mode === 'compare') {
          if (!METRIC_COMPARATORS.includes(t.comparator as MetricComparator)) errors.push(`${where}: pick a comparator`);
          if (t.value === undefined || t.value === null || String(t.value).trim() === '') errors.push(`${where}: value is required for compare mode`);
        } else {
          if (!t.pattern?.trim()) errors.push(`${where}: pattern is required for regex mode`);
          else { try { new RegExp(t.pattern); } catch (e) { errors.push(`${where}: invalid regex — ${(e as Error).message}`); } }
        }
        break;
      }
      case 'log': {
        if (!t.pattern.trim()) errors.push(`${where}: pattern is required`);
        else { try { new RegExp(t.pattern); } catch (e) { errors.push(`${where}: invalid regex — ${(e as Error).message}`); } }
        break;
      }
      case 'deviceStatus':
        if (t.toStatuses.length === 0) errors.push(`${where}: pick at least one target status`);
        break;
    }
  }
  if (draft.actions.length === 0) errors.push('Add at least one action');
  for (const [i, a] of draft.actions.entries()) {
    const where = `Action ${i + 1}`;
    switch (a.type) {
      case 'intent': {
        if (!a.pluginId) errors.push(`${where}: pick a plugin`);
        else if (!a.actionId) errors.push(`${where}: pick an action`);
        else if ((a.devices.deviceIds ?? []).length === 0) errors.push(`${where}: select at least one device`);
        break;
      }
      case 'webhook': {
        if (!a.url.trim()) errors.push(`${where}: URL is required`);
        else if (!/^https?:\/\//i.test(a.url)) errors.push(`${where}: URL must be http(s)`);
        break;
      }
      case 'notification': {
        if (!a.titleTemplate.trim()) errors.push(`${where}: title is required`);
        else if (a.titleTemplate.length > 300) errors.push(`${where}: title must be at most 300 characters`);
        if (!a.messageTemplate || !a.messageTemplate.trim()) errors.push(`${where}: message is required`);
        else if (a.messageTemplate.length > 2000) errors.push(`${where}: message must be at most 2000 characters`);
        break;
      }
      case 'internal': {
        if (a.kind === 'replicationSync' && !a.targetId) errors.push(`${where}: pick a replication target`);
        break;
      }
    }
  }
  return errors;
}

// ── Small shared bits ─────────────────────────────────────────────────────────

const inputCls = 'w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none disabled:opacity-50';
const labelCls = 'mb-1 block text-sm font-medium text-secondary';
const hintCls = 'mt-1 text-xs text-faint';

/** Collapsible optional device-scope editor (sites / tags / explicit ids). */
function ScopeEditor({ scope, onChange }: { scope?: { siteIds?: string[]; tags?: string[]; deviceIds?: string[] }; onChange: (scope: { siteIds?: string[]; tags?: string[]; deviceIds?: string[] }) => void }) {
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: () => api.sites() });
  const sites: Site[] = useMemo(() => sitesQuery.data ?? [], [sitesQuery.data]);
  const siteIds = scope?.siteIds ?? [];
  const tagsText = (scope?.tags ?? []).join(', ');

  function toggleSite(id: string) {
    const next = siteIds.includes(id) ? siteIds.filter((s) => s !== id) : [...siteIds, id];
    onChange({ ...scope, siteIds: next.length ? next : undefined });
  }

  return (
    <details className="mt-2 rounded-md border border-border bg-muted/30 px-3 py-2">
      <summary className="cursor-pointer select-none text-xs font-medium uppercase tracking-wide text-faint hover:text-secondary">Scope — which devices (optional, empty = all)</summary>
      {sites.length > 0 && (
        <div className="mt-2">
          <span className={labelCls}>Sites</span>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
            {sites.map((s) => (
              <label key={s.id} className="flex items-center gap-1.5">
                <input type="checkbox" checked={siteIds.includes(s.id)} onChange={() => toggleSite(s.id)} />
                {s.name}
              </label>
            ))}
          </div>
        </div>
      )}
      <div className="mt-2">
        <span className={labelCls}>Tags (comma-separated)</span>
        <input className={inputCls} value={tagsText} placeholder="e.g. core, lab" onChange={(e) => { const tags = e.target.value.split(',').map((t) => t.trim()).filter(Boolean); onChange({ ...scope, tags: tags.length ? tags : undefined }); }} />
      </div>
      <div className="mt-2">
        <span className={labelCls}>Device IDs (comma-separated)</span>
        <input className={inputCls} placeholder="optional — explicit device ids" value={(scope?.deviceIds ?? []).join(', ')} onChange={(e) => { const ids = e.target.value.split(',').map((t) => t.trim()).filter(Boolean); onChange({ ...scope, deviceIds: ids.length ? ids : undefined }); }} />
      </div>
    </details>
  );
}

/** Debounced "next runs" hint for a schedule spec (via GET /automations/preview-schedule). */
function SchedulePreview({ kind, expr }: { kind: 'cron' | 'interval' | 'dailyAt'; expr: string }) {
  const { formatDateTime } = useTimeFormat();
  const [runs, setRuns] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    // Only ask the server once the spec is plausibly complete.
    const valid = kind === 'cron' ? expr.trim().length > 0 : kind === 'interval' ? Number.isInteger(Number(expr)) && Number(expr) >= 1 : /^([01]\d|2[0-3]):[0-5]\d$/.test(expr);
    if (!valid) { setRuns(null); setError(null); return; }
    const t = setTimeout(async () => {
      try {
        const res = await api.previewSchedule(kind, expr, 3);
        if (!cancelled) { setRuns(res.runs); setError(null); }
      } catch (e) {
        if (!cancelled) { setRuns(null); setError((e as Error).message); }
      }
    }, 400);
    return () => { cancelled = true; clearTimeout(t); };
  }, [kind, expr]);

  if (error) return <p className={hintCls}>Schedule check: {error}</p>;
  if (!runs || runs.length === 0) return null;
  return <p className={hintCls}>Next runs: {runs.map((r) => formatDateTime(r)).join(' · ')}</p>;
}

// ── Trigger editors ───────────────────────────────────────────────────────────

function ScheduleTriggerEditor({ block, onChange }: { block: Extract<AutomationTriggerBlock, { type: 'schedule' }>; onChange: (b: AutomationTriggerBlock) => void }) {
  const s = block.schedule;
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Kind</span>
        <select className={inputCls} value={s.kind} onChange={(e) => {
          const kind = e.target.value as 'cron' | 'interval' | 'dailyAt';
          onChange({ ...block, schedule: kind === 'cron' ? { kind, expr: s.kind === 'cron' ? s.expr : '' } : kind === 'interval' ? { kind, everyMinutes: s.kind === 'interval' ? s.everyMinutes : 5 } : { kind, time: s.kind === 'dailyAt' ? s.time : '09:00' } });
        }}>
          <option value="cron">Cron expression</option>
          <option value="interval">Fixed interval</option>
          <option value="dailyAt">Daily at time</option>
        </select>
      </div>
      {s.kind === 'cron' && (
        <div>
          <span className={labelCls}>Cron expression</span>
          <input className={inputCls} value={s.expr} placeholder="*/5 * * * *" onChange={(e) => onChange({ ...block, schedule: { kind: 'cron', expr: e.target.value } })} />
        </div>
      )}
      {s.kind === 'interval' && (
        <div>
          <span className={labelCls}>Every (minutes)</span>
          <input type="number" min={1} className={inputCls} value={Number.isFinite(s.everyMinutes) ? s.everyMinutes : ''} onChange={(e) => onChange({ ...block, schedule: { kind: 'interval', everyMinutes: Number(e.target.value) } })} />
        </div>
      )}
      {s.kind === 'dailyAt' && (
        <div>
          <span className={labelCls}>Time (24h, server local)</span>
          <input type="time" className={inputCls} value={s.time} onChange={(e) => onChange({ ...block, schedule: { kind: 'dailyAt', time: e.target.value } })} />
        </div>
      )}
      <div className="sm:col-span-2">
        <SchedulePreview kind={s.kind} expr={s.kind === 'cron' ? s.expr : s.kind === 'interval' ? String(s.everyMinutes) : s.time} />
      </div>
    </div>
  );
}

function MetricTriggerEditor({ block, onChange, plugins }: { block: Extract<AutomationTriggerBlock, { type: 'metric' }>; onChange: (b: AutomationTriggerBlock) => void; plugins: Plugin[] }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Metric key</span>
        <input className={inputCls} value={block.metricKey} placeholder="e.g. ping.latency, cpu.load" onChange={(e) => onChange({ ...block, metricKey: e.target.value })} />
        <p className={hintCls}>Dot-notation key as it appears in the device's telemetry metrics.</p>
      </div>
      <div>
        <span className={labelCls}>Plugin (optional)</span>
        <select className={inputCls} value={block.pluginId ?? ''} onChange={(e) => onChange({ ...block, pluginId: e.target.value || undefined })}>
          <option value="">Any plugin</option>
          {plugins.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Mode</span>
        <select className={inputCls} value={block.mode} onChange={(e) => onChange({ ...block, mode: e.target.value as 'compare' | 'regex' })}>
          <option value="compare">Numeric compare</option>
          <option value="regex">Regex match (string values)</option>
        </select>
      </div>
      {block.mode === 'compare' ? (
        <>
          <div>
            <span className={labelCls}>Comparator</span>
            <select className={inputCls} value={block.comparator ?? ''} onChange={(e) => onChange({ ...block, comparator: e.target.value as MetricComparator })}>
              {METRIC_COMPARATORS.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <span className={labelCls}>Value</span>
            <input type="number" step="any" className={inputCls} value={block.value === undefined || block.value === null ? '' : String(block.value)} onChange={(e) => onChange({ ...block, value: e.target.value })} />
          </div>
        </>
      ) : (
        <div className="sm:col-span-2">
          <span className={labelCls}>Regex pattern</span>
          <input className={inputCls} value={block.pattern ?? ''} placeholder="e.g. ^up$" onChange={(e) => onChange({ ...block, pattern: e.target.value })} />
        </div>
      )}
      <div>
        <span className={labelCls}>Sustained for (seconds)</span>
        <input type="number" min={0} className={inputCls} value={block.durationSec ?? 0} onChange={(e) => onChange({ ...block, durationSec: Math.max(0, Number(e.target.value) || 0) })} />
        <p className={hintCls}>0 = fire immediately; &gt;0 requires the condition to hold continuously for that long.</p>
      </div>
      <ScopeEditor scope={block.scope} onChange={(scope) => onChange({ ...block, scope: Object.keys(scope).length ? scope : undefined })} />
    </div>
  );
}

function LogTriggerEditor({ block, onChange, plugins }: { block: Extract<AutomationTriggerBlock, { type: 'log' }>; onChange: (b: AutomationTriggerBlock) => void; plugins: Plugin[] }) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ count: number; matches: Array<{ deviceId: string | null; message: string }> } | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  async function runPatternTest() {
    if (!block.pattern.trim()) return;
    setTesting(true);
    setTestResult(null);
    setTestError(null);
    try {
      const res = await api.testAutomationPattern({
        source: block.source,
        pluginId: block.pluginId || undefined,
        levels: block.levels && block.levels.length ? block.levels : undefined,
        pattern: block.pattern,
      });
      setTestResult(res);
    } catch (e) {
      setTestError((e as Error).message);
    } finally {
      setTesting(false);
    }
  }

  function toggleLevel(level: LogLevel) {
    const levels = block.levels ?? [];
    const next = levels.includes(level) ? levels.filter((l) => l !== level) : [...levels, level];
    onChange({ ...block, levels: next.length ? next : undefined });
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Source</span>
        <select className={inputCls} value={block.source} onChange={(e) => { const source = e.target.value as 'plugin' | 'firewall'; setTestResult(null); onChange({ ...block, source, pluginId: source === 'firewall' ? undefined : block.pluginId }); }}>
          <option value="plugin">Plugin logs</option>
          <option value="firewall">Firewall events</option>
        </select>
      </div>
      {block.source === 'plugin' && (
        <div>
          <span className={labelCls}>Plugin (optional)</span>
          <select className={inputCls} value={block.pluginId ?? ''} onChange={(e) => { setTestResult(null); onChange({ ...block, pluginId: e.target.value || undefined }); }}>
            <option value="">Any plugin</option>
            {plugins.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
      )}
      <div className="sm:col-span-2">
        <span className={labelCls}>Levels (empty = all)</span>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {LOG_LEVELS.map((l) => (
            <label key={l} className="flex items-center gap-1.5">
              <input type="checkbox" checked={(block.levels ?? []).includes(l)} onChange={() => toggleLevel(l)} />
              {l}
            </label>
          ))}
        </div>
      </div>
      <div className="sm:col-span-2">
        <span className={labelCls}>Regex pattern (search on the message)</span>
        <div className="flex gap-2">
          <input className={inputCls} value={block.pattern} placeholder="e.g. monitoring failed|auth-failures" onChange={(e) => { setTestResult(null); onChange({ ...block, pattern: e.target.value }); }} />
          <button type="button" disabled={!block.pattern.trim() || testing} onClick={() => void runPatternTest()} className="shrink-0 rounded-md border border-border px-3 py-2 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50">
            {testing ? 'Testing…' : 'Test pattern'}
          </button>
        </div>
        <p className={hintCls}>Scans only NEW log rows since the last evaluation (first run covers the previous 24 h).</p>
        {testError && <p className="mt-1 text-xs text-danger">{testError}</p>}
        {testResult && (
          <div className="mt-2 rounded-md border border-border bg-muted/30 p-2 text-sm">
            <span className={testResult.count > 0 ? 'text-status-ok' : 'text-faint'}>{testResult.count} match{testResult.count === 1 ? '' : 'es'} in the recent window</span>
            {testResult.matches.slice(0, 5).map((m, i) => (
              <div key={i} className="mt-1 truncate text-xs text-faint" title={m.message}>{m.message}</div>
            ))}
          </div>
        )}
      </div>
      <ScopeEditor scope={block.scope} onChange={(scope) => onChange({ ...block, scope: Object.keys(scope).length ? scope : undefined })} />
    </div>
  );
}

function DeviceStatusTriggerEditor({ block, onChange }: { block: Extract<AutomationTriggerBlock, { type: 'deviceStatus' }>; onChange: (b: AutomationTriggerBlock) => void }) {
  function toggle(status: DeviceStatusValue) {
    const next = block.toStatuses.includes(status) ? block.toStatuses.filter((s) => s !== status) : [...block.toStatuses, status];
    onChange({ ...block, toStatuses: next });
  }
  return (
    <div>
      <span className={labelCls}>Fire when a device transitions INTO</span>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
        {DEVICE_STATUSES.map((s) => (
          <label key={s} className="flex items-center gap-1.5">
            <input type="checkbox" checked={block.toStatuses.includes(s)} onChange={() => toggle(s)} />
            {s}
          </label>
        ))}
      </div>
      <p className={hintCls}>Fires on the settled status (after the 60 s hysteresis window), not transient probe noise.</p>
      <ScopeEditor scope={block.scope} onChange={(scope) => onChange({ ...block, scope: Object.keys(scope).length ? scope : undefined })} />
    </div>
  );
}

// ── Action editors ────────────────────────────────────────────────────────────

function IntentActionEditor({ block, onChange, plugins }: { block: Extract<AutomationActionBlock, { type: 'intent' }>; onChange: (b: AutomationActionBlock) => void; plugins: Plugin[] }) {
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: () => api.devices() });
  const actionsQuery = useQuery({
    queryKey: ['pluginActions', block.pluginId],
    queryFn: () => api.pluginActions(block.pluginId),
    enabled: Boolean(block.pluginId),
  });
  const catalog: CatalogEntry[] = useMemo(() => actionsQuery.data?.actions ?? [], [actionsQuery.data]);
  const entry = catalog.find((c) => c.id === block.actionId);

  const eligibleDevices = useMemo(
    () => (devicesQuery.data ?? []).filter((d) => d.plugins?.some((p) => p.pluginId === block.pluginId)),
    [devicesQuery.data, block.pluginId],
  );
  const selectedIds = block.devices.deviceIds ?? [];

  function toggleDevice(id: string) {
    const next = selectedIds.includes(id) ? selectedIds.filter((d) => d !== id) : [...selectedIds, id];
    onChange({ ...block, devices: { deviceIds: next } });
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Plugin</span>
        <select className={inputCls} value={block.pluginId} onChange={(e) => onChange({ ...block, pluginId: e.target.value, actionId: '', input: {}, devices: { deviceIds: [] } })}>
          <option value="" disabled>Select a plugin</option>
          {plugins.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Action (catalog)</span>
        <select className={`${inputCls} disabled:opacity-50`} disabled={!block.pluginId || catalog.length === 0} value={block.actionId} onChange={(e) => {
          const next = catalog.find((c) => c.id === e.target.value);
          onChange({ ...block, actionId: e.target.value, input: next?.inputSchema ? defaultValues(next.inputSchema) : {} });
        }}>
          <option value="" disabled>{actionsQuery.isLoading ? 'Loading…' : 'Select an action'}</option>
          {catalog.map((c) => (
            <option key={c.id} value={c.id}>{c.label ?? c.id}{c.riskLevel === 'dangerous' ? ' ⚠' : ''}</option>
          ))}
        </select>
        {entry?.description && <p className={hintCls}>{entry.description}</p>}
      </div>
      {entry?.inputSchema && Object.keys(entry.inputSchema).length > 0 && (
        <div className="sm:col-span-2">
          <span className={labelCls}>Action input</span>
          <IntentInputForm schema={entry.inputSchema} values={block.input ?? {}} onChange={(input) => onChange({ ...block, input })} />
        </div>
      )}
      <div className="sm:col-span-2">
        <span className={labelCls}>Target devices ({eligibleDevices.length} with this plugin)</span>
        {eligibleDevices.length === 0 ? (
          <p className={hintCls}>{block.pluginId ? 'No device has this plugin assigned yet.' : 'Pick a plugin first.'}</p>
        ) : (
          <div className="max-h-40 overflow-y-auto rounded-md border border-border p-2">
            {eligibleDevices.map((d) => (
              <label key={d.id} className="flex items-center gap-2 py-0.5 text-sm">
                <input type="checkbox" checked={selectedIds.includes(d.id)} onChange={() => toggleDevice(d.id)} />
                <span>{d.name}</span>
                <span className="text-xs text-faint">{d.managementAddress}</span>
              </label>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/** SchemaForm wrapper that keeps its values inside the action block. */
function IntentInputForm({ schema, values, onChange }: { schema: InputSchema; values: Record<string, unknown>; onChange: (v: Record<string, unknown>) => void }) {
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  return (
    <div>
      <SchemaForm schema={schema} values={values} fieldErrors={fieldErrors} onChange={(next) => { onChange(next); setFieldErrors(validateSchema(schema, next)); }} />
    </div>
  );
}

function WebhookActionEditor({ block, onChange }: { block: Extract<AutomationActionBlock, { type: 'webhook' }>; onChange: (b: AutomationActionBlock) => void }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_140px]">
      <div>
        <span className={labelCls}>URL</span>
        <input className={inputCls} value={block.url} placeholder="https://hooks.example.com/unm" onChange={(e) => onChange({ ...block, url: e.target.value })} />
      </div>
      <div>
        <span className={labelCls}>Method</span>
        <select className={inputCls} value={block.method ?? 'POST'} onChange={(e) => onChange({ ...block, method: e.target.value as 'GET' | 'POST' | 'PUT' | 'PATCH' })}>
          {(['GET', 'POST', 'PUT', 'PATCH'] as const).map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>
      <div className="sm:col-span-2">
        <span className={labelCls}>Body template (JSON or raw text; empty = no body)</span>
        <textarea rows={3} className={`${inputCls} font-mono text-xs`} value={block.bodyTemplate ?? ''} placeholder='{"event": "{{trigger.type}}", "device": "{{device.name}}"}' onChange={(e) => onChange({ ...block, bodyTemplate: e.target.value })} />
        <p className={hintCls}>Tokens: {TEMPLATE_TOKENS}</p>
      </div>
    </div>
  );
}

function NotificationActionEditor({ block, onChange }: { block: Extract<AutomationActionBlock, { type: 'notification' }>; onChange: (b: AutomationActionBlock) => void }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-[160px_1fr]">
      <div>
        <span className={labelCls}>Severity</span>
        <select className={inputCls} value={block.severity} onChange={(e) => onChange({ ...block, severity: e.target.value as AutomationNotificationSeverity })}>
          {AUTOMATION_NOTIFICATION_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Title</span>
        <input className={inputCls} maxLength={300} value={block.titleTemplate} onChange={(e) => onChange({ ...block, titleTemplate: e.target.value })} />
      </div>
      <div className="sm:col-span-2">
        <span className={labelCls}>Message</span>
        <textarea rows={3} maxLength={2000} className={inputCls} value={block.messageTemplate} onChange={(e) => onChange({ ...block, messageTemplate: e.target.value })} />
        <p className={hintCls}>Tokens: {TEMPLATE_TOKENS}</p>
      </div>
    </div>
  );
}

function InternalActionEditor({ block, onChange }: { block: Extract<AutomationActionBlock, { type: 'internal' }>; onChange: (b: AutomationActionBlock) => void }) {
  const targetsQuery = useQuery({ queryKey: ['replication-targets'], queryFn: () => api.listReplicationTargets() });
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Operation</span>
        <select className={inputCls} value={block.kind} onChange={(e) => { const kind = e.target.value as 'backup' | 'replicationSync'; onChange({ ...block, kind, preset: kind === 'backup' ? (block.preset ?? 'config') : undefined, targetId: kind === 'replicationSync' ? block.targetId : undefined }); }}>
          <option value="backup">Backup UNM database</option>
          <option value="replicationSync">Replication sync push</option>
        </select>
      </div>
      {block.kind === 'backup' && (
        <>
          <div>
            <span className={labelCls}>Preset</span>
            <select className={inputCls} value={block.preset ?? 'config'} onChange={(e) => onChange({ ...block, preset: e.target.value as typeof block.preset })}>
              {BACKUP_PRESETS.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          <p className="sm:col-span-2 text-xs text-faint">Stored on the local volume (same path as the auto-backup worker).</p>
        </>
      )}
      {block.kind === 'replicationSync' && (
        <div>
          <span className={labelCls}>Target</span>
          <select className={`${inputCls} disabled:opacity-50`} disabled={(targetsQuery.data?.targets ?? []).length === 0} value={block.targetId ?? ''} onChange={(e) => onChange({ ...block, targetId: e.target.value })}>
            <option value="" disabled>{targetsQuery.isLoading ? 'Loading…' : 'Select a replication target'}</option>
            {(targetsQuery.data?.targets ?? []).map((t) => <option key={t.id} value={t.id}>{t.name} ({t.baseUrl})</option>)}
          </select>
        </div>
      )}
    </div>
  );
}

// ── Block cards ───────────────────────────────────────────────────────────────

const TRIGGER_LABEL: Record<AutomationTriggerBlock['type'], string> = { schedule: 'Schedule', metric: 'Metric condition', log: 'Log pattern', deviceStatus: 'Device status' };
const ACTION_LABEL: Record<AutomationActionBlock['type'], string> = { intent: 'Run plan (intent)', webhook: 'Webhook', notification: 'Notification', internal: 'Internal operation' };

function BlockCard({ title, onRemove, children }: { title: string; onRemove: () => void; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-card p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-sm font-semibold text-secondary">{title}</span>
        <button type="button" onClick={onRemove} aria-label={`Remove ${title}`} title="Remove block" className="rounded-md p-1 text-faint hover:bg-danger/10 hover:text-danger">
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
      {children}
    </div>
  );
}

// ── Dialog ────────────────────────────────────────────────────────────────────

interface RuleBuilderDialogProps {
  /** null = create; otherwise the rule being edited. */
  existing: Automation | null;
  onClose: () => void;
  onSaved: () => void;
}

/**
 * Create/edit dialog for an automation rule — a structured block-list builder
 * (no drag-drop canvas): trigger blocks + action blocks, each validated
 * client-side against the same rules as the API's validateAutomationDraft.
 */
export default function RuleBuilderDialog({ existing, onClose, onSaved }: RuleBuilderDialogProps) {
  const [name, setName] = useState(existing?.name ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [cooldownSec, setCooldownSec] = useState(String(existing?.cooldownSec ?? 0));

  // Deep-copy incoming blocks so edits never mutate the cached query data.
  const [triggers, setTriggers] = useState<AutomationTriggerBlock[]>(() => (existing ? JSON.parse(JSON.stringify(existing.triggers)) : [newScheduleTrigger()]));
  const [actions, setActions] = useState<AutomationActionBlock[]>(() => (existing ? JSON.parse(JSON.stringify(existing.actions)) : [newNotificationAction()]));
  // Show live client-side validation errors only after the first submit attempt.
  const [showErrors, setShowErrors] = useState(false);
  const draftErrors = showErrors ? validateDraft(buildDraft()) : [];

  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: () => api.plugins() });
  const plugins: Plugin[] = useMemo(() => pluginsQuery.data ?? [], [pluginsQuery.data]);

  const setTrigger = (block: AutomationTriggerBlock) => setTriggers((prev) => prev.map((t) => (t.id === block.id ? block : t)));
  const removeTrigger = (id: string) => setTriggers((prev) => prev.filter((t) => t.id !== id));
  const addAction = (block: AutomationActionBlock) => setActions((prev) => [...prev, block]);
  const setAction = (block: AutomationActionBlock) => setActions((prev) => prev.map((a) => (a.id === block.id ? block : a)));
  const removeAction = (id: string) => setActions((prev) => prev.filter((a) => a.id !== id));

  function buildDraft(): AutomationDraft {
    // Normalize metric compare values to numbers where possible.
    const cleanedTriggers = triggers.map((t): AutomationTriggerBlock => {
      if (t.type === 'metric' && t.mode === 'compare') {
        const raw = String(t.value ?? '').trim();
        return { ...t, value: raw !== '' && Number.isFinite(Number(raw)) ? Number(raw) : raw };
      }
      return t;
    });
    return {
      name: name.trim(),
      description: description.trim() || null,
      enabled,
      triggers: cleanedTriggers,
      actions,
      cooldownSec: Math.max(0, parseInt(cooldownSec, 10) || 0),
    };
  }

  const save = useMutation({ mutationFn: () => (existing ? api.updateAutomation(existing.id, buildDraft()) : api.createAutomation(buildDraft())) });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const errors = validateDraft(buildDraft());
    if (errors.length > 0) { setShowErrors(true); return; }
    save.mutate();
  }

  const apiDetails = save.error instanceof ApiError ? save.error.details : undefined;

  return (
    <DialogShell
      tag="form"
      title={existing ? `Edit rule — ${existing.name}` : 'New automation rule'}
      subtitle="When any trigger fires, all actions run in order and one run row is recorded."
      icon={<Workflow className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-3xl"
      onSubmit={handleSubmit}
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">Cancel</button>
          <button type="submit" disabled={save.isPending} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50">
            {save.isPending ? 'Saving…' : existing ? 'Save changes' : 'Create rule'}
          </button>
        </div>
      }
    >
      <div className="space-y-4">
        {(draftErrors.length > 0 || save.error || apiDetails) && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
            {apiDetails ? apiDetails.map((d, i) => <div key={i}>{d}</div>) : draftErrors.length > 0 ? draftErrors.map((d, i) => <div key={i}>{d}</div>) : <div>{(save.error as Error).message}</div>}
          </div>
        )}

        {/* Rule identity */}
        <section className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_140px]">
          <div>
            <label className={labelCls} htmlFor="rule-name">Name</label>
            <input id="rule-name" autoFocus maxLength={200} className={inputCls} value={name} placeholder="e.g. Alert on core router offline" onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <label className={labelCls} htmlFor="rule-cooldown">Cooldown (s)</label>
            <input id="rule-cooldown" type="number" min={0} className={inputCls} value={cooldownSec} onChange={(e) => setCooldownSec(e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <label className={labelCls} htmlFor="rule-desc">Description (optional)</label>
            <input id="rule-desc" maxLength={500} className={inputCls} value={description} placeholder="What this rule is for" onChange={(e) => setDescription(e.target.value)} />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled (disabled rules are never evaluated)
          </label>
        </section>

        {/* Triggers */}
        <section>
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-faint">Triggers — any one firing runs the actions</h3>
          <div className="space-y-3">
            {triggers.map((t) => (
              <BlockCard key={t.id} title={`${TRIGGER_LABEL[t.type]}${triggers.length > 1 ? ` (${t.id.slice(-4)})` : ''}`} onRemove={() => removeTrigger(t.id)}>
                {t.type === 'schedule' && <ScheduleTriggerEditor block={t} onChange={setTrigger} />}
                {t.type === 'metric' && <MetricTriggerEditor block={t} onChange={setTrigger} plugins={plugins} />}
                {t.type === 'log' && <LogTriggerEditor block={t} onChange={setTrigger} plugins={plugins} />}
                {t.type === 'deviceStatus' && <DeviceStatusTriggerEditor block={t} onChange={setTrigger} />}
              </BlockCard>
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <button type="button" onClick={() => setTriggers((p) => [...p, newScheduleTrigger()])} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Schedule</button>
            <button type="button" onClick={() => setTriggers((p) => [...p, newMetricTrigger()])} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Metric</button>
            <button type="button" onClick={() => setTriggers((p) => [...p, newLogTrigger()])} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Log</button>
            <button type="button" onClick={() => setTriggers((p) => [...p, newDeviceStatusTrigger()])} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Device status</button>
          </div>
        </section>

        {/* Actions */}
        <section>
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-faint">Actions — run in order on every firing</h3>
          <div className="space-y-3">
            {actions.map((a) => (
              <BlockCard key={a.id} title={`${ACTION_LABEL[a.type]}${actions.length > 1 ? ` (${a.id.slice(-4)})` : ''}`} onRemove={() => removeAction(a.id)}>
                {a.type === 'intent' && <IntentActionEditor block={a} onChange={setAction} plugins={plugins} />}
                {a.type === 'webhook' && <WebhookActionEditor block={a} onChange={setAction} />}
                {a.type === 'notification' && <NotificationActionEditor block={a} onChange={setAction} />}
                {a.type === 'internal' && <InternalActionEditor block={a} onChange={setAction} />}
              </BlockCard>
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <button type="button" onClick={() => addAction(newIntentAction())} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Run plan</button>
            <button type="button" onClick={() => addAction(newWebhookAction())} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Webhook</button>
            <button type="button" onClick={() => addAction(newNotificationAction())} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Notification</button>
            <button type="button" onClick={() => addAction(newInternalAction())} className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"><Plus className="h-3 w-3" /> Internal</button>
          </div>
        </section>

        <p className="text-xs text-faint">Cooldown applies to the whole rule: after any firing, no trigger of this rule can fire again until {cooldownSec || 0} s have passed.</p>
      </div>
    </DialogShell>
  );
}
