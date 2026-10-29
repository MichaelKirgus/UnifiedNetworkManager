import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { DndContext, KeyboardSensor, PointerSensor, closestCenter, useDraggable, useDroppable, useSensor, useSensors, type DragEndEvent } from '@dnd-kit/core';
import { SortableContext, arrayMove, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import clsx from 'clsx';
import { GripVertical, Trash2, Workflow } from 'lucide-react';
import {
  api, ApiError, Automation, AutomationActionBlock, AutomationDraft, AutomationNotificationSeverity, AutomationScheduleSpec, AutomationTriggerBlock,
  AUTOMATION_NOTIFICATION_SEVERITIES, BACKUP_PRESETS, CatalogEntry, DEVICE_STATUSES, DeviceStatusValue, FLOW_CLASSES, FLOW_DIRECTIONS,
  FlowClassValue, FlowDirectionValue, InputSchema, LOG_LEVELS, LogLevel, METRIC_COMPARATORS, MetricComparator, Plugin, Site,
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
function newFlowTrigger(): AutomationTriggerBlock {
  // 100 MB over a 5-minute window — a sane starting point the user will tune.
  return { id: newId('t'), type: 'flow', comparator: '>=', thresholdBytes: 104_857_600, windowSec: 300 };
}
function newContainerLogTrigger(): AutomationTriggerBlock {
  return { id: newId('t'), type: 'containerLog', pluginId: '', appName: '', pattern: '' };
}
function newUpdateTrigger(): AutomationTriggerBlock {
  return { id: newId('t'), type: 'updateAvailable', condition: 'available' };
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
      case 'flow': {
        if (!METRIC_COMPARATORS.includes(t.comparator)) errors.push(`${where}: pick a comparator`);
        if (!Number.isFinite(t.thresholdBytes) || t.thresholdBytes < 0) errors.push(`${where}: threshold must be a non-negative number of bytes`);
        if (t.windowSec !== undefined && (!Number.isFinite(t.windowSec) || t.windowSec < 60 || t.windowSec > 3_600_000)) {
          errors.push(`${where}: window must be between 60 s and one year`);
        }
        break;
      }
      case 'containerLog': {
        if (!t.pluginId) errors.push(`${where}: pick a plugin (one that exposes containers.logs.read)`);
        if (!t.appName.trim()) errors.push(`${where}: app / container name is required`);
        if (!t.pattern.trim()) errors.push(`${where}: pattern is required`);
        else { try { new RegExp(t.pattern); } catch (e) { errors.push(`${where}: invalid regex — ${(e as Error).message}`); } }
        if (t.tail !== undefined && (!Number.isInteger(t.tail) || t.tail < 20 || t.tail > 5000)) {
          errors.push(`${where}: tail must be an integer between 20 and 5000`);
        }
        break;
      }
      case 'updateAvailable': {
        if (t.namePattern) { try { new RegExp(t.namePattern); } catch (e) { errors.push(`${where}: invalid name regex — ${(e as Error).message}`); } }
        if (t.defer?.maxWaitHours !== undefined && (!Number.isFinite(t.defer.maxWaitHours) || t.defer.maxWaitHours <= 0)) {
          errors.push(`${where}: max wait must be a positive number of hours`);
        }
        break;
      }
    }
  }
  if (draft.actions.length === 0) errors.push('Add at least one action');
  for (const [i, a] of draft.actions.entries()) {
    const where = `Action ${i + 1}`;
    switch (a.type) {
      case 'intent': {
        // With resolveFromTrigger the row's apply path fills plugin/action/device at fire time.
        if (a.resolveFromTrigger !== 'update') {
          if (!a.pluginId) errors.push(`${where}: pick a plugin`);
          else if (!a.actionId) errors.push(`${where}: pick an action`);
          else if ((a.devices.deviceIds ?? []).length === 0) errors.push(`${where}: select at least one device`);
        }
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

/** Human byte formatting for the flow-threshold helper (≈ 100 MB). */
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v).toLocaleString() : v.toFixed(1)} ${units[i]}`;
}

/** Reorders a block list by id; dropping on the zone itself moves to the end. */
function reorderByIds<T extends { id: string }>(list: T[], activeId: string, overId: string): T[] {
  const from = list.findIndex((b) => b.id === activeId);
  let to = list.findIndex((b) => b.id === overId);
  if (to === -1) to = list.length - 1;
  if (from === -1 || from === to) return list;
  return arrayMove(list, from, to);
}

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

/** Shared schedule-spec fields (kind + value + preview) — used by the schedule
 * trigger editor and the updateAvailable defer window. */
function ScheduleSpecFields({ spec, onChange }: { spec: AutomationScheduleSpec; onChange: (s: AutomationScheduleSpec) => void }) {
  return (
    <>
      <div>
        <span className={labelCls}>Kind</span>
        <select className={inputCls} value={spec.kind} onChange={(e) => {
          const kind = e.target.value as 'cron' | 'interval' | 'dailyAt';
          onChange(kind === 'cron' ? { kind, expr: spec.kind === 'cron' ? spec.expr : '' } : kind === 'interval' ? { kind, everyMinutes: spec.kind === 'interval' ? spec.everyMinutes : 5 } : { kind, time: spec.kind === 'dailyAt' ? spec.time : '09:00' });
        }}>
          <option value="cron">Cron expression</option>
          <option value="interval">Fixed interval</option>
          <option value="dailyAt">Daily at time</option>
        </select>
      </div>
      {spec.kind === 'cron' && (
        <div>
          <span className={labelCls}>Cron expression</span>
          <input className={inputCls} value={spec.expr} placeholder="*/5 * * * *" onChange={(e) => onChange({ kind: 'cron', expr: e.target.value })} />
        </div>
      )}
      {spec.kind === 'interval' && (
        <div>
          <span className={labelCls}>Every (minutes)</span>
          <input type="number" min={1} className={inputCls} value={Number.isFinite(spec.everyMinutes) ? spec.everyMinutes : ''} onChange={(e) => onChange({ kind: 'interval', everyMinutes: Number(e.target.value) })} />
        </div>
      )}
      {spec.kind === 'dailyAt' && (
        <div>
          <span className={labelCls}>Time (24h, server local)</span>
          <input type="time" className={inputCls} value={spec.time} onChange={(e) => onChange({ kind: 'dailyAt', time: e.target.value })} />
        </div>
      )}
      <div className="sm:col-span-2">
        <SchedulePreview kind={spec.kind} expr={spec.kind === 'cron' ? spec.expr : spec.kind === 'interval' ? String(spec.everyMinutes) : spec.time} />
      </div>
    </>
  );
}

function ScheduleTriggerEditor({ block, onChange }: { block: Extract<AutomationTriggerBlock, { type: 'schedule' }>; onChange: (b: AutomationTriggerBlock) => void }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <ScheduleSpecFields spec={block.schedule} onChange={(s) => onChange({ ...block, schedule: s })} />
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

function FlowTriggerEditor({ block, onChange }: { block: Extract<AutomationTriggerBlock, { type: 'flow' }>; onChange: (b: AutomationTriggerBlock) => void }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Direction</span>
        <select className={inputCls} value={block.direction ?? 'any'} onChange={(e) => onChange({ ...block, direction: e.target.value as FlowDirectionValue })}>
          {FLOW_DIRECTIONS.map((d) => <option key={d} value={d}>{d === 'any' ? 'Either endpoint' : d.toUpperCase()}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Endpoint class (optional)</span>
        <select className={inputCls} value={block.endpointClass ?? ''} onChange={(e) => onChange({ ...block, endpointClass: e.target.value === '' ? undefined : (e.target.value as FlowClassValue) })}>
          <option value="">Any</option>
          {FLOW_CLASSES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>IP (optional)</span>
        <input className={inputCls} value={block.ip ?? ''} placeholder="e.g. 10.0.0.5 — empty = any endpoint" onChange={(e) => onChange({ ...block, ip: e.target.value.trim() || undefined })} />
      </div>
      <div>
        <span className={labelCls}>Window (seconds)</span>
        <input type="number" min={60} max={3_600_000} className={inputCls} value={block.windowSec ?? 300} onChange={(e) => onChange({ ...block, windowSec: e.target.value === '' ? undefined : Number(e.target.value) })} />
        <p className={hintCls}>Sliding window over the flow aggregates (default 300 s).</p>
      </div>
      <div>
        <span className={labelCls}>Comparator</span>
        <select className={inputCls} value={block.comparator} onChange={(e) => onChange({ ...block, comparator: e.target.value as MetricComparator })}>
          {METRIC_COMPARATORS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Threshold (bytes)</span>
        <input type="number" min={0} step="any" className={inputCls} value={Number.isFinite(block.thresholdBytes) ? block.thresholdBytes : ''} onChange={(e) => onChange({ ...block, thresholdBytes: e.target.value === '' ? NaN : Number(e.target.value) })} />
        <p className={hintCls}>≈ {formatBytes(Number(block.thresholdBytes) || 0)} per window (estimated bytes, summed across matching tuples).</p>
      </div>
      <div>
        <span className={labelCls}>Sustained for (seconds)</span>
        <input type="number" min={0} className={inputCls} value={block.durationSec ?? 0} onChange={(e) => onChange({ ...block, durationSec: Math.max(0, Number(e.target.value) || 0) })} />
        <p className={hintCls}>0 = fire immediately; &gt;0 requires the condition to hold continuously for that long.</p>
      </div>
      <ScopeEditor scope={block.scope} onChange={(scope) => onChange({ ...block, scope: Object.keys(scope).length ? scope : undefined })} />
    </div>
  );
}

function ContainerLogTriggerEditor({ block, onChange, plugins }: { block: Extract<AutomationTriggerBlock, { type: 'containerLog' }>; onChange: (b: AutomationTriggerBlock) => void; plugins: Plugin[] }) {
  // App-name suggestions from the live Containers overview — best-effort: users
  // without containers:read get a 403 and the datalist simply stays empty.
  const containersQuery = useQuery({ queryKey: ['containers'], queryFn: () => api.containers(), staleTime: 60_000 });
  const appNames = useMemo(() => {
    const names = new Set<string>();
    for (const row of containersQuery.data?.containers ?? []) {
      if (!block.pluginId || row.pluginId === block.pluginId) names.add(row.name);
    }
    return [...names].sort();
  }, [containersQuery.data, block.pluginId]);

  let regexError: string | null = null;
  if (block.pattern.trim()) { try { new RegExp(block.pattern); } catch (e) { regexError = (e as Error).message; } }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Plugin</span>
        <select className={inputCls} value={block.pluginId} onChange={(e) => onChange({ ...block, pluginId: e.target.value })}>
          <option value="" disabled>Select a plugin</option>
          {plugins.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <p className={hintCls}>Must expose the containers.logs.read action (e.g. TrueNAS SCALE, Docker).</p>
      </div>
      <div>
        <span className={labelCls}>App / container name</span>
        <input className={inputCls} list={`cl-apps-${block.id}`} value={block.appName} placeholder="as shown on the Containers page" onChange={(e) => onChange({ ...block, appName: e.target.value })} />
        {appNames.length > 0 && (
          <datalist id={`cl-apps-${block.id}`}>
            {appNames.map((n) => <option key={n} value={n} />)}
          </datalist>
        )}
      </div>
      <div>
        <span className={labelCls}>Tail (lines)</span>
        <input type="number" min={20} max={5000} className={inputCls} value={block.tail ?? 300} onChange={(e) => onChange({ ...block, tail: e.target.value === '' ? undefined : Number(e.target.value) })} />
        <p className={hintCls}>Recent lines re-scanned each tick (20–5000, default 300).</p>
      </div>
      <div>
        <span className={labelCls}>Regex pattern</span>
        <input className={inputCls} value={block.pattern} placeholder="e.g. error|fatal|OOM" onChange={(e) => onChange({ ...block, pattern: e.target.value })} />
        {regexError && <p className="mt-1 text-xs text-danger">Invalid regex — {regexError}</p>}
      </div>
      <div className="sm:col-span-2">
        <p className={hintCls}>Fires on NEW lines only — a persisted seen-line ring buffer dedupes, and the first run seeds without firing. At most one firing per tick, attributed to the device whose log matched.</p>
      </div>
      <ScopeEditor scope={block.scope} onChange={(scope) => onChange({ ...block, scope: Object.keys(scope).length ? scope : undefined })} />
    </div>
  );
}

function UpdateTriggerEditor({ block, onChange, plugins }: { block: Extract<AutomationTriggerBlock, { type: 'updateAvailable' }>; onChange: (b: AutomationTriggerBlock) => void; plugins: Plugin[] }) {
  let regexError: string | null = null;
  if (block.namePattern) { try { new RegExp(block.namePattern); } catch (e) { regexError = (e as Error).message; } }

  const setDefer = (defer: { schedule: AutomationScheduleSpec; maxWaitHours?: number } | undefined) => onChange({ ...block, defer });

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Condition</span>
        <select className={inputCls} value={block.condition} onChange={(e) => onChange({ ...block, condition: e.target.value as 'available' | 'resolved' })}>
          <option value="available">Update appeared / advanced</option>
          <option value="resolved">Update disappeared (applied/withdrawn)</option>
        </select>
      </div>
      <div>
        <span className={labelCls}>Plugin (optional)</span>
        <select className={inputCls} value={block.pluginId ?? ''} onChange={(e) => onChange({ ...block, pluginId: e.target.value || undefined })}>
          <option value="">Any plugin</option>
          {plugins.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Kinds (comma-separated, optional)</span>
        <input className={inputCls} value={(block.kinds ?? []).join(', ')} placeholder="firmware, os-package, docker-image, app" onChange={(e) => {
          const kinds = e.target.value.split(',').map((k) => k.trim()).filter(Boolean);
          onChange({ ...block, kinds: kinds.length ? kinds : undefined });
        }} />
      </div>
      <div>
        <span className={labelCls}>Name pattern (regex, optional)</span>
        <input className={inputCls} value={block.namePattern ?? ''} placeholder="e.g. ^os$" onChange={(e) => onChange({ ...block, namePattern: e.target.value || undefined })} />
        {regexError && <p className="mt-1 text-xs text-danger">Invalid regex — {regexError}</p>}
      </div>
      <div className="flex items-center gap-2">
        <input id={`upd-reboot-${block.id}`} type="checkbox" checked={block.rebootRequired === true} onChange={(e) => onChange({ ...block, rebootRequired: e.target.checked ? true : undefined })} />
        <label htmlFor={`upd-reboot-${block.id}`} className="text-sm text-secondary">Only rows that require a reboot</label>
      </div>
      <div className="flex items-center gap-2">
        <input id={`upd-noreboot-${block.id}`} type="checkbox" checked={block.rebootRequired === false} onChange={(e) => onChange({ ...block, rebootRequired: e.target.checked ? false : undefined })} />
        <label htmlFor={`upd-noreboot-${block.id}`} className="text-sm text-secondary">Only rows that do NOT require a reboot</label>
      </div>

      {block.defer && (
        <details open className="sm:col-span-2 rounded-md border border-border bg-muted/30 px-3 py-2">
          <summary className="cursor-pointer select-none text-xs font-medium uppercase tracking-wide text-faint hover:text-secondary">Deferral window — hold each firing until the next slot</summary>
          <div className="mt-2 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <ScheduleSpecFields spec={block.defer.schedule} onChange={(s) => setDefer({ ...block.defer!, schedule: s })} />
            <div>
              <span className={labelCls}>Max wait (hours, optional)</span>
              <input type="number" min={0.5} step={0.5} className={inputCls} value={block.defer.maxWaitHours ?? ''} placeholder="unbounded — run-asap on the slot" onChange={(e) => setDefer({ ...block.defer!, maxWaitHours: e.target.value === '' ? undefined : Number(e.target.value) })} />
              <p className={hintCls}>Fire immediately once an event has waited this long, even if no slot has passed yet.</p>
            </div>
          </div>
        </details>
      )}
      {!block.defer && (
        <button type="button" onClick={() => setDefer({ schedule: { kind: 'dailyAt', time: '02:00' } })} className="justify-self-start rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-muted">
          + Add deferral window
        </button>
      )}
      <div className="sm:col-span-2">
        <p className={hintCls}>Fires on TRANSITIONS only — a row that stays listed does not re-fire. With a deferral window, firings are held until the next slot (version advances refresh the snapshot without moving the slot; an 'available' update disappearing cancels its pending firing).</p>
      </div>
      <ScopeEditor scope={block.scope} onChange={(scope) => onChange({ ...block, scope: Object.keys(scope).length ? scope : undefined })} />
    </div>
  );
}

// ── Action editors ────────────────────────────────────────────────────────────

function IntentActionEditor({ block, onChange, plugins }: { block: Extract<AutomationActionBlock, { type: 'intent' }>; onChange: (b: AutomationActionBlock) => void; plugins: Plugin[] }) {
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: () => api.devices() });
  const actionsQuery = useQuery({
    queryKey: ['pluginActions', block.pluginId ?? ''],
    queryFn: () => api.pluginActions(block.pluginId as string),
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

  const fromTrigger = block.resolveFromTrigger === 'update';

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <span className={labelCls}>Plugin</span>
        <select className={`${inputCls} disabled:opacity-50`} value={block.pluginId ?? ''} onChange={(e) => onChange({ ...block, pluginId: e.target.value || undefined, actionId: '', input: {}, devices: { deviceIds: [] } })} disabled={fromTrigger}>
          <option value="" disabled>Select a plugin</option>
          {plugins.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>
      <div>
        <span className={labelCls}>Action (catalog)</span>
        <select className={`${inputCls} disabled:opacity-50`} disabled={!block.pluginId || catalog.length === 0 || fromTrigger} value={block.actionId ?? ''} onChange={(e) => {
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
      {fromTrigger && (
        <div className="sm:col-span-2 rounded-md border border-accent-indigo/40 bg-accent-indigo/10 px-3 py-2 text-xs text-secondary">
          Plugin, action and target device are filled at fire time from the firing update row's apply path (device_updates.applyActionId / applyInput). Rows without an apply path skip this action with a logged reason.
        </div>
      )}
      <div className="sm:col-span-2">
        <span className={labelCls}>Target devices ({eligibleDevices.length} with this plugin)</span>
        {fromTrigger ? (
          <p className={hintCls}>Ignored in trigger-resolved mode — the firing row's own device is always the target.</p>
        ) : eligibleDevices.length === 0 ? (
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
      <div className="flex items-center gap-4 sm:col-span-2">
        <label className="flex items-center gap-2 text-sm text-secondary">
          <input type="checkbox" checked={fromTrigger} onChange={(e) => onChange({ ...block, resolveFromTrigger: e.target.checked ? 'update' : undefined })} />
          Resolve plugin/action/device from the firing update row
        </label>
        <label className="flex items-center gap-2 text-sm text-secondary">
          <input type="checkbox" checked={block.requireNoReboot === true} onChange={(e) => onChange({ ...block, requireNoReboot: e.target.checked || undefined })} />
          Skip when the update requires a reboot
        </label>
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

const TRIGGER_LABEL: Record<AutomationTriggerBlock['type'], string> = { schedule: 'Schedule', metric: 'Metric condition', log: 'Log pattern', deviceStatus: 'Device status', flow: 'Flow traffic', containerLog: 'Container log', updateAvailable: 'Update available' };
const ACTION_LABEL: Record<AutomationActionBlock['type'], string> = { intent: 'Run plan (intent)', webhook: 'Webhook', notification: 'Notification', internal: 'Internal operation' };

/** Drop-zone ids for the two canvas columns. */
const ZONE_TRIGGERS = 'zone-triggers';
const ZONE_ACTIONS = 'zone-actions';

/** Palette entries — one per block type; `make` is the matching factory. */
const TRIGGER_PALETTE: Array<{ type: AutomationTriggerBlock['type']; label: string; make: () => AutomationTriggerBlock }> = [
  { type: 'schedule', label: 'Schedule', make: newScheduleTrigger },
  { type: 'metric', label: 'Metric', make: newMetricTrigger },
  { type: 'log', label: 'Log pattern', make: newLogTrigger },
  { type: 'deviceStatus', label: 'Device status', make: newDeviceStatusTrigger },
  { type: 'flow', label: 'Flow traffic', make: newFlowTrigger },
  { type: 'containerLog', label: 'Container log', make: newContainerLogTrigger },
  { type: 'updateAvailable', label: 'Update available', make: newUpdateTrigger },
];
const ACTION_PALETTE: Array<{ type: AutomationActionBlock['type']; label: string; make: () => AutomationActionBlock }> = [
  { type: 'intent', label: 'Run plan', make: newIntentAction },
  { type: 'webhook', label: 'Webhook', make: newWebhookAction },
  { type: 'notification', label: 'Notification', make: newNotificationAction },
  { type: 'internal', label: 'Internal op', make: newInternalAction },
];

/** Draggable palette chip — grip drags it into a zone; the label click-appends. */
function PaletteChip({ zone, entry, onAdd }: { zone: 'triggers' | 'actions'; entry: { type: string; label: string }; onAdd: () => void }) {
  const { attributes, listeners, setNodeRef, isDragging } = useDraggable({ id: `palette-${zone}-${entry.type}`, data: { kind: 'palette', zone, blockType: entry.type } });
  return (
    <div ref={setNodeRef} className={clsx('inline-flex items-stretch overflow-hidden rounded-md border bg-card', isDragging ? 'border-focus-ring opacity-60' : 'border-border')}>
      <button type="button" aria-label={`Drag ${entry.label} into the list`} title="Drag into the list — or click the label to append"
        className="cursor-grab touch-none px-1.5 text-faint hover:bg-muted active:cursor-grabbing" {...attributes} {...listeners}>
        <GripVertical className="h-3 w-3" />
      </button>
      <button type="button" onClick={onAdd} title={`Add ${entry.label}`} className="px-2 py-1 text-xs font-medium text-secondary hover:bg-muted">
        {entry.label}
      </button>
    </div>
  );
}

/** One droppable canvas zone (a column of sortable blocks + its palette row). */
function ZoneDrop({ id, children }: { id: string; children: React.ReactNode }) {
  const { setNodeRef, isOver } = useDroppable({ id });
  return (
    <div ref={setNodeRef} className={clsx('rounded-md border p-2 transition-colors', isOver ? 'border-focus-ring bg-muted/40' : 'border-border bg-muted/20')}>
      {children}
    </div>
  );
}

/** Sortable wrapper around a BlockCard — the grip handle carries dnd-kit. */
function SortableBlock({ id, title, onRemove, children }: { id: string; title: string; onRemove: () => void; children: React.ReactNode }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id });
  return (
    <div ref={setNodeRef} style={{ transform: CSS.Transform.toString(transform), transition }} className={clsx('relative', isDragging && 'z-10 opacity-70')}>
      <BlockCard title={title} onRemove={onRemove} dragHandle={
        <button type="button" aria-label={`Reorder ${title}`} title="Drag to reorder"
          className="-ml-1 cursor-grab touch-none rounded p-1 text-faint hover:bg-muted active:cursor-grabbing" {...attributes} {...listeners}>
          <GripVertical className="h-4 w-4" />
        </button>
      }>
        {children}
      </BlockCard>
    </div>
  );
}

function BlockCard({ title, onRemove, dragHandle, children }: { title: string; onRemove: () => void; dragHandle?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-card p-3 shadow-sm">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center text-sm font-semibold text-secondary">{dragHandle}<span className="truncate">{title}</span></span>
        <button type="button" onClick={onRemove} aria-label={`Remove ${title}`} title="Remove block" className="shrink-0 rounded-md p-1 text-faint hover:bg-danger/10 hover:text-danger">
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
  /** Pre-fill for a fresh rule (e.g. from a template) — block ids are regenerated so two rules never share them. */
  initialDraft?: Pick<AutomationDraft, 'name' | 'description' | 'enabled' | 'triggers' | 'actions' | 'cooldownSec'>;
  onClose: () => void;
  onSaved: () => void;
}

/**
 * Create/edit dialog for an automation rule — a drag-and-drop block canvas:
 * two drop zones (Triggers | Actions), each a sortable list of block cards with
 * a palette row of draggable chips. Reorder by dragging the grip handle; add by
 * dragging a chip into a zone or clicking its label. Every block is validated
 * client-side against the same rules as the API's validateAutomationDraft.
 */
export default function RuleBuilderDialog({ existing, initialDraft, onClose, onSaved }: RuleBuilderDialogProps) {
  // A template pre-fill is a CREATE with seed values — regenerate block ids so
  // the draft's placeholder ids never collide across rules.
  const seeded = !existing && initialDraft ? JSON.parse(JSON.stringify(initialDraft)) : null;
  const [name, setName] = useState(existing?.name ?? seeded?.name ?? '');
  const [description, setDescription] = useState(existing?.description ?? seeded?.description ?? '');
  const [enabled, setEnabled] = useState(existing?.enabled ?? (seeded ? seeded.enabled !== false : true));
  const [cooldownSec, setCooldownSec] = useState(String(existing?.cooldownSec ?? seeded?.cooldownSec ?? 0));

  // Deep-copy incoming blocks so edits never mutate the cached query data.
  const [triggers, setTriggers] = useState<AutomationTriggerBlock[]>(() => {
    if (existing) return JSON.parse(JSON.stringify(existing.triggers)) as AutomationTriggerBlock[];
    if (seeded?.triggers?.length) return (seeded.triggers as AutomationTriggerBlock[]).map((t) => ({ ...t, id: newId('t') }));
    return [newScheduleTrigger()];
  });
  const [actions, setActions] = useState<AutomationActionBlock[]>(() => {
    if (existing) return JSON.parse(JSON.stringify(existing.actions)) as AutomationActionBlock[];
    if (seeded?.actions?.length) return (seeded.actions as AutomationActionBlock[]).map((a) => ({ ...a, id: newId('a') }));
    return [newNotificationAction()];
  });
  // Show live client-side validation errors only after the first submit attempt.
  const [showErrors, setShowErrors] = useState(false);
  const draftErrors = showErrors ? validateDraft(buildDraft()) : [];

  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: () => api.plugins() });
  const plugins: Plugin[] = useMemo(() => pluginsQuery.data ?? [], [pluginsQuery.data]);

  const setTrigger = (block: AutomationTriggerBlock) => setTriggers((prev) => prev.map((t) => (t.id === block.id ? block : t)));
  const removeTrigger = (id: string) => setTriggers((prev) => prev.filter((t) => t.id !== id));
  const addAction = (block: AutomationActionBlock) => setActions((prev) => [...prev, block]);
  const setAction = (block: AutomationActionBlock) => setActions((prev) => prev.map((a) => (a.id === block.id ? block : a)));
  // ── Drag-and-drop canvas wiring ────────────────────────────────────────────
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor),
  );

  /** Which canvas zone a drag id belongs to (a zone droppable or one of its blocks). */
  function zoneOf(id: string): 'triggers' | 'actions' | null {
    if (id === ZONE_TRIGGERS) return 'triggers';
    if (id === ZONE_ACTIONS) return 'actions';
    if (triggers.some((t) => t.id === id)) return 'triggers';
    if (actions.some((a) => a.id === id)) return 'actions';
    return null;
  }

  function handleDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (!over) return;
    const data = active.data.current as { kind?: string; zone?: string; blockType?: string } | undefined;
    const overZone = zoneOf(String(over.id));
    if (!overZone) return;

    // Palette chip dropped into its own zone → insert a fresh block at the hovered position.
    if (data?.kind === 'palette') {
      if (data.zone !== overZone || !data.blockType) return; // chips only add to their own zone
      const blockType = data.blockType;
      if (overZone === 'triggers') {
        const make = TRIGGER_PALETTE.find((p) => p.type === blockType)?.make;
        if (!make) return;
        setTriggers((prev) => { const i = prev.findIndex((t) => t.id === String(over!.id)); const next = [...prev]; next.splice(i === -1 ? prev.length : i, 0, make()); return next; });
      } else {
        const make = ACTION_PALETTE.find((p) => p.type === blockType)?.make;
        if (!make) return;
        setActions((prev) => { const i = prev.findIndex((a) => a.id === String(over!.id)); const next = [...prev]; next.splice(i === -1 ? prev.length : i, 0, make()); return next; });
      }
      return;
    }

    // Existing block → reorder within its own zone only (cross-zone drops snap back).
    if (zoneOf(String(active.id)) !== overZone || active.id === over.id) return;
    const activeId = String(active.id);
    const overId = String(over.id);
    if (overZone === 'triggers') setTriggers((prev) => reorderByIds(prev, activeId, overId));
    else setActions((prev) => reorderByIds(prev, activeId, overId));
  }  const removeAction = (id: string) => setActions((prev) => prev.filter((a) => a.id !== id));

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
      subtitle="Drag blocks to reorder or drag a chip into a zone to add it — when any trigger fires, all actions run in order and one run row is recorded."
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

        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
          {/* Triggers */}
          <section>
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-faint">Triggers — any one firing runs the actions</h3>
            <ZoneDrop id={ZONE_TRIGGERS}>
              {triggers.length === 0 && (
                <p className="px-1 py-4 text-center text-xs text-faint">No triggers yet — drag a chip in, or click one to add it.</p>
              )}
              <SortableContext items={triggers.map((t) => t.id)} strategy={verticalListSortingStrategy}>
                <div className="space-y-3">
                  {triggers.map((t) => (
                    <SortableBlock key={t.id} id={t.id} title={`${TRIGGER_LABEL[t.type]}${triggers.length > 1 ? ` (${t.id.slice(-4)})` : ''}`} onRemove={() => removeTrigger(t.id)}>
                      {t.type === 'schedule' && <ScheduleTriggerEditor block={t} onChange={setTrigger} />}
                      {t.type === 'metric' && <MetricTriggerEditor block={t} onChange={setTrigger} plugins={plugins} />}
                      {t.type === 'log' && <LogTriggerEditor block={t} onChange={setTrigger} plugins={plugins} />}
                      {t.type === 'deviceStatus' && <DeviceStatusTriggerEditor block={t} onChange={setTrigger} />}
                      {t.type === 'flow' && <FlowTriggerEditor block={t} onChange={setTrigger} />}
                      {t.type === 'containerLog' && <ContainerLogTriggerEditor block={t} onChange={setTrigger} plugins={plugins} />}
                      {t.type === 'updateAvailable' && <UpdateTriggerEditor block={t} onChange={setTrigger} plugins={plugins} />}
                    </SortableBlock>
                  ))}
                </div>
              </SortableContext>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-border/60 pt-2">
                <span className="mr-1 text-[11px] font-medium uppercase tracking-wide text-faint">Add:</span>
                {TRIGGER_PALETTE.map((p) => (
                  <PaletteChip key={p.type} zone="triggers" entry={p} onAdd={() => setTriggers((prev) => [...prev, p.make()])} />
                ))}
              </div>
            </ZoneDrop>
          </section>

          {/* Actions */}
          <section>
            <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-faint">Actions — run in order on every firing</h3>
            <ZoneDrop id={ZONE_ACTIONS}>
              {actions.length === 0 && (
                <p className="px-1 py-4 text-center text-xs text-faint">No actions yet — drag a chip in, or click one to add it.</p>
              )}
              <SortableContext items={actions.map((a) => a.id)} strategy={verticalListSortingStrategy}>
                <div className="space-y-3">
                  {actions.map((a) => (
                    <SortableBlock key={a.id} id={a.id} title={`${ACTION_LABEL[a.type]}${actions.length > 1 ? ` (${a.id.slice(-4)})` : ''}`} onRemove={() => removeAction(a.id)}>
                      {a.type === 'intent' && <IntentActionEditor block={a} onChange={setAction} plugins={plugins} />}
                      {a.type === 'webhook' && <WebhookActionEditor block={a} onChange={setAction} />}
                      {a.type === 'notification' && <NotificationActionEditor block={a} onChange={setAction} />}
                      {a.type === 'internal' && <InternalActionEditor block={a} onChange={setAction} />}
                    </SortableBlock>
                  ))}
                </div>
              </SortableContext>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-border/60 pt-2">
                <span className="mr-1 text-[11px] font-medium uppercase tracking-wide text-faint">Add:</span>
                {ACTION_PALETTE.map((p) => (
                  <PaletteChip key={p.type} zone="actions" entry={p} onAdd={() => addAction(p.make())} />
                ))}
              </div>
            </ZoneDrop>
          </section>
        </DndContext>

        <p className="text-xs text-faint">Cooldown applies to the whole rule: after any firing, no trigger of this rule can fire again until {cooldownSec || 0} s have passed.</p>
      </div>
    </DialogShell>
  );
}
