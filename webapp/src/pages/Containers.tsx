import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowUpCircle, CheckCircle2, ChevronDown, ChevronRight, ChevronUp, Container, Download, EyeOff, FileCode2, FolderOpen, Loader2, Play, Plus, RotateCw, ScrollText, Square, Terminal as TerminalIcon, Trash2, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type FormEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { ConsoleDialog } from '../components/ConsoleDialog';
import { ContainerLogsView } from '../components/ContainerLogs';
import { CreateAppCandidate, type AppMode } from './CreateAppPage';
import { FileBrowserDialog } from '../components/FileBrowserDialog';
import { ResizableDialog } from '../components/ResizableDialog';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { DialogShell } from '../components/DialogShell';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, CatalogEntry, ContainerNetwork, ContainerRow, ContainerServiceDetail, DockerImageRow } from '../api/client';
import { useTimeFormat } from '../utils/time';

/** One container's live stat snapshot from a probe (key 'containerStats'). */
interface LiveContainerStat {
  name: string;
  cpuPct?: number;
  memUsedBytes?: number;
  memLimitBytes?: number;
  netRxRate?: number;
  netTxRate?: number;
  blkReadRate?: number;
  blkWriteRate?: number;
}

/** Aggregates live per-container stats into app-level totals (same rule as the
 * plugin: RAM + I/O summed, CPU = busiest container). Keys match extra.stats. */
function aggregateLiveStats(stats: LiveContainerStat[]): Record<string, number> | null {
  if (stats.length === 0) return null;
  const s: Record<string, number> = {};
  for (const c of stats) {
    if (c.cpuPct !== undefined) s['cpuMax'] = Math.max(s['cpuMax'] ?? 0, c.cpuPct);
    if (c.memUsedBytes !== undefined) s['memUsedBytes'] = (s['memUsedBytes'] ?? 0) + c.memUsedBytes;
    for (const k of ['netRxRate', 'netTxRate', 'blkReadRate', 'blkWriteRate'] as const) {
      if (c[k] !== undefined) s[k] = (s[k] ?? 0) + (c[k] as number);
    }
  }
  return s;
}

/** Looks up a live stat for one service/container by name (exact, then row-name fallback). */
function liveStatFor(byName: Record<string, LiveContainerStat>, serviceName?: string | null, rowName?: string): LiveContainerStat | undefined {
  if (!byName) return undefined;
  const keys = Object.keys(byName);
  if (serviceName && byName[serviceName]) return byName[serviceName];
  if (rowName && byName[rowName]) return byName[rowName];
  // TrueNAS names multi-container app containers `<app>-<service>` — try a suffix match.
  if (serviceName) {
    const hit = keys.find((k) => k === serviceName || k.endsWith(`-${serviceName}`));
    if (hit) return byName[hit];
  }
  return undefined;
}

/** Severity rank for aggregating non-running member states — a restarting or
 * created (mid-start) container outranks a plain exited one. */
function stateRank(s: string): number {
  if (s === 'restarting') return 3;
  if (s === 'created' || s === 'paused') return 2;
  return 1; // exited / dead / unknown
}

/** Normalizes one probe `containerStates` payload into name → lowercase docker
 * state. Fresh plugins report the real state ('exited', …); older ones reported
 * a bare running set ({ status: 'running' }) — normalize both to strings. */
function normalizeContainerStates(v: unknown): Record<string, string> | null {
  if (!v || typeof v !== 'object') return null;
  const out: Record<string, string> = {};
  for (const [name, s] of Object.entries(v as Record<string, unknown>)) {
    const st = typeof s === 'string' ? s : (s && typeof s === 'object' && typeof (s as Record<string, unknown>).status === 'string') ? String((s as Record<string, unknown>).status) : 'running';
    out[name] = st.toLowerCase();
  }
  return out;
}

/** Aggregated LIVE docker state for a set of candidate container names from
 * probe `containerStates` data (null = no data at all). The app is 'running'
 * when ANY member runs; otherwise the WORST non-running state wins so a
 * mid-transition app shows 'restarting', not just 'exited'. */
function liveStateForNames(names: string[], states?: Record<string, string>): string | null {
  if (!states || Object.keys(states).length === 0) return null;
  let anyRunning = false;
  let worst: string | null = null;
  for (const n of names) {
    // Exact docker-name match first, then the `<app>-<service>` convention.
    const direct = states[n];
    if (direct !== undefined) {
      if (direct === 'running') anyRunning = true;
      else if (!worst || stateRank(direct) > stateRank(worst)) worst = direct;
      continue;
    }
    for (const [k, v] of Object.entries(states)) {
      if (!k.endsWith(`-${n}`)) continue;
      if (v === 'running') anyRunning = true;
      else if (!worst || stateRank(v) > stateRank(worst)) worst = v;
    }
  }
  return anyRunning ? 'running' : worst;
}

/** Live docker state of an APP from probe data (null = no fresh data for its
 * device). TrueNAS multi-container apps name docker containers
 * `<app>-<service>`, so candidates are matched exactly or by suffix. */
function liveStateOf(row: ContainerRow, states?: Record<string, string>): string | null {
  const services = servicesOf(row);
  const candidates = Array.from(new Set([row.name, ...(services.length > 0 ? services.map((s) => s.service ?? row.name) : [])]));
  return liveStateForNames(candidates, states);
}

/**
 * Creates a plan for ONE plugin and executes it in the background (no navigation).
 * The first step is the plan's intent; any further steps are appended in one bulk
 * round-trip. Every step targets a single device with its own input, so this fans
 * out across devices that share the same plugin. Throws on failure — callers catch
 * ApiError 401 to offer two-factor revalidation and then retry from scratch.
 */
/** Creates a plan for ONE plugin. In Execute mode it is also executed in the
 * background (no navigation); in Plan mode it is saved WITHOUT executing and
 * only its id is returned — callers surface a "saved" notice instead of
 * tracking execution progress. Throws on failure — callers catch ApiError 401
 * to offer two-factor revalidation and then retry from scratch. */
async function createAndExecutePlan(
  pluginId: string,
  actionId: string,
  steps: Array<{ deviceId: string; input: Record<string, unknown> }>,
  mode: ExecutionMode,
): Promise<string> {
  const first = steps[0];
  const create = async () => {
    const plan = await api.createPlan({
      pluginId,
      intentActionId: actionId,
      inputs: first.input,
      devices: [{ deviceId: first.deviceId }],
    });
    if (steps.length > 1) {
      await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId, input: s.input })));
    }
    return plan;
  };
  return runAction(create, (id) => api.executePlan(id), mode);
}

/** Groups selected rows by (pluginId, deviceId), collecting a per-row value. */
function groupByDevice<T>(rows: T[], keyOf: (r: T) => { pluginId: string; deviceId: string }, valOf: (r: T) => string): Map<string, { pluginId: string; deviceId: string; values: string[] }> {
  const m = new Map<string, { pluginId: string; deviceId: string; values: string[] }>();
  for (const r of rows) {
    const k = keyOf(r);
    const entry = m.get(`${k.pluginId}|${k.deviceId}`) ?? { pluginId: k.pluginId, deviceId: k.deviceId, values: [] };
    entry.values.push(valOf(r));
    m.set(`${k.pluginId}|${k.deviceId}`, entry);
  }
  return m;
}

/**
 * YamlEditorDialog — edit the Docker Compose YAML of a single CUSTOM app. On open
 * it reads the current compose via the plugin's read-only `compose.config.read`
 * action (no plan row), shows it in an editable monospace textarea, and on save
 * submits `containers.update` through the plan workflow (2FA-gated) — executed in
 * the background without navigating. Catalog apps generate their compose from a
 * schema and have no editable string, so this is only offered for custom apps.
 */
function YamlEditorDialog({ app, onClose }: { app: ContainerRow; onClose: () => void }) {
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  // Read-Only: the compose change cannot be saved or applied.
  const isReadOnly = mode === 'readonly';
  const [yaml, setYaml] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  // Plan mode: the compose plan was saved without executing.
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.executePluginAction(app.pluginId, { deviceId: app.deviceId, actionId: 'compose.config.read', input: { name: app.name } });
        if (!cancelled) setYaml(typeof res.details.yaml === 'string' ? (res.details.yaml as string) : '');
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [app.pluginId, app.deviceId, app.name]);

  async function save() {
    if (isReadOnly) return; // Read-Only — the button is disabled; this is a safety net.
    setSaving(true);
    setError(null);
    try {
      await createAndExecutePlan(app.pluginId, 'containers.update', [{ deviceId: app.deviceId, input: { name: app.name, composeString: yaml } }], mode);
      if (isPlanMode) {
        setSaved(true);
        return;
      }
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  // Plan mode: the plan was saved without executing — offer to close.
  if (saved) {
    return (
      <DialogShell
        title={`Edit compose — ${app.name}`}
        onClose={onClose}
        maxWidth="max-w-2xl"
        footer={
          <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
            Close
          </button>
        }
      >
        <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
          <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
          Compose change saved as a plan — it was NOT executed and the app was not redeployed. Open the Plans
          center to run it later (or schedule it).
        </div>
      </DialogShell>
    );
  }

  return (
    <>
      <DialogShell
        title={`Edit compose — ${app.name}`}
        subtitle={`Applies via the plan workflow on ${app.deviceName ?? app.deviceId}. The app is redeployed after saving.`}
        onClose={onClose}
        maxWidth="max-w-2xl"
      >
        <div>
          {loading && (
            <div className="flex items-center gap-2 py-6 text-sm text-secondary">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading current compose…
            </div>
          )}

          {!loading && error && yaml === '' && (
            <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && yaml !== '' && (
            <>
              {isReadOnly && (
                <div className="mb-3 flex items-start gap-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                  <EyeOff className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  Read-only mode is active — this change cannot be saved or applied. Switch to Plan or Execute in the top bar.
                </div>
              )}
              {error && (
                <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
              )}
              <textarea
                value={yaml}
                onChange={(e) => setYaml(e.target.value)}
                spellCheck={false}
                className="h-[46vh] w-full resize-y rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed focus:border-focus-ring focus:outline-none"
              />
              <div className="mt-3 flex items-center justify-end gap-2">
                <button type="button" onClick={onClose} disabled={saving} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40">
                  Cancel
                </button>
                <button type="button" onClick={save} disabled={saving || yaml.trim() === '' || isReadOnly} title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-40">
                  {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  {isPlanMode ? 'Save as plan' : 'Apply & redeploy'}
                </button>
              </div>
            </>
          )}
        </div>
      </DialogShell>

      {reauth && (
        <div onClick={(e) => e.stopPropagation()}>
          <ReauthDialog
            contextLabel={`Edit compose for ${app.name}`}
            onClose={() => setReauth(false)}
            onSuccess={async () => { setReauth(false); await save(); }}
          />
        </div>
      )}
    </>
  );
}

/**
 * PullImageDialog — pull one or more arbitrary image references on a device via
 * the generic `images.pull` action (plan workflow, 2FA-gated). Offered from the
 * images panel header whenever ANY plugin assigned to that device advertises
 * `images.pull`; any future container backend gets this for free.
 */
function PullImageDialog({ deviceId, deviceName, pluginId, onClose }: { deviceId: string; deviceName?: string | null; pluginId: string; onClose: () => void }) {
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';
  const [refs, setRefs] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  const [saved, setSaved] = useState(false);

  async function submit() {
    if (isReadOnly) return; // Read-Only — the button is disabled; safety net.
    const list = refs.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    if (list.length === 0) { setError('Enter at least one image reference.'); return; }
    setSaving(true);
    setError(null);
    try {
      await createAndExecutePlan(pluginId, 'images.pull', [{ deviceId, input: { refs: list } }], mode);
      if (isPlanMode) { setSaved(true); return; }
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  return (
    <>
      <DialogShell
        title="Pull image"
        subtitle={`Pulls on ${deviceName ?? deviceId} via the plan workflow. One reference per line (or comma-separated).`}
        onClose={onClose}
        footer={
          saved ? (
            <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">Close</button>
          ) : (
            <>
              <button type="button" onClick={onClose} disabled={saving} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40">
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void submit()}
                disabled={saving || isReadOnly}
                title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-40"
              >
                {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <Download size={14} />
                {isPlanMode ? 'Save as plan' : 'Pull'}
              </button>
            </>
          )
        }
      >

        {saved ? (
          <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
            <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
            Pull saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
          </div>
        ) : (
          <>
            {isReadOnly && (
              <div className="mb-3 flex items-start gap-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                <EyeOff className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                Read-only mode is active — this action cannot be saved or applied. Switch to Plan or Execute in the top bar.
              </div>
            )}
            {error && (
              <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
            )}
            <textarea
              value={refs}
              onChange={(e) => setRefs(e.target.value)}
              spellCheck={false}
              rows={4}
              placeholder={'nginx:alpine\nghcr.io/your-org/app:1.2.3'}
              className="w-full resize-y rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed focus:border-focus-ring focus:outline-none"
            />
          </>
        )}
      </DialogShell>

      {reauth && (
        <div onClick={(e) => e.stopPropagation()}>
          <ReauthDialog
            contextLabel={`Pull image on ${deviceName ?? deviceId}`}
            onClose={() => setReauth(false)}
            onSuccess={async () => { setReauth(false); await submit(); }}
          />
        </div>
      )}
    </>
  );
}

/**
 * LogsDialog — read-only viewer for a single app's container log output, wrapped in
 * the shared draggable/resizable shell. The actual fetching + rendering lives in
 * <ContainerLogsView> (components/ContainerLogs.tsx), which is also used by the
 * full-window /container-logs page.
 */
function LogsDialog({ app, onClose }: { app: ContainerRow; onClose: () => void }) {
  const openInWindow = () => {
    const params = new URLSearchParams();
    params.set('app', JSON.stringify(app));
    window.open(`${window.location.origin}/container-logs/${app.deviceId}?${params.toString()}`, '_blank');
  };

  return (
    <ResizableDialog
      title={`Logs — ${app.name}`}
      subtitle={`Container log output on ${app.deviceName ?? app.deviceId}.`}
      icon={<ScrollText size={16} />}
      onClose={onClose}
      onOpenInWindow={openInWindow}
      defaultSize={{ w: 768, h: 520 }}
    >
      <ContainerLogsView app={app} />
    </ResizableDialog>
  );
}

/** Uptime cell — "running since". RUNNING + startedAt → duration; non-RUNNING
 * or no stamp → "—". The value is the real container start when the plugin
 * observed it via SSH (`docker inspect`), otherwise UNM-tracked from state
 * transitions (a lower bound that resets after restarts). */
function UptimeCell({ row }: { row: ContainerRow }) {
  const { formatDateTime } = useTimeFormat();
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-faint">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-faint">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span
      className="font-mono text-xs text-secondary"
      title={`Running since ${formatDateTime(row.startedAt)}`}
    >
      {formatDuration(secs)}
    </span>
  );
}

/** App workload state → badge style (TrueNAS SCALE states are uppercase; the
 * generic Docker plugin emits its own native states for child containers). */
const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-success text-success-fg border-success-border',
  STOPPED: 'bg-muted text-secondary border-border dark:text-foreground/85',
  ERROR: 'bg-danger text-danger-fg border-danger-border',
  FAILED: 'bg-danger text-danger-fg border-danger-border',
  // Docker-native states (generic docker plugin):
  EXITED: 'bg-muted text-secondary border-border dark:text-foreground/85',
  CREATED: 'bg-muted text-secondary border-border dark:text-foreground/85',
  RESTARTING: 'bg-warning text-warning-fg border-warning-border',
  REMOVING: 'bg-warning text-warning-fg border-warning-border',
  PAUSED: 'bg-accent-sky text-accent-sky-fg border-accent-sky-border',
  DEAD: 'bg-danger text-danger-fg border-danger-border',
};

function StateBadge({ state }: { state: string }) {
  // Case-tolerant lookup — inventory states are UPPERCASE, live probe states
  // are lowercase docker states; both must map to the same style (an unknown
  // case variant must NOT fall through to the orange warning default).
  const style = STATE_STYLES[state] ?? STATE_STYLES[state.toUpperCase()] ?? 'bg-warning text-warning-fg border-warning-border';
  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium', style)}>
      {state.toLowerCase()}
    </span>
  );
}

/** Reads the `extra` JSON object defensively — corrupt rows must not break the table. */
function extraOf(row: { extra?: Record<string, unknown> }): Record<string, unknown> {
  const e = row.extra;
  return e && typeof e === 'object' ? (e as Record<string, unknown>) : {};
}

/** App-level live stats from `extra.stats` (docker stats over SSH enrichment).
 * Absent until the first successful cycle — cells then show a dash. */
function appStatsOf(row?: ContainerRow): Record<string, number> | undefined {
  const s = row ? extraOf(row)['stats'] : undefined;
  return s && typeof s === 'object' ? (s as Record<string, number>) : undefined;
}

/** CPU cell — percent with amber/red tint at high utilization. */
function cpuCell(v?: number | null): ReactNode {
  if (v === undefined || v === null) return <span className="text-faint">—</span>;
  return (
    <span className={clsx('font-mono text-xs', v >= 90 ? 'text-danger-fg' : v >= 60 ? 'text-warning-fg' : 'text-foreground')}>
      {v.toFixed(1)}%
    </span>
  );
}

/** RAM cell — used (and limit when known), tinted near the ceiling. */
function memCell(used?: number | null, limit?: number | null): ReactNode {
  if (used === undefined || used === null) return <span className="text-faint">—</span>;
  const pct = limit && limit > 0 ? Math.min(100, (used / limit) * 100) : null;
  return (
    <span
      className={clsx('font-mono text-xs', pct !== null && pct >= 90 ? 'text-danger-fg' : pct !== null && pct >= 75 ? 'text-warning-fg' : 'text-foreground')}
      title={limit ? `${formatBytes(used)} of ${formatBytes(limit)}` : formatBytes(used)}
    >
      {formatBytes(used)}{limit ? ` / ${formatBytes(limit)}` : ''}
    </span>
  );
}

/** Throughput cell — "↓ rx · ↑ tx" in bytes/s (average since last collection). */
function rateCell(rx?: number | null, tx?: number | null): ReactNode {
  if ((rx === undefined || rx === null) && (tx === undefined || tx === null)) return <span className="text-faint">—</span>;
  const f = (v: number | null | undefined) => (v ? `${formatBytes(v)}/s` : '0');
  return (
    <span className="font-mono text-xs text-foreground" title={`rx ${f(rx)} · tx ${f(tx)} — average since the last collection`}>
      ↓ {f(rx)} · ↑ {f(tx)}
    </span>
  );
}

/** Networks[] from extra (defensive). */
function networksOf(row: ContainerRow): ContainerNetwork[] {
  const n = extraOf(row)['networks'];
  if (!Array.isArray(n)) return [];
  return n.filter((x): x is ContainerNetwork => !!x && typeof x === 'object' && typeof (x as ContainerNetwork).name === 'string');
}

/** Static container IPs from extra. */
function ipsOf(row: ContainerRow): string[] {
  const i = extraOf(row)['ips'];
  return Array.isArray(i) ? i.filter((x): x is string => typeof x === 'string') : [];
}

/** Published host ports from extra. */
function portsOf(row: ContainerRow): number[] {
  const p = extraOf(row)['ports'];
  return Array.isArray(p) ? p.filter((x): x is number => typeof x === 'number') : [];
}

/** Per-service detail for the expandable row (multi-container apps). */
function servicesOf(row: ContainerRow): ContainerServiceDetail[] {
  const c = extraOf(row)['containers'];
  if (!Array.isArray(c)) return [];
  return c.filter((x): x is ContainerServiceDetail => !!x && typeof x === 'object');
}

/** Splits a docker image reference into its repo and tag parts. Handles registry
 * hosts, ports, digests (`@sha256:`) and defaults to `latest` when no explicit
 * tag is present — so "Image" shows the name and "Tag" the version. */
function splitImage(image: string | null | undefined): { repo: string; tag: string } {
  if (!image || image.trim() === '') return { repo: '', tag: '' };
  const s = image.trim();
  // Digest reference — no tag part.
  const at = s.indexOf('@');
  if (at >= 0) return { repo: s.slice(0, at), tag: s.slice(at + 1) };
  const lastSlash = s.lastIndexOf('/');
  const lastColon = s.lastIndexOf(':');
  // A colon after the final slash is a tag separator; otherwise it's a port.
  if (lastColon > lastSlash) return { repo: s.slice(0, lastColon), tag: s.slice(lastColon + 1) };
  return { repo: s, tag: 'latest' };
}

/** One node in the App → Container(s) → Volume mounts display tree. Top-level
 * (app) nodes carry their source row so the main columns keep working; child
 * nodes (container/volume) carry just the fields their cells need. */
interface TreeNode {
  key: string;
  kind: 'app' | 'container' | 'volume';
  /** Source app row — set on `kind === 'app'` nodes only. */
  row?: ContainerRow;
  /** Set on container child nodes — the device + plugin that own this member,
   * needed to create a per-container plan (the `-one` actions). */
  deviceId?: string;
  pluginId?: string;
  /** The owning app's name (TrueNAS multi-container naming: docker names are often `<app>-<service>`). */
  appName?: string;
  service?: string;
  image?: string | null;
  state?: string | null;
  /** FRESH live docker state from the probe cache (lowercase, e.g. 'exited',
   * 'restarting') — overrides `state` in the badge when present and fresh. */
  liveState?: string | null;
  mac?: string | null;
  ip?: string | null;
  startedAt?: string | null;
  /** Live stats (docker stats over SSH) — container nodes only. */
  cpuPct?: number | null;
  memUsedBytes?: number | null;
  memLimitBytes?: number | null;
  netRxRate?: number | null;
  netTxRate?: number | null;
  blkReadRate?: number | null;
  blkWriteRate?: number | null;
  /** Volume mount text (kind=volume): "source → target" (+ mode). */
  volumeText?: string;
  /** The volume's HOST path (the bind-mount source, or a named docker volume) —
   * what the filesystem browser opens for this leaf. Absent when unresolvable. */
  volumeSource?: string | null;
  /** Path inside the container (the mount target) — shown as a hint in the dialog. */
  volumeTarget?: string | null;
}

/** Result of building one app's subtree: the app node + its containers, each
 * with its own volume nodes. Used to populate DataTable's child map. */
interface BuiltApp {
  app: TreeNode;
  containers: { node: TreeNode; volumes: TreeNode[] }[];
}

/** Builds the display tree for one app row: an app node, its container(s) as
 * children, and each container's declared volume mounts as grandchildren. A
 * single-container app still nests its container (uniform structure); an app
 * with no per-service detail yet falls back to a synthetic container from the
 * app-level image so nothing is lost. `liveStats` (probe data for this device)
 * overrides the enrichment stats when present — live wins, cached fills gaps.
 * `liveStates` carries the fresh probe docker states for each member's badge. */
function buildApp(row: ContainerRow, liveStats?: Record<string, LiveContainerStat>, liveStates?: Record<string, string>): BuiltApp {
  const base = `${row.deviceId}|${row.pluginId}|${row.name}`;
  const services = servicesOf(row);
  let list: ContainerServiceDetail[];
  if (services.length > 0) {
    list = services;
  } else if (row.image) {
    // No per-service detail yet — synthesize one container from the app image.
    list = [{ service: row.name, image: row.image, state: row.state.toLowerCase() }];
  } else {
    list = [];
  }

  const app: TreeNode = { key: base, kind: 'app', row };
  const containers: BuiltApp['containers'] = [];
  list.forEach((s, i) => {
    const ckey = `${base}#c${i}`;
    const vols: TreeNode[] = (Array.isArray(s.volumes) ? s.volumes : []).map((v, vi) => ({
      key: `${ckey}#v${vi}`,
      kind: 'volume',
      volumeText: [v.source, v.target ? `→ ${v.target}` : '', v.mode].filter(Boolean).join(' '),
      // The host path the filesystem browser opens for this mount (the source — a
      // bind-mount's absolute host path or a named docker volume). Named volumes
      // are resolved to their /var/lib/docker/volumes/<name>/_data location by the plugin.
      volumeSource: v.source || null,
      volumeTarget: v.target ?? null,
    }));
    // Live probe stats win over the enrichment snapshot; per-field fallback so
    // a partial live sample (e.g. first cycle has no I/O rates yet) still shows
    // whatever the slower path already collected.
    const svcName = s.service ?? (list.length > 1 ? undefined : row.name);
    const live = liveStats ? liveStatFor(liveStats, svcName ?? row.name, row.name) : undefined;
    containers.push({
      node: {
        key: ckey,
        kind: 'container',
        deviceId: row.deviceId,
        pluginId: row.pluginId,
        appName: row.name,
        service: svcName,
        image: s.image ?? null,
        state: s.state ?? null,
        // Fresh probe docker state for this member (exact or `<app>-<svc>` match).
        liveState: liveStates && svcName ? liveStateForNames([svcName], liveStates) : null,
        mac: s.mac ?? null,
        ip: s.ip ?? null,
        startedAt: s.startedAt ?? null,
        cpuPct: live?.cpuPct ?? s.cpuPct ?? null,
        memUsedBytes: live?.memUsedBytes ?? s.memUsedBytes ?? null,
        memLimitBytes: live?.memLimitBytes ?? s.memLimitBytes ?? null,
        netRxRate: live?.netRxRate ?? s.netRxRate ?? null,
        netTxRate: live?.netTxRate ?? s.netTxRate ?? null,
        blkReadRate: live?.blkReadRate ?? s.blkReadRate ?? null,
        blkWriteRate: live?.blkWriteRate ?? s.blkWriteRate ?? null,
      },
      volumes: vols,
    });
  });
  return { app, containers };
}

/** One docker-network chip — name on top, driver + subnets in the tooltip. */
function NetworkChip({ net }: { net: ContainerNetwork }) {
  const tip = [net.name, net.driver ? `driver: ${net.driver}` : '', ...(net.subnets ?? [])].filter(Boolean).join(' · ');
  return (
    <span title={tip} className="inline-flex items-center rounded border border-accent-sky-border bg-accent-sky px-1.5 py-0.5 font-mono text-[11px] leading-4 text-accent-sky-fg">
      {net.name}
    </span>
  );
}

/** One static IP chip (v4 blue / v6 violet — same convention as the Firewall page). */
function IpChip({ ip }: { ip: string }) {
  const isV6 = ip.includes(':');
  return (
    <span className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', isV6 ? 'border-accent-violet-border bg-accent-violet text-accent-violet-fg' : 'border-info-border bg-info text-info-fg')}>
      {ip}
    </span>
  );
}

/** Network + IP cell: static IPs first, then network chips; "—" when neither. */
function NetworkCell({ row }: { row: ContainerRow }) {
  const ips = ipsOf(row);
  const nets = networksOf(row);
  if (ips.length === 0 && nets.length === 0) return <span className="text-faint">—</span>;
  return (
    <div className="flex flex-col gap-1">
      {ips.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">{ips.map((ip) => <IpChip key={ip} ip={ip} />)}</span>
      )}
      {nets.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">
          {nets.slice(0, 4).map((n) => <NetworkChip key={n.name} net={n} />)}
          {nets.length > 4 && <span className="text-[11px] text-faint" title={nets.map((n) => n.name).join(', ')}>+{nets.length - 4}</span>}
        </span>
      )}
    </div>
  );
}

/** Published host ports — first three + "+N" overflow. */
function PortsCell({ row }: { row: ContainerRow }) {
  const ports = portsOf(row);
  if (ports.length === 0) return <span className="text-faint">—</span>;
  const shown = ports.slice(0, 3);
  return (
    <span title={ports.join(', ')} className="font-mono text-xs text-secondary">
      {shown.map((p) => p).join(', ')}
      {ports.length > 3 && <span className="text-faint"> +{ports.length - 3}</span>}
    </span>
  );
}

/** Status badge for the images panel — dangling (slate) / update available
 * (amber); plain hosts report neither, so most rows show a dash. */
function ImageStatusBadge({ row }: { row: DockerImageRow }) {
  if (row.dangling) {
    return (
      <span className="inline-flex items-center rounded-full border border-border bg-muted px-2.5 py-0.5 text-xs font-medium text-secondary" title="Dangling image — no tag references it">
        dangling
      </span>
    );
  }
  if (row.updateAvailable === true) {
    return (
      <span className="inline-flex items-center rounded-full border border-warning-border bg-warning px-2.5 py-0.5 text-xs font-medium text-warning-fg" title="A newer version of this image is available">
        update available
      </span>
    );
  }
  return <span className="text-faint">—</span>;
}

/** Version cell with an amber "update available" dot. */
function VersionCell({ row }: { row: ContainerRow }) {
  const v = row.version && row.version.trim() !== '' ? row.version : null;
  if (!v) return <span className="text-faint">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-secondary" title={row.upgradeAvailable ? 'Update available' : undefined}>
      {v}
      {row.upgradeAvailable && <span className="h-2 w-2 rounded-full bg-status-warn" title="Update available" />}
    </span>
  );
}

/** Top-level App cell — name + "custom" marker. The compose editor lives in the
 * Actions column (generic across plugins that advertise the compose actions). */
function AppCell({ row }: { row?: ContainerRow }) {
  if (!row) return null;
  const isCustom = typeof extraOf(row)['customApp'] === 'boolean' && (extraOf(row)['customApp'] as boolean);
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-medium text-foreground">{row.name}</span>
      {isCustom && (
        <span className="text-[10px] uppercase tracking-wide text-faint">custom</span>
      )}
    </div>
  );
}

/** Callbacks an expanded child row needs for per-container actions — bound in
 * the page component (catalog gating + plan tracking live there). */
interface ChildActionContext {
  hasAction: (pluginId: string, actionId: string) => boolean;
  run: (node: TreeNode, actionId: string, label: string) => void;
  /** True when the plugin advertises the 'filesystem' capability (Browse button). */
  canBrowse?: (pluginId: string) => boolean;
  /** Opens the filesystem browser for a volume leaf's host path. */
  browseVolume?: (node: TreeNode) => void;
  /** True when the plugin advertises the 'sshConsole' capability (console button). */
  canConsole?: (pluginId: string) => boolean;
  /** Opens an interactive shell INSIDE this container (docker exec over SSH). */
  openContainerConsole?: (node: TreeNode) => void;
  /** Read-Only mode — disables the lifecycle write actions (console stays available). */
  readOnly?: boolean;
}

/** Per-container lifecycle actions for child rows — rendered in the Actions cell
 * of an expanded container row. Availability is GENERIC: a button only renders
 * when the owning plugin advertises the matching `-one` action id (the Docker
 * plugin does; TrueNAS manages apps as units and advertises none, so its child
 * rows stay action-free). States are lowercase docker states from both plugins. */
function ContainerNodeActions({ node, ctx }: { node: TreeNode; ctx: ChildActionContext }) {
  const pid = node.pluginId ?? '';
  const state = (node.state ?? '').toLowerCase();
  const running = state === 'running' || state === 'restarting';
  const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean }[] = [
    { id: 'containers.start-one', label: 'Start', icon: <Play size={13} />, available: ctx.hasAction(pid, 'containers.start-one'), eligible: !running },
    { id: 'containers.stop-one', label: 'Stop', icon: <Square size={12} />, available: ctx.hasAction(pid, 'containers.stop-one'), eligible: running, danger: true },
    { id: 'containers.restart-one', label: 'Restart', icon: <RotateCw size={13} />, available: ctx.hasAction(pid, 'containers.restart-one'), eligible: true },
    { id: 'containers.delete-one', label: 'Delete', icon: <Trash2 size={13} />, available: ctx.hasAction(pid, 'containers.delete-one'), eligible: true, danger: true },
  ];
  // Interactive console (capability 'sshConsole') — a full shell INSIDE this
  // container via `docker exec -it` over the bound SSH credential. Rendered
  // alongside the lifecycle actions; only when the plugin advertises it.
  const canConsole = !!ctx.canConsole && ctx.canConsole(pid);
  return (
    <div className="flex items-center gap-0.5">
      {actions.map((a) => {
        if (!a.available) return null;
        const blockedByReadOnly = !!ctx.readOnly;
        const enabled = a.eligible && !blockedByReadOnly;
        return (
          <button
            key={a.id}
            type="button"
            aria-label={`${a.label} ${node.service ?? ''}`}
            title={enabled ? `${a.label} ${node.service ?? ''}` : blockedByReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : `Not applicable in state ${state || 'unknown'}`}
            disabled={!enabled}
            onClick={() => ctx.run(node, a.id, a.label)}
            className={clsx(
              'rounded-md p-1 hover:bg-muted',
              a.danger ? 'text-danger-fg hover:text-danger-fg' : 'text-secondary hover:text-foreground',
              !enabled && 'cursor-not-allowed opacity-30',
            )}
          >
            {a.icon}
          </button>
        );
      })}
      {canConsole && (
        <button
          type="button"
          aria-label={`Open console in ${node.service ?? ''}`}
          title={`Open an interactive shell inside ${node.service ?? 'this container'} (docker exec over SSH)`}
          onClick={() => ctx.openContainerConsole?.(node)}
          className="rounded-md p-1 text-secondary hover:bg-muted hover:text-foreground"
        >
          <TerminalIcon size={13} />
        </button>
      )}
    </div>
  );
}

/** Cell content for one column of an expanded child row — mirrors the top-level
 * column renders so children line up with the header. ONLY the name column is
 * indented (the hierarchy cue); every other cell aligns normally under its
 * header, exactly like a regular data row. Container rows fill most columns;
 * volume leaves only use the name column (indented one step deeper). */
function nodeCell(key: string, node: TreeNode, depth: number, actions?: ChildActionContext, fmtDateTime?: (v: string) => string): ReactNode {
  switch (key) {
    case 'name': {
      if (node.kind === 'container') {
        // text-foreground (not secondary): child rows sit on a tinted fill that
        // is lighter than the card in dark mode, where secondary text would drop
        // below readable contrast.
        return (
          <span className="block truncate font-medium text-foreground" style={{ paddingLeft: 18 + depth * 14 }} title={node.service ?? undefined}>
            {node.service ?? '—'}
          </span>
        );
      }
      // Volume leaf — the mount lives in the name column, indented under its container.
      // A Browse icon (when the plugin supports 'filesystem' and a host path is known)
      // opens the filesystem browser on this volume's HOST location.
      const browsable = !!actions?.canBrowse && node.volumeSource != null;
      return (
        <span className="flex items-center gap-1" style={{ paddingLeft: 32 + depth * 14 }}>
          <span className="block truncate font-mono text-[11px] text-muted-foreground" title={node.volumeText}>
            {node.volumeText}
          </span>
          {browsable && (
            <button
              type="button"
              aria-label={`Browse volume ${node.volumeSource}`}
              title={`Browse the files in this volume (${node.volumeSource})`}
              onClick={() => actions?.browseVolume?.(node)}
              className="shrink-0 rounded-md p-1 text-secondary hover:bg-muted hover:text-foreground"
            >
              <FolderOpen size={13} />
            </button>
          )}
        </span>
      );
    }
    case 'state': {
      // Fresh probe docker state wins over the cached inventory state — a
      // per-container start/stop flips its badge in ~3 s.
      if (node.kind === 'container' && node.liveState) return <StateBadge state={node.liveState.toUpperCase()} />;
      if (node.kind === 'container' && node.state) return <StateBadge state={node.state.toUpperCase()} />;
      return null;
    }
    case 'image': {
      if (node.kind !== 'container') return null;
      const repo = splitImage(node.image).repo;
      return repo ? (
        <span className="block truncate font-mono text-xs text-foreground" title={node.image ?? undefined}>{repo}</span>
      ) : (
        <span className="text-faint">—</span>
      );
    }
    case 'tag': {
      if (node.kind !== 'container') return null;
      const tag = splitImage(node.image).tag;
      return tag ? (
        <span className="inline-flex items-center rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px] leading-4 text-foreground" title={tag}>{tag}</span>
      ) : (
        <span className="text-faint">—</span>
      );
    }
    case 'networks': {
      if (node.kind !== 'container') return null;
      const parts: ReactNode[] = [];
      if (node.ip) {
        parts.push(
          <span key="ip" className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', node.ip.includes(':') ? 'border-accent-violet-border bg-accent-violet text-accent-violet-fg' : 'border-info-border bg-info text-info-fg')} title="IP">
            {node.ip}
          </span>
        );
      }
      if (node.mac) parts.push(<span key="mac" className="font-mono text-[11px] text-muted-foreground" title="MAC address">MAC {node.mac}</span>);
      if (parts.length === 0) return <span className="text-faint">—</span>;
      return <span className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">{parts}</span>;
    }
    case 'startedAt': {
      if (node.kind !== 'container' || !node.startedAt) return null;
      const since = new Date(node.startedAt).getTime();
      if (Number.isNaN(since)) return null;
      const secs = Math.max(0, (Date.now() - since) / 1000);
      return <span className="font-mono text-xs text-foreground" title={`Running since ${fmtDateTime ? fmtDateTime(node.startedAt) : node.startedAt}`}>{formatDuration(secs)}</span>;
    }
    case 'cpu':
      if (node.kind !== 'container') return null;
      return cpuCell(node.cpuPct);
    case 'ram':
      if (node.kind !== 'container') return null;
      return memCell(node.memUsedBytes, node.memLimitBytes);
    case 'netio':
      if (node.kind !== 'container') return null;
      return rateCell(node.netRxRate, node.netTxRate);
    case 'blockio':
      if (node.kind !== 'container') return null;
      return rateCell(node.blkReadRate, node.blkWriteRate);
    case 'actions': {
      // Per-container lifecycle buttons — only container children carry them,
      // and only when the page bound an action context for this table.
      if (node.kind !== 'container' || !actions) return null;
      return <ContainerNodeActions node={node} ctx={actions} />;
    }
    default:
      return null;
  }
}

/** One expanded child rendered as a FULL `<tr>` — a chevron cell plus one cell
 * per visible column (ctx.columns), so it stays aligned with the header. A
 * container that has volume mounts gets its own chevron for recursive expand. */
function ChildRow({ node, ctx, actions }: { node: TreeNode; ctx: ExpandChildContext; actions?: ChildActionContext }) {
  const { formatDateTime } = useTimeFormat();
  // Theme-aware fills — in dark mode a near-white bg-accent-sky/40 over the
  // card blends into a mid-gray band that kills text contrast, so children use
  // muted-panel shades instead (container rows lighter than volume leaves).
  return (
    <tr className={node.kind === 'volume' ? 'bg-background/60 dark:bg-muted/40' : 'bg-accent-sky/40 dark:bg-muted/70'}>
      <td className="px-1 py-2 align-middle">
        {ctx.hasChildren ? (
          <button
            type="button"
            onClick={ctx.onToggle}
            aria-expanded={ctx.expanded}
            title={ctx.expanded ? 'Collapse volume mounts' : 'Show volume mounts'}
            className="flex h-6 w-6 items-center justify-center rounded text-faint hover:bg-muted hover:text-secondary"
          >
            {ctx.expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
          </button>
        ) : (
          <span className="inline-block h-6 w-6" />
        )}
      </td>
      {/* Empty selection cell — the table is selectable, so parent rows carry a
       * checkbox column between chevron and data. Children are NOT selectable,
       * but without this cell every child's content shifts one column left. */}
      {ctx.selectable && <td className="px-3 py-2" />}
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
          {nodeCell(col.key, node, ctx.depth, actions, formatDateTime)}
        </td>
      ))}
    </tr>
  );
}

export default function Containers() {
  const navigate = useNavigate();
  const { formatDateTime } = useTimeFormat();
  // Global Execute/Plan mode — decides whether page actions run immediately or
  // are saved as (unexecuted) plans for later execution/scheduling.
  const { mode } = useExecutionMode();

  // The API polls plugins every ~30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const containersQuery = useQuery({
    queryKey: ['containers'],
    queryFn: () => api.containers(),
    refetchInterval: 30_000,
  });
  const queryClient = useQueryClient();

  // Action catalogs of every plugin that currently has container rows — drives
  // the per-row Actions column GENERICALLY: a button only renders when the row's
  // plugin advertises that action id, so any future plugin (docker, proxmox, …)
  // gets the same column for free.
  const catalogPluginIds = useMemo(
    () => Array.from(new Set((containersQuery.data?.containers ?? []).map((r) => r.pluginId))),
    [containersQuery.data],
  );
  const catalogsQuery = useQuery({
    queryKey: ['plugin-actions-catalogs', catalogPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        catalogPluginIds.map(async (pid) => [pid, (await api.pluginActions(pid)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: catalogPluginIds.length > 0,
  });

  /** True when the plugin's advertised action catalog contains `actionId`. */
  function hasAction(pluginId: string, actionId: string): boolean {
    const actions = catalogsQuery.data?.[pluginId];
    return Array.isArray(actions) && actions.some((a) => a.id === actionId);
  }

  // --- Create-app candidates ----------------------------------------------------
  // Any device whose assigned plugin advertises an install action (containers.install
  // or containers.deploy-compose) can host the "Create app" dialog — GENERIC: no
  // per-backend UI code, just catalog detection. Catalogs are fetched for every
  // distinct plugin across all devices (usually a handful; react-query caches).
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const allPluginIds = useMemo(
    () => Array.from(new Set((devicesQuery.data ?? []).flatMap((d) => (d.plugins ?? []).map((p) => p.pluginId)))),
    [devicesQuery.data],
  );
  const allCatalogsQuery = useQuery({
    queryKey: ['plugin-actions-catalogs-all', allPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        allPluginIds.map(async (pid) => [pid, (await api.pluginActions(pid)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: allPluginIds.length > 0,
  });

  /** Devices that can create apps — their plugin advertises at least one
   *  install action. Modes are derived from the catalog (generic): 'catalog'
   *  needs containers.install + catalog.templates.list; 'compose' needs either
   *  containers.install or containers.deploy-compose; 'image' needs
   *  containers.run-image. */
  const createCandidates = useMemo<CreateAppCandidate[]>(() => {
    const out: CreateAppCandidate[] = [];
    for (const d of devicesQuery.data ?? []) {
      for (const a of d.plugins ?? []) {
        const actions = allCatalogsQuery.data?.[a.pluginId];
        if (!Array.isArray(actions)) continue;
        const has = (id: string) => actions.some((x) => x.id === id);
        const modes: AppMode[] = [];
        const actionMap: Partial<Record<AppMode, string>> = {};
        if (has('containers.install') && has('catalog.templates.list')) {
          modes.push('catalog');
          actionMap.catalog = 'containers.install';
        }
        if (has('containers.deploy-compose')) {
          modes.push('compose');
          actionMap.compose = 'containers.deploy-compose';
        } else if (has('containers.install')) {
          // TrueNAS — custom compose via containers.install (mode=custom)
          modes.push('compose');
          actionMap.compose = 'containers.install';
        }
        if (has('containers.run-image')) {
          modes.push('image');
          actionMap.image = 'containers.run-image';
        }
        if (modes.length === 0) continue;
        out.push({
          deviceId: d.id,
          deviceName: d.name,
          managementAddress: d.managementAddress,
          pluginId: a.pluginId,
          pluginName: a.pluginName,
          modes,
          actions: actionMap,
        });
      }
    }
    return out;
  }, [devicesQuery.data, allCatalogsQuery.data]);

  // --- Live stats via PROBE (short-cycle, capability 'probe') -----------------
  // The CPU/RAM/Net I/O/Block I/O columns prefer LIVE data from the plugin's
  // POST /probe endpoint — polled every few seconds per device through the API
  // broker — and fall back to the slower 15-min SSH enrichment baked into
  // extra.stats when a probe is unavailable (no ssh slot, flaky sshd, ...).
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const probePluginIds = useMemo(
    () => new Set((pluginsQuery.data ?? []).filter((p) => (p.capabilities ?? []).includes('probe')).map((p) => p.id)),
    [pluginsQuery.data],
  );

  // One live probe per (device, plugin) pair that has container rows AND a
  // probe-capable plugin. Two keys per poll: 'containerStats' (CPU/RAM/I-O for
  // the stat columns) + 'containerStates' (live docker state of every
  // container from one cheap `docker ps -a` — feeds the settle watch so plan
  // outcomes are detected in ~3 s without a full /monitoring inventory poll,
  // and drives the live State badges below).
  const probeTargets = useMemo(() => {
    const seen = new Set<string>();
    const out: { deviceId: string; pluginId: string }[] = [];
    for (const r of containersQuery.data?.containers ?? []) {
      if (!probePluginIds.has(r.pluginId)) continue;
      const k = `${r.deviceId}|${r.pluginId}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ deviceId: r.deviceId, pluginId: r.pluginId });
    }
    return out;
  }, [containersQuery.data, probePluginIds]);

  const probeResults = useQueries({
    queries: probeTargets.map((t) => ({
      queryKey: ['device-probe', t.deviceId, 'containerStats+containerStates'],
      queryFn: () => api.deviceProbe(t.deviceId, ['containerStats', 'containerStates'], t.pluginId),
      refetchInterval: 3_000,
      // Short-cycle live data — a failed poll is retried by the NEXT interval
      // tick anyway; React Query's default retry storm (3× backoff per tick) only
      // floods the console/network tab for devices whose probe can't work (e.g.
      // no SSH slot bound). The page falls back to last-good data on failure.
      retry: false,
      staleTime: 0,
      gcTime: 30_000,
    })),
  });

  // deviceId|pluginId → live per-container stats (name → stat). Empty until the
  // first successful probe; a failed poll keeps serving the last good snapshot.
  const liveStatsByDevice = useMemo(() => {
    const m = new Map<string, Record<string, LiveContainerStat>>();
    probeTargets.forEach((t, i) => {
      const res = probeResults[i];
      if (!res?.data) return;
      const cs = res.data.probe.metrics['containerStats'];
      if (cs && typeof cs === 'object') m.set(`${t.deviceId}|${t.pluginId}`, cs as Record<string, LiveContainerStat>);
    });
    return m;
  }, [probeTargets, probeResults]);

  // (liveStatesByDevice is built further down — it merges this page-wide probe
  // with the fast transition probe that only exists while a plan settles.)

  /** Effective app-level stats: LIVE probe data when available, else the
   * enrichment snapshot in extra.stats (15-min cadence). */
  function effectiveAppStats(row?: ContainerRow): Record<string, number> | undefined {
    if (!row) return undefined;
    const live = liveStatsByDevice.get(`${row.deviceId}|${row.pluginId}`);
    if (live && Object.keys(live).length > 0) {
      const services = servicesOf(row);
      const names = Array.from(new Set(services.length > 0 ? services.map((s) => s.service ?? row.name) : [row.name]));
      const stats: LiveContainerStat[] = [];
      for (const n of names) {
        const st = liveStatFor(live, n, row.name);
        if (st) stats.push(st);
      }
      const agg = aggregateLiveStats(stats);
      if (agg) return agg;
    }
    return appStatsOf(row); // fallback: enrichment data in extra.stats
  }

  // --- Bulk actions + YAML editor (plan-workflow backed) ---------------------
  /** In-session 2FA revalidation prompt (shown when a plan call returns 401). */
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);

  // --- Filesystem browser (capability 'filesystem') ---------------------------
  // The Browse icon on volume leaves only renders when the owning plugin advertises
  // the 'filesystem' capability — GENERIC: any future container plugin serving POST
  // /filesystem gets the file browser for free. Capabilities come from the plugins
  // catalog (react-query caches it).
  const [pluginsForCaps, setPluginsForCaps] = useState<Record<string, string[]>>({});
  useEffect(() => {
    let cancelled = false;
    api.plugins().then((ps) => {
      if (cancelled) return;
      const m: Record<string, string[]> = {};
      for (const p of ps) m[p.id] = p.capabilities ?? [];
      setPluginsForCaps(m);
    }).catch(() => { /* capabilities unavailable — Browse stays hidden */ });
    return () => { cancelled = true; };
  }, []);
  const canBrowseFs = (pluginId: string): boolean => (pluginsForCaps[pluginId] ?? []).includes('filesystem');

  /** The volume leaf whose host path the file browser is showing (null = closed). */
  const [browseVolume, setBrowseVolume] = useState<TreeNode | null>(null);

  // --- SSH console (capability 'sshConsole') ---------------------------------
  // A per-container console button only renders when the owning plugin advertises
  // the 'sshConsole' capability — GENERIC: any future container plugin serving
  // /console gets in-container shells for free. Opens `docker exec -it` into the
  // member via the bound SSH credential (the plugin resolves the docker name).
  const canConsole = (pluginId: string): boolean => (pluginsForCaps[pluginId] ?? []).includes('sshConsole');

  /** The container node whose shell is open in the console dialog (null = closed). */
  const [consoleNode, setConsoleNode] = useState<TreeNode | null>(null);

  /** Custom app whose compose YAML is being edited. */
  const [yamlApp, setYamlApp] = useState<ContainerRow | null>(null);
  const [logsApp, setLogsApp] = useState<ContainerRow | null>(null);
  /** Device target of the "Pull image" dialog (null = closed). */
  const [pullTarget, setPullTarget] = useState<{ deviceId: string; deviceName?: string | null; pluginId: string } | null>(null);
  /** Dismissible status banner (info / error only — plan execution itself is
   * surfaced globally by the top-bar plans icon, not per page). */
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);

  // --- Plan tracking → auto-refresh ------------------------------------------
  // Plans created by this page are tracked ONLY for data freshness: while one
  // is executing the affected apps may be mid-transition, and when it settles
  // the touched devices are force-refreshed once so states update immediately
  // (container state is inventory data that otherwise re-collects every ~15
  // min). Execution status/progress lives in the top-bar plans icon.
  /** Plan id → the apps + devices its steps touch. */
  const [pendingPlans, setPendingPlans] = useState<Record<string, { deviceIds: string[]; names: string[] }>>({});
  const pendingRef = useRef(pendingPlans);
  useEffect(() => { pendingRef.current = pendingPlans; }, [pendingPlans]);

  /** Track a plan created by this page so its devices refresh on settle. */
  function trackPlan(planId: string, deviceIds: string[], names: string[]) {
    setPendingPlans((prev) => ({ ...prev, [planId]: { deviceIds, names } }));
  }

  // --- Settle watch (transitional states after a plan) -----------------------
  /** Apps still in an in-flight state (DEPLOYING / STOPPING / RESTARTING) after
   * their plan finished. Container state is INVENTORY data — it only re-collects
   * every ~15 min per device, so the one-shot refresh at plan completion can
   * catch a mid-transition snapshot and leave it stale. While this watch is
   * active we check the LIVE probe cache (docker ps via POST /probe, 3 s
   * cadence — zero appliance API load) every tick; only when the live state is
   * stable across ticks do we trigger ONE heavy refreshDevices (throttled to
   * one per 15 s), and only a SETTLED DB clears the watch. Without probe data
   * (no ssh slot / capability) it degrades to the legacy 15 s heavy loop.
   */
  const [settleWatch, setSettleWatch] = useState<{ deviceIds: string[]; names: string[]; until: number } | null>(null);
  const containersRef = useRef(containersQuery.data);
  useEffect(() => { containersRef.current = containersQuery.data; }, [containersQuery.data]);

  /** (Re)starts or extends the settle watch for the given apps + devices. */
  function watchSettle(deviceIds: string[], names: string[]) {
    if (names.length === 0) return;
    setSettleWatch((prev) => ({
      deviceIds: Array.from(new Set([...(prev?.deviceIds ?? []), ...deviceIds])),
      names: Array.from(new Set([...(prev?.names ?? []), ...names])),
      until: Math.max(prev?.until ?? 0, Date.now() + 5 * 60_000),
    }));
  }

  // --- Fast transition probe (tight cadence while a plan settles) --------------
  // While the settle watch is active we poll the plugin's POST /probe AGAIN —
  // but with `names` restricted to ONLY the transitioning containers, at a
  // tighter 1.5 s cadence than the page-wide 3 s probe. The response is merged
  // into liveStatesByDevice (per-name overlay), so the State badges flip in
  // ~1.5 s after a start/stop instead of waiting for the next inventory poll.
  const fastProbeTargets = useMemo(() => {
    if (!settleWatch) return [] as { deviceId: string; pluginId: string; names: string[] }[];
    const byKey = new Map<string, Set<string>>();
    for (const r of containersQuery.data?.containers ?? []) {
      if (!probePluginIds.has(r.pluginId)) continue;
      if (!settleWatch.deviceIds.includes(r.deviceId)) continue;
      // Only the watched apps' members — keep the selection small. The plugin
      // filters by EXACT docker name, so request every naming convention: the
      // app name, each service name, and `<app>-<service>` (TrueNAS multi-
      // container apps).
      const services = servicesOf(r);
      const svcNames = services.length > 0 ? services.map((s) => s.service ?? r.name) : [];
      const names = Array.from(new Set([r.name, ...svcNames, ...svcNames.map((n) => `${r.name}-${n}`)]));
      if (!names.some((n) => settleWatch.names.includes(n))) continue;
      const k = `${r.deviceId}|${r.pluginId}`;
      byKey.set(k, new Set([...(byKey.get(k) ?? []), ...names]));
    }
    return Array.from(byKey.entries()).map(([k, names]) => {
      const [deviceId, pluginId] = k.split('|');
      return { deviceId: deviceId!, pluginId: pluginId!, names: Array.from(names).sort() };
    });
  }, [settleWatch, containersQuery.data, probePluginIds]);

  const fastProbeResults = useQueries({
    queries: fastProbeTargets.map((t) => ({
      // Distinct key from the page-wide probe — this one carries a `names`
      // selection, so its (partial) response must not clobber the full cache.
      queryKey: ['device-probe-fast', t.deviceId, 'containerStates', t.names.join(',')],
      queryFn: () => api.deviceProbe(t.deviceId, ['containerStates'], t.pluginId, t.names),
      refetchInterval: 1_500,
      // Short-cycle transition probe — no retry storm; the next tick retries.
      retry: false,
      staleTime: 0,
      gcTime: 30_000,
    })),
  });

  // deviceId|pluginId → fresh LIVE docker state per container name (probe key
  // 'containerStates' = one cheap `docker ps -a` — real states, not just the
  // running set). Merges the page-wide probe with the fast transition probe's
  // per-name updates. Feeds both the settle watch's cheap live check and the
  // live State badges; a failed poll keeps serving the last good snapshot.
  const liveStatesByDevice = useMemo(() => {
    const m = new Map<string, { at: number; states: Record<string, string> }>();
    probeTargets.forEach((t, i) => {
      const res = probeResults[i];
      if (!res?.data) return;
      const norm = normalizeContainerStates(res.data.probe.metrics['containerStates']);
      if (norm) m.set(`${t.deviceId}|${t.pluginId}`, { at: Date.parse(res.data.probe.collectedAt) || Date.now(), states: norm });
    });
    // Overlay the fast probe's fresh per-name states on top of the full set.
    fastProbeTargets.forEach((t, i) => {
      const res = fastProbeResults[i];
      if (!res?.data) return;
      const norm = normalizeContainerStates(res.data.probe.metrics['containerStates']);
      if (!norm) return;
      const key = `${t.deviceId}|${t.pluginId}`;
      const at = Date.parse(res.data.probe.collectedAt) || Date.now();
      const prev = m.get(key);
      m.set(key, { at: Math.max(prev?.at ?? 0, at), states: { ...(prev?.states ?? {}), ...norm } });
    });
    return m;
  }, [probeTargets, probeResults, fastProbeTargets, fastProbeResults]);

  const liveStatesRef = useRef(liveStatesByDevice);
  useEffect(() => { liveStatesRef.current = liveStatesByDevice; }, [liveStatesByDevice]);

  /** Fresh (≤30 s) live states for one device+plugin — null when the probe has
   * no recent data, so callers fall back to the inventory state. */
  function freshLiveStates(deviceId: string, pluginId: string): Record<string, string> | null {
    const e = liveStatesByDevice.get(`${deviceId}|${pluginId}`);
    return e && Date.now() - e.at < 30_000 ? e.states : null;
  }

  useEffect(() => {
    if (!settleWatch) return;
    // The caller (singleApp / runBulk) already did one heavy refresh at plan
    // completion — start the throttle clock there so this watch only adds
    // follow-ups, never a redundant immediate one.
    let lastHeavyAt = Date.now();
    /** app name → live state on previous tick. Stability gate: TrueNAS
     * app.state lags docker state during transitions, so one sample can still
     * be mid-flight — require the same answer twice before syncing the DB. */
    const prevLive = new Map<string, string>();
    const timer = setInterval(async () => {
      if (Date.now() > settleWatch.until) { setSettleWatch(null); return; }
      const data = containersRef.current;

      // Authoritative exit: the DB no longer shows any watched app as transitional.
      const dbTransitional = new Set(
        (data?.containers ?? []).filter((c) => TRANSITIONAL_STATES.has(c.state)).map((c) => c.name),
      );
      if (!settleWatch.names.some((n) => dbTransitional.has(n))) { setSettleWatch(null); return; }

      // Cheap live check: docker ps -a via the probe cache (3 s cadence, zero
      // appliance API load — unlike refreshDevices which triggers a full
      // /monitoring inventory poll on the device).
      const rows = data?.containers ?? [];
      let allLive = true;
      let allStable = true;
      const nextPrev = new Map<string, string>();
      for (const name of settleWatch.names) {
        const row = rows.find((r) => r.name === name);
        if (!row) continue; // vanished from inventory — settled by definition
        const live = liveStatesRef.current.get(`${row.deviceId}|${row.pluginId}`);
        const fresh = live && Date.now() - live.at < 30_000 ? live.states : undefined;
        const state = liveStateOf(row, fresh);
        if (state === null) { allLive = false; continue; } // no probe data for this device
        nextPrev.set(name, state);
        if (prevLive.has(name) && prevLive.get(name) !== state) allStable = false;
      }
      prevLive.clear();
      for (const [k, v] of nextPrev) prevLive.set(k, v);

      // Nudge the DB only when a heavy poll is worth it: no live data at all
      // (legacy path), or live data stable across ticks. Either way throttled
      // to one heavy refresh per 15 s — the cheap probe keeps watching between.
      const shouldRefresh = !allLive || (nextPrev.size > 0 && allStable);
      if (!shouldRefresh) return;
      if (Date.now() - lastHeavyAt < 15_000) return;
      lastHeavyAt = Date.now();
      try { await api.refreshDevices(settleWatch.deviceIds); } catch { /* fall back to the 30s poll */ }
      void queryClient.invalidateQueries({ queryKey: ['containers'] });
      // DB verification happens on the NEXT tick (top of loop) — only a settled
      // DB clears the watch, so a lagging app.state can never get stuck stale.
    }, 3_000);
    return () => clearInterval(timer);
  }, [settleWatch, queryClient]);

  useEffect(() => {
    if (Object.keys(pendingPlans).length === 0) return;
    const timer = setInterval(async () => {
      for (const [planId, entry] of Object.entries(pendingRef.current)) {
        let p;
        try {
          p = await api.getPlan(planId);
        } catch { continue; } // transient API error — keep waiting
        if (!['succeeded', 'failed', 'cancelled'].includes(p.status)) continue;
        setPendingPlans((prev) => {
          const next = { ...prev };
          delete next[planId];
          return next;
        });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['containers'] });
        watchSettle(entry.deviceIds, entry.names); // keep re-polling while apps transition
        if (p.status !== 'succeeded') {
          const what = entry.names[0] ?? entry.deviceIds.join(', ');
          setNotice({ kind: 'error', text: `A plan for ${what} finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  // State sets used to filter which selected rows are eligible for an action.
  const STOPPED_STATES = useMemo(() => new Set(['STOPPED', 'STOPPING']), []);
  const RUNNING_STATES = useMemo(() => new Set(['RUNNING', 'DEPLOYING']), []);
  /** In-flight transition states — a row in one of these may still change. */
  const TRANSITIONAL_STATES = useMemo(() => new Set(['DEPLOYING', 'STOPPING', 'RESTARTING']), []);

  /**
   * Runs a bulk container/image action through the plan workflow, grouped by
   * plugin (each group becomes its own background-executed plan). On a 401 it
   * offers two-factor revalidation and retries from scratch — safe because the
   * first createPlan would have thrown before any plan row existed.
   */
  async function runBulk(
    label: string,
    buildGroups: () => Array<{ pluginId: string; actionId: string; steps: Array<{ deviceId: string; input: Record<string, unknown> }> }>,
  ) {
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      let savedCount = 0;
      for (const g of buildGroups()) {
        if (g.steps.length === 0) continue;
        const planId = await createAndExecutePlan(g.pluginId, g.actionId, g.steps, mode);
        if (mode === 'plan') {
          // Saved without executing — nothing to track; one notice at the end.
          savedCount += 1;
          continue;
        }
        // Track per group so the touched devices refresh when execution settles.
        const deviceIds = Array.from(new Set(g.steps.map((s) => s.deviceId)));
        const names = Array.isArray(g.steps[0].input['names']) ? (g.steps[0].input['names'] as string[]) : [];
        trackPlan(planId, deviceIds, names);
      }
      if (mode === 'plan' && savedCount > 0) {
        setNotice({
          kind: 'ok',
          text: `${label}: ${savedCount} plan${savedCount === 1 ? '' : 's'} saved without executing — open the Plans center to run them later.`,
        });
      }
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  /** One-click row action — runs a single-app plan and tracks it so the row
   * auto-refreshes when execution settles. Same 401 → reauth flow as bulk. */
  async function singleApp(row: ContainerRow, actionId: string, label: string) {
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { names: [row.name] } }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `${label} ${row.name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [row.deviceId], [row.name]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `${label} — ${row.name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  /** One-click PER-CONTAINER action — runs a single-member plan (`*-one`
   * actions, exact docker-name resolution) for one child row and tracks it so
   * the device auto-refreshes when execution settles. Same 401 → reauth flow
   * as app-level actions; tracked under its own key space (…|app#svc) so it
   * never collides with an app-level plan on the same row. */
  async function singleContainer(node: TreeNode, actionId: string, label: string) {
    const name = node.service ?? '';
    if (!node.deviceId || !node.pluginId || !name) return;
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(node.pluginId!, actionId, [{ deviceId: node.deviceId!, input: { names: [name] } }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `${label} ${name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [node.deviceId!], []);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `${label} — ${name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  /** Container bulk action — filters eligible rows by state, groups per device. */
  function containerBulk(actionId: string, label: string, eligible: (r: ContainerRow) => boolean, noEligibleMsg: string) {
    return (rows: TreeNode[]) => {
      const apps = rows.filter((n) => n.row && eligible(n.row));
      if (apps.length === 0) {
        setNotice({ kind: 'info', text: noEligibleMsg });
        return;
      }
      runBulk(label, () =>
        Array.from(groupByDevice(apps.map((n) => n.row!), (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.name).values()).map(
          (g) => ({ pluginId: g.pluginId, actionId, steps: [{ deviceId: g.deviceId, input: { names: g.values } }] }),
        ),
      );
    };
  }

  /** Image bulk delete — groups selected images per device by their appliance id. */
  function imageBulkDelete(rows: DockerImageRow[]) {
    const ids = rows.map((r) => (typeof extraOf(r)['id'] === 'string' ? (extraOf(r)['id'] as string) : r.name));
    if (ids.length === 0) return;
    runBulk('Delete image(s)', () =>
      Array.from(groupByDevice(rows, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => (typeof extraOf(r)['id'] === 'string' ? (extraOf(r)['id'] as string) : r.name)).values()).map(
        (g) => ({ pluginId: g.pluginId, actionId: 'images.delete', steps: [{ deviceId: g.deviceId, input: { ids: g.values } }] }),
      ),
    );
  }

  /** One-click PER-IMAGE action — runs a single-image plan for the row's ref and
   * tracks it so the device auto-refreshes when execution settles. Same 401 →
   * reauth flow as container actions; `input` carries the generic image contract
   * (`refs[]`, optional `restart`). */
  async function singleImage(row: DockerImageRow, actionId: string, label: string, input: Record<string, unknown>) {
    const attempt = async () => {
      if (mode === 'readonly') { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input }], mode);
      if (mode === 'plan') {
        setNotice({ kind: 'ok', text: `${label} ${row.name}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [row.deviceId], []);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `${label} — ${row.name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  /** Image bulk pull/update — groups selected images per device by their ref.
   * Rows whose plugin does not advertise the action (or dangling rows for
   * pull/update) are skipped so mixed selections never create invalid steps. */
  function imageBulkRefs(actionId: string, label: string, rows: DockerImageRow[], extra?: Record<string, unknown>) {
    const eligible = rows.filter((r) => hasAction(r.pluginId, actionId) && !r.dangling);
    if (eligible.length === 0) return;
    runBulk(label, () =>
      Array.from(groupByDevice(eligible, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.name).values()).map(
        (g) => ({ pluginId: g.pluginId, actionId, steps: [{ deviceId: g.deviceId, input: { refs: Array.from(new Set(g.values)), ...extra } }] }),
      ),
    );
  }

  /** Image bulk prune — one step per device that advertises `images.prune`
   * (prune is a host-wide operation; the selection only picks the devices). */
  function imageBulkPrune(rows: DockerImageRow[], all: boolean) {
    const eligible = rows.filter((r) => hasAction(r.pluginId, 'images.prune'));
    if (eligible.length === 0) return;
    const devices = Array.from(new Set(eligible.map((r) => `${r.pluginId}|${r.deviceId}`))).map((k) => {
      const [pluginId, deviceId] = k.split('|');
      return { pluginId: pluginId!, deviceId: deviceId! };
    });
    runBulk(all ? 'Prune all unused images' : 'Prune dangling images', () =>
      devices.map((d) => ({ pluginId: d.pluginId, actionId: 'images.prune', steps: [{ deviceId: d.deviceId, input: { all } }] })),
    );
  }

  // Horizontal splitter: container table (top) vs image panel (bottom). The
  // table gets a fixed share of the page height; collapsing the images below
  // gives its space back to the table — same pattern as the Storage page.
  const [imagesOpen, setImagesOpen] = useState(true);
  const [tablePct, setTablePct] = useState(58);
  const vSplitRef = useRef<HTMLDivElement>(null);
  const vDragCleanup = useRef<(() => void) | null>(null);

  useEffect(() => () => { vDragCleanup.current?.(); }, []);

  const startVDrag = (e: ReactMouseEvent) => {
    e.preventDefault();
    const el = vSplitRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const move = (ev: globalThis.MouseEvent) => {
      const pct = ((ev.clientY - rect.top) / rect.height) * 100;
      setTablePct(Math.min(85, Math.max(20, pct)));
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      vDragCleanup.current = null;
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    vDragCleanup.current = up;
  };

  // Display tree for expandable rows: app → container(s) → volume mounts.
  // `roots` are the top-level (app) nodes; `childMap` maps a node key to its
  // DIRECT children so DataTable can render + recursively expand each level.
  const tree = useMemo(() => {
    const childMap = new Map<string, TreeNode[]>();
    const roots: TreeNode[] = [];
    for (const row of containersQuery.data?.containers ?? []) {
      // Live probe stats + states for this device+plugin override the
      // enrichment data — live wins, cached fills gaps.
      const key = `${row.deviceId}|${row.pluginId}`;
      const liveEntry = liveStatesByDevice.get(key);
      const freshStates = liveEntry && Date.now() - liveEntry.at < 30_000 ? liveEntry.states : undefined;
      const built = buildApp(row, liveStatsByDevice.get(key), freshStates);
      roots.push(built.app);
      childMap.set(built.app.key, built.containers.map((c) => c.node));
      for (const c of built.containers) if (c.volumes.length > 0) childMap.set(c.node.key, c.volumes);
    }
    return { roots, childMap };
  }, [containersQuery.data, liveStatsByDevice, liveStatesByDevice]);

  const columns: DataTableColumn<TreeNode>[] = [
    {
      header: 'App',
      key: 'name',
      width: 210,
      exportValue: (node) => node.row?.name ?? '',
      render: (node) => <AppCell row={node.row} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 230,
      exportValue: (node) => `${node.row?.deviceName ?? '?'} (${node.row?.managementAddress ?? '?'})`,
      render: (node) => {
        const r = node.row;
        if (!r) return null;
        return <DeviceChip deviceName={r.deviceName} managementAddress={r.managementAddress} pluginName={r.pluginName} siteName={r.siteName} interfaces={[]} />;
      },
    },
    {
      // LIVE docker state from the probe cache when fresh — a start/stop shows
      // up in ~3 s instead of waiting for the next inventory poll. Falls back
      // to the (slower) inventory state otherwise.
      header: 'State',
      key: 'state',
      width: 110,
      exportValue: (node) => node.row?.state ?? '',
      render: (node) => {
        const r = node.row;
        if (!r) return null;
        const live = freshLiveStates(r.deviceId, r.pluginId);
        const ls = live ? liveStateOf(r, live) : null;
        // Uppercase — inventory states are uppercase; StateBadge is case-tolerant.
        return <StateBadge state={(ls ?? r.state).toUpperCase()} />;
      },
    },
    {
      header: 'Uptime',
      key: 'startedAt',
      width: 120,
      exportValue: (node) => node.row?.startedAt ?? '',
      sortAccessor: (node) => (node.row?.startedAt ? new Date(node.row.startedAt).getTime() : null),
      render: (node) => (node.row ? <UptimeCell row={node.row} /> : null),
    },
    {
      header: 'Image',
      key: 'image',
      width: 210,
      exportValue: (node) => splitImage(node.row?.image).repo || '',
      render: (node) => {
        const repo = splitImage(node.row?.image).repo;
        return repo ? (
          <span className="block truncate font-mono text-xs text-secondary" title={node.row?.image ?? undefined}>{repo}</span>
        ) : (
          <span className="text-faint">—</span>
        );
      },
    },
    {
      header: 'Tag',
      key: 'tag',
      width: 120,
      exportValue: (node) => splitImage(node.row?.image).tag || '',
      render: (node) => {
        const tag = splitImage(node.row?.image).tag;
        return tag ? (
          <span className="inline-flex items-center rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px] leading-4 text-secondary" title={tag}>{tag}</span>
        ) : (
          <span className="text-faint">—</span>
        );
      },
    },
    {
      header: 'Network / IPs',
      key: 'networks',
      width: 230,
      exportValue: (node) => (node.row ? [...ipsOf(node.row), ...networksOf(node.row).map((n) => n.name)].join(', ') : ''),
      render: (node) => (node.row ? <NetworkCell row={node.row} /> : null),
    },
    {
      header: 'Ports',
      key: 'ports',
      width: 120,
      exportValue: (node) => (node.row ? portsOf(node.row).join(',') : ''),
      render: (node) => (node.row ? <PortsCell row={node.row} /> : null),
    },
    {
      header: 'Version',
      key: 'version',
      width: 130,
      exportValue: (node) => node.row?.version ?? '',
      render: (node) => (node.row ? <VersionCell row={node.row} /> : null),
    },
    {
      // Live per-app stats — LIVE probe data (3s cadence, capability 'probe')
      // aggregated from the app's containers; falls back to the 15-min SSH
      // enrichment snapshot in extra.stats when no probe is available.
      header: 'CPU',
      key: 'cpu',
      width: 90,
      sortAccessor: (node) => effectiveAppStats(node.row)?.['cpuMax'] ?? null,
      exportValue: (node) => { const v = effectiveAppStats(node.row)?.['cpuMax']; return typeof v === 'number' ? `${v.toFixed(1)}%` : ''; },
      render: (node) => cpuCell(effectiveAppStats(node.row)?.['cpuMax']),
    },
    {
      header: 'RAM',
      key: 'ram',
      width: 130,
      sortAccessor: (node) => effectiveAppStats(node.row)?.['memUsedBytes'] ?? null,
      exportValue: (node) => { const v = effectiveAppStats(node.row)?.['memUsedBytes']; return typeof v === 'number' ? formatBytes(v) : ''; },
      render: (node) => memCell(effectiveAppStats(node.row)?.['memUsedBytes']),
    },
    {
      header: 'Net I/O',
      key: 'netio',
      width: 170,
      exportValue: (node) => { const s = effectiveAppStats(node.row); return s && (s['netRxRate'] || s['netTxRate']) ? `↓ ${formatBytes(s['netRxRate'] ?? 0)}/s ↑ ${formatBytes(s['netTxRate'] ?? 0)}/s` : ''; },
      render: (node) => { const s = effectiveAppStats(node.row); return rateCell(s?.['netRxRate'], s?.['netTxRate']); },
    },
    {
      header: 'Block I/O',
      key: 'blockio',
      width: 170,
      exportValue: (node) => { const s = effectiveAppStats(node.row); return s && (s['blkReadRate'] || s['blkWriteRate']) ? `↓ ${formatBytes(s['blkReadRate'] ?? 0)}/s ↑ ${formatBytes(s['blkWriteRate'] ?? 0)}/s` : ''; },
      render: (node) => { const s = effectiveAppStats(node.row); return rateCell(s?.['blkReadRate'], s?.['blkWriteRate']); },
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (node) => new Date(node.row?.collectedAt ?? '').getTime(),
      render: (node) => (node.row ? formatDateTime(node.row.collectedAt) : null),
    },
    {
      // One-click per-row actions. Availability is GENERIC — a button only
      // renders when the row's plugin advertises that action id in its catalog,
      // so any future plugin (docker, proxmox, …) gets the same column for free.
      header: 'Actions',
      key: 'actions',
      width: 150,
      sortable: false,
      excludeFromExport: true,
      render: (node) => {
        const r = node.row;
        if (!r) return null;
        // Read-Only mode disables every WRITE action but keeps the log viewer.
        const readOnly = mode === 'readonly';
        const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean; write?: boolean }[] = [
          { id: 'containers.start', label: 'Start', icon: <Play size={14} />, available: hasAction(r.pluginId, 'containers.start'), eligible: STOPPED_STATES.has(r.state), write: true },
          { id: 'containers.stop', label: 'Stop', icon: <Square size={13} />, available: hasAction(r.pluginId, 'containers.stop'), eligible: RUNNING_STATES.has(r.state), danger: true, write: true },
          { id: 'containers.restart', label: 'Restart', icon: <RotateCw size={14} />, available: hasAction(r.pluginId, 'containers.restart'), eligible: true, write: true },
          { id: 'containers.upgrade', label: 'Update', icon: <ArrowUpCircle size={14} />, available: hasAction(r.pluginId, 'containers.upgrade'), eligible: r.upgradeAvailable === true, write: true },
          // Compose editing is offered whenever the plugin advertises BOTH the
          // read and write side of the contract (TrueNAS custom apps today).
          { id: 'compose.config.read+containers.update', label: 'Edit compose YAML', icon: <FileCode2 size={14} />, available: hasAction(r.pluginId, 'compose.config.read') && hasAction(r.pluginId, 'containers.update'), eligible: true, write: true },
          // Log viewer — read-only, no plan row. TrueNAS serves it over SSH
          // (docker logs), the Docker plugin via the Engine API. Stays enabled in Read-Only mode.
          { id: 'containers.logs.read', label: 'View logs', icon: <ScrollText size={14} />, available: hasAction(r.pluginId, 'containers.logs.read'), eligible: true },
        ];
        return (
          <div className="flex items-center gap-0.5">
            {actions.map((a) => {
              if (!a.available) return null;
              const blockedByReadOnly = readOnly && a.write === true;
              const enabled = a.eligible && !blockedByReadOnly;
              return (
                <button
                  key={a.id}
                  type="button"
                  aria-label={`${a.label} ${r.name}`}
                  title={enabled ? `${a.label} ${r.name}` : blockedByReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : `Not applicable in state ${r.state.toLowerCase()}`}
                  disabled={!enabled}
                  onClick={() => {
                    if (a.id === 'compose.config.read+containers.update') setYamlApp(r);
                    else if (a.id === 'containers.logs.read') setLogsApp(r);
                    else void singleApp(r, a.id, a.label);
                  }}
                  className={clsx(
                    'rounded-md p-1.5 hover:bg-muted',
                    a.danger ? 'text-danger-fg hover:text-danger-fg' : 'text-secondary hover:text-foreground',
                    !enabled && 'cursor-not-allowed opacity-30',
                  )}
                >
                  {a.icon}
                </button>
              );
            })}
          </div>
        );
      },
    },
  ];

  // Images panel data + summary numbers (total size across non-dangling rows).
  const images: DockerImageRow[] = containersQuery.data?.images ?? [];
  const imageTotalBytes = images.reduce((sum, i) => sum + (i.sizeBytes && i.sizeBytes > 0 ? i.sizeBytes : 0), 0);
  const danglingCount = images.filter((i) => i.dangling).length;

  // Container count across all app rows (extra.containerCount when known).
  const containerTotal = tree.roots.reduce((sum, n) => {
    if (!n.row) return sum;
    const c = extraOf(n.row)['containerCount'];
    return sum + (typeof c === 'number' && c > 0 ? c : 1);
  }, 0);

  const imageColumns: DataTableColumn<DockerImageRow>[] = [
    {
      header: 'Image',
      key: 'name',
      width: 280,
      exportValue: (row) => row.name,
      render: (row) => {
        const { repo, tag } = splitImage(row.name);
        return (
          <span className="flex items-center gap-1.5" title={row.name}>
            <span className="block truncate font-mono text-xs text-secondary">{repo || row.name}</span>
            {tag && tag !== 'latest' ? (
              <span className="inline-flex shrink-0 items-center rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px] leading-4 text-secondary">{tag}</span>
            ) : (
              tag === 'latest' && <span className="inline-flex shrink-0 items-center rounded border border-accent-sky-border bg-accent-sky px-1.5 py-0.5 font-mono text-[11px] leading-4 text-accent-sky-fg">latest</span>
            )}
          </span>
        );
      },
    },
    {
      header: 'Size',
      key: 'sizeBytes',
      width: 110,
      sortAccessor: (row) => row.sizeBytes ?? -1,
      exportValue: (row) => formatBytes(row.sizeBytes ?? 0),
      render: (row) => (
        <span className="font-mono text-xs">
          {row.sizeBytes !== null && row.sizeBytes !== undefined ? formatBytes(row.sizeBytes) : '—'}
        </span>
      ),
    },
    {
      // All tags of the image (the first is shown in the Image column; the rest
      // live here). Dangling images have no real tags.
      header: 'Tags',
      key: 'tags',
      width: 200,
      exportValue: (row) => { const t = extraOf(row)['tags']; return Array.isArray(t) ? t.join(', ') : ''; },
      render: (row) => {
        const t = extraOf(row)['tags'];
        const tags = Array.isArray(t) ? t.filter((x): x is string => typeof x === 'string') : [];
        if (tags.length === 0) return <span className="text-faint">—</span>;
        return (
          <span className="flex flex-wrap gap-x-1 gap-y-0.5" title={tags.join(', ')}>
            {tags.slice(0, 4).map((tag) => (
              <span key={tag} className="inline-flex items-center rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px] leading-4 text-secondary">{tag}</span>
            ))}
            {tags.length > 4 && <span className="text-[11px] text-faint">+{tags.length - 4}</span>}
          </span>
        );
      },
    },
    {
      header: 'Created',
      key: 'createdAt',
      width: 170,
      sortAccessor: (row) => new Date(row.createdAt ?? '').getTime(),
      render: (row) => (row.createdAt ? <span className="text-xs text-secondary">{formatDateTime(row.createdAt)}</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Status',
      key: 'status',
      width: 130,
      render: (row) => <ImageStatusBadge row={row} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => (
        <DeviceChip deviceName={row.deviceName} managementAddress={row.managementAddress} pluginName={row.pluginName} siteName={row.siteName} interfaces={[]} />
      ),
    },
    {
      // Per-image actions — GENERIC over the image contract: a button only
      // renders when the row's plugin advertises that action id, so any future
      // container backend (TrueNAS, Proxmox, …) gets this column for free.
      header: 'Actions',
      key: 'actions',
      width: 120,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (row) => {
        const readOnly = mode === 'readonly';
        // Dangling images have no pullable ref — only delete applies.
        const actions: { id: string; label: string; icon: ReactNode; available: boolean; danger?: boolean }[] = [
          { id: 'images.pull', label: 'Pull (re-fetch)', icon: <Download size={14} />, available: hasAction(row.pluginId, 'images.pull') && !row.dangling },
          { id: 'images.update', label: 'Update image + restart containers using it', icon: <ArrowUpCircle size={14} />, available: hasAction(row.pluginId, 'images.update') && !row.dangling },
          { id: 'images.delete', label: 'Delete image', icon: <Trash2 size={13} />, available: hasAction(row.pluginId, 'images.delete'), danger: true },
        ];
        return (
          <div className="flex items-center gap-0.5">
            {actions.map((a) => {
              if (!a.available) return null;
              const blockedByReadOnly = readOnly;
              const enabled = !blockedByReadOnly;
              return (
                <button
                  key={a.id}
                  type="button"
                  aria-label={`${a.label} ${row.name}`}
                  title={enabled ? a.label : 'Read-only mode — switch to Plan or Execute to make changes'}
                  disabled={!enabled}
                  onClick={() => {
                    if (a.id === 'images.pull') void singleImage(row, 'images.pull', `Pull image`, { refs: [row.name] });
                    else if (a.id === 'images.update') {
                      if (!window.confirm(`Update ${row.name} and RESTART every running container that uses it?`)) return;
                      void singleImage(row, 'images.update', `Update image`, { refs: [row.name], restart: true });
                    } else if (a.id === 'images.delete') {
                      const id = typeof extraOf(row)['id'] === 'string' ? (extraOf(row)['id'] as string) : row.name;
                      if (!window.confirm(`Permanently delete image ${row.name}?`)) return;
                      void singleImage(row, 'images.delete', `Delete image`, { ids: [id] });
                    }
                  }}
                  className={clsx(
                    'rounded-md p-1.5 hover:bg-muted',
                    a.danger ? 'text-danger-fg hover:text-danger-fg' : 'text-secondary hover:text-foreground',
                    !enabled && 'cursor-not-allowed opacity-30',
                  )}
                >
                  {a.icon}
                </button>
              );
            })}
          </div>
        );
      },
    },
  ];

  return (
    <Layout title="Containers">
      {/* Full-height column: container / image tables split by a horizontal
          splitter — collapsing the images gives its space back to the table
          instead of leaving it empty below. */}
      <div className="flex h-full min-h-0 flex-col">
        {containersQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading containers...</p>}
        {containersQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load containers: {(containersQuery.error as Error).message}</p>
        )}

        {/* Info / error banner (plan execution itself is shown by the top-bar plans icon). */}
        {notice && (
          <div
            className={clsx(
              'mb-3 flex shrink-0 items-center gap-2 rounded-lg border px-4 py-2 text-xs',
              notice.kind === 'ok' && 'border-success-border bg-success text-success-fg',
              notice.kind === 'info' && 'border-info-border bg-info text-info-fg',
              notice.kind === 'error' && 'border-danger-border bg-danger text-danger-fg',
            )}
          >
            <span className="flex-1">{notice.text}</span>
            <button type="button" aria-label="Dismiss notice" onClick={() => setNotice(null)} className="rounded p-0.5 opacity-70 hover:opacity-100">
              <X size={14} />
            </button>
          </div>
        )}

        {/* Summary strip — app/container counts + image inventory. */}
        {!containersQuery.isLoading && !containersQuery.isError && (
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card px-4 py-2 text-xs">
            <span className="flex items-center gap-2 text-secondary">
              <Container size={13} className="text-accent-solid" />
              {tree.roots.length} app{tree.roots.length === 1 ? '' : 's'} · {containerTotal} container{containerTotal === 1 ? '' : 's'}
            </span>
            <span className="flex items-center gap-2 text-secondary">
              <Container size={13} className="text-muted-foreground" />
              {images.length} image{images.length === 1 ? '' : 's'}
              {imageTotalBytes > 0 && (
                <span className="font-mono text-secondary">· {formatBytes(imageTotalBytes)} total</span>
              )}
              {danglingCount > 0 && <span className="text-faint">({danglingCount} dangling)</span>}
            </span>
            {/* Create app — shown when any device's plugin advertises an install action. */}
            {createCandidates.length > 0 && (
              <button
                type="button"
                onClick={() => navigate('/containers/create-app?from=/containers')}
                className="ml-auto inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
              >
                <Plus size={14} /> Create app
              </button>
            )}
          </div>
        )}

        <div ref={vSplitRef} className="flex min-h-0 flex-1 flex-col">
          {/* Container table (top) — fixed share of the page height while the
              image panel is open; when collapsed it takes everything left. */}
          <div
            className={clsx('min-h-0 pr-1', !imagesOpen && 'flex-1')}
            style={{ height: imagesOpen ? `${tablePct}%` : undefined }}
          >
            {containersQuery.data && (
              <DataTable<TreeNode>
                columns={columns}
                rows={tree.roots}
                rowKey={(node) => node.key}
                storageKey="containers"
                autoRefresh={{ intervalMs: 30_000, queries: [containersQuery] }}
                fillHeight
                searchPlaceholder="Search containers…"
                selectable
                bulkActions={[
                  { label: 'Stop', onClick: containerBulk('containers.stop', 'Stop selected', (r) => RUNNING_STATES.has(r.state), 'No selected apps are running — nothing to stop.') },
                  { label: 'Start', onClick: containerBulk('containers.start', 'Start selected', (r) => STOPPED_STATES.has(r.state), 'No selected apps are stopped — nothing to start.') },
                  { label: 'Restart', onClick: containerBulk('containers.restart', 'Restart selected', () => true, '') },
                  { label: 'Update', onClick: containerBulk('containers.upgrade', 'Update selected', (r) => r.upgradeAvailable === true, 'No selected apps have an update available.') },
                  {
                    label: 'Delete',
                    confirm: (count) => `Permanently delete ${count} app(s) and their docker resources? This is destructive.`,
                    onClick: containerBulk('containers.delete', 'Delete selected', () => true, ''),
                  },
                ]}
                expandable={{
                  childrenOf: (node) => tree.childMap.get(node.key) ?? [],
                  // Bind the per-container action callbacks so expanded child rows
                  // can offer start/stop/restart/delete for a single member.
                  renderChild: (child, _parent, ctx) => (
                    <ChildRow
                      node={child}
                      ctx={ctx}
                      actions={{
                        hasAction,
                        run: singleContainer,
                        canBrowse: canBrowseFs,
                        browseVolume: (node) => setBrowseVolume(node),
                        canConsole,
                        openContainerConsole: (node) => setConsoleNode(node),
                        readOnly: mode === 'readonly',
                      }}
                    />
                  ),
                }}
                emptyMessage="No containers collected yet — assign a TrueNAS or Docker plugin to a device and wait for the next poll."
              />
            )}
          </div>

          {/* Horizontal splitter between the two tables. */}
          {imagesOpen && (
            <div
              role="separator"
              aria-orientation="horizontal"
              onMouseDown={startVDrag}
              className="group relative -my-1 h-3 shrink-0 cursor-row-resize"
              title="Drag to resize — or collapse the image panel for full container height"
            >
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-muted transition-colors group-hover:bg-accent-hover" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-status-neutral transition-colors group-hover:bg-accent-hover" />
              </div>
            </div>
          )}

          {/* Image panel (bottom) — takes the remaining height. The header stays
              mounted when collapsed so it can be re-opened. */}
          <div className={clsx('shrink-0 min-h-0 pl-1', imagesOpen && 'flex-1')}>
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-border bg-card">
              {/* Header row — the title + chevron toggle collapse; the Pull button
                  lives beside them (a nested <button> inside a <button> is invalid). */}
              <div className="flex w-full shrink-0 items-center gap-2 px-4 py-3 text-left">
                <button
                  type="button"
                  onClick={() => setImagesOpen((o) => !o)}
                  className="flex min-w-0 flex-1 items-center justify-between"
                  aria-expanded={imagesOpen}
                >
                  <span className="flex items-center gap-2 text-sm font-semibold text-secondary">
                    <Container size={16} className="text-muted-foreground" />
                    Docker images{containersQuery.data ? ` (${images.length})` : ''}
                  </span>
                  {/* Expanded panel → chevron points DOWN (click collapses it);
                      collapsed → UP (click expands). */}
                  {imagesOpen ? <ChevronDown size={18} className="text-faint" /> : <ChevronUp size={18} className="text-faint" />}
                </button>
                {/* Pull image — offered when ANY device's plugin advertises the
                    generic `images.pull` action; pick a target device in the dialog. */}
                {devicesQuery.data?.some((d) => (d.plugins ?? []).some((p) => hasAction(p.pluginId, 'images.pull'))) && (
                  <button
                    type="button"
                    onClick={() => {
                      const d = devicesQuery.data!.find((x) => (x.plugins ?? []).some((p) => hasAction(p.pluginId, 'images.pull')));
                      if (!d) return;
                      const p = (d.plugins ?? []).find((pp) => hasAction(pp.pluginId, 'images.pull'));
                      setPullTarget({ deviceId: d.id, deviceName: d.name, pluginId: p!.pluginId });
                    }}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-secondary hover:bg-muted"
                  >
                    <Download size={13} /> Pull image
                  </button>
                )}
              </div>
              {imagesOpen && containersQuery.data && (
                <div className="min-h-0 flex-1 border-t border-border p-3">
                  <DataTable<DockerImageRow>
                    columns={imageColumns}
                    rows={images}
                    rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
                    storageKey="containers-images"
                    autoRefresh={{ intervalMs: 30_000, queries: [containersQuery] }}
                    fillHeight
                    searchPlaceholder="Search images…"
                    selectable
                    bulkActions={[
                      {
                        label: 'Pull',
                        enabled: (rows) => rows.some((r) => hasAction(r.pluginId, 'images.pull') && !r.dangling),
                        onClick: (rows) => imageBulkRefs('images.pull', `Pull ${rows.length} image(s)`, rows),
                      },
                      {
                        label: 'Update + restart',
                        confirm: (count) => `Re-pull ${count} image(s) and RESTART every running container that uses them?`,
                        enabled: (rows) => rows.some((r) => hasAction(r.pluginId, 'images.update') && !r.dangling),
                        onClick: (rows) => imageBulkRefs('images.update', `Update ${rows.length} image(s)`, rows, { restart: true }),
                      },
                      {
                        label: 'Prune unused',
                        confirm: () => 'Remove all dangling images on the selected device(s)? Images in use are never removed.',
                        enabled: (rows) => rows.some((r) => hasAction(r.pluginId, 'images.prune')),
                        onClick: (rows) => imageBulkPrune(rows, false),
                      },
                      {
                        label: 'Delete',
                        confirm: (count) => `Permanently delete ${count} image(s) from the appliance? Images in use by a running app may fail to remove.`,
                        onClick: imageBulkDelete,
                      },
                    ]}
                    emptyMessage="No image data reported yet — Docker hosts (generic Docker plugin) and TrueNAS SCALE appliances report their images within a poll cycle."
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* In-session 2FA revalidation (plan create/execute returned 401). */}
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

      {/* Custom-app compose YAML editor. */}
      {yamlApp && <YamlEditorDialog app={yamlApp} onClose={() => setYamlApp(null)} />}
      {logsApp && <LogsDialog app={logsApp} onClose={() => setLogsApp(null)} />}

      {/* Filesystem browser — browse a container volume's HOST location over SFTP (capability 'filesystem'). */}
      {browseVolume && browseVolume.volumeSource != null && (
        <FileBrowserDialog
          deviceId={browseVolume.deviceId ?? ''}
          pluginId={browseVolume.pluginId}
          context={{ kind: 'container-volume', source: browseVolume.volumeSource, ...(browseVolume.volumeTarget ? { target: browseVolume.volumeTarget } : {}) }}
          title={`Browse volume ${browseVolume.volumeSource}`}
          subtitle={`${browseVolume.service ?? ''}${browseVolume.volumeTarget ? ` · mounted at ${browseVolume.volumeTarget} in the container` : ''}`}
          onClose={() => setBrowseVolume(null)}
        />
      )}

      {/* SSH console — an interactive shell INSIDE one container member (capability 'sshConsole'). */}
      {consoleNode && consoleNode.kind === 'container' && (
        <ConsoleDialog
          deviceId={consoleNode.deviceId ?? ''}
          pluginId={consoleNode.pluginId}
          context={{ kind: 'container', service: consoleNode.service, ...(consoleNode.appName ? { app: consoleNode.appName } : {}) }}
          title={`Console — ${consoleNode.service ?? 'container'}`}
          subtitle={`${consoleNode.image ?? ''}${consoleNode.state ? ` · ${consoleNode.state}` : ''}`}
          onClose={() => setConsoleNode(null)}
        />
      )}

      {/* Create app is a full-page wizard now (/containers/create-app) — it owns
          its own candidate detection, clone prefill and plan submission. */}

      {/* Pull image — arbitrary refs on one device via the generic images.pull action. */}
      {pullTarget && (
        <PullImageDialog deviceId={pullTarget.deviceId} deviceName={pullTarget.deviceName} pluginId={pullTarget.pluginId} onClose={() => setPullTarget(null)} />
      )}
    </Layout>
  );
}
