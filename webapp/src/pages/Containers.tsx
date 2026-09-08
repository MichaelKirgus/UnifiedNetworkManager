import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowUpCircle, ChevronDown, ChevronRight, ChevronUp, Container, FileCode2, Loader2, Play, Plus, RotateCw, ScrollText, Square, Trash2, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type FormEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { CreateAppDialog, CreateAppCandidate, type AppMode } from '../components/CreateAppDialog';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { api, ApiError, CatalogEntry, ContainerNetwork, ContainerRow, ContainerServiceDetail, DockerImageRow } from '../api/client';

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
async function createAndExecutePlan(
  pluginId: string,
  actionId: string,
  steps: Array<{ deviceId: string; input: Record<string, unknown> }>,
): Promise<string> {
  const first = steps[0];
  const plan = await api.createPlan({
    pluginId,
    intentActionId: actionId,
    inputs: first.input,
    devices: [{ deviceId: first.deviceId }],
  });
  if (steps.length > 1) {
    await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId, input: s.input })));
  }
  await api.executePlan(plan.id);
  return plan.id;
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
  const [yaml, setYaml] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);

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
    setSaving(true);
    setError(null);
    try {
      await createAndExecutePlan(app.pluginId, 'containers.update', [{ deviceId: app.deviceId, input: { name: app.name, composeString: yaml } }]);
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-2xl rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Edit compose — {app.name}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Applies via the plan workflow on {app.deviceName ?? app.deviceId}. The app is redeployed after saving.
            </p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="p-4">
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
              {error && (
                <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
              )}
              <textarea
                value={yaml}
                onChange={(e) => setYaml(e.target.value)}
                spellCheck={false}
                className="h-[46vh] w-full resize-y rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed focus:border-slate-500 focus:outline-none"
              />
              <div className="mt-3 flex items-center justify-end gap-2">
                <button type="button" onClick={onClose} disabled={saving} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40">
                  Cancel
                </button>
                <button type="button" onClick={save} disabled={saving || yaml.trim() === ''} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-40">
                  {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />} Apply &amp; redeploy
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {reauth && (
        <ReauthDialog
          contextLabel={`Edit compose for ${app.name}`}
          onClose={() => setReauth(false)}
          onSuccess={async () => { setReauth(false); await save(); }}
        />
      )}
    </div>
  );
}

/** One container's log section as returned by `containers.logs.read`. Both the
 * TrueNAS plugin (SSH docker logs) and the Docker plugin (Engine API) emit this
 * same shape, so one renderer covers both. */
interface LogSection { id?: string; service?: string; state?: string; logs: string; error?: string }

/**
 * LogsDialog — read-only viewer for a single app's container log output. On open
 * (and on tail-change / refresh) it calls the plugin's read-only `containers.logs.read`
 * action via the generic execute path (no plan row, no 2FA). TrueNAS serves this over
 * SSH (`docker logs --tail N`) because its API has no log RPC; the Docker plugin uses
 * the Engine API directly. Multi-container apps render one section per container.
 */
function LogsDialog({ app, onClose }: { app: ContainerRow; onClose: () => void }) {
  const [tail, setTail] = useState(300);
  const [refreshTick, setRefreshTick] = useState(0); // bump to re-fetch the same tail
  const [sections, setSections] = useState<LogSection[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.executePluginAction(app.pluginId, { deviceId: app.deviceId, actionId: 'containers.logs.read', input: { name: app.name, tail } });
        if (!cancelled) {
          const c = res.details.containers;
          setSections(Array.isArray(c) ? (c as LogSection[]) : []);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [app.pluginId, app.deviceId, app.name, tail, refreshTick]);

  const totalLines = (sections ?? []).reduce((n, s) => n + (s.logs ? s.logs.split('\n').length : 0), 0);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-3xl rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-foreground">Logs — {app.name}</h2>
            <p className="mt-0.5 truncate text-xs text-muted-foreground">
              Last {tail} lines per container on {app.deviceName ?? app.deviceId}.
            </p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="flex items-center gap-2 border-b border-border px-4 py-2">
          <label htmlFor="logs-tail" className="text-xs font-medium text-secondary">Tail</label>
          <select
            id="logs-tail"
            value={tail}
            onChange={(e) => setTail(Number(e.target.value))}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus:border-slate-500 focus:outline-none"
          >
            {[100, 300, 500, 1000].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
          <button type="button" onClick={() => setRefreshTick((t) => t + 1)} disabled={loading} className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-background disabled:opacity-40">
            {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCw className="h-3 w-3" />} Refresh
          </button>
          {!loading && !error && sections !== null && (
            <span className="ml-auto text-xs text-faint">{totalLines} line{totalLines === 1 ? '' : 's'}</span>
          )}
        </div>

        <div className="p-4">
          {loading && (
            <div className="flex items-center gap-2 py-8 text-sm text-secondary">
              <Loader2 className="h-4 w-4 animate-spin" /> Reading logs…
            </div>
          )}

          {!loading && error && (
            <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {!loading && !error && sections !== null && sections.length === 0 && (
            <div className="py-6 text-center text-sm text-secondary">No log output available for this app.</div>
          )}

          {!loading && !error && sections !== null && sections.length > 0 && (
            <div className="space-y-3">
              {sections.map((s, i) => (
                <div key={s.id ?? i}>
                  {sections.length > 1 && (
                    <div className="mb-1 flex items-center gap-2 text-xs font-medium text-secondary">
                      <span>{s.service || s.id?.slice(0, 12) || `container ${i + 1}`}</span>
                      {s.state && <span className="text-faint">({s.state})</span>}
                    </div>
                  )}
                  {s.error ? (
                    <div className="rounded-md border border-danger-border bg-danger px-3 py-2 font-mono text-xs text-danger-fg">{s.error}</div>
                  ) : s.logs === '' ? (
                    <div className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-faint">(no output)</div>
                  ) : (
                    <pre className="max-h-[52vh] overflow-auto rounded-md border border-border bg-background p-3 font-mono text-[11px] leading-relaxed">
                      {s.logs.split('\n').map((line, li) => (
                        line.startsWith('[err] ')
                          ? <span key={li} className="text-danger-fg">{line.slice(6)}{'\n'}</span>
                          : <span key={li}>{line}{'\n'}</span>
                      ))}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <footer className="flex items-center justify-end border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background">
            Close
          </button>
        </footer>
      </div>
    </div>
  );
}

/** Uptime cell — "running since". RUNNING + startedAt → duration; non-RUNNING
 * or no stamp → "—". The value is the real container start when the plugin
 * observed it via SSH (`docker inspect`), otherwise UNM-tracked from state
 * transitions (a lower bound that resets after restarts). */
function UptimeCell({ row }: { row: ContainerRow }) {
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-faint">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-faint">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span
      className="font-mono text-xs text-secondary"
      title={`Running since ${new Date(row.startedAt).toLocaleString()}`}
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
  PAUSED: 'bg-sky-100 text-sky-800 border-sky-300 dark:bg-sky-950/40 dark:text-sky-300 dark:border-sky-900/70',
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
    <span title={tip} className="inline-flex items-center rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-sky-800 dark:border-sky-900/70 dark:bg-sky-950/40 dark:text-sky-300">
      {net.name}
    </span>
  );
}

/** One static IP chip (v4 blue / v6 violet — same convention as the Firewall page). */
function IpChip({ ip }: { ip: string }) {
  const isV6 = ip.includes(':');
  return (
    <span className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', isV6 ? 'border-violet-200 bg-violet-50 text-violet-800 dark:border-violet-900/70 dark:bg-violet-950/40 dark:text-violet-300' : 'border-info-border bg-info text-info-fg')}>
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
      {row.upgradeAvailable && <span className="h-2 w-2 rounded-full bg-amber-400" title="Update available" />}
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
  return (
    <div className="flex items-center gap-0.5">
      {actions.map((a) => {
        if (!a.available) return null;
        const enabled = a.eligible;
        return (
          <button
            key={a.id}
            type="button"
            aria-label={`${a.label} ${node.service ?? ''}`}
            title={enabled ? `${a.label} ${node.service ?? ''}` : `Not applicable in state ${state || 'unknown'}`}
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
    </div>
  );
}

/** Cell content for one column of an expanded child row — mirrors the top-level
 * column renders so children line up with the header. ONLY the name column is
 * indented (the hierarchy cue); every other cell aligns normally under its
 * header, exactly like a regular data row. Container rows fill most columns;
 * volume leaves only use the name column (indented one step deeper). */
function nodeCell(key: string, node: TreeNode, depth: number, actions?: ChildActionContext): ReactNode {
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
      return (
        <span className="block truncate font-mono text-[11px] text-muted-foreground" style={{ paddingLeft: 32 + depth * 14 }} title={node.volumeText}>
          {node.volumeText}
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
          <span key="ip" className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', node.ip.includes(':') ? 'border-violet-200 bg-violet-50 text-violet-800 dark:border-violet-900/70 dark:bg-violet-950/40 dark:text-violet-300' : 'border-info-border bg-info text-info-fg')} title="IP">
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
      return <span className="font-mono text-xs text-foreground" title={`Running since ${new Date(node.startedAt).toLocaleString()}`}>{formatDuration(secs)}</span>;
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
  // Theme-aware fills — in dark mode a near-white bg-sky-50/40 over the dark
  // card blends into a mid-gray band that kills text contrast, so children use
  // muted-panel shades instead (container rows lighter than volume leaves).
  return (
    <tr className={node.kind === 'volume' ? 'bg-background/60 dark:bg-muted/40' : 'bg-sky-50/40 dark:bg-muted/70'}>
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
          {nodeCell(col.key, node, ctx.depth, actions)}
        </td>
      ))}
    </tr>
  );
}

export default function Containers() {
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
  /** Custom app whose compose YAML is being edited. */
  const [yamlApp, setYamlApp] = useState<ContainerRow | null>(null);
  const [logsApp, setLogsApp] = useState<ContainerRow | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
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
      for (const g of buildGroups()) {
        if (g.steps.length === 0) continue;
        const planId = await createAndExecutePlan(g.pluginId, g.actionId, g.steps);
        // Track per group so the touched devices refresh when execution settles.
        const deviceIds = Array.from(new Set(g.steps.map((s) => s.deviceId)));
        const names = Array.isArray(g.steps[0].input['names']) ? (g.steps[0].input['names'] as string[]) : [];
        trackPlan(planId, deviceIds, names);
      }
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  /** Create-app submit — a single-step plan through the standard workflow
   * (2FA-gated), tracked so the device is force-refreshed when execution settles.
   * Throws on failure so the dialog can surface it; a 401 opens the reauth flow
   * AND throws, keeping the dialog open for retry after revalidation. */
  async function runInstall(candidate: CreateAppCandidate, mode: AppMode, input: Record<string, unknown>) {
    const actionId = candidate.actions[mode];
    if (!actionId) throw new Error(`No install action for mode '${mode}' on ${candidate.deviceName}`);
    const label = `Create app ${String(input['name'])}`;
    const attempt = async () => {
      const planId = await createAndExecutePlan(candidate.pluginId, actionId, [{ deviceId: candidate.deviceId, input }]);
      trackPlan(planId, [candidate.deviceId], typeof input['name'] === 'string' ? [input['name']] : []);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // ReauthDialog takes over — the dialog closes and the plan runs after revalidation.
        setReauth({ label, retry: attempt });
        return;
      }
      throw err; // dialog renders this as its submit error
    }
  }

  /** One-click row action — runs a single-app plan and tracks it so the row
   * auto-refreshes when execution settles. Same 401 → reauth flow as bulk. */
  async function singleApp(row: ContainerRow, actionId: string, label: string) {
    const attempt = async () => {
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { names: [row.name] } }]);
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
      const planId = await createAndExecutePlan(node.pluginId!, actionId, [{ deviceId: node.deviceId!, input: { names: [name] } }]);
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
      render: (node) => (node.row ? new Date(node.row.collectedAt).toLocaleString() : null),
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
        const actions: { id: string; label: string; icon: ReactNode; available: boolean; eligible: boolean; danger?: boolean }[] = [
          { id: 'containers.start', label: 'Start', icon: <Play size={14} />, available: hasAction(r.pluginId, 'containers.start'), eligible: STOPPED_STATES.has(r.state) },
          { id: 'containers.stop', label: 'Stop', icon: <Square size={13} />, available: hasAction(r.pluginId, 'containers.stop'), eligible: RUNNING_STATES.has(r.state), danger: true },
          { id: 'containers.restart', label: 'Restart', icon: <RotateCw size={14} />, available: hasAction(r.pluginId, 'containers.restart'), eligible: true },
          { id: 'containers.upgrade', label: 'Update', icon: <ArrowUpCircle size={14} />, available: hasAction(r.pluginId, 'containers.upgrade'), eligible: r.upgradeAvailable === true },
          // Compose editing is offered whenever the plugin advertises BOTH the
          // read and write side of the contract (TrueNAS custom apps today).
          { id: 'compose.config.read+containers.update', label: 'Edit compose YAML', icon: <FileCode2 size={14} />, available: hasAction(r.pluginId, 'compose.config.read') && hasAction(r.pluginId, 'containers.update'), eligible: true },
          // Log viewer — read-only, no plan row. TrueNAS serves it over SSH
          // (docker logs), the Docker plugin via the Engine API.
          { id: 'containers.logs.read', label: 'View logs', icon: <ScrollText size={14} />, available: hasAction(r.pluginId, 'containers.logs.read'), eligible: true },
        ];
        return (
          <div className="flex items-center gap-0.5">
            {actions.map((a) => {
              if (!a.available) return null;
              const enabled = a.eligible;
              return (
                <button
                  key={a.id}
                  type="button"
                  aria-label={`${a.label} ${r.name}`}
                  title={enabled ? `${a.label} ${r.name}` : `Not applicable in state ${r.state.toLowerCase()}`}
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
              tag === 'latest' && <span className="inline-flex shrink-0 items-center rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-sky-700 dark:border-sky-900/70 dark:bg-sky-950/40 dark:text-sky-300">latest</span>
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
      render: (row) => (row.createdAt ? <span className="text-xs text-secondary">{new Date(row.createdAt).toLocaleString()}</span> : <span className="text-faint">—</span>),
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
              <Container size={13} className="text-indigo-500" />
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
                onClick={() => setCreateOpen(true)}
                className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90"
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
                    <ChildRow node={child} ctx={ctx} actions={{ hasAction, run: singleContainer }} />
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
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-muted transition-colors group-hover:bg-indigo-400" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-slate-300 transition-colors group-hover:bg-indigo-400" />
              </div>
            </div>
          )}

          {/* Image panel (bottom) — takes the remaining height. The header stays
              mounted when collapsed so it can be re-opened. */}
          <div className={clsx('shrink-0 min-h-0 pl-1', imagesOpen && 'flex-1')}>
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-border bg-card">
              <button
                type="button"
                onClick={() => setImagesOpen((o) => !o)}
                className="flex w-full shrink-0 items-center justify-between px-4 py-3 text-left"
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

      {/* Create app (catalog template or custom compose) — generic over any
          backend whose plugin advertises an install action. `apps` feeds the
          "Duplicate existing" source picker + clone prefill. */}
      {createOpen && createCandidates.length > 0 && (
        <CreateAppDialog candidates={createCandidates} apps={containersQuery.data?.containers ?? []} onSubmit={(c, mode, input) => runInstall(c, mode, input)} onClose={() => setCreateOpen(false)} />
      )}
    </Layout>
  );
}
