import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronRight, ChevronUp, Container, ExternalLink, FileCode2, Loader2, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type FormEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { api, ApiError, ContainerNetwork, ContainerRow, ContainerServiceDetail, DockerImageRow } from '../api/client';

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
  STOPPED: 'bg-muted text-secondary border-border',
  ERROR: 'bg-danger text-danger-fg border-danger-border',
  FAILED: 'bg-danger text-danger-fg border-danger-border',
  // Docker-native states (generic docker plugin):
  EXITED: 'bg-muted text-secondary border-border',
  CREATED: 'bg-muted text-secondary border-border',
  RESTARTING: 'bg-warning text-warning-fg border-warning-border',
  REMOVING: 'bg-warning text-warning-fg border-warning-border',
  PAUSED: 'bg-sky-100 text-sky-800 border-sky-300',
  DEAD: 'bg-danger text-danger-fg border-danger-border',
};

function StateBadge({ state }: { state: string }) {
  const style = STATE_STYLES[state] ?? 'bg-warning text-warning-fg border-warning-border';
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
  service?: string;
  image?: string | null;
  state?: string | null;
  mac?: string | null;
  ip?: string | null;
  startedAt?: string | null;
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
 * app-level image so nothing is lost. */
function buildApp(row: ContainerRow): BuiltApp {
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
    containers.push({
      node: {
        key: ckey,
        kind: 'container',
        service: s.service ?? (list.length > 1 ? undefined : row.name),
        image: s.image ?? null,
        state: s.state ?? null,
        mac: s.mac ?? null,
        ip: s.ip ?? null,
        startedAt: s.startedAt ?? null,
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
    <span title={tip} className="inline-flex items-center rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-sky-800">
      {net.name}
    </span>
  );
}

/** One static IP chip (v4 blue / v6 violet — same convention as the Firewall page). */
function IpChip({ ip }: { ip: string }) {
  const isV6 = ip.includes(':');
  return (
    <span className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', isV6 ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-info-border bg-info text-info-fg')}>
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

/** Top-level App cell — name + "custom" marker (+ an edit-compose button for custom apps). */
function AppCell({ row, onEditCompose }: { row?: ContainerRow; onEditCompose?: (row: ContainerRow) => void }) {
  if (!row) return null;
  const isCustom = typeof extraOf(row)['customApp'] === 'boolean' && (extraOf(row)['customApp'] as boolean);
  return (
    <div className="flex flex-col gap-0.5">
      <span className="flex items-center gap-1.5">
        <span className="font-medium text-foreground">{row.name}</span>
        {isCustom && onEditCompose && (
          <button
            type="button"
            onClick={() => onEditCompose(row)}
            title="Edit this custom app's Docker Compose YAML"
            aria-label={`Edit compose for ${row.name}`}
            className="rounded p-0.5 text-faint hover:bg-muted hover:text-secondary"
          >
            <FileCode2 size={13} />
          </button>
        )}
      </span>
      {isCustom && (
        <span className="text-[10px] uppercase tracking-wide text-faint">custom</span>
      )}
    </div>
  );
}

/** Cell content for one column of an expanded child row — mirrors the top-level
 * column renders so children line up with the header. ONLY the name column is
 * indented (the hierarchy cue); every other cell aligns normally under its
 * header, exactly like a regular data row. Container rows fill most columns;
 * volume leaves only use the name column (indented one step deeper). */
function nodeCell(key: string, node: TreeNode, depth: number): ReactNode {
  switch (key) {
    case 'name': {
      if (node.kind === 'container') {
        return (
          <span className="block truncate font-medium text-secondary" style={{ paddingLeft: 18 + depth * 14 }} title={node.service ?? undefined}>
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
    case 'state':
      if (node.kind === 'container' && node.state) return <StateBadge state={node.state.toUpperCase()} />;
      return null;
    case 'image': {
      if (node.kind !== 'container') return null;
      const repo = splitImage(node.image).repo;
      return repo ? (
        <span className="block truncate font-mono text-xs text-secondary" title={node.image ?? undefined}>{repo}</span>
      ) : (
        <span className="text-faint">—</span>
      );
    }
    case 'tag': {
      if (node.kind !== 'container') return null;
      const tag = splitImage(node.image).tag;
      return tag ? (
        <span className="inline-flex items-center rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px] leading-4 text-secondary" title={tag}>{tag}</span>
      ) : (
        <span className="text-faint">—</span>
      );
    }
    case 'networks': {
      if (node.kind !== 'container') return null;
      const parts: ReactNode[] = [];
      if (node.ip) {
        parts.push(
          <span key="ip" className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', node.ip.includes(':') ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-info-border bg-info text-info-fg')} title="IP">
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
      return <span className="font-mono text-xs text-secondary" title={`Running since ${new Date(node.startedAt).toLocaleString()}`}>{formatDuration(secs)}</span>;
    }
    default:
      return null;
  }
}

/** One expanded child rendered as a FULL `<tr>` — a chevron cell plus one cell
 * per visible column (ctx.columns), so it stays aligned with the header. A
 * container that has volume mounts gets its own chevron for recursive expand. */
function ChildRow({ node, ctx }: { node: TreeNode; ctx: ExpandChildContext }) {
  return (
    <tr className={node.kind === 'volume' ? 'bg-background/60' : 'bg-sky-50/40'}>
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
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
          {nodeCell(col.key, node, ctx.depth)}
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

  // --- Bulk actions + YAML editor (plan-workflow backed) ---------------------
  const navigate = useNavigate();
  /** In-session 2FA revalidation prompt (shown when a plan call returns 401). */
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
  /** Custom app whose compose YAML is being edited. */
  const [yamlApp, setYamlApp] = useState<ContainerRow | null>(null);
  /** Dismissible status banner (plan started / info / error). */
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string; planId?: string } | null>(null);

  // State sets used to filter which selected rows are eligible for an action.
  const STOPPED_STATES = useMemo(() => new Set(['STOPPED', 'STOPPING']), []);
  const RUNNING_STATES = useMemo(() => new Set(['RUNNING', 'DEPLOYING']), []);

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
      let lastPlanId: string | null = null;
      for (const g of buildGroups()) {
        if (g.steps.length === 0) continue;
        lastPlanId = await createAndExecutePlan(g.pluginId, g.actionId, g.steps);
      }
      if (lastPlanId) setNotice({ kind: 'ok', text: `${label} — plan started in the background.`, planId: lastPlanId });
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
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
      const built = buildApp(row);
      roots.push(built.app);
      childMap.set(built.app.key, built.containers.map((c) => c.node));
      for (const c of built.containers) if (c.volumes.length > 0) childMap.set(c.node.key, c.volumes);
    }
    return { roots, childMap };
  }, [containersQuery.data]);

  const columns: DataTableColumn<TreeNode>[] = [
    {
      header: 'App',
      key: 'name',
      width: 210,
      exportValue: (node) => node.row?.name ?? '',
      render: (node) => <AppCell row={node.row} onEditCompose={(r) => setYamlApp(r)} />,
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
      header: 'State',
      key: 'state',
      width: 110,
      exportValue: (node) => node.row?.state ?? '',
      render: (node) => (node.row ? <StateBadge state={node.row.state} /> : null),
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
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (node) => new Date(node.row?.collectedAt ?? '').getTime(),
      render: (node) => (node.row ? new Date(node.row.collectedAt).toLocaleString() : null),
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
              tag === 'latest' && <span className="inline-flex shrink-0 items-center rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-sky-700">latest</span>
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

        {/* Background-execution / info / error banner (bulk actions + YAML edits). */}
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
            {notice.planId && (
              <button
                type="button"
                onClick={() => navigate(`/plans/${notice.planId}`)}
                className="inline-flex items-center gap-1 font-medium underline-offset-2 hover:underline"
              >
                View plan <ExternalLink size={12} />
              </button>
            )}
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
                  { label: 'Stop', onClick: containerBulk('containers.stop', 'Stop selected', (r) => !RUNNING_STATES.has(r.state), 'No selected apps are running — nothing to stop.') },
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
                  renderChild: (child, _parent, ctx) => <ChildRow node={child} ctx={ctx} />,
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
    </Layout>
  );
}
