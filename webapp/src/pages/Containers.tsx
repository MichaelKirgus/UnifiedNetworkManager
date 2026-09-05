import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronRight, ChevronUp, Container } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { api, ContainerNetwork, ContainerRow, ContainerServiceDetail, DockerImageRow } from '../api/client';

/** Uptime cell — "running since". RUNNING + startedAt → duration; non-RUNNING
 * or no stamp → "—". The value is the real container start when the plugin
 * observed it via SSH (`docker inspect`), otherwise UNM-tracked from state
 * transitions (a lower bound that resets after restarts). */
function UptimeCell({ row }: { row: ContainerRow }) {
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-slate-400">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-slate-400">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span
      className="font-mono text-xs text-slate-700"
      title={`Running since ${new Date(row.startedAt).toLocaleString()}`}
    >
      {formatDuration(secs)}
    </span>
  );
}

/** App workload state → badge style (TrueNAS SCALE states are uppercase; the
 * generic Docker plugin emits its own native states for child containers). */
const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  STOPPED: 'bg-slate-200 text-slate-600 border-slate-300',
  ERROR: 'bg-red-100 text-red-800 border-red-300',
  FAILED: 'bg-red-100 text-red-800 border-red-300',
  // Docker-native states (generic docker plugin):
  EXITED: 'bg-slate-200 text-slate-600 border-slate-300',
  CREATED: 'bg-slate-200 text-slate-600 border-slate-300',
  RESTARTING: 'bg-amber-100 text-amber-800 border-amber-300',
  REMOVING: 'bg-amber-100 text-amber-800 border-amber-300',
  PAUSED: 'bg-sky-100 text-sky-800 border-sky-300',
  DEAD: 'bg-red-100 text-red-800 border-red-300',
};

function StateBadge({ state }: { state: string }) {
  const style = STATE_STYLES[state] ?? 'bg-amber-100 text-amber-800 border-amber-300';
  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium', style)}>
      {state.toLowerCase()}
    </span>
  );
}

/** Reads the `extra` JSON object defensively — corrupt rows must not break the table. */
function extraOf(row: ContainerRow): Record<string, unknown> {
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
    <span className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', isV6 ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-blue-200 bg-blue-50 text-blue-800')}>
      {ip}
    </span>
  );
}

/** Network + IP cell: static IPs first, then network chips; "—" when neither. */
function NetworkCell({ row }: { row: ContainerRow }) {
  const ips = ipsOf(row);
  const nets = networksOf(row);
  if (ips.length === 0 && nets.length === 0) return <span className="text-slate-400">—</span>;
  return (
    <div className="flex flex-col gap-1">
      {ips.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">{ips.map((ip) => <IpChip key={ip} ip={ip} />)}</span>
      )}
      {nets.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">
          {nets.slice(0, 4).map((n) => <NetworkChip key={n.name} net={n} />)}
          {nets.length > 4 && <span className="text-[11px] text-slate-400" title={nets.map((n) => n.name).join(', ')}>+{nets.length - 4}</span>}
        </span>
      )}
    </div>
  );
}

/** Published host ports — first three + "+N" overflow. */
function PortsCell({ row }: { row: ContainerRow }) {
  const ports = portsOf(row);
  if (ports.length === 0) return <span className="text-slate-400">—</span>;
  const shown = ports.slice(0, 3);
  return (
    <span title={ports.join(', ')} className="font-mono text-xs text-slate-700">
      {shown.map((p) => p).join(', ')}
      {ports.length > 3 && <span className="text-slate-400"> +{ports.length - 3}</span>}
    </span>
  );
}

/** Status badge for the images panel — dangling (slate) / update available
 * (amber); plain hosts report neither, so most rows show a dash. */
function ImageStatusBadge({ row }: { row: DockerImageRow }) {
  if (row.dangling) {
    return (
      <span className="inline-flex items-center rounded-full border border-slate-300 bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600" title="Dangling image — no tag references it">
        dangling
      </span>
    );
  }
  if (row.updateAvailable === true) {
    return (
      <span className="inline-flex items-center rounded-full border border-amber-300 bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-800" title="A newer version of this image is available">
        update available
      </span>
    );
  }
  return <span className="text-slate-400">—</span>;
}

/** Version cell with an amber "update available" dot. */
function VersionCell({ row }: { row: ContainerRow }) {
  const v = row.version && row.version.trim() !== '' ? row.version : null;
  if (!v) return <span className="text-slate-400">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-700" title={row.upgradeAvailable ? 'Update available' : undefined}>
      {v}
      {row.upgradeAvailable && <span className="h-2 w-2 rounded-full bg-amber-400" title="Update available" />}
    </span>
  );
}

/** Top-level App cell — name + "custom" marker. */
function AppCell({ row }: { row?: ContainerRow }) {
  if (!row) return null;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-medium text-slate-800">{row.name}</span>
      {typeof extraOf(row)['customApp'] === 'boolean' && (extraOf(row)['customApp'] as boolean) && (
        <span className="text-[10px] uppercase tracking-wide text-slate-400">custom</span>
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
          <span className="block truncate font-medium text-slate-700" style={{ paddingLeft: 18 + depth * 14 }} title={node.service ?? undefined}>
            {node.service ?? '—'}
          </span>
        );
      }
      // Volume leaf — the mount lives in the name column, indented under its container.
      return (
        <span className="block truncate font-mono text-[11px] text-slate-500" style={{ paddingLeft: 32 + depth * 14 }} title={node.volumeText}>
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
        <span className="block truncate font-mono text-xs text-slate-700" title={node.image ?? undefined}>{repo}</span>
      ) : (
        <span className="text-slate-400">—</span>
      );
    }
    case 'tag': {
      if (node.kind !== 'container') return null;
      const tag = splitImage(node.image).tag;
      return tag ? (
        <span className="inline-flex items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-slate-600" title={tag}>{tag}</span>
      ) : (
        <span className="text-slate-400">—</span>
      );
    }
    case 'networks': {
      if (node.kind !== 'container') return null;
      const parts: ReactNode[] = [];
      if (node.ip) {
        parts.push(
          <span key="ip" className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', node.ip.includes(':') ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-blue-200 bg-blue-50 text-blue-800')} title="IP">
            {node.ip}
          </span>
        );
      }
      if (node.mac) parts.push(<span key="mac" className="font-mono text-[11px] text-slate-500" title="MAC address">MAC {node.mac}</span>);
      if (parts.length === 0) return <span className="text-slate-400">—</span>;
      return <span className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">{parts}</span>;
    }
    case 'startedAt': {
      if (node.kind !== 'container' || !node.startedAt) return null;
      const since = new Date(node.startedAt).getTime();
      if (Number.isNaN(since)) return null;
      const secs = Math.max(0, (Date.now() - since) / 1000);
      return <span className="font-mono text-xs text-slate-700" title={`Running since ${new Date(node.startedAt).toLocaleString()}`}>{formatDuration(secs)}</span>;
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
    <tr className={node.kind === 'volume' ? 'bg-slate-50/60' : 'bg-sky-50/40'}>
      <td className="px-1 py-2 align-middle">
        {ctx.hasChildren ? (
          <button
            type="button"
            onClick={ctx.onToggle}
            aria-expanded={ctx.expanded}
            title={ctx.expanded ? 'Collapse volume mounts' : 'Show volume mounts'}
            className="flex h-6 w-6 items-center justify-center rounded text-slate-400 hover:bg-slate-200 hover:text-slate-600"
          >
            {ctx.expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
          </button>
        ) : (
          <span className="inline-block h-6 w-6" />
        )}
      </td>
      {ctx.columns.map((col) => (
        <td key={col.key} className="overflow-hidden px-4 py-2 text-slate-700">
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
          <span className="block truncate font-mono text-xs text-slate-700" title={node.row?.image ?? undefined}>{repo}</span>
        ) : (
          <span className="text-slate-400">—</span>
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
          <span className="inline-flex items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-slate-600" title={tag}>{tag}</span>
        ) : (
          <span className="text-slate-400">—</span>
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
            <span className="block truncate font-mono text-xs text-slate-700">{repo || row.name}</span>
            {tag && tag !== 'latest' ? (
              <span className="inline-flex shrink-0 items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-slate-600">{tag}</span>
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
      header: 'Created',
      key: 'createdAt',
      width: 170,
      sortAccessor: (row) => new Date(row.createdAt ?? '').getTime(),
      render: (row) => (row.createdAt ? <span className="text-xs text-slate-600">{new Date(row.createdAt).toLocaleString()}</span> : <span className="text-slate-400">—</span>),
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
        {containersQuery.isLoading && <p className="shrink-0 text-sm text-slate-500">Loading containers...</p>}
        {containersQuery.isError && (
          <p className="shrink-0 text-sm text-red-600">Failed to load containers: {(containersQuery.error as Error).message}</p>
        )}

        {/* Summary strip — app/container counts + image inventory. */}
        {!containersQuery.isLoading && !containersQuery.isError && (
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs">
            <span className="flex items-center gap-2 text-slate-600">
              <Container size={13} className="text-indigo-500" />
              {tree.roots.length} app{tree.roots.length === 1 ? '' : 's'} · {containerTotal} container{containerTotal === 1 ? '' : 's'}
            </span>
            <span className="flex items-center gap-2 text-slate-600">
              <Container size={13} className="text-slate-500" />
              {images.length} image{images.length === 1 ? '' : 's'}
              {imageTotalBytes > 0 && (
                <span className="font-mono text-slate-700">· {formatBytes(imageTotalBytes)} total</span>
              )}
              {danglingCount > 0 && <span className="text-slate-400">({danglingCount} dangling)</span>}
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
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-slate-200 transition-colors group-hover:bg-indigo-400" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-slate-300 transition-colors group-hover:bg-indigo-400" />
              </div>
            </div>
          )}

          {/* Image panel (bottom) — takes the remaining height. The header stays
              mounted when collapsed so it can be re-opened. */}
          <div className={clsx('shrink-0 min-h-0 pl-1', imagesOpen && 'flex-1')}>
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-slate-200 bg-white">
              <button
                type="button"
                onClick={() => setImagesOpen((o) => !o)}
                className="flex w-full shrink-0 items-center justify-between px-4 py-3 text-left"
                aria-expanded={imagesOpen}
              >
                <span className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                  <Container size={16} className="text-slate-500" />
                  Docker images{containersQuery.data ? ` (${images.length})` : ''}
                </span>
                {/* Expanded panel → chevron points DOWN (click collapses it);
                    collapsed → UP (click expands). */}
                {imagesOpen ? <ChevronDown size={18} className="text-slate-400" /> : <ChevronUp size={18} className="text-slate-400" />}
              </button>
              {imagesOpen && containersQuery.data && (
                <div className="min-h-0 flex-1 border-t border-slate-100 p-3">
                  <DataTable<DockerImageRow>
                    columns={imageColumns}
                    rows={images}
                    rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
                    storageKey="containers-images"
                    autoRefresh={{ intervalMs: 30_000, queries: [containersQuery] }}
                    fillHeight
                    searchPlaceholder="Search images…"
                    emptyMessage="No image data reported yet — Docker hosts (generic Docker plugin) and TrueNAS SCALE appliances report their images within a poll cycle."
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
