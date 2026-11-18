import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download, Globe2, Loader2, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';
import { api, FlowMapInternationalPair, FlowMapNationalPair, MapBasemapFeature } from '../api/client';
import { can } from '../auth/permissions';
import { formatBytes } from './formatMetric';
import { LoadingBar } from './LoadingBar';

/**
 * WorldTrafficMap — flat equirectangular world map of flow traffic (Flows page
 * "Map" tab). No chart/map library: plain SVG with a 2:1 projection, country
 * polygons from the stored basemap GeoJSON and quadratic-Bézier arcs between
 * endpoints. International pairs are COUNTRY→COUNTRY (blue), national pairs are
 * SITE→SITE (green) with site markers.
 */

const W = 1000;
const H = 500;

/** Equirectangular projection: [lng, lat] → SVG x/y. */
function project(lng: number, lat: number): { x: number; y: number } {
  return { x: ((lng + 180) / 360) * W, y: ((90 - lat) / 180) * H };
}

/** ISO-3166 alpha-2 → flag emoji (regional indicators). */
function flagEmoji(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '';
  const upper = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return '';
  try {
    return String.fromCodePoint(...[...upper].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
  } catch {
    return '';
  }
}

/** One GeoJSON feature → SVG path (all rings, evenodd fill handles holes). */
function featurePath(f: MapBasemapFeature): string | null {
  const g = f.geometry;
  if (!g) return null;
  const shapes = g.type === 'MultiPolygon' ? (g.coordinates as number[][][][]) : [g.coordinates as number[][][]];
  let d = '';
  for (const poly of shapes) {
    for (const ring of poly) {
      if (!Array.isArray(ring) || ring.length < 4) continue;
      d += `M${ring.map(([lng, lat]) => `${project(lng, lat).x.toFixed(1)},${project(lng, lat).y.toFixed(1)}`).join('L')}Z`;
    }
  }
  return d || null;
}

/** Anchor point for arcs: centroid of the largest outer ring. */
function featureAnchor(f: MapBasemapFeature): { x: number; y: number } | null {
  const g = f.geometry;
  if (!g) return null;
  const shapes = g.type === 'MultiPolygon' ? (g.coordinates as number[][][][]) : [g.coordinates as number[][][]];
  let best: number[][] | null = null;
  for (const poly of shapes) {
    const outer = Array.isArray(poly[0]) ? poly[0] : null;
    if (!outer || outer.length < 4) continue;
    if (!best || outer.length > best.length) best = outer;
  }
  if (!best) return null;
  let sx = 0, sy = 0;
  for (const [lng, lat] of best) { const p = project(lng, lat); sx += p.x; sy += p.y; }
  return { x: sx / best.length, y: sy / best.length };
}

/** Quadratic-Bézier arc between two points — control point lifted so the arc
 * always bulges "up" (toward the top of the map), like flight-path maps. */
function arcPath(a: { x: number; y: number }, b: { x: number; y: number }): string {
  const dist = Math.hypot(b.x - a.x, b.y - a.y);
  if (dist < 1) return '';
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  // Perpendicular to AB.
  let nx = -(b.y - a.y) / dist;
  let ny = (b.x - a.x) / dist;
  if (ny > 0) { nx = -nx; ny = -ny; } // keep the lift pointing up-screen
  const lift = Math.min(dist * 0.25, 90);
  return `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${(mx + nx * lift).toFixed(1)},${(my + ny * lift).toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
}

/** Log-scaled stroke width 1–8 px relative to the busiest pair. */
function strokeWidthFor(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0 || bytes <= 0) return 1;
  const t = Math.log10(1 + bytes) / Math.log10(1 + maxBytes);
  return 1 + 7 * Math.max(0, Math.min(1, t));
}

type Scope = 'all' | 'international' | 'national';

const MIN_BYTES_OPTIONS: Array<{ label: string; value: number }> = [
  { label: 'Any size', value: 0 },
  { label: '≥ 1 MB', value: 1_000_000 },
  { label: '≥ 10 MB', value: 10_000_000 },
  { label: '≥ 100 MB', value: 100_000_000 },
  { label: '≥ 1 GB', value: 1_000_000_000 },
];

interface HoverInfo { title: string; sub?: string; bytes: number }

export function WorldTrafficMap({ from, to, siteId, onLoadingChange }: {
  from?: string;
  to?: string;
  siteId?: string;
  /** Reports the component's initial-load state (drives the Flows tab dot). */
  onLoadingChange?: (loading: boolean) => void;
}) {
  const [scope, setScope] = useState<Scope>('all');
  const [minBytes, setMinBytes] = useState(0);
  const [topN, setTopN] = useState(25);
  const [hover, setHover] = useState<HoverInfo | null>(null);
  // Map viewport — viewBox-based zoom/pan (k=1 is the full world). Strokes and
  // labels are counter-scaled by 1/k so they keep a constant on-screen size.
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });

  // Pairs refresh with the page cadence; the basemap only changes when a build
  // runs — poll faster while one is in flight (progress "N/M" non-empty).
  const mapQuery = useQuery({
    queryKey: ['flows', 'map', from, to, siteId],
    queryFn: () => api.flowsMap({ from, to, siteId }),
    refetchInterval: 60_000,
  });
  const basemapQuery = useQuery({
    queryKey: ['flows', 'map-basemap'],
    queryFn: () => api.mapBasemap(),
    refetchInterval: (query) => {
      const d = query.state.data;
      return d?.progress ? 15_000 : 300_000; // building → poll, idle → rarely
    },
  });

  // Initial-load state — true until both the pair query and the basemap have
  // returned their first response (refetches never re-trigger it). The cleanup
  // clears the flag on unmount so a stale dot can't keep pulsing on other tabs.
  const loading = mapQuery.isLoading || basemapQuery.isLoading;
  useEffect(() => {
    onLoadingChange?.(loading);
    return () => onLoadingChange?.(false);
  }, [loading, onLoadingChange]);

  // Zoom/pan — viewBox math. k clamped to 1..8; pan is clamped so the world
  // always covers the viewport (at k=1 both clamps collapse to 0). Wheel zoom
  // uses a native non-passive listener: React registers onWheel as passive,
  // which would swallow preventDefault() and let the page scroll while zooming.
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragRef = useRef<{ px: number; py: number; k: number } | null>(null);

  const clampK = (k: number) => Math.min(8, Math.max(1, k));
  const clampX = (x: number, k: number) => Math.min(0, Math.max(W - W / k, x));
  const clampY = (y: number, k: number) => Math.min(0, Math.max(H - H / k, y));

  // Zoom by factor f around the current viewport center (button clicks).
  const zoomBy = (f: number) =>
    setView((v) => {
      const k2 = clampK(v.k * f);
      if (k2 === v.k) return v;
      const cx = v.x + W / (2 * v.k); // center of the current view in map coords
      const cy = v.y + H / (2 * v.k);
      return { x: clampX(cx - W / k2 / 2, k2), y: clampY(cy - H / k2 / 2, k2), k: k2 };
    });

  const onPointerDown = (e: ReactPointerEvent<SVGSVGElement>) => {
    if (view.k <= 1) return; // nothing to pan at full view
    dragRef.current = { px: e.clientX, py: e.clientY, k: view.k };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onPointerMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    const d = dragRef.current;
    if (!d) return;
    const el = svgRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const dx = ((e.clientX - d.px) / rect.width) * (W / d.k);
    const dy = ((e.clientY - d.py) / rect.height) * (H / d.k);
    dragRef.current = { px: e.clientX, py: e.clientY, k: d.k };
    setView((v) => ({ ...v, x: clampX(v.x - dx, v.k), y: clampY(v.y - dy, v.k) }));
  };
  const onPointerUp = () => { dragRef.current = null; };

  const fetchNow = async () => {
    await api.fetchMapBasemap();
    void basemapQuery.refetch();
  };

  // Basemap geometry — paths + per-country arc anchors (memoized per file).
  const geo = useMemo(() => {
    const fc = basemapQuery.data?.geojson;
    if (!fc) return null;
    const paths: Array<{ iso: string; d: string }> = [];
    const anchors = new Map<string, { x: number; y: number }>();
    for (const f of fc.features) {
      const iso = String(f.properties?.iso ?? '').toUpperCase();
      if (!iso) continue;
      const d = featurePath(f);
      if (d) paths.push({ iso, d });
      const a = featureAnchor(f);
      if (a) anchors.set(iso, a);
    }
    return { paths, anchors };
  }, [basemapQuery.data?.fileId]);

  // Filtered + capped pair lists.
  const intlPairs: FlowMapInternationalPair[] = useMemo(() => {
    const all = mapQuery.data?.international ?? [];
    return all.filter((p) => p.estBytes >= minBytes).slice(0, topN);
  }, [mapQuery.data, minBytes, topN]);
  const natPairs: FlowMapNationalPair[] = useMemo(() => {
    const all = mapQuery.data?.national ?? [];
    return all.filter((p) => p.estBytes >= minBytes).slice(0, topN);
  }, [mapQuery.data, minBytes, topN]);

  const maxBytes = Math.max(
    ...intlPairs.map((p) => p.estBytes),
    ...natPairs.map((p) => p.estBytes),
    0
  );

  // Drawn arcs (pairs whose endpoints both have a position on the map).
  const intlArcs: Array<{ key: string; d: string; width: number; pair: FlowMapInternationalPair }> = [];
  let skippedIntl = 0;
  if (geo) {
    for (const p of intlPairs) {
      const a = geo.anchors.get(p.srcCountry);
      const b = geo.anchors.get(p.dstCountry);
      if (!a || !b) { skippedIntl++; continue; } // country missing from basemap
      intlArcs.push({ key: `i|${p.srcCountry}|${p.dstCountry}`, d: arcPath(a, b), width: strokeWidthFor(p.estBytes, maxBytes), pair: p });
    }
  }
  const natArcs: Array<{ key: string; d: string; width: number; pair: FlowMapNationalPair }> = [];
  let skippedNat = 0;
  for (const p of natPairs) {
    if (p.srcLatitude == null || p.srcLongitude == null || p.dstLatitude == null || p.dstLongitude == null) { skippedNat++; continue; }
    const a = project(p.srcLongitude, p.srcLatitude);
    const b = project(p.dstLongitude, p.dstLatitude);
    natArcs.push({ key: `n|${p.srcSiteId}|${p.dstSiteId}`, d: arcPath(a, b), width: strokeWidthFor(p.estBytes, maxBytes), pair: p });
  }

  // Site markers (all sites from the response — context even without traffic).
  const siteMarkers = useMemo(() => {
    return (mapQuery.data?.sites ?? [])
      .filter((s) => s.latitude != null && s.longitude != null)
      .map((s) => ({ ...s, pos: project(s.longitude!, s.latitude!) }));
  }, [mapQuery.data]);

  const building = Boolean(basemapQuery.data?.progress);
  const hasMap = Boolean(geo && geo.paths.length > 0);

  // Wheel zoom — native non-passive listener (React's onWheel is passive and
  // would swallow preventDefault()). Re-runs when the SVG mounts: while the
  // basemap is still loading there is no element to attach to.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      setView((v) => {
        const k2 = clampK(v.k * Math.exp(-e.deltaY * 0.0015));
        if (k2 === v.k) return v;
        // Keep the point under the cursor fixed while zooming.
        const px = (e.clientX - rect.left) / rect.width;
        const py = (e.clientY - rect.top) / rect.height;
        const mx = v.x + px * (W / v.k);
        const my = v.y + py * (H / v.k);
        return { x: clampX(mx - px * (W / k2), k2), y: clampY(my - py * (H / k2), k2), k: k2 };
      });
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [hasMap]);

  return (
    <div className="flex shrink-0 flex-col gap-3">
      {/* Initial-load indicator — the pair query can take >10 s on big databases. */}
      {loading && <LoadingBar label="Loading map…" />}

      {/* Local filters — scope, minimum size, top-N. Global range/site stay above. */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <select className="rounded-md border border-border px-2 py-1" value={scope} onChange={(e) => setScope(e.target.value as Scope)} title="Traffic scope">
          <option value="all">All traffic</option>
          <option value="international">International only</option>
          <option value="national">National only</option>
        </select>
        <select className="rounded-md border border-border px-2 py-1" value={minBytes} onChange={(e) => setMinBytes(Number(e.target.value))} title="Minimum pair size">
          {MIN_BYTES_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <select className="rounded-md border border-border px-2 py-1" value={topN} onChange={(e) => setTopN(Number(e.target.value))} title="Number of pairs shown">
          {[10, 25, 50].map((n) => (
            <option key={n} value={n}>Top {n}</option>
          ))}
        </select>
        {/* Legend */}
        <span className="ml-auto flex items-center gap-3 text-secondary">
          <span className="flex items-center gap-1"><span className="inline-block h-0.5 w-4 rounded" style={{ background: 'rgb(var(--status-info))' }} /> international</span>
          <span className="flex items-center gap-1"><span className="inline-block h-0.5 w-4 rounded" style={{ background: 'rgb(var(--status-ok))' }} /> national (site→site)</span>
          <span className="text-faint">scroll to zoom · drag to pan</span>
        </span>
      </div>

      {/* Basemap unavailable — never fetched yet or the last build failed. */}
      {!basemapQuery.isLoading && !hasMap && (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-border bg-card px-4 py-8 text-sm">
          <Globe2 size={20} className="text-faint" />
          <p className="font-medium">World map not available yet</p>
          {basemapQuery.data?.lastError && (
            <p className="max-w-lg text-center text-xs text-secondary">{basemapQuery.data.lastError}</p>
          )}
          {!building && can('system:write') && (
            <button type="button" onClick={fetchNow} className="mt-1 flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover">
              <Download size={12} /> Fetch map now
            </button>
          )}
        </div>
      )}

      {/* Building banner — the worker fetches countries in paced batches. */}
      {building && (
        <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-xs text-secondary">
          <Loader2 size={13} className="animate-spin" />
          Building world map: {basemapQuery.data?.progress} countries fetched — the map appears as soon as the first batch lands.
        </div>
      )}

      {/* Map + top-pairs list side by side (stacks on narrow screens). */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_280px]">
        <div className="relative overflow-hidden rounded-lg border border-border bg-card">
          {/* max-w keeps the map a sane size on wide (16:9) monitors — it used
           * to stretch across the whole grid column and look flat. */}
          {basemapQuery.isLoading ? (
            <div className="flex h-72 items-center justify-center text-sm text-muted-foreground">Loading map…</div>
          ) : hasMap && geo ? (
            <svg
              ref={svgRef}
              viewBox={`${view.x.toFixed(2)} ${view.y.toFixed(2)} ${(W / view.k).toFixed(2)} ${(H / view.k).toFixed(2)}`}
              className={`mx-auto block h-auto w-full max-w-[1080px] select-none ${view.k > 1 ? 'cursor-grab active:cursor-grabbing' : ''}`}
              role="img"
              aria-label="World traffic map — scroll to zoom, drag to pan"
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerCancel={onPointerUp}
            >
              {/* Country polygons */}
              {geo.paths.map((p) => (
                <path key={p.iso} d={p.d} fillRule="evenodd" fill="rgb(var(--muted) / 0.65)" stroke="rgb(var(--border))" strokeWidth={0.4 / view.k} />
              ))}
              {/* International arcs */}
              {scope !== 'national' && intlArcs.map((a) => (
                <path
                  key={a.key}
                  d={a.d}
                  fill="none"
                  stroke="rgb(var(--status-info))"
                  strokeWidth={(hover?.title === `i|${a.pair.srcCountry}|${a.pair.dstCountry}` ? a.width + 1.5 : a.width) / view.k}
                  strokeLinecap="round"
                  opacity={hover && hover.title !== `i|${a.pair.srcCountry}|${a.pair.dstCountry}` ? 0.25 : 0.7}
                  onMouseEnter={() => setHover({ title: `i|${a.pair.srcCountry}|${a.pair.dstCountry}`, sub: `${flagEmoji(a.pair.srcCountry)} ${a.pair.srcCountry} → ${flagEmoji(a.pair.dstCountry)} ${a.pair.dstCountry}`, bytes: a.pair.estBytes })}
                  onMouseLeave={() => setHover(null)}
                />
              ))}
              {/* National arcs */}
              {scope !== 'international' && natArcs.map((a) => (
                <path
                  key={a.key}
                  d={a.d}
                  fill="none"
                  stroke="rgb(var(--status-ok))"
                  strokeWidth={(hover?.title === `n|${a.pair.srcSiteId}|${a.pair.dstSiteId}` ? a.width + 1.5 : a.width) / view.k}
                  strokeLinecap="round"
                  opacity={hover && hover.title !== `n|${a.pair.srcSiteId}|${a.pair.dstSiteId}` ? 0.25 : 0.75}
                  onMouseEnter={() => setHover({ title: `n|${a.pair.srcSiteId}|${a.pair.dstSiteId}`, sub: `${a.pair.srcSiteName} → ${a.pair.dstSiteName}`, bytes: a.pair.estBytes })}
                  onMouseLeave={() => setHover(null)}
                />
              ))}
              {/* Site markers — counter-scaled so they stay the same size on screen. */}
              {siteMarkers.map((s) => (
                <g key={s.id}>
                  <circle cx={s.pos.x} cy={s.pos.y} r={3.2 / view.k} fill="rgb(var(--card))" stroke="rgb(var(--status-ok))" strokeWidth={1.4 / view.k} />
                  <text x={s.pos.x + 5 / view.k} y={s.pos.y + 3 / view.k} fontSize={9 / view.k} fill="rgb(var(--secondary))">{s.name}</text>
                </g>
              ))}
            </svg>
          ) : null}

          {/* Zoom controls — wheel zoom + drag pan live on the SVG itself. */}
          {hasMap && geo && (
            <div className="absolute right-2 top-2 flex flex-col gap-1">
              <button type="button" onClick={() => zoomBy(1.5)} title="Zoom in" className="rounded-md border border-border bg-card/95 p-1.5 text-secondary hover:bg-muted"><ZoomIn size={13} /></button>
              <button type="button" onClick={() => zoomBy(1 / 1.5)} title="Zoom out" disabled={view.k <= 1} className="rounded-md border border-border bg-card/95 p-1.5 text-secondary hover:bg-muted disabled:opacity-40"><ZoomOut size={13} /></button>
              <button type="button" onClick={() => setView({ x: 0, y: 0, k: 1 })} title="Reset view" disabled={view.k <= 1} className="rounded-md border border-border bg-card/95 p-1.5 text-secondary hover:bg-muted disabled:opacity-40"><RotateCcw size={13} /></button>
            </div>
          )}

          {/* Hover readout — pinned corner box (arcs are thin, no cursor-follow). */}
          {hover && (
            <div className="pointer-events-none absolute left-2 top-2 rounded-md border border-border bg-card/95 px-3 py-1.5 text-xs shadow-sm">
              <p className="font-medium">{hover.sub}</p>
              <p className="font-mono text-secondary">{formatBytes(hover.bytes)}</p>
            </div>
          )}

          {/* Data notes — pairs that could not be placed on the map. */}
          {(skippedIntl > 0 || skippedNat > 0 || (mapQuery.data?.unplacedInternationalBytes ?? 0) > 0) && hasMap && (
            <div className="absolute bottom-2 left-2 rounded-md border border-border bg-card/95 px-3 py-1.5 text-[11px] text-secondary">
              {skippedIntl > 0 && <span>{skippedIntl} international pair(s) without map data · </span>}
              {skippedNat > 0 && <span>{skippedNat} national pair(s) with unplaced sites · </span>}
              {(mapQuery.data?.unplacedInternationalBytes ?? 0) > 0 && (
                <span>{formatBytes(mapQuery.data!.unplacedInternationalBytes)} from sites without a resolvable country</span>
              )}
            </div>
          )}

          {!hasMap && !building && !basemapQuery.isLoading && (
            <div className="flex h-72 items-center justify-center text-sm text-muted-foreground">No map data.</div>
          )}
        </div>

        {/* Top pairs list — hover a row to highlight its arc. */}
        <div className="rounded-lg border border-border bg-card">
          <p className="border-b border-border px-3 py-2 text-xs font-medium text-secondary">Top pairs</p>
          <div className="max-h-[460px] overflow-y-auto">
            {((scope === 'all' && intlArcs.length === 0 && natArcs.length === 0) ||
              (scope === 'international' && intlArcs.length === 0) ||
              (scope === 'national' && natArcs.length === 0)) && (
              <p className="px-3 py-4 text-xs text-faint">No traffic in this window.</p>
            )}
            {scope !== 'national' && intlArcs.map((a) => (
              <button
                key={a.key}
                type="button"
                onMouseEnter={() => setHover({ title: `i|${a.pair.srcCountry}|${a.pair.dstCountry}`, sub: `${flagEmoji(a.pair.srcCountry)} ${a.pair.srcCountry} → ${flagEmoji(a.pair.dstCountry)} ${a.pair.dstCountry}`, bytes: a.pair.estBytes })}
                onMouseLeave={() => setHover(null)}
                className="flex w-full items-center gap-2 border-b border-border/60 px-3 py-1.5 text-left text-xs hover:bg-muted"
              >
                <span className="inline-block h-0.5 w-3 shrink-0 rounded" style={{ background: 'rgb(var(--status-info))' }} />
                <span className="truncate">{flagEmoji(a.pair.srcCountry)} {a.pair.srcCountry} → {flagEmoji(a.pair.dstCountry)} {a.pair.dstCountry}</span>
                <span className="ml-auto shrink-0 font-mono text-secondary">{formatBytes(a.pair.estBytes)}</span>
              </button>
            ))}
            {scope !== 'international' && natArcs.map((a) => (
              <button
                key={a.key}
                type="button"
                onMouseEnter={() => setHover({ title: `n|${a.pair.srcSiteId}|${a.pair.dstSiteId}`, sub: `${a.pair.srcSiteName} → ${a.pair.dstSiteName}`, bytes: a.pair.estBytes })}
                onMouseLeave={() => setHover(null)}
                className="flex w-full items-center gap-2 border-b border-border/60 px-3 py-1.5 text-left text-xs hover:bg-muted"
              >
                <span className="inline-block h-0.5 w-3 shrink-0 rounded" style={{ background: 'rgb(var(--status-ok))' }} />
                <span className="truncate">{a.pair.srcSiteName} → {a.pair.dstSiteName}</span>
                <span className="ml-auto shrink-0 font-mono text-secondary">{formatBytes(a.pair.estBytes)}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
