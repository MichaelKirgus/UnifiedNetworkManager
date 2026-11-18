/**
 * GeoJSON polygon simplification (Douglas-Peucker) for the map basemap builder.
 *
 * OpenStreetMap Nominatim returns FULL-resolution country boundaries — a few
 * megabytes per country, hundreds of thousands of points. A flat world map in
 * the browser needs none of that detail: this module reduces each ring to the
 * points that are still visible at world scale before the basemap is stored,
 * so the webapp renders one small GeoJSON instead of ~700 MB of OSM data.
 */

type Point = [number, number]; // [lon, lat]

/** Squared perpendicular distance from point p to the segment a→b. */
function perpDistSq(p: Point, a: Point, b: Point): number {
  if (a[0] === b[0] && a[1] === b[1]) return (p[0] - a[0]) ** 2 + (p[1] - a[1]) ** 2;
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  // Project p onto the infinite line through a/b, clamp to the segment.
  let t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy);
  t = Math.max(0, Math.min(1, t));
  const cx = a[0] + t * dx;
  const cy = a[1] + t * dy;
  return (p[0] - cx) ** 2 + (p[1] - cy) ** 2;
}

/**
 * Douglas-Peucker: returns the simplified ring. `tolerance` is in degrees (the
 * input is lon/lat); ~0.02° ≈ 2 km keeps coastlines recognizable at world scale
 * while dropping most of the point count. Iterative (explicit segment stack) —
 * OSM rings can hold >100k points, and recursive DP would risk a stack overflow
 * on deeply nested deviations.
 */
export function simplifyRing(ring: Point[], tolerance: number): Point[] {
  const n = ring.length;
  if (n < 2) return [...ring];
  const tolSq = tolerance * tolerance;
  const keep = new Array<boolean>(n).fill(false);
  keep[0] = true;
  keep[n - 1] = true;
  const stack: Array<[number, number]> = [[0, n - 1]];
  while (stack.length > 0) {
    const [a, b] = stack.pop() as [number, number];
    let maxDist = -1;
    let maxIdx = -1;
    for (let i = a + 1; i < b; i++) {
      const d = perpDistSq(ring[i], ring[a], ring[b]);
      if (d > maxDist) {
        maxDist = d;
        maxIdx = i;
      }
    }
    if (maxDist > tolSq && maxIdx > 0) {
      keep[maxIdx] = true;
      // Push right first so the LEFT segment is processed next (LIFO order).
      stack.push([maxIdx, b], [a, maxIdx]);
    }
  }
  return ring.filter((_, i) => keep[i]);
}

/** Absolute shoelace area of a (possibly open) ring, in degree². */
function ringArea(ring: Point[]): number {
  let a = 0;
  for (let i = 0; i < ring.length - 1; i++) {
    a += ring[i][0] * ring[i + 1][1] - ring[i + 1][0] * ring[i][1];
  }
  return Math.abs(a) / 2;
}

/** Simplifies one ring; GeoJSON rings close on themselves (first === last). */
function simplifyClosedRing(ring: Point[], tolerance: number): Point[] {
  if (ring.length < 4) return [];
  const closed = ring[0][0] === ring[ring.length - 1][0] && ring[0][1] === ring[ring.length - 1][1];
  const body = closed ? ring.slice(0, -1) : ring;
  const simplified = simplifyRing(body, tolerance);
  if (simplified.length < 3) return []; // degenerate after simplification — drop the ring
  // A collinear "ring" (a line, not an area) can survive DP with ≥3 points —
  // drop it by area. Real territories are ≫1e-7 degree² (Vatican ≈ 1.6e-5).
  if (ringArea(simplified) < 1e-7) return [];
  if (!closed) return simplified;
  return [...simplified, [simplified[0][0], simplified[0][1]]];
}

/** A simplified GeoJSON polygon geometry (discriminated union). */
export type SimplifiedGeometry =
  | { type: 'Polygon'; coordinates: Point[][] }
  | { type: 'MultiPolygon'; coordinates: Point[][][] };

/**
 * Simplifies a GeoJSON Polygon or MultiPolygon geometry in place-free style.
 * Returns null when nothing survives (the feature should be dropped).
 */
export function simplifyGeometry(
  geometry: { type: string; coordinates: unknown },
  tolerance = 0.02
): SimplifiedGeometry | null {
  if (geometry.type === 'Polygon') {
    const rings = (geometry.coordinates as Point[][]).map((r) => simplifyClosedRing(r, tolerance));
    const outer = rings[0];
    if (!outer || outer.length < 4) return null;
    return { type: 'Polygon', coordinates: [outer, ...rings.slice(1)] };
  }
  if (geometry.type === 'MultiPolygon') {
    const polys = (geometry.coordinates as Point[][][])
      .map((poly) => poly.map((r) => simplifyClosedRing(r, tolerance)))
      .filter((poly) => poly[0] && poly[0].length >= 4);
    if (polys.length === 0) return null;
    return { type: 'MultiPolygon', coordinates: polys };
  }
  return null; // Point/LineString — not a basemap shape
}

/** Rough point count of a geometry (for build logging). */
export function countGeometryPoints(geometry: { type: string; coordinates: unknown }): number {
  let n = 0;
  const walk = (c: unknown): void => {
    if (!Array.isArray(c)) return;
    if (typeof c[0] === 'number') {
      n += 1; // a single [lon, lat] point
      return;
    }
    for (const item of c) walk(item);
  };
  walk(geometry.coordinates);
  return n;
}
