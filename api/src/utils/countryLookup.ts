import { getEffectiveValues } from '../systemSettings';
import { getRepoFile, openRepoFile } from '../fileRepo';

/**
 * Offline country lookup for site coordinates — point-in-polygon against the
 * stored map basemap (the same GeoJSON the Flows "Map" tab draws).
 *
 * Why this exists: flow aggregates only store a GeoIP country code on
 * EXTERNAL endpoints (`class = 'internet'`). The internal side of an
 * international pair is a device at one of our sites — its country comes from
 * the site's WGS84 coordinates, resolved HERE against the basemap polygons.
 * No external service involved: firewalled deployments work as long as the
 * basemap file exists (which the map-basemap worker keeps fresh).
 */

/** GeoJSON ring order: [lng, lat]. */
type Ring = [number, number][];

interface Polygon {
  /** [minLng, minLat, maxLng, maxLat] — cheap pre-filter. */
  bbox: [number, number, number, number];
  outer: Ring;
  holes: Ring[];
}

interface CountryShape {
  iso: string;
  polygons: Polygon[];
}

let cache: { fileId: string; countries: CountryShape[] } | null = null;

function ringBbox(ring: Ring): [number, number, number, number] {
  let minLng = Infinity, minLat = Infinity, maxLng = -Infinity, maxLat = -Infinity;
  for (const [lng, lat] of ring) {
    if (lng < minLng) minLng = lng;
    if (lat < minLat) minLat = lat;
    if (lng > maxLng) maxLng = lng;
    if (lat > maxLat) maxLat = lat;
  }
  return [minLng, minLat, maxLng, maxLat];
}

function toPolygons(geometry: { type?: string; coordinates?: unknown }): Polygon[] | null {
  const coords = geometry.coordinates as number[][][][] | undefined;
  if (!Array.isArray(coords)) return null;
  const polys: Polygon[] = [];
  // Normalize Polygon (one) and MultiPolygon (many) to a flat list.
  const shapes = geometry.type === 'MultiPolygon' ? coords : [coords];
  for (const poly of shapes) {
    if (!Array.isArray(poly) || poly.length < 1) continue;
    const outer = poly[0] as Ring;
    if (!Array.isArray(outer) || outer.length < 4) continue; // degenerate — skip
    polys.push({ bbox: ringBbox(outer), outer, holes: (poly.slice(1) as Ring[]).filter((h) => Array.isArray(h) && h.length >= 4) });
  }
  return polys.length > 0 ? polys : null;
}

/** Loads the active basemap's country polygons (cached per file id). */
async function loadCountries(): Promise<CountryShape[]> {
  const values = await getEffectiveValues();
  const fileId = String(values.mapBasemapFileId ?? '').trim();
  if (!fileId) return [];
  if (cache && cache.fileId === fileId) return cache.countries;

  try {
    const entry = await getRepoFile(fileId);
    if (!entry) return [];
    const opened = await openRepoFile(entry.id);
    if (!opened) return [];
    const chunks: Buffer[] = [];
    for await (const chunk of opened.stream) chunks.push(chunk as Buffer);
    const fc = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { features?: Array<{ properties?: { iso?: string }; geometry?: { type?: string; coordinates?: unknown } }> };
    const countries: CountryShape[] = [];
    for (const f of fc.features ?? []) {
      const iso = String(f.properties?.iso ?? '').toUpperCase();
      if (!iso || !f.geometry) continue;
      const polygons = toPolygons(f.geometry);
      if (polygons) countries.push({ iso, polygons });
    }
    cache = { fileId, countries };
    return countries;
  } catch (err) {
    console.warn('[country-lookup] could not load basemap:', (err as Error).message);
    return [];
  }
}

/** Even-odd ray cast against one ring. */
function pointInRing(x: number, y: number, ring: Ring): boolean {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0], yi = ring[i][1];
    const xj = ring[j][0], yj = ring[j][1];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

/**
 * ISO-3166 alpha-2 code of the country containing (lat, lng), or null when no
 * basemap is stored or the point falls outside every polygon (e.g. open sea).
 */
export async function countryForPoint(lat: number, lng: number): Promise<string | null> {
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  const countries = await loadCountries();
  for (const c of countries) {
    for (const p of c.polygons) {
      const [minLng, minLat, maxLng, maxLat] = p.bbox;
      if (lng < minLng || lng > maxLng || lat < minLat || lat > maxLat) continue;
      if (!pointInRing(lng, lat, p.outer)) continue;
      let inHole = false;
      for (const h of p.holes) {
        if (pointInRing(lng, lat, h)) { inHole = true; break; }
      }
      if (!inHole) return c.iso;
    }
  }
  return null;
}
