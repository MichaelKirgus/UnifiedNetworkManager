import { countGeometryPoints, simplifyGeometry, simplifyRing } from './geoSimplify';

describe('simplifyRing (Douglas-Peucker)', () => {
  it('keeps a straight line as its endpoints', () => {
    const ring: [number, number][] = [[0, 0], [1, 0], [2, 0], [3, 0]];
    expect(simplifyRing(ring, 0.01)).toEqual([[0, 0], [3, 0]]);
  });

  it('keeps a corner that deviates beyond the tolerance', () => {
    // A square: every corner is 1° off any chord → all kept at tol 0.5°.
    const ring: [number, number][] = [[0, 0], [1, 0], [1, 1], [0, 1]];
    expect(simplifyRing(ring, 0.5)).toEqual(ring);
  });

  it('drops points that sit within tolerance of the chord', () => {
    // Midpoint bulges only 0.001° — below a 0.01° tolerance.
    const ring: [number, number][] = [[0, 0], [1, 0.001], [2, 0]];
    expect(simplifyRing(ring, 0.01)).toEqual([[0, 0], [2, 0]]);
  });

  it('returns tiny rings unchanged', () => {
    const ring: [number, number][] = [[0, 0], [1, 0], [0, 1]];
    expect(simplifyRing(ring, 0.5)).toEqual(ring);
  });
});

describe('simplifyGeometry (GeoJSON)', () => {
  it('simplifies a Polygon and keeps the ring closed', () => {
    const geom = {
      type: 'Polygon' as const,
      coordinates: [
        // A long straight coast with one real corner — closing point repeated.
        [[0, 0], [1, 0], [2, 0], [3, 0], [4, 1], [4, 0], [0, 0]],
      ],
    };
    const out = simplifyGeometry(geom, 0.01);
    expect(out).not.toBeNull();
    if (out?.type === 'Polygon') {
      const ring = out.coordinates[0];
      // The straight run collapses to its endpoints; the corner survives.
      expect(ring.length).toBeLessThan(7);
      expect(ring.length).toBeGreaterThanOrEqual(4);
      // Closed: first point repeated at the end.
      expect(ring[ring.length - 1]).toEqual(ring[0]);
    } else {
      fail('expected a Polygon');
    }
  });

  it('simplifies a MultiPolygon and drops degenerate polygons', () => {
    const geom = {
      type: 'MultiPolygon' as const,
      coordinates: [
        // Real island.
        [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]],
        // A "polygon" that is actually a straight line — must be dropped.
        [[[5, 0], [6, 0], [7, 0], [5, 0]]],
      ],
    };
    const out = simplifyGeometry(geom, 0.01);
    expect(out).not.toBeNull();
    if (out?.type === 'MultiPolygon') {
      expect(out.coordinates.length).toBe(1);
    } else {
      fail('expected a MultiPolygon');
    }
  });

  it('returns null when nothing survives', () => {
    const geom = {
      type: 'Polygon' as const,
      coordinates: [[[0, 0], [1, 0], [2, 0], [0, 0]]], // a line, not an area
    };
    expect(simplifyGeometry(geom, 0.01)).toBeNull();
  });

  it('ignores non-polygon geometry types', () => {
    expect(simplifyGeometry({ type: 'Point', coordinates: [1, 2] })).toBeNull();
  });
});

describe('countGeometryPoints', () => {
  it('counts points across nested coordinate arrays', () => {
    const geom = {
      type: 'MultiPolygon' as const,
      coordinates: [[[[0, 0], [1, 0], [1, 1]]]],
    };
    expect(countGeometryPoints(geom)).toBe(3);
  });
});
