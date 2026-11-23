/**
 * Unit tests for workers/flowSecurity.ts — the pure egress-baseline verdict
 * (extracted from detectEgressBaseline so its threshold semantics are pinned:
 * no-history skip, multiple×median gate with a strict <, zero-median anomaly,
 * one-decimal ratio rounding and the critical escalation at ratio ≥ 10).
 */

// uuid v14 ships an ESM node entry that jest cannot require — the worker only
// needs it for row ids, which these tests never assert on.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import { beaconVerdict, egressVerdict } from './flowSecurity';

const MB = 1_048_576;
/** One flow_agg_5m bucket (must match BUCKET_MS in the worker). */
const B = 300_000;
/** Bucket-aligned epoch ms for deterministic interval math. */
const T0 = 1_700_000_000_000 - (1_700_000_000_000 % B);

describe('egressVerdict', () => {
  it('returns null when there is no baseline history (first-time pair → detector 1)', () => {
    expect(egressVerdict(300 * MB, 6, [], 3)).toBeNull();
  });

  it('returns null while the window average stays below multiple×median', () => {
    // median 20 MB/h × 3 = 60 MB/h gate; 60 MB over 6 h = 10 MB/h avg → normal
    expect(egressVerdict(60 * MB, 6, [20 * MB], 3)).toBeNull();
  });

  it('fires exactly AT the threshold (the comparison is strict <)', () => {
    // 360 MB over 6 h = 60 MB/h avg == 3 × 20 MB/h → NOT skipped
    const v = egressVerdict(360 * MB, 6, [20 * MB], 3);
    expect(v).toEqual({ severity: 'warning', ratio: 3.0, baselineMedianBytes: 20 * MB });
  });

  it('treats a zero-median baseline as anomalous for ANY volume (ratio null)', () => {
    // odd count with middle value 0 → median 0; any transfer above the floor is flagged
    const v = egressVerdict(300 * MB, 6, [0, 0, 100 * MB], 3);
    expect(v).toEqual({ severity: 'warning', ratio: null, baselineMedianBytes: 0 });
  });

  it('uses the true median (odd and even counts), not the mean', () => {
    // sorted [1MB, 2MB, 100MB] → median 2MB; avg = 6h*? total 36MB/6h = 6MB/h = 3×median → fires at threshold
    expect(egressVerdict(36 * MB, 6, [100 * MB, 1 * MB, 2 * MB], 3)).toMatchObject({ ratio: 3.0 });
    // even count: sorted [1MB, 3MB] → median 2MB (mean would be 2MB too — use asymmetric values)
    expect(egressVerdict(36 * MB, 6, [1 * MB, 3 * MB], 3)).toMatchObject({ ratio: 3.0 });
  });

  it('rounds the ratio to one decimal', () => {
    // median 3 MB/h; total 171 MB over 6 h = 28.5 MB/h avg → ratio 9.5 (not 9 or 10)
    expect(egressVerdict(171 * MB, 6, [3 * MB], 3)).toMatchObject({ severity: 'warning', ratio: 9.5 });
  });

  it('escalates to critical at ratio ≥ 10 and stays warning just below', () => {
    // median 1 MB/h; total 60 MB over 6 h = 10 MB/h → exactly 10× → critical
    expect(egressVerdict(60 * MB, 6, [1 * MB], 3)).toMatchObject({ severity: 'critical', ratio: 10.0 });
    // total 62_337_850 B over 6 h = 9.908× the median → rounds to 9.9 → warning
    expect(egressVerdict(62_337_850, 6, [1 * MB], 3)).toMatchObject({ severity: 'warning', ratio: 9.9 });
  });

  it('honours a custom multiple setting', () => {
    // median 20 MB/h; avg 50 MB/h — below 3× (60) but above 2× (40)
    expect(egressVerdict(300 * MB, 6, [20 * MB], 3)).toBeNull();
    expect(egressVerdict(300 * MB, 6, [20 * MB], 2)).toMatchObject({ severity: 'warning', ratio: 2.5 });
  });
});

describe('beaconVerdict', () => {
  it('returns null below the minimum active-bucket count', () => {
    expect(beaconVerdict([T0, T0 + B, T0 + 2 * B], 6, 25)).toBeNull();
  });

  it('fires on perfectly periodic activity and reports period/span/jitter', () => {
    // every 3rd bucket = 15-min period; 6 buckets → span 75 min = 1.25 h (→ 1.3)
    const starts = [T0, T0 + 3 * B, T0 + 6 * B, T0 + 9 * B, T0 + 12 * B, T0 + 15 * B];
    expect(beaconVerdict(starts, 6, 25)).toEqual({
      severity: 'warning', periodMinutes: 15, bucketCount: 6, spanHours: 1.3, jitterCv: 0,
    });
  });

  it('escalates to critical on perfect periodicity over ≥ 2× the minimum count', () => {
    // 8 consecutive buckets with minBuckets=4 → 8 ≥ 8 and cv = 0 → critical
    const starts = Array.from({ length: 8 }, (_, i) => T0 + i * B);
    expect(beaconVerdict(starts, 4, 25)).toMatchObject({ severity: 'critical', periodMinutes: 5 });
  });

  it('stays warning at exactly the minimum count even with zero jitter', () => {
    const starts = Array.from({ length: 6 }, (_, i) => T0 + i * B);
    expect(beaconVerdict(starts, 6, 25)).toMatchObject({ severity: 'warning' });
  });

  it('rejects high-jitter (irregular) spacing', () => {
    // intervals [1,4,2,7,3] buckets → cv ≈ 60% ≫ 25%
    const starts = [T0, T0 + B, T0 + 5 * B, T0 + 7 * B, T0 + 14 * B, T0 + 17 * B];
    expect(beaconVerdict(starts, 6, 25)).toBeNull();
  });

  it('accepts mild jitter within the threshold', () => {
    // intervals [3,4,3,4] → mean 3.5 buckets, population std 0.5 → cv ≈ 14.3%
    const starts = [T0, T0 + 3 * B, T0 + 7 * B, T0 + 10 * B, T0 + 14 * B];
    expect(beaconVerdict(starts, 5, 25)).toMatchObject({ periodMinutes: 18, spanHours: 1.2 });
  });

  it('honours a stricter jitter setting', () => {
    const starts = [T0, T0 + 3 * B, T0 + 7 * B, T0 + 10 * B, T0 + 14 * B]; // cv ≈ 14.3%
    expect(beaconVerdict(starts, 5, 10)).toBeNull();
    expect(beaconVerdict(starts, 5, 25)).not.toBeNull();
  });

  it('treats sub-5-minute beacons as every-bucket activity (period = one bucket)', () => {
    // a C2 check-in every 30 s shows up in EVERY 5-min bucket → interval = 1 unit
    const starts = Array.from({ length: 6 }, (_, i) => T0 + i * B);
    expect(beaconVerdict(starts, 6, 25)).toMatchObject({ periodMinutes: 5 });
  });
});
