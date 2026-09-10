import { useQuery } from '@tanstack/react-query';
import { api, DeviceProbe } from './client';

/**
 * useDeviceProbe — generic short-cycle live telemetry for one (device, plugin)
 * assignment. The page opts in per device + probe keys; the API brokers to the
 * plugin's POST /probe endpoint (capability 'probe'). Polls at `intervalMs`
 * while enabled — designed for 1–5 s cadences that would be wasteful through
 * the background /monitoring worker.
 *
 * Usage:
 *   const probe = useDeviceProbe(deviceId, ['containerStats'], { intervalMs: 3000 });
 *   const stats = probe.data?.probe.metrics['containerStats'];
 *
 * Notes:
 * - `enabled` gates the whole query (pass false when the page is hidden or the
 *   plugin doesn't advertise 'probe' — check via the plugins list).
 * - A failed poll keeps serving the last good snapshot (react-query default) —
 *   the UI should treat stale data as a fallback, not an error.
 */
export interface UseDeviceProbeOptions {
  /** Poll cadence in ms (default 3000). Keep ≥1 s to be polite to the device. */
  intervalMs?: number;
  /** Gate the query entirely (e.g. page visibility / capability check). Default true. */
  enabled?: boolean;
}

export function useDeviceProbe(
  deviceId: string | null | undefined,
  keys?: string[],
  opts: UseDeviceProbeOptions = {}
): ReturnType<typeof useQuery<DeviceProbe>> {
  const intervalMs = opts.intervalMs ?? 3_000;
  const enabled = (opts.enabled ?? true) && Boolean(deviceId);
  return useQuery({
    queryKey: ['device-probe', deviceId, keys?.join(',') ?? ''],
    queryFn: () => api.deviceProbe(deviceId as string, keys),
    enabled,
    refetchInterval: intervalMs,
    // Short-cycle live data — a failed poll is retried by the NEXT interval tick.
    // React Query's default retry storm (3× backoff per tick) only floods the
    // console/network tab for devices whose probe can't work; callers fall back
    // to last-good data on failure, so retries add nothing but noise.
    retry: false,
    // Short-cycle data is inherently ephemeral — don't hold onto it long after
    // the page unmounts (the next visit re-probes fresh).
    staleTime: 0,
    gcTime: 30_000,
  });
}
