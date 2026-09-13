/**
 * Shared metric value formatting. A plugin declares how its value should be
 * humanized via the descriptor's `format` hint (bytes → 1.2 GB, bits → 850
 * Mbps, duration → 3d 4h, ...). Both the detail view (MetricView) and the
 * overview table (MetricCell) use these helpers so rendering stays consistent.
 */

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const num = i === 0 ? v.toFixed(0) : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return `${num} ${units[i]}`;
}

export function formatBits(bits: number): string {
  if (!Number.isFinite(bits) || bits < 0) return '—';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let v = bits;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  const num = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return `${num} ${units[i]}`;
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (s || parts.length === 0) parts.push(`${s}s`);
  return parts.join(' ');
}

export function formatNumber(value: number, unit?: string): string {
  const num = Number.isInteger(value) ? value.toLocaleString() : value.toFixed(1);
  return unit ? `${num} ${unit}` : num;
}

/** Humanizes a metric value according to the descriptor's `format` hint. */
export function formatValue(value: unknown, unit?: string, format?: string): string {
  if (value === undefined || value === null) return '—';
  if (typeof value === 'number') {
    switch (format) {
      case 'bytes':
        return formatBytes(value);
      case 'bits':
        return formatBits(value);
      case 'duration':
        return formatDuration(value);
      case 'number':
      default:
        return formatNumber(value, unit);
    }
  }
  return String(value);
}

/** Rounds a value up to the next "nice" bound (1/2/5 × 10ⁿ) for auto-scaled gauges. */
export function niceCeil(value: number): number {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const exp = Math.floor(Math.log10(value));
  const base = Math.pow(10, exp);
  for (const m of [1, 2, 5, 10]) {
    if (value <= m * base) return m * base;
  }
  return 10 * base;
}
