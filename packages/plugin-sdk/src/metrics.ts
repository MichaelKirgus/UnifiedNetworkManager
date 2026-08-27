/**
 * Metric descriptor factories + shared constants (kills the repeated push
 * blocks in every monitoring plugin).
 */

import { MetricDescriptor } from './types';

/** Slow-path (inventory) refresh cadence — matches the plugins' 15-min TTL. */
export const INVENTORY_INTERVAL_MS = 15 * 60 * 1000;

/** The descriptor pushed alongside `system.error` on failed probes. */
export function errorDescriptor(key: string = 'system.error'): MetricDescriptor {
  return { key, label: 'Error', type: 'string', visualization: 'text', group: 'System' };
}

/** Descriptors for the user-selected model/firmware echo metrics (only when set). */
export function modelFirmwareDescriptors(selectedModel?: string | null, selectedFirmware?: string | null): MetricDescriptor[] {
  const out: MetricDescriptor[] = [];
  if (selectedModel) out.push({ key: 'system.model', label: 'Selected Model', type: 'string', visualization: 'text', group: 'System' });
  if (selectedFirmware) out.push({ key: 'system.firmwareVersion', label: 'Selected Firmware', type: 'string', visualization: 'text', group: 'System' });
  return out;
}

/** Convenience factory for a gauge metric. */
export function gaugeMetric(
  key: string,
  label: string,
  opts: { unit?: string; min?: number; max?: number; color?: string; group?: string; summary?: boolean; intervalMs?: number } = {}
): MetricDescriptor {
  return { key, label, type: 'number', visualization: 'gauge', ...opts };
}

/** Convenience factory for a text metric. */
export function textMetric(key: string, label: string, opts: { unit?: string; group?: string; intervalMs?: number } = {}): MetricDescriptor {
  return { key, label, type: 'string', visualization: 'text', ...opts };
}

/** Convenience factory for a table metric. */
export function tableMetric(
  key: string,
  label: string,
  columns: string[],
  opts: { rows?: string[]; group?: string; intervalMs?: number } = {}
): MetricDescriptor {
  return { key, label, type: 'string', visualization: 'table', columns, ...opts };
}
