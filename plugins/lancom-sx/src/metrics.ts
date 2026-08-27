/**
 * Metric descriptors for the LANCOM SX-Series switch plugin. The webapp renders
 * entirely from these — no per-plugin UI code exists anywhere in the stack.
 *
 * Descriptor shape mirrors `MetricDescriptor` in webapp/src/api/client.ts:
 *   key, label, unit?, format? ('bytes'|'bits'|'duration'|'number'|'text'),
 *   type ('number'|'string'|'boolean'|'enum'), visualization
 *   ('gauge'|'plot'|'text'|'table'), group?, min?, max?, color?, rows?,
 *   columns?, summary? (true = quick metric in the devices table), intervalMs?
 */

import { SxVariant } from './sxClient';
import { INVENTORY_INTERVAL_MS, MetricDescriptor } from '@unm/plugin-sdk';

// Re-exported so sibling files keep importing from './metrics'.
export type { MetricDescriptor };
export { INVENTORY_INTERVAL_MS };

/**
 * Builds the full descriptor set for a monitoring response. The variant
 * controls which groups exist: PoE + LAG are unified-4.x-only features (the
 * legacy GS-2310 tree has no such tables), so their descriptors are only
 * advertised when data can actually be collected.
 */
export function buildDescriptors(inventoryTtlMs: number, variant: SxVariant): MetricDescriptor[] {
  const d: MetricDescriptor[] = [
    // --- System ----------------------------------------------------------
    { key: 'system.name', label: 'Device name', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.modelNumber', label: 'Model (hardware)', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.swVersion', label: 'Software version', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.serialNumber', label: 'Serial number', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.hostMac', label: 'Management MAC', type: 'string', visualization: 'text', group: 'System' },
    // LCOS-SX reports uptime as a DisplayString, not seconds.
    { key: 'system.uptime', label: 'Uptime', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.cpuLoad', label: 'CPU load', unit: '%', min: 0, max: 100, color: '#f59e0b', type: 'number', visualization: 'gauge', group: 'System', summary: true },
    { key: 'system.memoryUsedPct', label: 'Memory used', unit: '%', min: 0, max: 100, color: '#8b5cf6', type: 'number', visualization: 'gauge', group: 'System', summary: true },

    // --- Hardware (PSU / fans / temperature) -------------------------------
    { key: 'hardware.psuA', label: 'Power supply A', type: 'string', visualization: 'text', group: 'Hardware' },
    { key: 'hardware.psuB', label: 'Power supply B', type: 'string', visualization: 'text', group: 'Hardware' },
    { key: 'hardware.fanSpeed', label: 'Fan speed', type: 'string', visualization: 'text', group: 'Hardware' },
    { key: 'hardware.temperature1', label: 'Temperature 1', unit: '°C', color: '#ef4444', type: 'number', visualization: 'gauge', group: 'Hardware' },
    { key: 'hardware.temperature2', label: 'Temperature 2', unit: '°C', color: '#ef4444', type: 'number', visualization: 'gauge', group: 'Hardware' },
    { key: 'hardware.temperature3', label: 'Temperature 3', unit: '°C', color: '#ef4444', type: 'number', visualization: 'gauge', group: 'Hardware' },

    // --- Ports -------------------------------------------------------------
    {
      key: 'ports.table',
      label: 'Ports',
      type: 'string',
      visualization: 'table',
      group: 'Ports',
      columns: ['name', 'linkUp', 'speedStatus', 'vlanModeLabel', 'pvid', 'allowedVlans'],
      intervalMs: inventoryTtlMs,
    },
    // Live per-port throughput (fast path) — rows filled at runtime.
    { key: 'ports.rates', label: 'Port throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'table', group: 'Ports', columns: ['rx', 'tx'] },
  ];

  // --- PoE + LAG (unified 4.x only) ------------------------------------------
  if (variant === 'sx4') {
    d.push(
      { key: 'poe.totalUsedWatts', label: 'PoE power used', unit: 'W', color: '#22c55e', type: 'number', visualization: 'gauge', group: 'PoE', summary: true },
      {
        key: 'poe.ports',
        label: 'PoE ports',
        type: 'string',
        visualization: 'table',
        group: 'PoE',
        columns: ['port', 'pdClass', 'powerRequestedWatts', 'powerAllocatedWatts', 'powerUsedWatts', 'priorityLabel', 'portStatusLabel'],
        intervalMs: inventoryTtlMs,
      },
      {
        key: 'lag.members',
        label: 'LAG members (LACP)',
        type: 'string',
        visualization: 'table',
        group: 'LAG',
        columns: ['port', 'lacpLabel', 'key', 'aggrId', 'partnerSystemId', 'partnerPort'],
        intervalMs: inventoryTtlMs,
      },
    );
  }

  return d;
}

/** The static descriptor set advertised in /discover (variant-agnostic union). */
export const DISCOVER_METRICS: MetricDescriptor[] = buildDescriptors(INVENTORY_INTERVAL_MS, 'sx4');
