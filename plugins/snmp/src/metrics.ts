/**
 * Metric descriptors for the SNMP plugin. The webapp renders entirely from
 * these — no per-plugin UI code exists anywhere in the stack.
 *
 * Descriptor shape mirrors `MetricDescriptor` in webapp/src/api/client.ts:
 *   key, label, unit?, format? ('bytes'|'bits'|'duration'|'number'|'text'),
 *   type ('number'|'string'|'boolean'|'enum'), visualization
 *   ('gauge'|'plot'|'text'|'table'), group?, min?, max?, color?, rows?,
 *   columns?, summary? (true = quick metric in the devices table), intervalMs?
 */

export interface MetricDescriptor {
  key: string;
  label: string;
  unit?: string;
  format?: 'bytes' | 'bits' | 'duration' | 'number' | 'text';
  type: 'number' | 'string' | 'boolean' | 'enum';
  visualization: 'gauge' | 'plot' | 'text' | 'table';
  group?: string;
  min?: number;
  max?: number;
  color?: string;
  rows?: string[];
  columns?: string[];
  summary?: boolean;
  intervalMs?: number;
}

/** Slow-path (inventory) refresh cadence hint — matches the plugin's TTL. */
export const INVENTORY_INTERVAL_MS = 15 * 60 * 1000;

/**
 * Builds the full descriptor set for a monitoring response. `ifaceNames` are
 * the display names of the interfaces seen on this device (drives the table
 * rows so the UI always matches real data — opnsense's descriptorsFromMetrics
 * pattern).
 */
export function buildDescriptors(ifaceNames: string[], inventoryTtlMs: number): MetricDescriptor[] {
  const d: MetricDescriptor[] = [
    // --- System group (SNMPv2-MIB) -------------------------------------
    { key: 'system.description', label: 'Description', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.objectId', label: 'Object ID', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.name', label: 'Sys name', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.location', label: 'Location', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.contact', label: 'Contact', type: 'string', visualization: 'text', group: 'System' },
    {
      key: 'system.uptime',
      label: 'Uptime',
      unit: 's',
      format: 'duration',
      type: 'number',
      visualization: 'text',
      group: 'System',
    },

    // --- Live interface rates (IF-MIB counters) --------------------------
    {
      key: 'interfaces',
      label: 'Interface throughput',
      unit: 'bps',
      format: 'bits',
      type: 'number',
      visualization: 'table',
      group: 'Network',
      rows: ifaceNames,
      columns: ['rx', 'tx'],
    },
    {
      key: 'throughput.total',
      label: 'Total throughput',
      unit: 'bps',
      format: 'bits',
      type: 'number',
      visualization: 'plot',
      group: 'Network',
      color: '#3b82f6',
      summary: true, // headline metric in the devices table quick-metric column
    },

    // --- Inventory (slow-changing facts, TTL-cached) ---------------------
    {
      key: 'inventory.interfaces',
      label: 'Interfaces',
      type: 'string',
      visualization: 'table',
      group: 'Inventory',
      columns: ['name', 'type', 'speed', 'mac', 'status'],
      intervalMs: inventoryTtlMs,
    },
  ];

  return d;
}

/** Static baseline set advertised in /discover (rows filled at runtime). */
export const DISCOVER_METRICS: MetricDescriptor[] = buildDescriptors([], INVENTORY_INTERVAL_MS);
