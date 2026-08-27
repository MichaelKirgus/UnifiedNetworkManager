/**
 * Metric descriptors for the LANCOM LCOS router plugin. The webapp renders
 * entirely from these — no per-plugin UI code exists anywhere in the stack.
 *
 * Descriptor shape mirrors `MetricDescriptor` in webapp/src/api/client.ts:
 *   key, label, unit?, format? ('bytes'|'bits'|'duration'|'number'|'text'),
 *   type ('number'|'string'|'boolean'|'enum'), visualization
 *   ('gauge'|'plot'|'text'|'table'), group?, min?, max?, color?, rows?,
 *   columns?, summary? (true = quick metric in the devices table), intervalMs?
 */

import { INVENTORY_INTERVAL_MS, MetricDescriptor } from '@unm/plugin-sdk';

// Re-exported so sibling files keep importing from './metrics'.
export type { MetricDescriptor };
export { INVENTORY_INTERVAL_MS };

/**
 * Builds the full descriptor set for a monitoring response. `hasWifi` adds the
 * WiFi group only when WLAN data was actually collected (most LCOS routers have
 * no built-in radios — those still get System/LAN/WAN/VPN groups).
 */
export function buildDescriptors(inventoryTtlMs: number, hasWifi = false): MetricDescriptor[] {
  const d: MetricDescriptor[] = [
    // --- System ----------------------------------------------------------
    { key: 'system.name', label: 'Device name', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.swVersion', label: 'Software version', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.modelNumber', label: 'Model (hardware)', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.serialNumber', label: 'Serial number', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.cpuType', label: 'CPU', type: 'string', visualization: 'text', group: 'System' },
    // LCOS reports uptime as a DisplayString ("3 days, 4 hours"), not seconds.
    { key: 'system.uptime', label: 'Uptime', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.cpuLoad', label: 'CPU load (60 s)', unit: '%', min: 0, max: 100, color: '#f59e0b', type: 'number', visualization: 'gauge', group: 'System', summary: true },
    { key: 'system.memoryUsedPct', label: 'Memory used', unit: '%', min: 0, max: 100, color: '#8b5cf6', type: 'number', visualization: 'gauge', group: 'System', summary: true },

    // --- LAN --------------------------------------------------------------
    {
      key: 'lan.ports',
      label: 'LAN ports',
      type: 'string',
      visualization: 'table',
      group: 'LAN',
      columns: ['name', 'linkUp', 'connectorLabel', 'mac'],
      intervalMs: inventoryTtlMs,
    },
    // Live per-port throughput (fast path) — rows filled at runtime.
    { key: 'lan.rates', label: 'Port throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'table', group: 'LAN', columns: ['rx', 'tx'] },

    // --- WAN --------------------------------------------------------------
    {
      key: 'wan.ips',
      label: 'WAN interfaces',
      type: 'string',
      visualization: 'table',
      group: 'WAN',
      columns: ['peer', 'typeLabel', 'address', 'netmask', 'gateway'],
      intervalMs: inventoryTtlMs,
    },
    // Live per-WAN throughput (fast path) — rows filled at runtime.
    { key: 'wan.rates', label: 'WAN throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'table', group: 'WAN', columns: ['rx', 'tx'] },
    // Headline aggregate for the device overview table (summary: true).
    { key: 'wan.throughputTotal', label: 'WAN total throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'text', group: 'WAN', summary: true },

    // --- VPN --------------------------------------------------------------
    {
      key: 'vpn.connections',
      label: 'VPN connections',
      type: 'string',
      visualization: 'table',
      group: 'VPN',
      columns: ['peer', 'physConn', 'ikeType', 'cryptAlg', 'stateLabel', 'modeLabel', 'connTimeSeconds'],
      intervalMs: inventoryTtlMs,
    },

    // --- WiFi (built-in radios only) --------------------------------------
    ...(hasWifi
      ? [
          {
            key: 'wifi.radios',
            label: 'Radios',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['ifc', 'bandLabel', 'channel', 'noiseFloorDbm', 'modemLoadPct', 'txPower', 'utilizationPct'],
            intervalMs: inventoryTtlMs,
          },
          {
            key: 'wifi.ssids',
            label: 'Networks (SSIDs)',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['ifc', 'name', 'operating', 'bssid', 'stations', 'vlanId'],
            intervalMs: inventoryTtlMs,
          },
          {
            key: 'wifi.clients',
            label: 'Connected clients',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['mac', 'hostname', 'ifc', 'ip4', 'signalDbm', 'txRateMbps', 'rxRateMbps', 'vlanId'],
            intervalMs: inventoryTtlMs,
          },
        ]
      : []),

    // --- Temperature ------------------------------------------------------
    {
      key: 'temperature.extremes',
      label: 'Temperature extremes (min/max)',
      type: 'string',
      visualization: 'table',
      group: 'System',
      columns: ['sensor', 'kind', 'valueTenthsC'],
      intervalMs: inventoryTtlMs,
    },
  ];

  return d;
}

/** Static baseline set advertised in /discover (rows filled at runtime). */
export const DISCOVER_METRICS: MetricDescriptor[] = buildDescriptors(INVENTORY_INTERVAL_MS);
