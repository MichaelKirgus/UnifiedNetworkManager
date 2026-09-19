/**
 * Metric descriptors for the LANCOM LX-Series plugin. The webapp renders
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
 * WiFi groups only when WLAN data was actually collected (a LANCOM AP without
 * radios enabled still gets System/LAN groups).
 */
export function buildDescriptors(inventoryTtlMs: number, hasWifi = true): MetricDescriptor[] {
  const d: MetricDescriptor[] = [
    // --- System ----------------------------------------------------------
    { key: 'system.name', label: 'Device name', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.swVersion', label: 'Software version', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.serialNumber', label: 'Serial number', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.uptime', label: 'Uptime', unit: 's', format: 'duration', type: 'number', visualization: 'text', group: 'System' },
    { key: 'system.cpuLoad', label: 'CPU load (60 s)', unit: '%', min: 0, max: 100, color: '#f59e0b', type: 'number', visualization: 'gauge', group: 'System' },
    { key: 'system.memoryUsedPct', label: 'Memory used', unit: '%', min: 0, max: 100, color: '#8b5cf6', type: 'number', visualization: 'gauge', group: 'System' },
    { key: 'system.bootcount', label: 'Boot count', type: 'number', visualization: 'text', group: 'System' },

    // --- Management (CAPWAP / LMC cloud) ---------------------------------
    { key: 'management.mode', label: 'Management mode', type: 'string', visualization: 'text', group: 'Management' },
    { key: 'management.controller', label: 'Controller (WLC)', type: 'string', visualization: 'text', group: 'Management' },
    { key: 'management.lmcStatus', label: 'LMC cloud status', type: 'string', visualization: 'text', group: 'Management' },

    // --- Radios -----------------------------------------------------------
    ...(hasWifi
      ? [
          {
            key: 'wifi.radios',
            label: 'Radios',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['band', 'channel', 'mode', 'txPowerDbm', 'noiseFloorDbm', 'modemLoadPct', 'stations', 'temperatureC'],
            intervalMs: inventoryTtlMs,
          },
          // Scalar summaries for the device overview table (summary: true) —
          // one channel + radio-load metric per band. Load comes from the
          // RADIOS table (modemLoadPct), which reports ALL bands including
          // 6 GHz; the agent's airtime-utilization table has no 6 GHz rows,
          // so it is NOT usable for a per-band summary (see wifi.channelUtilization).
          { key: 'wifi.channel2g', label: 'Channel 2.4 GHz', type: 'string' as const, visualization: 'text' as const, group: 'WiFi', summary: true },
          { key: 'wifi.channel5g', label: 'Channel 5 GHz', type: 'string' as const, visualization: 'text' as const, group: 'WiFi', summary: true },
          { key: 'wifi.channel6g', label: 'Channel 6 GHz', type: 'string' as const, visualization: 'text' as const, group: 'WiFi', summary: true },
          { key: 'wifi.radioLoad2g', label: 'Radio load 2.4 GHz', unit: '%', min: 0, max: 100, color: '#f59e0b', type: 'number' as const, visualization: 'gauge' as const, group: 'WiFi', summary: true },
          { key: 'wifi.radioLoad5g', label: 'Radio load 5 GHz', unit: '%', min: 0, max: 100, color: '#0ea5e9', type: 'number' as const, visualization: 'gauge' as const, group: 'WiFi', summary: true },
          { key: 'wifi.radioLoad6g', label: 'Radio load 6 GHz', unit: '%', min: 0, max: 100, color: '#8b5cf6', type: 'number' as const, visualization: 'gauge' as const, group: 'WiFi', summary: true },
          {
            key: 'wifi.ssids',
            label: 'Networks (SSIDs)',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['ssid', 'bssid', 'band', 'vlanId', 'encryption', 'maxStations', 'pskFailures'],
            intervalMs: inventoryTtlMs,
          },
          {
            key: 'wifi.clients',
            label: 'Connected clients',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['mac', 'hostname', 'ssid', 'band', 'signalDbm', 'txRateMbps', 'rxRateMbps', 'vlanId', 'mode'],
            intervalMs: inventoryTtlMs,
          },
          {
            key: 'wifi.channelUtilization',
            label: 'Channel airtime utilization',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['channel', 'utilizationPct', 'overload'],
            intervalMs: inventoryTtlMs,
          },
          {
            key: 'wifi.rates',
            label: 'Radio throughput',
            unit: 'bps',
            format: 'bits' as const,
            type: 'number' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['rx', 'tx'],
          },
          {
            key: 'wifi.events',
            label: 'Station events (since last poll)',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['event', 'count'],
          },
          {
            key: 'wifi.neighbors',
            label: 'RF neighbors (scan results)',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['bssid', 'ssid', 'channel', 'band', 'signalDbm'],
            intervalMs: inventoryTtlMs,
          },
          {
            key: 'wifi.wdsLinks',
            label: 'WDS / mesh links',
            type: 'string' as const,
            visualization: 'table' as const,
            group: 'WiFi',
            columns: ['name', 'remoteMac', 'connected', 'signalDbm'],
            intervalMs: inventoryTtlMs,
          },
        ]
      : []),

    // --- LAN --------------------------------------------------------------
    {
      key: 'lan.ports',
      label: 'LAN ports',
      type: 'string',
      visualization: 'table',
      group: 'LAN',
      columns: ['name', 'linkUp', 'speedLabel', 'mac'],
      intervalMs: inventoryTtlMs,
    },

    // --- Live rates (fast path) -------------------------------------------
    {
      key: 'lan.rates',
      label: 'Port throughput',
      unit: 'bps',
      format: 'bits',
      type: 'number',
      visualization: 'table',
      group: 'LAN',
      columns: ['rx', 'tx'],
    },
  ];

  return d;
}

/** Static baseline set advertised in /discover (rows filled at runtime). */
export const DISCOVER_METRICS: MetricDescriptor[] = buildDescriptors(INVENTORY_INTERVAL_MS);
