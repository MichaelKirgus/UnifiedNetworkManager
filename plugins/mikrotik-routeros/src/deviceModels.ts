/**
 * Supported MikroTik RouterOS hardware catalog.
 *
 * A deliberately modest starter list of the most common RouterOS boxes (CCR
 * rackmounts, hEX/RB desktop units, CHR virtual routers). The "Custom /
 * RouterOS" entry covers everything else — DeviceIcon falls back to the plugin
 * icon when a model has no iconPath. Every model suggests the 'core' network
 * layer: RouterOS devices are routers/firewalls and the topology heuristic
 * already maps type `router` → core; declaring it explicitly keeps them in the
 * core band even when typed generically (same pattern as opnsense/lancom-lcos).
 *
 * Firmware = ROS major.minor lines (point updates excluded) — REST API is
 * available since 7.1beta4, so all listed lines support this plugin.
 */

export interface DeviceModelEntry {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
  /** Suggested network layer for topology auto-classification (routers → core). */
  defaultLayerId?: string;
}

/** Recent RouterOS 7.x lines (REST API available since 7.1beta4). */
const ROS_FIRMWARE = ['7.8', '7.9', '7.10', '7.11', '7.12', '7.13', '7.14'];

export const DEVICE_MODELS: DeviceModelEntry[] = [
  // --- CCR (Cloud Core Router, rackmount) ------------------------------------
  { vendor: 'mikrotik', model: 'CCR1009-7G-1C-2X+D', iconPath: '/icons/router-rack.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },
  { vendor: 'mikrotik', model: 'CCR1016-12S-1G+EMS', iconPath: '/icons/router-rack.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },
  { vendor: 'mikrotik', model: 'CCR2004-1G-12S+2XS+', iconPath: '/icons/router-rack.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },

  // --- hEX / RB (desktop) ------------------------------------------------------
  { vendor: 'mikrotik', model: 'hEX S (RB750Gr3)', iconPath: '/icons/router-desktop.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },
  { vendor: 'mikrotik', model: 'hEX (RB750Gr2)', iconPath: '/icons/router-desktop.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },
  { vendor: 'mikrotik', model: 'RB4011iGS+', iconPath: '/icons/router-desktop.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },
  { vendor: 'mikrotik', model: 'RB5009', iconPath: '/icons/router-desktop.svg', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },

  // --- CHR (virtual router) ------------------------------------------------------
  { vendor: 'mikrotik', model: 'CHR (virtual)', firmwareVersions: ROS_FIRMWARE, defaultLayerId: 'core' },

  // Generic entry — any other RouterOS device (no icon → plugin icon fallback).
  { vendor: 'mikrotik', model: 'Custom / RouterOS', defaultLayerId: 'core' },
];
