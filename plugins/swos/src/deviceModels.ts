/**
 * Supported MikroTik SwOS / SwOS Lite switch catalog.
 *
 * Sources:
 *  - Hardware list: the python-mikrotik-swos reference project's confirmed
 *    compatibility matrix (CRS305-1G-4S+, CRS309-1G-8S+, CRS310-8G+2S+,
 *    CRS326-24S+2Q, CSS610-8G-2S+, CSS610-8P-2S+) plus the models named in its
 *    module docs (CRS328-24P-2S+Q, CSS326-24G-2S+).
 *  - Firmware lines: SwOS 2.17 / 2.18 and SwOS Lite 2.17–2.20 are the versions
 *    confirmed working by that project (mikrotik.com changelogs list further
 *    point releases; the major.minor line is what matters for compatibility).
 *
 * Both firmware families share one plugin: SwOS (CRS/RB series) and SwOS Lite
 * (CSS series) speak the same .b-file protocol with different field IDs — the
 * platform is detected at runtime from sys.b, so no per-model logic is needed.
 * RouterOS devices are deliberately NOT listed here; they get their own plugin.
 */

export interface DeviceModelEntry {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
}

/** SwOS (CRS series) firmware lines confirmed by the reference project. */
const SWOS_FIRMWARE = ['2.17', '2.18'];

/** SwOS Lite (CSS series) firmware lines confirmed by the reference project. */
const SWOS_LITE_FIRMWARE = ['2.17', '2.18', '2.19', '2.20'];

export const DEVICE_MODELS: DeviceModelEntry[] = [
  // --- SwOS (CRS series) -----------------------------------------------------
  { vendor: 'mikrotik', model: 'CRS305-1G-4S+', iconPath: '/icons/crs-rack.svg', firmwareVersions: SWOS_FIRMWARE },
  { vendor: 'mikrotik', model: 'CRS309-1G-8S+', iconPath: '/icons/crs-rack.svg', firmwareVersions: SWOS_FIRMWARE },
  { vendor: 'mikrotik', model: 'CRS309-1G-8S-2H+P', iconPath: '/icons/crs-rack.svg', firmwareVersions: SWOS_FIRMWARE },
  { vendor: 'mikrotik', model: 'CRS310-8G+2S+', iconPath: '/icons/crs-rack.svg', firmwareVersions: SWOS_FIRMWARE },
  { vendor: 'mikrotik', model: 'CRS326-24S+2Q', iconPath: '/icons/crs-rack.svg', firmwareVersions: SWOS_FIRMWARE },
  { vendor: 'mikrotik', model: 'CRS328-24P-2S+Q', iconPath: '/icons/crs-rack.svg', firmwareVersions: SWOS_FIRMWARE },

  // --- SwOS Lite (CSS series) --------------------------------------------------
  { vendor: 'mikrotik', model: 'CSS610-8G-2S+', iconPath: '/icons/css-desktop.svg', firmwareVersions: SWOS_LITE_FIRMWARE },
  { vendor: 'mikrotik', model: 'CSS610-8P-2S+', iconPath: '/icons/css-desktop.svg', firmwareVersions: SWOS_LITE_FIRMWARE },
  { vendor: 'mikrotik', model: 'CSS326-24G-2S+', iconPath: '/icons/css-desktop.svg', firmwareVersions: SWOS_LITE_FIRMWARE },

  // Generic entry — any other SwOS/SwOS Lite switch (no icon → DeviceIcon falls
  // back to the plugin icon).
  { vendor: 'mikrotik', model: 'Custom / SwOS' },
];
