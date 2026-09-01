/**
 * Supported device model catalog, advertised in /discover (`deviceModels`).
 * The API persists it and the webapp renders Model + Firmware dropdowns from
 * it; the user's selection is forwarded to every /monitoring call so this
 * plugin can adapt its data gathering to the specific hardware.
 *
 * Vendor values MUST match PLUGIN_VENDORS entries (the webapp matches them
 * against the device form's vendor select). Model names are display strings —
 * keep them stable, they become part of stored device rows.
 *
 * Sources (checked 2026-08):
 * - Hardware: https://www.deciso.com/hardware/ — Deciso is OPNsense's official
 *   hardware vendor; the line covers rack security appliances (DEC39xx, DEC42xx,
 *   DEC27xx, DEC38xx, DEC26xx) and desktop appliances (DEC850 … DEC677). The
 *   wall-mount bracket set is an accessory, not a device model. Deciso product
 *   pages ship video instead of static artwork, so the per-model icons are
 *   original house-style placeholders in two form factors (rack / desktop).
 * - Firmware: https://pkg.opnsense.org/releases/ — OPNsense uses year.month
 *   release lines with major releases in January and July. Point updates
 *   (e.g. 26.1.2, 26.1.6) exist within a line; the dropdown lists base lines
 *   only. Pre-2022 lines are long EOL and no longer mirrored — not listed.
 * - Editions: Community Edition and Business Edition share the SAME base
 *   releases (BE adds the licensed OPNcentral sync surface), so there is one
 *   firmware list per model, not per edition. The plugin detects the running
 *   edition at runtime (client/editions.ts probes /api/opncentral/sync/listClasses).
 * - Per-model ranges: none needed — OPNsense images are generic amd64 and any
 *   release runs on any appliance (unlike LCOS-LX, where the MIB surface
 *   differs per hardware generation), so every model gets the full list.
 */

export interface OpnsenseDeviceModel {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
  /** Suggested topology layer (network_layers id) — see DeviceModelEntry in the plugin SDK. */
  defaultLayerId?: string;
}

// OPNsense release lines (year.month) currently published on the official
// package mirror https://pkg.opnsense.org/releases/.
const RELEASES = [
  '22.1',
  '22.7',
  '23.1',
  '23.7',
  '24.1',
  '24.7',
  '25.1',
  '25.7',
  '26.1',
  '26.7', // current (Jul 2026)
];

// OPNsense boxes are edge gateways/firewalls — they sit in the CORE band of
// the topology view. The suggestion rides on every model entry; a user's
// manual override always wins, and devices without a selected model fall back
// to the type/vendor heuristic (which also lands opnsense vendors in core).
const RAW_MODELS: OpnsenseDeviceModel[] = [
  // Deciso rack security appliances (deciso.com/hardware).
  { vendor: 'opnsense', model: 'DEC3920', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC3940', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC3960', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC4280', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC4240', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC2770', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC2752', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC3862', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC3852', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC2687', iconPath: '/icons/dec-rack.svg', firmwareVersions: RELEASES },
  // Deciso desktop security appliances.
  { vendor: 'opnsense', model: 'DEC850', iconPath: '/icons/dec-desktop.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC750', iconPath: '/icons/dec-desktop.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC740', iconPath: '/icons/dec-desktop.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC697', iconPath: '/icons/dec-desktop.svg', firmwareVersions: RELEASES },
  { vendor: 'opnsense', model: 'DEC677', iconPath: '/icons/dec-desktop.svg', firmwareVersions: RELEASES },
  // Generic entry for non-Deciso installs (OPNsense runs on any x86_64 box —
  // most home-lab devices are DIY servers or VMs). No iconPath → the webapp's
  // DeviceIcon falls back to the plugin icon automatically.
  { vendor: 'opnsense', model: 'Custom / DIY', firmwareVersions: RELEASES },
];

export const DEVICE_MODELS: OpnsenseDeviceModel[] = RAW_MODELS.map((m) => ({ ...m, defaultLayerId: 'core' }));
