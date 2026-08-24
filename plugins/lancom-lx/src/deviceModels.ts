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
 * - Model list: https://ftp.lancom.de/LANCOM-Releases/ (current LC-LX-* folders)
 *   plus archived lancom-systems.com product pages for former models. All
 *   indoor LC-LX access points run LCOS-LX and share the same MIB surface, so
 *   the plugin behaves identically for every entry; the selection documents
 *   the hardware and enables future model-specific behavior.
 * - Firmware lines: https://ftp.lancom.de/Documentation/Release-Notes/LCOS LX/
 *   (RN_LCOS-LX-<line>-*.pdf, 4.00 … 7.14). Per-model ranges are approximate
 *   by launch era — a model name can span several hardware revisions (e.g. the
 *   LC-LX-6400 line exists since 2019), so overlapping lines are listed once.
 */

export interface LancomDeviceModel {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
}

// Every LCOS-LX release line ever shipped (major.minor, as LANCOM names them).
const ALL_LINES = [
  '4.00', // May 2019 — first LCOS-LX line
  '5.10',
  '5.20',
  '5.30',
  '5.32',
  '5.34',
  '5.36', // Apr 2022 — Wi-Fi 6E generation launch era
  '5.38',
  '6.10',
  '6.12',
  '6.14',
  '7.00', // Oct 2024 — Wi-Fi 7 generation launch era
  '7.10',
  '7.12',
  '7.14', // current (Jul 2026)
];

// Lines from the Wi-Fi 6E generation onward (LC-LX-6xxx, launched ~2022).
const LINES_536_PLUS = ALL_LINES.slice(ALL_LINES.indexOf('5.36'));

// Lines of the Wi-Fi 7 generation (LC-LX-7xxx, launched late 2024).
const LINES_700_PLUS = ['7.00', '7.10', '7.12', '7.14'];

export const DEVICE_MODELS: LancomDeviceModel[] = [
  // Wi-Fi 6E generation (indoor)
  { vendor: 'lancom', model: 'LC-LX-6200', iconPath: '/icons/lx-6200.svg', firmwareVersions: LINES_536_PLUS },
  { vendor: 'lancom', model: 'LC-LX-6200E', iconPath: '/icons/lx-6200.svg', firmwareVersions: LINES_536_PLUS },
  { vendor: 'lancom', model: 'LC-LX-6212', iconPath: '/icons/lx-6212.svg', firmwareVersions: LINES_536_PLUS },
  // LC-LX-6400/6402 line since 2019 (Wi-Fi 5 original, refreshed for Wi-Fi 6) — full range.
  { vendor: 'lancom', model: 'LC-LX-6400', iconPath: '/icons/lx-6400.svg', firmwareVersions: ALL_LINES },
  { vendor: 'lancom', model: 'LC-LX-6402', iconPath: '/icons/lx-6402.svg', firmwareVersions: ALL_LINES },
  { vendor: 'lancom', model: 'LC-LX-6500', iconPath: '/icons/lx-6500.svg', firmwareVersions: LINES_536_PLUS },
  { vendor: 'lancom', model: 'LC-LX-6500E', iconPath: '/icons/lx-6500.svg', firmwareVersions: LINES_536_PLUS },
  // Wi-Fi 7 generation (indoor)
  { vendor: 'lancom', model: 'LC-LX-7200', iconPath: '/icons/lx-7200.svg', firmwareVersions: LINES_700_PLUS },
  { vendor: 'lancom', model: 'LC-LX-7200E', iconPath: '/icons/lx-7200.svg', firmwareVersions: LINES_700_PLUS },
  { vendor: 'lancom', model: 'LC-LX-7300', iconPath: '/icons/lx-7300.svg', firmwareVersions: LINES_700_PLUS },
  { vendor: 'lancom', model: 'LC-LX-7400', iconPath: '/icons/lx-7400.svg', firmwareVersions: LINES_700_PLUS },
  { vendor: 'lancom', model: 'LC-LX-7500', iconPath: '/icons/lx-7500.svg', firmwareVersions: LINES_700_PLUS },
];
