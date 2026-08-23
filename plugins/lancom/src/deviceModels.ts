/**
 * Supported device model catalog, advertised in /discover (`deviceModels`).
 * The API persists it and the webapp renders Model + Firmware dropdowns from
 * it; the user's selection is forwarded to every /monitoring call so this
 * plugin can adapt its data gathering to the specific hardware.
 *
 * Vendor values MUST match PLUGIN_VENDORS entries (the webapp matches them
 * against the device form's vendor select). Model names are display strings —
 * keep them stable, they become part of stored device rows.
 */

export interface LancomDeviceModel {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
}

// Major LCOS-LX release lines (placeholder set — refine to exact release
// strings per model line as the catalog grows). All LX models share the same
// MIB surface, so the plugin behaves identically for every entry today; the
// selection still lets users document their hardware and enables future
// model-specific behavior.
const LCOS_LINES = ['13', '14', '15'];

export const DEVICE_MODELS: LancomDeviceModel[] = [
  { vendor: 'lancom', model: 'LX10', iconPath: '/icons/lx.svg', firmwareVersions: LCOS_LINES },
  { vendor: 'lancom', model: 'LX20', iconPath: '/icons/lx.svg', firmwareVersions: LCOS_LINES },
  { vendor: 'lancom', model: 'LX30', iconPath: '/icons/lx.svg', firmwareVersions: LCOS_LINES },
  { vendor: 'lancom', model: 'LX40', iconPath: '/icons/lx.svg', firmwareVersions: LCOS_LINES },
  { vendor: 'lancom', model: 'LX45', iconPath: '/icons/lx.svg', firmwareVersions: LCOS_LINES },
];
