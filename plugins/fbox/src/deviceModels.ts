/**
 * FBox device model catalog — drives the webapp Model/Firmware dropdowns.
 *
 * Vendor is the factual `avm`; model names are plain numbers (the brand prefix
 * of device-reported product names is stripped by normalizeModelName()). The
 * trailing generic entry has no iconPath → DeviceIcon falls back to the plugin
 * icon, exactly like the OPNsense "Custom / DIY" pattern. Firmware lines are
 * firmware major versions (point updates excluded) — verify/trim against live
 * hardware in the probe step.
 */

import { DeviceModelEntry } from '@unm/plugin-sdk';

const FIRMWARE_LINES = ['175', '183'];

export const DEVICE_MODELS: DeviceModelEntry[] = [
  { vendor: 'avm', model: '4060', iconPath: '/icons/fbox-dsl.svg', firmwareVersions: FIRMWARE_LINES },
  { vendor: 'avm', model: '7530 AX', iconPath: '/icons/fbox-wifi.svg', firmwareVersions: FIRMWARE_LINES },
  { vendor: 'avm', model: '7590', iconPath: '/icons/fbox-wifi.svg', firmwareVersions: FIRMWARE_LINES },
  { vendor: 'avm', model: '7690', iconPath: '/icons/fbox-cable.svg', firmwareVersions: FIRMWARE_LINES },
  // Generic fallback — no icon, plugin icon is used instead.
  { vendor: 'avm', model: 'Custom / Other' },
];
