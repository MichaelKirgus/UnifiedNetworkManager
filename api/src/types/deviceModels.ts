/**
 * Device model catalog entries — part of the self-description a plugin emits
 * in its `/discover` response (`deviceModels`). Vendor-specific plugins use it
 * to tell the webapp which hardware models they support (and optionally which
 * firmware versions per model), so the device create/edit form can offer
 * Model + Firmware dropdowns. The user's selection is stored on the device row
 * and forwarded to every /monitoring call, letting the plugin adapt its data
 * gathering to the specific device.
 *
 * Plugins without a meaningful catalog (e.g. ICMP) simply omit `deviceModels`
 * from /discover — the form then shows no model fields for their vendors.
 *
 * The canonical contract lives in @unm/plugin-sdk — re-exported here so API
 * modules keep their existing imports.
 */

export type { DeviceModelEntry } from '@unm/plugin-sdk';
