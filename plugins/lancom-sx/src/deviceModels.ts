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
 * Sources: the `lcsProducts` subtree of the unified LCOS-SX MIB
 * (mibs/LC-GS-3510XP-4.30.0439-RU9.mib) plus the legacy GS-2310 line from
 * mibs/LC-GS-2310-3.34.0371-RU11.mib. Deliberately EXCLUDED: LC-LX access
 * points (lancom-lx plugin), SwOS switches (swos plugin), and routers
 * (lancom-lcos plugin). All listed models share the same MIB surface per
 * firmware line, so the plugin behaves identically for every entry; the
 * selection documents the hardware.
 */

export interface LancomSxDeviceModel {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
}

// Current LCOS SX release line (major.minor, as LANCOM names it):
const LINES_CURRENT = ['4.30']; // current line (2026) — LCOS SX 4.30
// The legacy GS-2310 line runs the older firmware generation:
const LINES_LEGACY = ['3.34', '4.30'];

export const DEVICE_MODELS: LancomSxDeviceModel[] = [
  // --- Legacy entry switch (3.x MIB tree) ----------------------------------
  { vendor: 'lancom', model: 'GS-2310', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_LEGACY },

  // --- GS-24xx compact switches ---------------------------------------------
  { vendor: 'lancom', model: 'GS-2412', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-2412P', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-2426', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-2426P', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },

  // --- GS-31xx / IGS-31xx (X = SFP uplinks, XP/XSP = PoE) --------------------
  { vendor: 'lancom', model: 'GS-3126X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3126XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3128X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3128XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'IGS-3128XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'IGS-3128XF', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },

  // --- GS-315xx / 3252 --------------------------------------------------------
  { vendor: 'lancom', model: 'GS-3152X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3152XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3152XSP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3152P', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3252P', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },

  // --- GS-35xx / IGS/XS-35xx (10G uplinks) ------------------------------------
  { vendor: 'lancom', model: 'GS-3510XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3510X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'IGS-3510XUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'XS-3510YUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'XS-3526YUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },

  // --- GS-3528 / XS-3550 --------------------------------------------------------
  { vendor: 'lancom', model: 'GS-3528XSP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3528XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3528X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3528XUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'XS-3550YUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },

  // --- GS-36xx (25G generation) ---------------------------------------------------
  { vendor: 'lancom', model: 'GS-3628X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3628XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3628XUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3652X', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3652XP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'GS-3652XUP', iconPath: '/icons/lancom-sx.svg', firmwareVersions: LINES_CURRENT },

  // --- Generic fallback ---------------------------------------------------------
  { vendor: 'lancom', model: 'Other / custom SX switch', iconPath: '/icons/lancom-sx.svg', firmwareVersions: [...LINES_LEGACY] },
];
