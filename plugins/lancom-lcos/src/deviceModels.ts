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
 * Sources (checked 2026-08): https://ftp.lancom.de/LANCOM-Releases/ — every
 * LC-* router folder that ships the unified LCOS MIB (module `lcos`, base OID
 * .1.3.6.1.4.1.2356.11). Deliberately EXCLUDED:
 *   - LC-LX-*        access points  → lancom-lx plugin (LCOS-LX, base 2356.13)
 *   - LC-GS/XS/YS    switches       → SwOS plugin (different OS + MIB tree)
 *   - WLC / OAP / OW / OX            → controllers/APs, not routers
 * All listed models share the same unified-MIB surface, so the plugin behaves
 * identically for every entry; the selection documents the hardware and enables
 * future model-specific behavior (e.g. WAN technology hints).
 */

export interface LancomDeviceModel {
  vendor: string;
  model: string;
  iconPath?: string;
  firmwareVersions?: string[];
}

// Current LCOS release lines for routers (major.minor, as LANCOM names them):
const LINES_CURRENT = ['10.94']; // current line (2026)
// Older/longer-supported models also run the previous line:
const LINES_LEGACY = ['10.92', '10.94'];

export const DEVICE_MODELS: LancomDeviceModel[] = [
  // --- Entry / residential routers --------------------------------------
  { vendor: 'lancom', model: 'LC-730VA', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
  { vendor: 'lancom', model: 'LC-883-VoIP', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
  { vendor: 'lancom', model: 'LC-884-VoIP', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },

  // --- Mid-range routers --------------------------------------------------
  { vendor: 'lancom', model: 'LC-1640E', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
  { vendor: 'lancom', model: 'LC-1650E', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },

  // --- LC-17xx business routers -------------------------------------------
  { vendor: 'lancom', model: 'LC-1781VA', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
  { vendor: 'lancom', model: 'LC-1780EF', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1790EF', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1793VA', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- LC-18xx routers (EF / VA / W+4G / 5G variants) ----------------------
  { vendor: 'lancom', model: 'LC-1800EF', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1803VA', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1803VAW', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1803VAW-5G', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- LC-19xx routers ------------------------------------------------------
  { vendor: 'lancom', model: 'LC-1900EF', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1906VA', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1926VAG', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1930EF', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-1936VAG', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- LC-21xx flagship ------------------------------------------------------
  { vendor: 'lancom', model: 'LC-2100EF', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- LTE / cellular routers -----------------------------------------------
  { vendor: 'lancom', model: 'LC-IAP-821', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
  { vendor: 'lancom', model: 'LC-IAP-822', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-OAP-5G', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- Industrial routers -----------------------------------------------------
  { vendor: 'lancom', model: 'LC-ISG-1000', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
  { vendor: 'lancom', model: 'LC-ISG-4000', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-ISG-5000', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },
  { vendor: 'lancom', model: 'LC-ISG-8000', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- vRouter -----------------------------------------------------
  { vendor: 'lancom', model: 'vRouter', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_CURRENT },

  // --- Generic fallback ---------------------------------------------------------
  // Any other LCOS router (older or unlisted model) — the unified MIB surface is
  // shared, so monitoring works; this entry just keeps the dropdown usable.
  { vendor: 'lancom', model: 'Other / custom LCOS router', iconPath: '/icons/lancom-lcos.svg', firmwareVersions: LINES_LEGACY },
];
