/**
 * Device support metadata for the generic-ntp plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const GENERIC_NTP_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'NTP/SNTP service checks (drift, stratum)' },
    { name: 'probe', label: 'Time-page on-demand refresh' },
  ],
};
