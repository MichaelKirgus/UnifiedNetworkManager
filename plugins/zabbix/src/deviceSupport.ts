/**
 * Device support metadata for the zabbix plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const ZABBIX_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://www.zabbix.com/documentation',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'Fleet metrics from a Zabbix server' },
    // NOTE: this is the plugin's own `inventorySync` capability — it pushes UNM's
    // host inventory INTO Zabbix. It does not feed UNM's inventory pages, so it
    // must NOT be named 'inventory'.
    { name: 'inventorySync', label: 'Host inventory sync into Zabbix' },
  ],
};
