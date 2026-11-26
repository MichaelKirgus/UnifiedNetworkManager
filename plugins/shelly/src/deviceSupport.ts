/**
 * Device support metadata for the _template plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const _TEMPLATE_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://github.com/MichaelKirgus/UnifiedNetworkManager/blob/main/docs/PLUGIN-DEVELOPMENT.md',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'Monitoring' },
  ],
};
