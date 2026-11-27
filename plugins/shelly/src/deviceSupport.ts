/**
 * Device support metadata for the Shelly plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const SHELLY_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  // Shelly's developer documentation (Gen1 REST + Gen2+ JSON-RPC reference).
  helpUrl: 'https://www.shelly.com/en-us/business/developers',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'Monitoring' },
    { name: 'updates', label: 'Firmware updates' },
    { name: 'configuration', label: 'Actions (firmware update, reboot)' },
    { name: 'planning', label: 'Plan execution' },
    { name: 'quickActions', label: 'Quick actions' },
  ],
};
