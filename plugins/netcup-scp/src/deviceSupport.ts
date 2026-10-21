/**
 * Device support metadata for the netcup SCP plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const NETCUP_SCP_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://www.netcup.com/en/helpcenter/documentation/servercontrolpanel/api',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'VM inventory, state and task metrics from netcup SCP' },
    // Feeds UNM's own Networks + Firewall pages via the /monitoring inventory
    // propagation (networks[] + firewallRules[]) — hence named 'inventory'.
    { name: 'inventory', label: 'Network + firewall rule inventory into UNM' },
    { name: 'configuration', label: 'Plan-gated VM management (power, snapshots, ISO, image, firewall)' },
  ],
};
