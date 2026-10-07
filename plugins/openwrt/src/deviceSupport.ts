/**
 * Device support metadata for the openwrt plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const OPENWRT_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://openwrt.org/docs/guide-user',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'System + interface monitoring (ubus/uci)' },
    { name: 'inventory', label: 'Inventory (interfaces, wireless, tunnels, services)' },
    { name: 'configuration', label: 'Configuration actions (firewall, DNS, DHCP, VPN)' },
    { name: 'planning', label: 'Planning / rollouts' },
    { name: 'updates', label: 'Firmware + package updates' },
    { name: 'securityChecks', label: 'Security checks over SSH' },
  ],
};
