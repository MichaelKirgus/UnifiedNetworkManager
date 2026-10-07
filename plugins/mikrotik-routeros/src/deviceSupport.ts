/**
 * Device support metadata for the MikroTik RouterOS plugin — advertised in
 * /discover as `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Tells
 * UNM which capabilities are effective on a SPECIFIC router:
 *
 *   - WiFi handling is only meaningful when the box actually has wireless
 *     radios (detected feature 'wifi' — an interface of type `wireless`, or
 *     associated clients in the ROS 7 registration table). A pure-wired CCR
 *     shows the capability as not effective.
 *   - The interactive SSH console works on every box: when no dedicated `ssh`
 *     slot is bound, the primary username/password login is reused (RouterOS
 *     shares one account across REST + SSH), so it carries no condition.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const ROUTEROS_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://wiki.mikrotik.com/wiki/Main_Page',
  docPath: 'docs/README.md',

  // Effective on every RouterOS box this plugin serves (REST API since 7.1).
  defaultCapabilities: [
    { name: 'monitoring', label: 'Monitoring' },
    { name: 'inventory', label: 'Inventory (interfaces, ARP, DHCP leases, routes, firewall)' },
    { name: 'configuration', label: 'Configuration actions' },
    { name: 'planning', label: 'Planning / rollouts' },
    { name: 'updates', label: 'Firmware status (available-without-apply)' },
    // Interactive CLI shell over SSH — always effective: the primary login is
    // reused when no dedicated `ssh` slot is bound.
    { name: 'sshConsole', label: 'SSH console' },
    // Service-exposure + failed-login checks over the REST API (no extra slots).
    { name: 'securityChecks', label: 'Security checks' },
    // WiFi — only when the box has radios (detected feature 'wifi'). Wired-only
    // hardware (most CCRs, CHR) shows this as not effective.
    {
      name: 'wifi',
      label: 'WiFi (wireless interfaces)',
      conditions: { requiresFeatures: ['wifi'] },
    },
  ],

  profiles: [
    // All supported RouterOS lines share the same REST surface — no extra slots
    // required: both write paths are pure REST (/ip/address, /interface bridge, …).
    {
      vendor: 'mikrotik',
      minFirmware: '7.1',
      capabilities: [],
      intents: [
        { actionId: 'network.create', label: 'Create network' },
        { actionId: 'network.delete', label: 'Delete network' },
      ],
    },
    // Catch-all for devices whose firmware version is unknown (ranged profiles
    // deliberately skip them) — the REST surface has been stable since 7.1, so
    // grant the same intents unconditionally.
    {
      vendor: 'mikrotik',
      capabilities: [],
      intents: [
        { actionId: 'network.create', label: 'Create network' },
        { actionId: 'network.delete', label: 'Delete network' },
      ],
    },
  ],
};
