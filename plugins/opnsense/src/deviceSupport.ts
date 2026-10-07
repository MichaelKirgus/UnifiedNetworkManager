/**
 * Device support metadata for the OPNsense plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Tells UNM which
 * capabilities/intents are effective on a SPECIFIC appliance:
 *
 *   - ZFS inventory + security checks need an SSH slot bound AND (for ZFS) the
 *     appliance to actually run ZFS storage (detected feature 'zfs').
 *   - The canonical network intents (network.create / network.delete) write
 *     interface assignments through TWO paths: REST setAssignmentItem when the
 *     firmware's model can hold an L3 address (full assignment model — master/
 *     27.x+), or an SSH config upsert otherwise. On every RELEASED build that
 *     matters today (≤26.4 and 26.7.x) a bound `ssh` slot is therefore required;
 *     the support matrix encodes exactly that, so the webapp can show "network
 *     rollout unavailable — bind an SSH credential" instead of failing at
 *     plan-execution time.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const OPNSENSE_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://docs.opnsense.org/',
  docPath: 'docs/README.md',

  // Effective on every OPNsense appliance this plugin serves.
  defaultCapabilities: [
    { name: 'monitoring', label: 'Monitoring' },
    { name: 'inventory', label: 'Inventory (networks, hosts, tunnels, firewall)' },
    { name: 'configuration', label: 'Configuration actions' },
    { name: 'planning', label: 'Planning / rollouts' },
    { name: 'deviceState', label: 'Live device state (Config page)' },
    { name: 'updates', label: 'Firmware + package updates' },
    // ZFS pool/dataset inventory — the OPNsense API has no ZFS listing, so this
    // rides the SSH slot AND only exists when the appliance actually runs ZFS.
    {
      name: 'zfsInventory',
      label: 'ZFS storage inventory',
      conditions: { requiresFeatures: ['zfs'], requiredSlots: ['ssh'] },
    },
    // Per-appliance security checks run over the same SSH slot (file integrity,
    // failed logins, rate limiting).
    {
      name: 'securityChecks',
      label: 'Security checks',
      conditions: { requiredSlots: ['ssh'] },
    },
  ],

  profiles: [
    // OPNsense 26.7+ — the REST API gained setAssignmentItem + reconfigure, but
    // on every RELEASED build in this line (26.7.x) the model cannot hold an L3
    // address, so assignment writes fall back to the SSH config edit and need a
    // bound `ssh` slot. A future full-model build would make REST sufficient —
    // until then the slot requirement is what makes 26.7.x configurable at all.
    {
      vendor: 'opnsense',
      minFirmware: '26.7',
      capabilities: [
        { name: 'interfaceAssignment', label: 'Interface assignment (REST or SSH fallback)', conditions: { requiredSlots: ['ssh'] } },
      ],
      intents: [
        { actionId: 'network.create', label: 'Create network', conditions: { requiredSlots: ['ssh'] } },
        { actionId: 'network.delete', label: 'Delete network', conditions: { requiredSlots: ['ssh'] } },
      ],
    },
    // OPNsense ≤26.4 — assignment writes go through an SSH config upsert, so a
    // bound `ssh` slot is REQUIRED for the network intents to be effective.
    {
      vendor: 'opnsense',
      capabilities: [
        {
          name: 'interfaceAssignment',
          label: 'Interface assignment (SSH)',
          conditions: { requiredSlots: ['ssh'] },
        },
      ],
      intents: [
        { actionId: 'network.create', label: 'Create network', conditions: { requiredSlots: ['ssh'] } },
        { actionId: 'network.delete', label: 'Delete network', conditions: { requiredSlots: ['ssh'] } },
      ],
    },
  ],
};
