/**
 * Device support metadata for the ix-truenas plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const IX_TRUENAS_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://www.truenas.com/docs/',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'System / pool / share monitoring (JSON-RPC)' },
    { name: 'configuration', label: 'Configuration actions (VMs, containers, storage, shares)' },
    { name: 'planning', label: 'Planning / rollouts' },
    { name: 'updates', label: 'Firmware + package updates' },
    { name: 'deviceState', label: 'Live device state (Config page)' },
    { name: 'sshConsole', label: 'Interactive SSH console' },
    { name: 'filesystem', label: 'SFTP file manager' },
  ],
};
