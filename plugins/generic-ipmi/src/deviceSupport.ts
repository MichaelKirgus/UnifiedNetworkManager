/**
 * Device support metadata for the generic IPMI plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license info,
 * help URL and built-in documentation path that UNM's Plugins page renders; the full
 * EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the API's asset
 * proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const GENERIC_IPMI_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://www.intel.com/content/www/us/en/developer/articles/software/intel-ipmi-spec.html',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'Chassis power state, SDR sensor readings with threshold states, FRU identity and SEL events' },
    // Feeds UNM's own Networks page via the /monitoring inventory propagation (networks[] row from the BMC LAN config).
    { name: 'inventory', label: 'BMC LAN channel IP/MAC into UNM\'s network inventory' },
    { name: 'configuration', label: 'Plan-gated server control (power on/off/reset, boot options, SEL clear, NMI pulse, BMC LAN settings)' },
    { name: 'probe', label: 'On-demand chassis status probe for the Devices page' },
    // The webapp renders a generic "Shell" button for any plugin advertising 'sshConsole';
    // here it opens an IPMI SOL (Serial-over-LAN) console to the server's serial port.
    { name: 'sshConsole', label: 'SOL serial console (interactive terminal over IPMI Serial-over-LAN)' },
  ],
};
