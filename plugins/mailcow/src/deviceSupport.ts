/**
 * Device support metadata for the mailcow plugin — advertised in /discover as
 * `deviceSupport` (see @unm/plugin-sdk deviceSupport.ts). Carries the license
 * info, help URL and built-in documentation path that UNM's Plugins page renders;
 * the full EUPL-1.2 text lives in LICENSE.md at the plugin root (served via the
 * API's asset proxy) and the docs in docs/README.md.
 */

import type { DeviceSupport } from '@unm/plugin-sdk';

export const MAILCOW_DEVICE_SUPPORT: DeviceSupport = {
  license: {
    name: 'EUPL-1.2',
    url: 'https://eupl.eu/1.2/en/',
    file: 'LICENSE.md',
  },
  helpUrl: 'https://docs.mailcow.email/',
  docPath: 'docs/README.md',
  defaultCapabilities: [
    { name: 'monitoring', label: 'System version + service health' },
    { name: 'inventory', label: 'Domains, mailboxes, aliases inventory' },
    { name: 'configuration', label: 'Domain / mailbox / alias CRUD actions' },
    { name: 'planning', label: 'Planning / rollouts' },
    { name: 'securityChecks', label: 'Security checks (failed logins)' },
  ],
};
