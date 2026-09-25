/**
 * Shared plugin state store for the OpenWRT plugin — ONE instance per process.
 *
 * File-integrity baselines live in UNM's database via the SDK's generic state
 * store, NOT on local disk: a container rebuild must not re-baseline every
 * watched host.
 *
 * MULTI-INSTANCE CORRECTNESS — this is why the store lives here and nowhere else:
 *  - The API scopes every state row to the plugin's EFFECTIVE uuid
 *    (`<uuid>:<instanceId>` when `PLUGIN_INSTANCE_ID` is set, bare `<uuid>` otherwise).
 *  - Both the /monitoring security-collection path AND the `security.rebaseline`
 *    action must read/write the SAME instance-scoped store. If each built its own
 *    from a raw env var they could disagree (e.g. an unset/incorrect base uuid),
 *    so we compute the effective uuid ONCE here and share one bound client.
 *  - Two instances of this plugin watching the same host therefore keep SEPARATE
 *    baselines — each instance is a distinct "plugin" from UNM's perspective, which
 *    is exactly what multi-instance support requires.
 */

import { createPluginStateStore } from '@unm/plugin-sdk';

/** Base plugin UUID — single source of truth (index.ts re-exports this). */
export const PLUGIN_UUID = 'aa9f941c-f63c-432c-adef-19049b320d03';

// Effective uuid mirrors resolvePluginIdentity(): `<uuid>:<instanceId>` when the
// instance is named, else the bare base uuid. Computed from env so it always
// matches what /discover advertises for THIS process.
const instanceId = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = instanceId ? `${PLUGIN_UUID}:${instanceId}` : PLUGIN_UUID;

/** The single shared state store, bound to this instance's effective uuid. */
export const stateStore = createPluginStateStore({ effectiveUuid: EFFECTIVE_UUID });
