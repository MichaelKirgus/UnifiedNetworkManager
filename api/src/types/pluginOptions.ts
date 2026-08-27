/**
 * Plugin option descriptors — the self-description a plugin emits in its
 * `/discover` response (`options`) so the API can persist user-set values and
 * the webapp can render a generic settings form.
 *
 * The contract is a discriminated union on `type`. Adding a new option type
 * later = add one member to @unm/plugin-sdk + one validator branch in
 * `pluginSettings.ts` + one renderer branch in the webapp's `OptionForm`. No
 * breaking changes to existing types, no DB migration (values are stored as
 * JSON text).
 *
 * The canonical contract lives in @unm/plugin-sdk — re-exported here so API
 * modules keep their existing imports.
 */

export type {
  PluginOptionBase,
  StringOption,
  IntegerOption,
  BooleanOption,
  PluginOptionDescriptor,
} from '@unm/plugin-sdk';
