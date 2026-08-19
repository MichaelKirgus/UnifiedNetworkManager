/**
 * Plugin option descriptors — the self-description a plugin emits in its
 * `/discover` response (`options`) so the API can persist user-set values and
 * the webapp can render a generic settings form.
 *
 * The contract is a discriminated union on `type`. Adding a new option type
 * later = add one member here + one validator branch in `pluginSettings.ts`
 * + one renderer branch in the webapp's `OptionForm`. No breaking changes to
 * existing types, no DB migration (values are stored as JSON text).
 */

export interface PluginOptionBase {
  /** Short internal name; unique per plugin. Used as the settings key. */
  key: string;
  /** Human-readable display name shown in the UI. */
  label: string;
  type: 'string' | 'integer' | 'boolean';
  /** Default value used when the user has not set an override. */
  default?: unknown;
  /** Longer description / help text for the option. */
  description?: string;
  /** Optional URI where the user can find more information about this option. */
  docsUrl?: string;
}

export interface StringOption extends PluginOptionBase {
  type: 'string';
  /** Regex pattern the user input must match (validated by the API). */
  pattern?: string;
  minLength?: number;
  maxLength?: number;
}

export interface IntegerOption extends PluginOptionBase {
  type: 'integer';
  min?: number;
  max?: number;
}

export interface BooleanOption extends PluginOptionBase {
  type: 'boolean';
}

export type PluginOptionDescriptor = StringOption | IntegerOption | BooleanOption;
