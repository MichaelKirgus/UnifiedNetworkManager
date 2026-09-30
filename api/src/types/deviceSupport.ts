/**
 * Device support metadata — part of the self-description a plugin emits in its
 * `/discover` response (`deviceSupport`). Carries license info, an optional
 * help URL, the path of built-in markdown documentation (served by the API's
 * asset proxy), and the standardized supported-device matrix: profiles of
 * vendor/model/firmware ranges mapped to effective capabilities + allowed
 * intents with gating conditions (detected features, bound credential slots,
 * firmware bounds).
 *
 * The canonical contract lives in @unm/plugin-sdk — re-exported here so API
 * modules keep their existing imports. Evaluation (which capability is
 * effective for which device) runs in the SDK's pure `evaluateDeviceSupport`.
 */

export type {
  PluginLicense,
  SupportCondition,
  SupportCapabilityGrant,
  SupportIntentGrant,
  DeviceSupportProfile,
  DeviceSupport,
  CapabilityEvaluation,
  DeviceSupportContext,
  DeviceSupportEvaluation,
} from '@unm/plugin-sdk';
export { evaluateDeviceSupport, matchSupportProfile, describeProfile } from '@unm/plugin-sdk';
