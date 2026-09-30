/**
 * Device support metadata + effective-capability evaluation.
 *
 * Extends the plugin contract so UNM can answer, per device and per assigned
 * plugin: "which capabilities does THIS device actually have, which intents
 * are allowed on it, and why is something unavailable?" — without any
 * webapp code per plugin.
 *
 * The model has two halves:
 *   1. STATIC declaration (this file's types) — the plugin advertises in
 *      /discover a `deviceSupport` document: license, help URL, built-in
 *      markdown documentation path, and a standardized catalog of supported
 *      device profiles (vendor/model/firmware ranges → capabilities + intents).
 *      The catalog is DATA, not code: it scales to 100+ devices per plugin
 *      because the API evaluates it generically.
 *   2. DYNAMIC detection — the plugin emits `metrics['detectedFeatures']`
 *      (a string array) during /monitoring when it observes hardware or
 *      software features on a specific device (e.g. wifi radios, ZFS pools).
 *      The API persists this with the telemetry snapshot and feeds it to the
 *      evaluator below.
 *
 * A capability is EFFECTIVE for a device when:
 *   - some matching profile grants it (or `defaultCapabilities` does), AND
 *   - every gating condition holds:
 *       requiresFeatures ⊆ detected features (hardware present on THIS box)
 *       requiredSlots all bound with a secret of an allowed type (credentials)
 *       minFirmware/maxFirmware satisfied by the device's firmware version
 */

import { compareVersions } from './updates';

// ---------------------------------------------------------------------------
// Static declaration (/discover `deviceSupport`)
// ---------------------------------------------------------------------------

/** License metadata propagated to UNM. The full text lives in an optional
 *  LICENSE.md at the plugin root, served via the API's asset proxy when
 *  `licenseFile` is set; `name`/`url` are always shown in the UI. */
export interface PluginLicense {
  /** SPDX-style identifier or display name (e.g. "MIT", "GPL-3.0-or-later"). */
  name: string;
  /** Optional link to the canonical license text / project page. */
  url?: string;
  /** Path of the bundled LICENSE.md relative to the plugin root (served by the API's asset proxy). */
  file?: string;
}

/** One gating condition on a capability or intent grant. All conditions must hold. */
export interface SupportCondition {
  /** Device-detected feature ids that MUST be present (see `detectedFeatures` metric), e.g. ["wifi"]. */
  requiresFeatures?: string[];
  /** Credential slot names that MUST be bound to a secret of an allowed type, e.g. ["ssh"]. */
  requiredSlots?: string[];
  /** Inclusive minimum firmware/software version (compared with compareVersions). */
  minFirmware?: string;
  /** Inclusive maximum firmware/software version. */
  maxFirmware?: string;
}

/** One capability grant: a named capability + the conditions under which it is effective. */
export interface SupportCapabilityGrant {
  /** Capability id — should match one of the plugin's advertised capabilities or a feature key. */
  name: string;
  /** Short human-readable label for UI display (e.g. "WiFi configuration"). */
  label?: string;
  conditions?: SupportCondition;
}

/** One intent grant: an action id from this plugin's catalog + gating conditions. */
export interface SupportIntentGrant {
  /** Action id as declared in the plugin's /discover `actions` catalog. */
  actionId: string;
  label?: string;
  conditions?: SupportCondition;
}

/**
 * One supported device profile — a row of the standardized support matrix.
 * Matching is AND over all present fields (vendor, model, firmware range);
 * an absent field = wildcard for that dimension. The FIRST matching profile
 * wins (plugins order their catalog most-specific-first).
 */
export interface DeviceSupportProfile {
  /** Vendor key as used in UNM device records (e.g. "opnsense", "mikrotik"). Wildcard when omitted. */
  vendor?: string;
  /** Hardware model name (case-insensitive compare against devices.model). Wildcard when omitted. */
  model?: string;
  /** Inclusive minimum firmware/software version for this profile to apply. */
  minFirmware?: string;
  /** Inclusive maximum firmware/software version. */
  maxFirmware?: string;
  /** Capabilities effective on devices matching this profile (subject to their conditions). */
  capabilities: SupportCapabilityGrant[];
  /** Intents (catalog action ids) allowed on devices matching this profile. */
  intents?: SupportIntentGrant[];
}

/** The full device-support document a plugin advertises in /discover. */
export interface DeviceSupport {
  license?: PluginLicense;
  /** Optional help/documentation URL (vendor docs, project page). */
  helpUrl?: string;
  /** Path of the built-in markdown documentation relative to the plugin root
   *  (e.g. "docs/README.md"), served by the API's asset proxy and rendered in UNM. */
  docPath?: string;
  /** Capabilities effective on EVERY device this plugin serves — applied on top
   *  of any matched profile (a grant present in both is reported once). */
  defaultCapabilities?: SupportCapabilityGrant[];
  /** Ordered support matrix — first matching profile wins (most specific first).
   *  Optional: a document may carry only license/help/docs metadata. */
  profiles?: DeviceSupportProfile[];
}

// ---------------------------------------------------------------------------
// Dynamic detection (/monitoring `metrics['detectedFeatures']`)
// ---------------------------------------------------------------------------

/** The metric key under which a plugin emits the feature ids it detected on a device. */
export const DETECTED_FEATURES_METRIC_KEY = 'detectedFeatures';

// ---------------------------------------------------------------------------
// Effective-capability evaluation (pure — shared by API + tests)
// ---------------------------------------------------------------------------

/** One evaluated capability/intent: effective or not, with machine-readable reasons. */
export interface CapabilityEvaluation {
  name: string;
  label?: string;
  /** True when the grant matched AND every gating condition holds for this device. */
  effective: boolean;
  /** Human-readable reasons why it is NOT effective (empty when effective). */
  reasons: string[];
}

/** Everything the evaluator needs to know about one (device, plugin) pair. */
export interface DeviceSupportContext {
  /** devices.vendor — matched against profile.vendor (case-insensitive). */
  vendor?: string | null;
  /** devices.model — user-selected hardware model (case-insensitive compare). */
  model?: string | null;
  /** devices.firmwareVersion — the device's firmware/software version. */
  firmwareVersion?: string | null;
  /** Feature ids detected on this device by the plugin (metrics['detectedFeatures']). */
  detectedFeatures: string[];
  /** Slot name → true when a secret of an allowed type is bound to it. */
  boundSlots: Record<string, boolean>;
}

/** The evaluated support state for one (device, plugin) pair. */
export interface DeviceSupportEvaluation {
  /** True when at least one profile matched the device's vendor/model/firmware. */
  profileMatched: boolean;
  /** Label of the winning profile (vendor + model + firmware range), for UI display. */
  matchedProfile?: string;
  capabilities: CapabilityEvaluation[];
  intents: CapabilityEvaluation[];
}

/** Case-insensitive version compare that tolerates missing/unknown versions. */
function versionSatisfies(version: string | null | undefined, min?: string, max?: string): boolean {
  if (!version) return true; // unknown firmware → do not gate on it (profile match already applied the range)
  if (min && compareVersions(version, min) < 0) return false;
  if (max && compareVersions(version, max) > 0) return false;
  return true;
}

/** Evaluates one grant's conditions against the device context. Returns failure reasons ([] = effective). */
function evaluateConditions(conditions: SupportCondition | undefined, ctx: DeviceSupportContext): string[] {
  const reasons: string[] = [];
  if (!conditions) return reasons;
  for (const f of conditions.requiresFeatures ?? []) {
    if (!ctx.detectedFeatures.includes(f)) reasons.push(`requires detected feature "${f}"`);
  }
  for (const s of conditions.requiredSlots ?? []) {
    if (!ctx.boundSlots[s]) reasons.push(`requires credential slot "${s}" to be bound`);
  }
  if (conditions.minFirmware && !versionSatisfies(ctx.firmwareVersion, conditions.minFirmware)) {
    reasons.push(`requires firmware >= ${conditions.minFirmware}`);
  }
  if (conditions.maxFirmware && !versionSatisfies(ctx.firmwareVersion, undefined, conditions.maxFirmware)) {
    reasons.push(`requires firmware <= ${conditions.maxFirmware}`);
  }
  return reasons;
}

/** Finds the first profile matching vendor + model + firmware range. */
export function matchSupportProfile(support: DeviceSupport, ctx: DeviceSupportContext): DeviceSupportProfile | null {
  for (const p of support.profiles ?? []) {
    if (p.vendor && ctx.vendor && p.vendor.toLowerCase() !== String(ctx.vendor).toLowerCase()) continue;
    if (p.model && ctx.model && p.model.toLowerCase() !== String(ctx.model).toLowerCase()) continue;
    // A profile with a firmware range only matches when the device's version is
    // KNOWN and inside it — an unknown version must not claim a specific ranged
    // profile (it should fall through to a broader catch-all profile instead).
    if (p.minFirmware || p.maxFirmware) {
      if (!ctx.firmwareVersion) continue;
      if (!versionSatisfies(ctx.firmwareVersion, p.minFirmware, p.maxFirmware)) continue;
    }
    return p;
  }
  return null;
}

/** Human-readable label for a profile (used in the UI's "matched support entry" hint). */
export function describeProfile(p: DeviceSupportProfile): string {
  const parts: string[] = [];
  if (p.vendor) parts.push(p.vendor);
  if (p.model) parts.push(p.model);
  else if (!p.vendor) parts.push('any model');
  if (p.minFirmware || p.maxFirmware) {
    parts.push(`firmware ${p.minFirmware ?? '*'}–${p.maxFirmware ?? '*'}`);
  }
  return parts.join(' / ');
}

/** Evaluates a list of capability grants against the device context. */
function evalCapabilities(grants: SupportCapabilityGrant[], ctx: DeviceSupportContext): CapabilityEvaluation[] {
  return grants.map((g): CapabilityEvaluation => {
    const reasons = evaluateConditions(g.conditions, ctx);
    return { name: g.name, label: g.label, effective: reasons.length === 0, reasons };
  });
}

/** Evaluates a list of intent grants against the device context. */
function evalIntents(grants: SupportIntentGrant[], ctx: DeviceSupportContext): CapabilityEvaluation[] {
  return grants.map((g): CapabilityEvaluation => {
    const reasons = evaluateConditions(g.conditions, ctx);
    return { name: g.actionId, label: g.label ?? g.actionId, effective: reasons.length === 0, reasons };
  });
}

/** Merges two evaluation lists by grant id — the FIRST list wins on duplicates. */
function mergeEvaluations(primary: CapabilityEvaluation[], secondary: CapabilityEvaluation[]): CapabilityEvaluation[] {
  const seen = new Set(primary.map((e) => e.name));
  return [...primary, ...secondary.filter((e) => !seen.has(e.name))];
}

/**
 * Evaluates the plugin's device-support document against one device context.
 * Pure function — no I/O, safe to run per assignment in a list view.
 *
 * Semantics: `defaultCapabilities` apply on TOP of any matched profile (they
 * are effective for every device this plugin serves); the matched profile adds
 * its own grants. A capability granted by both is reported once (profile wins).
 */
export function evaluateDeviceSupport(support: DeviceSupport | null | undefined, ctx: DeviceSupportContext): DeviceSupportEvaluation {
  if (!support) return { profileMatched: false, capabilities: [], intents: [] };

  const profile = matchSupportProfile(support, ctx);
  const defaults = support.defaultCapabilities ?? [];

  // Nothing to evaluate at all — the plugin advertised no grants for this device.
  if (!profile && defaults.length === 0) {
    return { profileMatched: false, capabilities: [], intents: [] };
  }

  const capabilities = mergeEvaluations(
    profile ? evalCapabilities(profile.capabilities, ctx) : [],
    evalCapabilities(defaults, ctx),
  );
  const intents = mergeEvaluations(evalIntents(profile?.intents ?? [], ctx), []);

  return {
    profileMatched: profile !== null,
    ...(profile ? { matchedProfile: describeProfile(profile) } : {}),
    capabilities,
    intents,
  };
}
