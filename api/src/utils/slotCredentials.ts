import { getSecret } from '../secretsProvider';
import type { ExtraCredentials } from '../types/credentialSlots';

/**
 * Decrypts every bound credential slot of an assignment, keyed by slot name.
 * Workers merge the result into the plugin request body as
 * `credentials.slots.<name>` — the PRIMARY credential stays at the top level
 * of `credentials`, unchanged (see workers/telemetry.ts, configJob.ts,
 * planExecutor.ts). A single failing slot never sinks the whole call: it is
 * logged and skipped so the plugin can still serve everything else.
 */
export async function decryptCredentialSlots(
  extraCredentials: ExtraCredentials
): Promise<Record<string, Record<string, string>>> {
  const slots: Record<string, Record<string, string>> = {};
  for (const [name, secretId] of Object.entries(extraCredentials)) {
    try {
      const material = await getSecret(secretId);
      slots[name] = material.fields;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(
        `[slots] failed to decrypt credential slot "${name}" (${secretId}):`,
        (err as Error).message
      );
    }
  }
  return slots;
}

/** Merges decrypted slots into a credentials object under the `slots` key. */
export function withSlots(
  credentials: Record<string, unknown>,
  slots: Record<string, Record<string, string>>
): Record<string, unknown> {
  if (Object.keys(slots).length === 0) return credentials;
  return { ...credentials, slots };
}
