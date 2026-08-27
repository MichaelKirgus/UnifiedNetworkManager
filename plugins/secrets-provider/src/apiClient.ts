import { createApiClient, isNotFound } from '@unm/plugin-sdk';

/**
 * Client for the UnifiedNetworkManager API's internal secrets-data endpoints.
 *
 * The API owns the `secrets` table (the single source of truth). This plugin
 * does NOT connect to Postgres directly; it stores ciphertext and reads it
 * back through the API's internal routes (gated by the shared
 * `x-plugin-api-key`). The plugin is the crypto holder: it encrypts before
 * storing and decrypts after reading.
 *
 * The axios bootstrap + 404 helper come from @unm/plugin-sdk; base URL is
 * `UNM_API_URL` (defaults to `http://localhost:3000/v1`; set to
 * `http://api:3000/v1` inside Docker).
 */

const http = createApiClient();

/** A secret row as stored by the API (ciphertext). */
export interface SecretRecord {
  id: string;
  label: string | null;
  type: string;
  providerId: string | null;
  encryptedValue: string;
  userId: string;
  expiresAt: string | null;
  createdAt: string;
}

/** Secret metadata (no ciphertext) as returned by the list endpoint. */
export interface SecretMeta {
  id: string;
  label: string | null;
  type: string;
  providerId: string | null;
  userId: string;
  expiresAt: string | null;
  createdAt: string;
}

/**
 * Stores a new secret (ciphertext) via the API. Returns the created record.
 */
export async function storeSecret(input: {
  type: string;
  providerId: string;
  label: string | null;
  encryptedValue: string;
  userId: string;
  expiresAt: string | null;
}): Promise<SecretRecord> {
  const res = await http.post<SecretRecord>('/plugin/secrets', input);
  return res.data;
}

/**
 * Lists secret metadata (no ciphertext).
 */
export async function listSecrets(): Promise<SecretMeta[]> {
  const res = await http.get<SecretMeta[]>('/plugin/secrets');
  return res.data;
}

/**
 * Fetches a single secret (ciphertext) by id. Returns `null` on 404.
 */
export async function getSecret(id: string): Promise<SecretRecord | null> {
  try {
    const res = await http.get<SecretRecord>(`/plugin/secrets/${encodeURIComponent(id)}`);
    return res.data;
  } catch (err) {
    if (isNotFound(err)) {
      return null;
    }
    throw err;
  }
}

/**
 * Updates an existing secret's ciphertext IN PLACE (same id). Used for key
 * rotation / regeneration so references to the id keep working.
 */
export async function updateSecret(id: string, encryptedValue: string): Promise<void> {
  await http.patch(`/plugin/secrets/${encodeURIComponent(id)}`, { encryptedValue });
}

/**
 * Deletes a secret by id.
 */
export async function deleteSecret(id: string): Promise<void> {
  await http.delete(`/plugin/secrets/${encodeURIComponent(id)}`);
}
