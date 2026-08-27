import { createApiClient, isNotFound } from '@unm/plugin-sdk';

/**
 * Client for the UnifiedNetworkManager API's internal user-data endpoints.
 *
 * The API owns the `users` table (the single source of truth for local
 * identities). This plugin does NOT connect to Postgres directly; instead it
 * reads and writes user records through the API's internal routes (gated by
 * the shared `x-plugin-api-key`). This keeps the plugin free of any database
 * dependency and lets the API stay the single owner of platform data.
 *
 * The axios bootstrap + 404 helper come from @unm/plugin-sdk; base URL is
 * `UNM_API_URL` (defaults to `http://localhost:3000/v1`; set to
 * `http://api:3000/v1` inside Docker).
 */

const http = createApiClient();

/** A user record as returned by the API's internal user endpoints. */
export interface UserRecord {
  id: string;
  username: string;
  passwordHash: string;
  totpSecret: string | null;
  roles: string;
  permissions: string;
  createdAt: string;
}

/**
 * Looks up a user by username. Returns `null` when the user does not exist
 * (404), so callers can treat "no such user" as a normal outcome.
 */
export async function getUserByUsername(username: string): Promise<UserRecord | null> {
  try {
    // Internal plugin routes are namespaced under /plugin/* (see api/src/routes/internal.ts).
    const res = await http.get<UserRecord>(`/plugin/users/username/${encodeURIComponent(username)}`);
    return res.data;
  } catch (err) {
    if (isNotFound(err)) {
      return null;
    }
    throw err;
  }
}

/**
 * Looks up a user by id. Returns `null` when the user does not exist (404).
 */
export async function getUserById(id: string): Promise<UserRecord | null> {
  try {
    const res = await http.get<UserRecord>(`/plugin/users/${encodeURIComponent(id)}`);
    return res.data;
  } catch (err) {
    if (isNotFound(err)) {
      return null;
    }
    throw err;
  }
}

/**
 * Creates a user. The API hashes the supplied `password` server-side, so the
 * plugin never handles password hashing itself.
 */
export async function createUser(input: {
  username: string;
  password: string;
  totpSecret?: string | null;
  roles?: string[];
  permissions?: string[];
}): Promise<UserRecord> {
  const res = await http.post<UserRecord>('/plugin/users', input);
  return res.data;
}

/**
 * Updates a user. Only the provided fields are changed.
 */
export async function updateUser(
  id: string,
  patch: {
    password?: string;
    totpSecret?: string | null;
    roles?: string[];
    permissions?: string[];
  }
): Promise<UserRecord> {
  const res = await http.patch<UserRecord>(`/plugin/users/${encodeURIComponent(id)}`, patch);
  return res.data;
}

/**
 * Deletes a user.
 */
export async function deleteUser(id: string): Promise<void> {
  await http.delete(`/plugin/users/${encodeURIComponent(id)}`);
}
