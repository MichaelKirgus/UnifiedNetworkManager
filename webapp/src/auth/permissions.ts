/**
 * Client-side permission awareness.
 *
 * The API returns `permissions` (flat string array) with every successful
 * login; we persist it next to the access token and expose a tiny `can(perm)`
 * helper so the UI can hide/gate actions the server would reject anyway. This
 * is UX polish, NOT security — enforcement always happens server-side via
 * `requirePermission` (403).
 */

const PERMISSIONS_KEY = 'unm:permissions';

/** Reads the persisted permission list for the current session. */
export function getPermissions(): string[] {
  try {
    const raw = localStorage.getItem(PERMISSIONS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as unknown[]).filter((p): p is string => typeof p === 'string') : [];
  } catch {
    return [];
  }
}

/** Persists the permission list returned by a successful login. */
export function setPermissions(permissions: string[]): void {
  try {
    localStorage.setItem(PERMISSIONS_KEY, JSON.stringify(permissions));
  } catch {
    // Storage unavailable (private mode); gating degrades to "no permissions".
  }
}

/** Clears the persisted list on sign-out. */
export function clearPermissions(): void {
  try {
    localStorage.removeItem(PERMISSIONS_KEY);
  } catch {
    /* ignore */
  }
}

/** True when the current session carries the given permission. */
export function can(permission: string): boolean {
  return getPermissions().includes(permission);
}
