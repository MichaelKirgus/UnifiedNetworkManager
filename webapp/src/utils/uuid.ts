/**
 * Client-side id generation that works in INSECURE contexts too.
 *
 * `crypto.randomUUID()` is only exposed by browsers on secure origins (HTTPS or
 * localhost). UNM is commonly served over plain HTTP on a LAN IP
 * (e.g. http://10.37.1.4:8080) — there the function is undefined and any
 * component calling it crashes on mount (blank form + console TypeError).
 * The ids produced here are React keys / row identifiers, not security tokens,
 * so a Math.random fallback is acceptable when randomUUID is unavailable.
 */
export function newId(prefix = ''): string {
  const base = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  return prefix ? `${prefix}-${base}` : base;
}
