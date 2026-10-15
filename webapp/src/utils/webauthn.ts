/**
 * WebAuthn option conversion helpers.
 *
 * The API returns SimpleWebAuthn JSON options where the binary members are
 * base64url strings (`challenge`, `user.id`) and the credential descriptors
 * (`allowCredentials[]` / `excludeCredentials[]`) are `{ id: string }` objects
 * (SimpleWebAuthn v10+ shape). The browser's WebAuthn API requires all of
 * those as ArrayBufferView — passing the raw JSON throws a TypeError before
 * any prompt appears.
 */

/** Extracts the base64url id from a descriptor that may be a plain string or an `{ id }` object. */
function descriptorId(c: unknown): string | undefined {
  if (typeof c === 'string') return c;
  const id = (c as { id?: unknown })?.id;
  return typeof id === 'string' ? id : undefined;
}

/** base64url (no padding) → Uint8Array. Returns undefined for empty input. */
export function b64uToBytes(b64u?: string): Uint8Array | undefined {
  if (!b64u) return undefined;
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Registration options JSON → browser-ready PublicKeyCredentialCreationOptions. */
export function toCreationOptions(options: unknown): PublicKeyCredentialCreationOptions {
  const o = options as Record<string, any>;
  return {
    ...o,
    challenge: b64uToBytes(o.challenge)!,
    user: {
      id: b64uToBytes(o.user?.id) ?? new Uint8Array(),
      name: o.user?.name ?? '',
      displayName: o.user?.displayName ?? o.user?.name ?? '',
    },
    excludeCredentials: Array.isArray(o.excludeCredentials)
      ? o.excludeCredentials.map((c: unknown) => ({ type: 'public-key' as const, id: b64uToBytes(descriptorId(c))! }))
      : [],
  } as unknown as PublicKeyCredentialCreationOptions;
}

/** Assertion options JSON → browser-ready PublicKeyCredentialRequestOptions. */
export function toRequestOptions(options: unknown): PublicKeyCredentialRequestOptions {
  const o = options as Record<string, any>;
  return {
    ...o,
    challenge: b64uToBytes(o.challenge)!,
    allowCredentials: Array.isArray(o.allowCredentials)
      ? o.allowCredentials.map((c: unknown) => ({ type: 'public-key' as const, id: b64uToBytes(descriptorId(c))! }))
      : [],
  } as unknown as PublicKeyCredentialRequestOptions;
}
