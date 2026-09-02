/**
 * WebAuthn option conversion helpers.
 *
 * The API returns SimpleWebAuthn JSON options where the binary members are
 * base64url strings (`challenge`, `user.id`). The browser's WebAuthn API
 * requires those as ArrayBufferView — passing the raw JSON throws a
 * TypeError ("'challenge' member … could not be converted to any of:
 * ArrayBufferView, ArrayBuffer") before any prompt appears.
 */

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
  } as unknown as PublicKeyCredentialCreationOptions;
}

/** Assertion options JSON → browser-ready PublicKeyCredentialRequestOptions. */
export function toRequestOptions(options: unknown): PublicKeyCredentialRequestOptions {
  const o = options as Record<string, any>;
  return {
    ...o,
    challenge: b64uToBytes(o.challenge)!,
    allowCredentials: Array.isArray(o.allowCredentials)
      ? o.allowCredentials.map((id: string) => ({ type: 'public-key' as const, id: b64uToBytes(id)! }))
      : [],
  } as unknown as PublicKeyCredentialRequestOptions;
}
