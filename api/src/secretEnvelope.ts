import crypto from 'crypto';

/**
 * Passphrase-encrypted envelope for portable device credentials.
 *
 * Backups normally carry the `secrets` table as CIPHERTEXT encrypted under the
 * source instance's secrets-provider key (MASTER_KEY + CRYPTO_SALT) — on a
 * different instance those values are undecryptable, so restored devices have
 * credential references that never work. The optional `secrets` backup section
 * solves this: every secret is DECRYPTED via the provider broker and re-wrapped
 * in an envelope keyed by a user-chosen PASSPHRASE (scrypt → AES-256-GCM).
 *
 * Properties:
 *   - No plaintext ever lands in the archive; only passphrase-holders can read it.
 *   - The envelope is fully self-contained (own salt/params) — decryptable on ANY
 *     instance regardless of its provider keys, which is what makes cross-instance
 *     restore possible. On import the values are re-encrypted under the TARGET's
 *     own provider key and stored with their ORIGINAL ids so device/plan/session
 *     references keep working.
 *   - The passphrase itself is never stored anywhere.
 */

export const SECRET_ENVELOPE_FORMAT = 'unm-secret-envelope';
export const SECRET_ENVELOPE_VERSION = 1;

/** scrypt parameters — tuned for a user-typed passphrase (not high-throughput). */
const SCRYPT_PARAMS = { N: 65536, r: 8, p: 1 } as const;
// Working memory is N*r*p*128 bytes = 64 MiB here — above Node's 32 MiB scrypt
// default cap, so every call must raise maxmem explicitly or it throws.
const SCRYPT_MAXMEM = 128 * 1024 * 1024;
const SALT_BYTES = 32;
const KEY_BYTES = 32;

/** One decrypted secret as carried inside the envelope. */
export interface EnvelopeSecret {
  id: string;
  label: string | null;
  type: string;
  /** Source provider id — used to prefer a same-uuid provider on import, else default. */
  providerId: string | null;
  userId: string;
  expiresAt: string | null;
  interactiveLoginAllowed: boolean;
  fileAccessAllowed: boolean;
  createdAt: string;
  /** Decrypted field values (the actual credential material). */
  fields: Record<string, string>;
}

/** The serialized envelope as stored in the archive's `data.secrets.envelope[0]`. */
export interface SecretEnvelope {
  format: typeof SECRET_ENVELOPE_FORMAT;
  version: number;
  kdf: 'scrypt';
  salt: string; // hex
  params: { N: number; r: number; p: number };
  iv: string; // hex (12 bytes)
  tag: string; // hex (16 bytes, GCM auth tag)
  /** base64 ciphertext of the JSON-serialized EnvelopeSecret[] */
  ciphertext: string;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.scryptSync(Buffer.from(passphrase, 'utf8'), salt, KEY_BYTES, { ...SCRYPT_PARAMS, maxmem: SCRYPT_MAXMEM });
}

/** Decrypts every secret in the archive and wraps them under `passphrase`. */
export function wrapSecrets(secrets: EnvelopeSecret[], passphrase: string): SecretEnvelope {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('A non-empty passphrase is required to encrypt device credentials');
  }
  const salt = crypto.randomBytes(SALT_BYTES);
  const key = deriveKey(passphrase, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(secrets), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: SECRET_ENVELOPE_FORMAT,
    version: SECRET_ENVELOPE_VERSION,
    kdf: 'scrypt',
    salt: salt.toString('hex'),
    params: { ...SCRYPT_PARAMS },
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    ciphertext: ciphertext.toString('base64'),
  };
}

/** Unwraps an envelope. Throws a descriptive error on wrong passphrase / corrupt data. */
export function unwrapSecrets(envelope: SecretEnvelope, passphrase: string): EnvelopeSecret[] {
  if (!envelope || typeof envelope !== 'object') throw new Error('Missing secrets envelope');
  if (envelope.format !== SECRET_ENVELOPE_FORMAT) throw new Error(`Unknown secret envelope format "${String(envelope.format)}"`);
  if (Number(envelope.version ?? 0) > SECRET_ENVELOPE_VERSION) {
    throw new Error(`Secret envelope was created by a newer UNM version (v${envelope.version}) — upgrade before restoring`);
  }
  const salt = Buffer.from(String(envelope.salt ?? ''), 'hex');
  if (salt.length !== SALT_BYTES) throw new Error('Corrupt secret envelope (bad salt)');
  // Use the params recorded in the envelope so future parameter bumps stay readable.
  const key = crypto.scryptSync(
    Buffer.from(passphrase, 'utf8'),
    salt,
    KEY_BYTES,
    { N: Number(envelope.params?.N ?? SCRYPT_PARAMS.N), r: Number(envelope.params?.r ?? SCRYPT_PARAMS.r), p: Number(envelope.params?.p ?? SCRYPT_PARAMS.p), maxmem: SCRYPT_MAXMEM },
  );
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(String(envelope.iv ?? ''), 'hex'));
  decipher.setAuthTag(Buffer.from(String(envelope.tag ?? ''), 'hex'));
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(Buffer.from(String(envelope.ciphertext ?? ''), 'base64')), decipher.final()]);
  } catch {
    throw new Error('Wrong passphrase or corrupt secret envelope');
  }
  const parsed: unknown = JSON.parse(plaintext.toString('utf8'));
  if (!Array.isArray(parsed)) throw new Error('Corrupt secret envelope (payload is not a list)');
  return parsed as EnvelopeSecret[];
}
