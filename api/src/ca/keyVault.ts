/**
 * keyVault — at-rest encryption for EAP-TLS client private keys.
 *
 * Enrolled WiFi client certs store their PRIVATE KEY in Postgres (so the
 * download endpoint can hand out a ready-to-install bundle). The key is never
 * stored in plaintext: AES-256-GCM with a master key that follows the same
 * persistence pattern as adminKey.ts — env override, else generated once and
 * persisted 0600 on the shared CA config volume. Losing the master key means
 * losing the private keys (the certs stay usable for auth; re-enrollment is
 * the recovery path).
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const DEFAULT_KEY_PATH = process.env.UNM_CA_KEY_VAULT_PATH ?? '/data/ca/key-vault.key';

let cachedMasterKey: Buffer | null = null;

/** Loads (or generates + persists) the 32-byte master key. */
function loadMasterKey(): Buffer {
  if (cachedMasterKey) return cachedMasterKey;

  const envHex = process.env.UNM_CA_KEY_VAULT_KEY ?? '';
  if (envHex) {
    const buf = Buffer.from(envHex, 'hex');
    if (buf.length !== 32) throw new Error('UNM_CA_KEY_VAULT_KEY must be 64 hex chars (32 bytes)');
    cachedMasterKey = buf;
    return buf;
  }

  if (fs.existsSync(DEFAULT_KEY_PATH)) {
    const raw = fs.readFileSync(DEFAULT_KEY_PATH, 'utf8').trim();
    const buf = Buffer.from(raw, 'hex');
    if (buf.length !== 32) throw new Error(`key vault master key at ${DEFAULT_KEY_PATH} is corrupt (expected 64 hex chars)`);
    cachedMasterKey = buf;
    return buf;
  }

  // First use: generate + persist (0600, same pattern as admin-jwk.pem).
  const fresh = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(DEFAULT_KEY_PATH), { recursive: true });
  fs.writeFileSync(DEFAULT_KEY_PATH, fresh.toString('hex'), { mode: 0o600 });
  cachedMasterKey = fresh;
  return fresh;
}

/**
 * Encrypts a PEM private key → base64(iv(12) ‖ tag(16) ‖ ciphertext).
 * The layout keeps the auth tag up front so a corrupted/wrong-key blob fails
 * fast with a clear error instead of garbage.
 */
export function encryptKeyPem(pem: string): string {
  const key = loadMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

/** Decrypts a blob produced by encryptKeyPem. Throws with descriptive errors. */
export function decryptKeyPem(blob: string): string {
  let raw: Buffer;
  try {
    raw = Buffer.from(blob, 'base64');
  } catch {
    throw new Error('key vault blob is not valid base64');
  }
  if (raw.length < 12 + 16) throw new Error('key vault blob too short to be a valid AES-256-GCM envelope');

  const key = loadMasterKey();
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch (err) {
    throw new Error(
      `key vault decryption failed (${(err as Error).message}) — the master key does not match this blob or it is corrupted`
    );
  }
}
