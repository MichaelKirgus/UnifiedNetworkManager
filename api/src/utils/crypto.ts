import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const MASTER_KEY = process.env.MASTER_KEY ?? 'default-master-key-must-be-changed-in-production';
if (process.env.NODE_ENV === 'production' && MASTER_KEY === 'default-master-key-must-be-changed-in-production') {
  throw new Error('MASTER_KEY must be provided in production environment');
}

const CRYPTO_SALT = process.env.CRYPTO_SALT ?? 'salt';

// Ensure the master key is 32 bytes for aes-256-gcm
const key = crypto.scryptSync(MASTER_KEY, CRYPTO_SALT, 32);

export function encrypt(text: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decrypt(encryptedData: string): string {
  const [ivHex, authTagHex, encryptedTextHex] = encryptedData.split(':');
  if (ivHex && authTagHex && encryptedTextHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const cipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    cipher.setAuthTag(authTag);
    let decrypted = cipher.update(encryptedTextHex, 'utf8', 'hex');
    decrypted += cipher.final('utf8');
    return decrypted;
  }
  throw new Error('Invalid encrypted data format');
}