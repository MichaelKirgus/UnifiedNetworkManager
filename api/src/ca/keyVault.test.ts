/**
 * Unit tests for at-rest private-key encryption (keyVault.ts).
 *
 * The master key is module-cached, so each scenario runs in an isolated module
 * registry with a controlled UNM_CA_KEY_VAULT_KEY env value. Covers the happy
 * path, tamper detection (GCM auth tag), wrong-key failure and blob-shape
 * validation — losing or corrupting these blobs must fail LOUD, never return
 * garbage that looks like a PEM.
 */

import * as crypto from 'crypto';

const SAMPLE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHoUQBME0CQQChZQ==
-----END PRIVATE KEY-----
`;

interface KeyVaultModule {
  encryptKeyPem: (p: string) => string;
  decryptKeyPem: (b: string) => string;
}

/**
 * Loads keyVault in a fresh module registry with the given master key (hex).
 * The env var must stay set for the WHOLE lifetime of the returned module —
 * loadMasterKey reads it at call time, not import time. Call `restore()` when
 * done (each test restores in a finally block so scenarios never leak keys).
 */
function loadKeyVault(masterHex: string): { kv: KeyVaultModule; restore: () => void } {
  const prev = process.env.UNM_CA_KEY_VAULT_KEY;
  process.env.UNM_CA_KEY_VAULT_KEY = masterHex;
  let mod!: KeyVaultModule;
  jest.isolateModules(() => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    mod = require('./keyVault');
  });
  return {
    kv: mod,
    restore: () => {
      if (prev === undefined) delete process.env.UNM_CA_KEY_VAULT_KEY;
      else process.env.UNM_CA_KEY_VAULT_KEY = prev;
    },
  };
}

const KEY_A = crypto.randomBytes(32).toString('hex');
const KEY_B = crypto.randomBytes(32).toString('hex');

describe('keyVault (AES-256-GCM)', () => {
  it('round-trips a PEM private key', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      expect(kv.decryptKeyPem(kv.encryptKeyPem(SAMPLE_KEY_PEM))).toBe(SAMPLE_KEY_PEM);
    } finally {
      restore();
    }
  });

  it('produces a different ciphertext for the same plaintext (random IV)', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      expect(kv.encryptKeyPem(SAMPLE_KEY_PEM)).not.toBe(kv.encryptKeyPem(SAMPLE_KEY_PEM));
    } finally {
      restore();
    }
  });

  it('never stores the plaintext inside the blob', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      expect(Buffer.from(kv.encryptKeyPem(SAMPLE_KEY_PEM), 'base64').toString('utf8')).not.toContain('PRIVATE KEY');
    } finally {
      restore();
    }
  });

  it('rejects a blob encrypted with a DIFFERENT master key (auth tag mismatch)', () => {
    // Encrypt FIRST while the env still carries KEY_A — loadMasterKey reads the
    // env lazily on first use and caches per module instance.
    const enc = loadKeyVault(KEY_A);
    try {
      const blob = enc.kv.encryptKeyPem(SAMPLE_KEY_PEM); // cached under KEY_A
      const dec = loadKeyVault(KEY_B);
      try {
        expect(() => dec.kv.decryptKeyPem(blob)).toThrow();
      } finally {
        dec.restore();
      }
    } finally {
      enc.restore();
    }
  });

  it('rejects a tampered ciphertext byte (GCM integrity)', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      const raw = Buffer.from(kv.encryptKeyPem(SAMPLE_KEY_PEM), 'base64');
      raw[raw.length - 1] ^= 0xff; // flip the last ciphertext bit
      expect(() => kv.decryptKeyPem(raw.toString('base64'))).toThrow();
    } finally {
      restore();
    }
  });

  it('rejects a tampered auth tag', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      const raw = Buffer.from(kv.encryptKeyPem(SAMPLE_KEY_PEM), 'base64');
      raw[12] ^= 0x01; // first tag byte (tag occupies bytes 12..27)
      expect(() => kv.decryptKeyPem(raw.toString('base64'))).toThrow();
    } finally {
      restore();
    }
  });

  it('rejects blobs that are too short to be a valid envelope', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      expect(() => kv.decryptKeyPem(Buffer.alloc(10).toString('base64'))).toThrow(/too short/i);
    } finally {
      restore();
    }
  });

  it('rejects non-base64 input with a clear error', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      expect(() => kv.decryptKeyPem('!!!not-base64!!!')).toThrow();
    } finally {
      restore();
    }
  });

  it('handles empty and multi-line PEM payloads', () => {
    const { kv, restore } = loadKeyVault(KEY_A);
    try {
      for (const payload of ['', 'x\ny\nz\n']) {
        expect(kv.decryptKeyPem(kv.encryptKeyPem(payload))).toBe(payload);
      }
    } finally {
      restore();
    }
  });

  it('rejects a malformed UNM_CA_KEY_VAULT_KEY length at first use', () => {
    const { kv, restore } = loadKeyVault('deadbeef'); // too short (8 bytes)
    try {
      expect(() => kv.encryptKeyPem(SAMPLE_KEY_PEM)).toThrow(/64 hex chars/i);
    } finally {
      restore();
    }
  });
});
