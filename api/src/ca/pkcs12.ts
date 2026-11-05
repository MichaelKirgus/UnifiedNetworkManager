/**
 * pkcs12 — build a PKCS#12 (.p12) install bundle for one EAP-TLS client cert.
 *
 * Windows, Android, iOS and macOS all import PKCS#12 (PEM is not accepted by
 * their standard import flows), so the download route offers `?format=p12` in
 * addition to the plain PEM bundle. The P12 contains the leaf + intermediate(s)
 * + private key, encrypted with a freshly generated random password that is
 * returned ONCE alongside the blob (the UI shows it for re-entry on import).
 *
 * Implementation: shell out to `openssl pkcs12 -export` (installed in the API
 * image — see api/Dockerfile). The PEMs are written to a temp dir, deleted
 * before return; the password is generated with crypto.randomBytes and never
 * logged. AES-256-CBC + SHA-256 MAC keeps the file compatible with every
 * current OS import dialog (the legacy 3DES default of older openssl builds
 * is rejected by modern Windows).
 */

import { execFile } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';

export interface Pkcs12Bundle {
  /** Base64-encoded .p12 bytes (the UI downloads it as a Blob). */
  p12Base64: string;
  /** Random import password — shown to the user for re-entry on import. */
  password: string;
}

/** Generate a random P12 import password (16 chars, unambiguous charset). */
export function generateP12Password(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

/**
 * Build a PKCS#12 bundle from the leaf+intermediate chain PEM and the PKCS#8
 * private key PEM. Throws with a readable message when openssl is missing or
 * fails (the route maps that to a 500).
 */
export async function buildPkcs12(chainPem: string, keyPem: string): Promise<Pkcs12Bundle> {
  const password = generateP12Password();

  // Temp dir with the two PEM inputs + the output file. Everything is deleted
  // in `finally` — the decrypted key must not linger on disk.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'unm-p12-'));
  try {
    // Split the bundle: first PEM block = leaf (paired with the key via -in),
    // remaining blocks = intermediates (added via -certfile, order preserved).
    const blocks = chainPem.split(/(?=-----BEGIN CERTIFICATE-----)/g).map((b) => b.trim()).filter(Boolean);
    if (blocks.length === 0) throw new Error('no certificates in the provided chain');
    const leafPath = path.join(tmpDir, 'leaf.pem');
    const keyPath = path.join(tmpDir, 'key.pem');
    const outPath = path.join(tmpDir, 'bundle.p12');
    fs.writeFileSync(leafPath, blocks[0] + '\n', { mode: 0o600 });
    fs.writeFileSync(keyPath, keyPem.replace(/\n+$/, '') + '\n', { mode: 0o600 });

    const args = [
      'pkcs12', '-export',
      '-in', leafPath,
      '-inkey', keyPath,
    ];
    if (blocks.length > 1) {
      const caPath = path.join(tmpDir, 'ca.pem');
      fs.writeFileSync(caPath, blocks.slice(1).join('\n') + '\n', { mode: 0o600 });
      args.push('-certfile', caPath);
    }

    await new Promise<void>((resolve, reject) => {
      execFile(
        'openssl',
        [
          ...args,
          '-name', 'unm-eaptls-client',
          '-caname', 'unm-ca-intermediate',
          '-password', `pass:${password}`,
          '-out', outPath,
          // Modern crypto — required for current Windows/macOS import dialogs.
          '-keypbe', 'AES-256-CBC',
          '-certpbe', 'AES-256-CBC',
          '-macalg', 'SHA256',
        ],
        { timeout: 30_000 },
        (err, _stdout, stderr) => {
          if (err) reject(new Error(stderr?.trim() || `openssl pkcs12 failed (${err.message})`));
          else resolve();
        }
      );
    });

    const p12Base64 = fs.readFileSync(outPath).toString('base64');
    return { p12Base64, password };
  } finally {
    // Best-effort cleanup of the whole temp dir (key material included).
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore — temp dir is OS-managed */
    }
  }
}
