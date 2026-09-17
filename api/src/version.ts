/**
 * Stack self-versioning for the Updates page's "UNM itself" card.
 *
 * The API reports its own version from the UNM_VERSION env var (set in
 * docker-compose.yml) with a fallback to the baked-in package.json — so a
 * release can stamp the image without code changes. Plugin versions are NOT
 * read here; they live in the `plugins` table (upserted by discovery) and are
 * joined on by stackUpdates.ts.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

let cachedVersion: string | null = null;

/** The running API's version ("0.1.0" or the stamped UNM_VERSION). */
export function apiVersion(): string {
  if (cachedVersion) return cachedVersion;
  const env = process.env.UNM_VERSION?.trim();
  if (env) {
    cachedVersion = env;
    return env;
  }
  try {
    // Works from both layouts: dist/src/version.js → ../../package.json (Docker,
    // WORKDIR /app/api) and src/version.ts under ts-node-dev → ../package.json.
    for (const candidate of [join(__dirname, '..', 'package.json'), join(__dirname, '..', '..', 'package.json'), join(process.cwd(), 'package.json')]) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, 'utf8')) as { version?: string };
        if (typeof pkg.version === 'string' && pkg.version) {
          cachedVersion = pkg.version;
          return cachedVersion;
        }
      } catch {
        // try next candidate
      }
    }
  } catch {
    // fall through
  }
  cachedVersion = 'unknown';
  return cachedVersion;
}
