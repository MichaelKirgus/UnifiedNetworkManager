/**
 * CVE vulnerability tracking — ecosystem tag mapping (pure).
 *
 * Plugins emit a free-form `ecosystem` tag per installed package ("debian",
 * "alpine", "npm", …). Each provider maps those tags onto ITS source's
 * ecosystem names; this file holds the OSV.dev mapping. Future providers add
 * their own mapping function here (or in their module) — the worker only sees
 * the CveProvider interface, never these details.
 */

/**
 * Maps a plugin-emitted ecosystem tag onto an OSV.dev ecosystem name. Returns
 * null when the tag has no known OSV source — those packages are skipped (the
 * worker logs how many were skipped so a new ecosystem is easy to spot).
 *
 * Alpine is RELEASE-SPECIFIC: OSV.dev's Alpine source keys advisories per
 * release ("Alpine:v3.19"), and versioned queries against the bare "Alpine"
 * name match nothing (live-verified 2026-10 — the old "Alpine Linux" name is
 * rejected outright). Plugins therefore emit `alpine` or `alpine:vX.Y`; a tag
 * without a release falls back to plain "Alpine", which still resolves for
 * versionless lookups.
 */
export function mapToOsvEcosystem(tag: string | null | undefined): string | null {
  const t = (tag ?? '').trim().toLowerCase();
  if (!t || t === 'unknown') return null;
  if (t.includes('debian') || t.includes('ubuntu')) return 'Debian';
  if (t.includes('alpine')) {
    const m = t.match(/v?(\d+\.\d+)/); // "alpine:v3.19" / "alpine:3.19" → release line
    return m ? `Alpine:v${m[1]}` : 'Alpine';
  }
  if (t === 'npm' || t.includes('node')) return 'npm';
  if (t.includes('pypi') || t.includes('python')) return 'PyPI';
  return null; // no OSV source for this ecosystem yet — extend here as needed
}
