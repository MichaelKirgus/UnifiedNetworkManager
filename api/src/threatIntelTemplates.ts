/**
 * Built-in threat-intel source templates — pre-verified public IOC feeds the
 * Security page can import with one click (mirrors the automation-template
 * pattern in automations/templates.ts). The webapp renders these as a catalog;
 * picking one only PRE-FILLS the create dialog, nothing is created until the
 * user saves.
 *
 * THE FEED DEFINITIONS LIVE IN data/threat-intel-templates.json — adding a
 * template is a pure data edit (no code change): append an object to the
 * "templates" array with exactly these keys:
 *   - id:          stable kebab-case key, unique; never reuse or rename one
 *                  that already exists (it is the dialog-preset key)
 *   - name:        source name pre-filled into the create dialog (unique)
 *   - description: one-line human description shown on the catalog card
 *   - url:         http(s) feed URL — re-verify it live before adding
 *   - format:      'ip-list' | 'domain-list' (what the worker already parses)
 *
 * Every entry is validated at import time by validateThreatIntelSourceTemplates
 * and a malformed file fails startup with a precise error — a broken template
 * must never reach the catalog. Keep the list small and boring: stable, free,
 * no-key feeds. (All current URLs were verified live on 2026-11-27.)
 */

import rawTemplates from './data/threat-intel-templates.json';

export interface ThreatIntelSourceTemplate {
  /** Stable id used as the dialog-preset key — never reuse or rename. */
  id: string;
  /** Source name pre-filled into the create dialog (unique per install). */
  name: string;
  /** One-line human description shown in the catalog card. */
  description: string;
  url: string;
  format: 'ip-list' | 'domain-list';
}

const FORMATS: readonly ThreatIntelSourceTemplate['format'][] = ['ip-list', 'domain-list'];
const REQUIRED_KEYS: readonly (keyof ThreatIntelSourceTemplate)[] = [
  'id',
  'name',
  'description',
  'url',
  'format',
];

/** Strict per-entry check; throws with a message that names the bad entry. */
function validateEntry(raw: unknown, index: number): ThreatIntelSourceTemplate {
  const where = `threat-intel-templates.json: templates[${index}]`;
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${where}: expected an object`);
  }
  const entry = raw as Record<string, unknown>;
  for (const key of Object.keys(entry)) {
    if (!(REQUIRED_KEYS as readonly string[]).includes(key)) {
      throw new Error(`${where}: unknown key "${key}" (allowed: ${REQUIRED_KEYS.join(', ')})`);
    }
  }
  const id = entry.id;
  const name = entry.name;
  const description = entry.description;
  const url = entry.url;
  if (typeof id !== 'string' || !id.trim()) throw new Error(`${where}: "id" must be a non-empty string`);
  if (typeof name !== 'string' || !name.trim()) {
    throw new Error(`${where} (${id}): "name" must be a non-empty string`);
  }
  if (typeof description !== 'string' || !description.trim()) {
    throw new Error(`${where} (${id}): "description" must be a non-empty string`);
  }
  if (typeof url !== 'string' || !url.trim()) throw new Error(`${where} (${id}): "url" must be a non-empty string`);
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error(`${where} (${id}): "url" is not a valid URL: ${url}`);
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error(`${where} (${id}): "url" must be http(s): ${url}`);
  }
  const format = entry.format;
  if (!FORMATS.includes(format as ThreatIntelSourceTemplate['format'])) {
    throw new Error(
      `${where} (${id}): "format" must be one of ${FORMATS.join(', ')} (got ${JSON.stringify(format)})`,
    );
  }
  return { id, name, description, url, format: format as ThreatIntelSourceTemplate['format'] };
}

/**
 * Validate the whole catalog (array shape, non-empty, unique ids/names) and
 * return typed templates. Exported so tests can feed it malformed data; the
 * module-level call below runs it on import — a bad file fails startup fast.
 */
export function validateThreatIntelSourceTemplates(raw: unknown): ThreatIntelSourceTemplate[] {
  if (!Array.isArray(raw)) {
    throw new Error('threat-intel-templates.json: "templates" must be an array');
  }
  if (raw.length === 0) {
    throw new Error('threat-intel-templates.json: catalog is empty — add at least one template');
  }
  const ids = new Set<string>();
  const names = new Set<string>();
  return raw.map((entry, index) => {
    const t = validateEntry(entry, index);
    if (ids.has(t.id)) throw new Error(`threat-intel-templates.json: duplicate template id "${t.id}"`);
    if (names.has(t.name)) throw new Error(`threat-intel-templates.json: duplicate template name "${t.name}"`);
    ids.add(t.id);
    names.add(t.name);
    return t;
  });
}

export const THREAT_INTEL_SOURCE_TEMPLATES: ThreatIntelSourceTemplate[] =
  validateThreatIntelSourceTemplates(rawTemplates.templates);
