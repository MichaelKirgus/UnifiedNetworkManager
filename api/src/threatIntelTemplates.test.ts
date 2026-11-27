import { THREAT_INTEL_SOURCE_TEMPLATES, ThreatIntelSourceTemplate, validateThreatIntelSourceTemplates } from './threatIntelTemplates';

describe('THREAT_INTEL_SOURCE_TEMPLATES', () => {
  it('has at least one template with a stable unique id and name', () => {
    expect(THREAT_INTEL_SOURCE_TEMPLATES.length).toBeGreaterThan(0);
    const ids = THREAT_INTEL_SOURCE_TEMPLATES.map((t) => t.id);
    const names = THREAT_INTEL_SOURCE_TEMPLATES.map((t) => t.name);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(names).size).toBe(names.length);
  });

  it('only carries http(s) URLs and known formats', () => {
    for (const t of THREAT_INTEL_SOURCE_TEMPLATES) {
      const u = new URL(t.url);
      expect(['http:', 'https:']).toContain(u.protocol);
      expect(['ip-list', 'domain-list']).toContain(t.format);
      expect(t.name.length).toBeGreaterThan(0);
      expect(t.description.length).toBeGreaterThan(0);
    }
  });

  it('exposes plain data only (no secrets, no functions)', () => {
    for (const t of THREAT_INTEL_SOURCE_TEMPLATES) {
      const serialized = JSON.parse(JSON.stringify(t)) as ThreatIntelSourceTemplate;
      expect(serialized).toEqual(t);
    }
  });
});

describe('validateThreatIntelSourceTemplates (JSON catalog guard)', () => {
  const validEntry = {
    id: 'test-feed',
    name: 'Test Feed',
    description: 'A test feed.',
    url: 'https://example.com/feed.txt',
    format: 'ip-list',
  };

  it('accepts well-formed entries', () => {
    expect(validateThreatIntelSourceTemplates([validEntry])).toEqual([validEntry]);
  });

  it('rejects a non-array or empty catalog', () => {
    expect(() => validateThreatIntelSourceTemplates({})).toThrow(/must be an array/);
    expect(() => validateThreatIntelSourceTemplates([])).toThrow(/empty/);
  });

  it('rejects unknown keys (typo guard for data edits)', () => {
    const bad = { ...validEntry, formart: 'ip-list' };
    delete (bad as Record<string, unknown>).format;
    expect(() => validateThreatIntelSourceTemplates([bad])).toThrow(/unknown key "formart"/);
  });

  it('rejects missing or empty required fields', () => {
    for (const key of ['id', 'name', 'description', 'url'] as const) {
      const bad = { ...validEntry, [key]: '' };
      expect(() => validateThreatIntelSourceTemplates([bad])).toThrow(new RegExp(`"${key}" must be a non-empty string`));
    }
    expect(() => validateThreatIntelSourceTemplates([{}])).toThrow(/"id" must be a non-empty string/);
  });

  it('rejects unknown formats', () => {
    expect(() =>
      validateThreatIntelSourceTemplates([{ ...validEntry, format: 'stix' }]),
    ).toThrow(/"format" must be one of ip-list, domain-list/);
  });

  it('rejects duplicate ids and names', () => {
    expect(() => validateThreatIntelSourceTemplates([validEntry, validEntry])).toThrow(/duplicate template id "test-feed"/);
    expect(() =>
      validateThreatIntelSourceTemplates([validEntry, { ...validEntry, id: 'other' }]),
    ).toThrow(/duplicate template name "Test Feed"/);
  });

  it('rejects non-http(s) or unparseable URLs', () => {
    expect(() =>
      validateThreatIntelSourceTemplates([{ ...validEntry, url: 'ftp://example.com/feed.txt' }]),
    ).toThrow(/must be http\(s\)/);
    expect(() =>
      validateThreatIntelSourceTemplates([{ ...validEntry, url: 'not a url' }]),
    ).toThrow(/not a valid URL/);
  });
});
