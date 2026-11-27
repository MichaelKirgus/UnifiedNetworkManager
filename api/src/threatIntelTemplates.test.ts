import { THREAT_INTEL_SOURCE_TEMPLATES, ThreatIntelSourceTemplate } from './threatIntelTemplates';

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
