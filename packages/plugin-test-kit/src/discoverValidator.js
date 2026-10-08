/**
 * @unm/plugin-test-kit — /discover contract validation (test T2).
 *
 * A broken descriptor is the #1 fatal-flaw class: it registers fine, then
 * silently breaks webapp rendering or API-side validation later. This module
 * validates the payload against the shapes declared in @unm/plugin-sdk types
 * (MetricDescriptor, PluginOptionDescriptor, CatalogEntry, DeviceModelEntry,
 * CredentialSlotDescriptor) without importing the SDK — the kit stays
 * dependency-free so it runs anywhere Node does.
 */

const CAPABILITIES = new Set([
  'monitoring', 'inventory', 'configuration', 'planning', 'deviceState',
  'ssh', 'filesystem', 'probe', 'sshConsole', 'updates', 'securityChecks',
  'quickActions', 'identityProvider', 'secretsProvider', 'fileRepo',
  'webFetch', 'inventorySync', 'logIngestion',
]);

const METRIC_TYPES = new Set(['number', 'string', 'boolean', 'enum']);
const METRIC_VIZ = new Set(['gauge', 'plot', 'text', 'table']);
const RISK_LEVELS = new Set(['read', 'write', 'dangerous']);
const OPTION_TYPES = new Set(['string', 'integer', 'boolean']);

/**
 * Validates a /discover payload.
 * @param {Record<string, unknown>} d  The parsed GET /discover body.
 * @returns {{errors: string[], warnings: string[]}}
 */
export function validateDiscover(d) {
  const errors = [];
  const warnings = [];
  if (!d || typeof d !== 'object') return { errors: ['/discover returned no JSON object'], warnings };

  // --- Identity core ---------------------------------------------------------
  // Repo convention: stable hand-assigned ids `00000000-…-NNNN` whose FINAL
  // GROUP is 10 hex digits (legacy: flow-collector, web-fetch) or 12; a few
  // plugins use random v4s. The API stores the id as text and keys everything
  // on it, so any well-formed 8-4-4-4-(10|12) hex string passes — only a
  // malformed shape is fatal.
  if (typeof d.uuid !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{10,12}$/i.test(d.uuid)) {
    errors.push(`uuid is not a well-formed UUID (expected 8-4-4-4-(10|12) hex): ${JSON.stringify(d.uuid)}`);
  }
  if (typeof d.name !== 'string' || !d.name.trim()) errors.push('name missing or empty');
  if (typeof d.version !== 'string' || !/^\d+\.\d+\.\d+/.test(d.version)) {
    errors.push(`version is not semver-like: ${JSON.stringify(d.version)}`);
  }
  if (!Array.isArray(d.vendors) || d.vendors.length === 0 || d.vendors.some((v) => typeof v !== 'string' || !v.trim())) {
    errors.push('vendors must be a non-empty array of strings');
  }
  if (typeof d.endpoint !== 'string' || !/^https?:\/\//.test(d.endpoint)) {
    errors.push(`endpoint is not an http(s) URL: ${JSON.stringify(d.endpoint)}`);
  }

  // --- Capabilities ----------------------------------------------------------
  const caps = Array.isArray(d.capabilities) ? d.capabilities : [];
  if (caps.length === 0) warnings.push('no capabilities advertised');
  for (const c of caps) {
    if (!CAPABILITIES.has(c)) errors.push(`unknown capability: ${JSON.stringify(c)}`);
  }

  // --- Metrics ---------------------------------------------------------------
  const metrics = d.metrics ?? [];
  if (!Array.isArray(metrics)) {
    errors.push('metrics must be an array');
  } else {
    const seen = new Set();
    metrics.forEach((m, i) => {
      const where = `metrics[${i}]`;
      if (typeof m?.key !== 'string' || !m.key.trim()) return void errors.push(`${where}: missing key`);
      if (seen.has(m.key)) errors.push(`${where}: duplicate metric key ${JSON.stringify(m.key)}`);
      seen.add(m.key);
      if (typeof m.label !== 'string' || !m.label.trim()) errors.push(`${where} (${m.key}): missing label`);
      if (!METRIC_TYPES.has(m.type)) errors.push(`${where} (${m.key}): bad type ${JSON.stringify(m.type)}`);
      if (!METRIC_VIZ.has(m.visualization)) errors.push(`${where} (${m.key}): bad visualization ${JSON.stringify(m.visualization)}`);
      if (typeof m.min === 'number' && typeof m.max === 'number' && m.min > m.max) {
        errors.push(`${where} (${m.key}): min ${m.min} > max ${m.max}`);
      }
      if (m.visualization === 'table' && (!Array.isArray(m.columns) || m.columns.length === 0)) {
        warnings.push(`${where} (${m.key}): table visualization without columns`);
      }
    });
  }

  // --- Options ---------------------------------------------------------------
  const options = d.options ?? [];
  if (!Array.isArray(options)) {
    errors.push('options must be an array');
  } else {
    const seen = new Set();
    options.forEach((o, i) => {
      const where = `options[${i}]`;
      if (typeof o?.key !== 'string' || !o.key.trim()) return void errors.push(`${where}: missing key`);
      if (seen.has(o.key)) errors.push(`${where}: duplicate option key ${JSON.stringify(o.key)}`);
      seen.add(o.key);
      if (!OPTION_TYPES.has(o.type)) {
        errors.push(`${where} (${o.key}): bad type ${JSON.stringify(o.type)}`);
        return;
      }
      // Missing default is a CONVENTION issue, not fatal: readSettings() yields
      // undefined and well-written plugins guard it (e.g. icmp's optional pingHost).
      if (o.default === undefined) warnings.push(`${where} (${o.key}): no default declared — plugin must tolerate an absent value`);
      else if (o.type === 'integer' && !Number.isInteger(o.default)) errors.push(`${where} (${o.key}): default is not an integer`);
      else if (o.type === 'string' && typeof o.default !== 'string') errors.push(`${where} (${o.key}): default is not a string`);
      else if (o.type === 'boolean' && typeof o.default !== 'boolean') errors.push(`${where} (${o.key}): default is not a boolean`);
      if (o.type === 'integer') {
        if (typeof o.min === 'number' && typeof o.max === 'number' && o.min > o.max) {
          errors.push(`${where} (${o.key}): min ${o.min} > max ${o.max}`);
        }
        if ((o.min !== undefined && !Number.isInteger(o.min)) || (o.max !== undefined && !Number.isInteger(o.max))) {
          errors.push(`${where} (${o.key}): integer bounds must be integers`);
        }
      }
      if (Array.isArray(o.enumOptions)) {
        if (o.enumOptions.length === 0) errors.push(`${where} (${o.key}): enumOptions is empty`);
        else if (o.default !== undefined && !o.enumOptions.includes(o.default)) {
          errors.push(`${where} (${o.key}): default ${JSON.stringify(o.default)} not in enumOptions`);
        }
      }
    });
  }

  // --- Actions ---------------------------------------------------------------
  const actions = d.actions ?? [];
  if (!Array.isArray(actions)) {
    errors.push('actions must be an array');
  } else {
    const seen = new Set();
    actions.forEach((a, i) => {
      const where = `actions[${i}]`;
      if (typeof a?.id !== 'string' || !a.id.trim()) return void errors.push(`${where}: missing id`);
      if (seen.has(a.id)) errors.push(`${where}: duplicate action id ${JSON.stringify(a.id)}`);
      seen.add(a.id);
      if (!RISK_LEVELS.has(a.riskLevel)) errors.push(`${where} (${a.id}): bad riskLevel ${JSON.stringify(a.riskLevel)}`);
      // SDK type is `number | 'N'` — exact device counts (e.g. 2 for a
      // two-endpoint tunnel intent) are legal, not just 1.
      if (!(Number.isInteger(a.deviceCount) && a.deviceCount >= 1) && a.deviceCount !== 'N') {
        errors.push(`${where} (${a.id}): deviceCount must be a positive integer or 'N'`);
      }
      if (!a.inputSchema || typeof a.inputSchema !== 'object') {
        warnings.push(`${where} (${a.id}): missing inputSchema`);
      }
    });
  }

  // --- Device models -----------------------------------------------------------
  const models = d.deviceModels ?? [];
  if (Array.isArray(models)) {
    const vendors = new Set(Array.isArray(d.vendors) ? d.vendors : []);
    models.forEach((m, i) => {
      if (typeof m?.vendor !== 'string' || !m.vendor.trim()) errors.push(`deviceModels[${i}]: missing vendor`);
      else if (vendors.size > 0 && !vendors.has(m.vendor)) {
        warnings.push(`deviceModels[${i}] (${m.vendor}): vendor not in identity vendors [${[...vendors].join(', ')}]`);
      }
      if (typeof m?.model !== 'string' || !m.model.trim()) errors.push(`deviceModels[${i}]: missing model`);
    });
  } else {
    errors.push('deviceModels must be an array when present');
  }

  // --- Credential slots ----------------------------------------------------------
  const slots = d.credentialSlots ?? [];
  if (Array.isArray(slots)) {
    const seen = new Set();
    slots.forEach((s, i) => {
      if (typeof s?.name !== 'string' || !s.name.trim()) return void errors.push(`credentialSlots[${i}]: missing name`);
      if (seen.has(s.name)) errors.push(`credentialSlots[${i}]: duplicate slot ${JSON.stringify(s.name)}`);
      seen.add(s.name);
      const types = s.secretTypes ?? (s.secretType ? [s.secretType] : []);
      if (!Array.isArray(types) || types.length === 0) {
        errors.push(`credentialSlots[${i}] (${s.name}): no secretType/secretTypes`);
      }
    });
  }

  return { errors, warnings };
}
