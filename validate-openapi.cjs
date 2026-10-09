/* Temp validator: parse + basic structural checks on the OpenAPI spec. */
const fs = require('fs');
const path = require('path');

let yaml;
try {
  yaml = require(path.join(__dirname, 'node_modules', 'js-yaml'));
} catch {
  try {
    yaml = require('/home/michael/Git/MichaelKirgus/UnifiedNetworkManager/api/node_modules/js-yaml');
  } catch (e) {
    console.error('js-yaml not found:', e.message);
    process.exit(2);
  }
}

const specPath = path.join(__dirname, 'openapi', 'unified-network-manager.openapi.yaml');
const doc = yaml.load(fs.readFileSync(specPath, 'utf8'));

let errors = [];

// 1. All $refs resolve.
function collectRefs(node, acc) {
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (typeof v === 'string' && v.startsWith('#/')) acc.push(v);
      else collectRefs(v, acc);
    }
  } else if (Array.isArray(node)) {
    node.forEach((x) => collectRefs(x, acc));
  }
}
const refs = [];
collectRefs(doc, refs);
for (const ref of new Set(refs)) {
  const parts = ref.replace(/^#\//, '').split('/');
  let cur = doc;
  for (const p of parts) {
    if (!cur || typeof cur !== 'object' || !(p in cur)) {
      errors.push(`Unresolved $ref: ${ref}`);
      break;
    }
    cur = cur[p];
  }
}

// 2. Every path has at least one operation with responses.
for (const [p, ops] of Object.entries(doc.paths ?? {})) {
  for (const method of ['get', 'post', 'put', 'delete']) {
    if (ops[method]) {
      if (!ops[method].responses) errors.push(`${method.toUpperCase()} ${p}: missing responses`);
    }
  }
}

// 3. No `nullable: true` without a sibling `type` (validator startup crash).
function checkNullable(node, where) {
  if (node && typeof node === 'object' && !Array.isArray(node)) {
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === 'object') {
        if (v.nullable === true && !('type' in v) && !(v.oneOf || v.anyOf)) {
          errors.push(`nullable without type at ${where}.${k}`);
        }
        checkNullable(v, `${where}.${k}`);
      }
    }
  } else if (Array.isArray(node)) {
    node.forEach((x, i) => checkNullable(x, `${where}[${i}]`));
  }
}
checkNullable(doc, 'doc');

// 4. New multi-plugin surface exists.
const requiredPaths = [
  '/devices/{id}/plugins',
  '/devices/{id}/plugins/{pluginId}',
  '/devices/{id}/plugins/{pluginId}/options',
  '/devices/{id}/plugins/{pluginId}/settings',
];
for (const p of requiredPaths) {
  if (!doc.paths[p]) errors.push(`Missing path: ${p}`);
}
const schemas = doc.components?.schemas ?? {};
for (const s of ['DevicePluginAssignment', 'DevicePluginAssignmentInput', 'PluginTelemetrySnapshot']) {
  if (!schemas[s]) errors.push(`Missing schema: ${s}`);
}

if (errors.length) {
  console.error('SPEC ERRORS:');
  for (const e of errors) console.error(' -', e);
  process.exit(1);
}
console.log(`OK — spec valid. paths=${Object.keys(doc.paths).length}, schemas=${Object.keys(schemas).length}`);
