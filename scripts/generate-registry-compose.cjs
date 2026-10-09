#!/usr/bin/env node
// Generates docker-compose.registry.yml from docker-compose.yml for END USERS:
// every service that is built locally (build:) becomes a pull-from-GHCR image,
// so `docker compose -f docker-compose.registry.yml up` needs no build step.
//
//   UNM_REGISTRY    registry prefix  (default ghcr.io/michaelkirgus/unifiednetworkmanager)
//   UNM_IMAGE_TAG   image tag        (default dev — main maps to "dev" in CI;
//                                     use a release tag like v0.1.0 for releases)
//
// Regenerate after changing docker-compose.yml:  node scripts/generate-registry-compose.cjs
// The file is committed on purpose — users must not need Node to run UNM.

const fs = require('node:fs');
const path = require('node:path');
const YAML = require(path.join(__dirname, '..', 'api', 'node_modules', 'yaml'));

const root = path.join(__dirname, '..');
const srcPath = path.join(root, 'docker-compose.yml');
const outPath = path.join(root, 'docker-compose.registry.yml');

const doc = YAML.parse(fs.readFileSync(srcPath, 'utf8'));
const services = doc.services || {};

const kept = [];
const skipped = [];
for (const [name, svc] of Object.entries(services)) {
  if (!svc.build) {
    // External images (postgres, test-only fixtures) — keep verbatim.
    kept.push([name, svc]);
    continue;
  }
  const out = { ...svc };
  delete out.build;
  // Image reference with runtime-overridable registry + tag (see header).
  out.image = `\${UNM_REGISTRY:-ghcr.io/michaelkirgus/unifiednetworkmanager}/${name}:\${UNM_IMAGE_TAG:-dev}`;
  kept.push([name, out]);
  skipped.push(name);
}

const outDoc = { ...doc, services: Object.fromEntries(kept) };

const header = `# UNM — registry compose (END USERS: no local build required).
#
# Generated from docker-compose.yml by scripts/generate-registry-compose.cjs —
# do not edit by hand; change the dev compose and regenerate. Every service
# that is built locally in docker-compose.yml is pulled here as a GHCR image
# instead (same service names, ports, env vars and volumes).
#
#   docker compose -f docker-compose.registry.yml up -d
#
# Overrides (.env or environment):
#   UNM_REGISTRY    registry prefix  (default ghcr.io/michaelkirgus/unifiednetworkmanager)
#   UNM_IMAGE_TAG   image tag        (default dev; use a release tag like v0.1.0)
`;

const body = YAML.stringify(outDoc, { lineWidth: 0 });
fs.writeFileSync(outPath, header + '\n' + body);
console.log(`wrote ${path.relative(root, outPath)} — ${skipped.length} services switched to GHCR images`);
for (const n of skipped) console.log('  ' + n);
