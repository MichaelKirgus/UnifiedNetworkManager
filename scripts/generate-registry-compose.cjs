#!/usr/bin/env node
// Generates the STANDARD docker-compose.yml (end-user deployment) from
// docker-compose.dev.yml: every service that is built locally in the dev compose
// (build:) becomes a pull-from-GHCR image, so `docker compose up -d` needs no
// build step and no Node.js on the host.
//
//   UNM_REGISTRY    registry prefix  (default ghcr.io/michaelkirgus/unifiednetworkmanager)
//   UNM_IMAGE_TAG   image tag        (default dev — main maps to "dev" in CI;
//                                     use a release tag like v0.1.0 for releases)
//
// Port standardization applied on the way out:
//   - webapp is published on host port 8080 (${UNM_WEB_PORT:-8080}:5173) — same
//     as the dev compose and the vite dev server.
//   - mcp gets NO host port by default: it carries an API token with full agent
//     capabilities, so exposing it to all interfaces is opt-in (see header note).
//
// Regenerate after changing docker-compose.dev.yml:
//   node scripts/generate-registry-compose.cjs
// The file is committed on purpose — users must not need Node to run UNM.

const fs = require('node:fs');
const path = require('node:path');
const YAML = require(path.join(__dirname, '..', 'api', 'node_modules', 'yaml'));

const root = path.join(__dirname, '..');
const srcPath = path.join(root, 'docker-compose.dev.yml');
const outPath = path.join(root, 'docker-compose.yml');

const doc = YAML.parse(fs.readFileSync(srcPath, 'utf8'));
const services = doc.services || {};

const kept = [];
const skipped = [];
for (const [name, svc] of Object.entries(services)) {
  if (!svc.build) {
    // External images — keep verbatim, except Postgres: end users reach it only
    // from inside the compose network (api/mcp), so drop its host port mapping.
    // The dev file keeps a loopback-only bind for host-side tooling; re-add a
    // "5432:5432" entry here if you want psql-from-host in an end-user deploy.
    const out = name === 'postgres' ? { ...svc } : svc;
    if (name === 'postgres') delete out.ports;
    kept.push([name, out]);
    continue;
  }
  const out = { ...svc };
  delete out.build;
  // Port standardization for the end-user file (see header):
  if (name === 'webapp' && Array.isArray(out.ports)) {
    out.ports = out.ports.map((p) =>
      String(p).includes(':5173') ? '${UNM_WEB_PORT:-8080}:5173' : p
    );
  }
  if (name === 'mcp') delete out.ports; // not exposed by default — opt-in via UNM_MCP_PORT
  // Image reference with runtime-overridable registry + tag (see header).
  out.image = `\${UNM_REGISTRY:-ghcr.io/michaelkirgus/unifiednetworkmanager}/${name}:\${UNM_IMAGE_TAG:-dev}`;
  kept.push([name, out]);
  skipped.push(name);
}

const outDoc = { ...doc, services: Object.fromEntries(kept) };

const header = `# UNM — standard deployment compose (END USERS: no local build required).
#
# Generated from docker-compose.dev.yml by scripts/generate-registry-compose.cjs —
# do not edit by hand; change the dev compose and regenerate. Every service that
# is built locally in the dev compose is pulled here as a GHCR image instead
# (same service names, env vars and volumes).
#
#   docker compose up -d
#
# Overrides (.env or environment):
#   UNM_REGISTRY    registry prefix  (default ghcr.io/michaelkirgus/unifiednetworkmanager)
#   UNM_IMAGE_TAG   image tag        (default dev; use a release tag like v0.1.0)
#   UNM_WEB_PORT    webapp host port (default 8080)
#
# The MCP server is NOT published to the host by default — it carries an API
# token with full agent capabilities, so exposing it on all interfaces is a
# deliberate choice. If you need remote MCP access, add your own mapping in .env
# or a reverse proxy (with auth), e.g. UNM_MCP_PORT=8081.
#
# Postgres is likewise NOT published to the host — api/mcp reach it over the
# internal compose network only. Re-add a "5432:5432" ports entry if you need
# psql-from-host (bind 127.0.0.1, not 0.0.0.0).
`;

const body = YAML.stringify(outDoc, { lineWidth: 0 });
fs.writeFileSync(outPath, header + '\n' + body);
console.log(`wrote ${path.relative(root, outPath)} — ${skipped.length} services switched to GHCR images`);
for (const n of skipped) console.log('  ' + n);
