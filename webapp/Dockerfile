# Build tag baked in at image build time (CI sets UNM_BUILD_TAG; empty = local).
# The static bundle has no runtime process to report it, so the final stage writes
# a tiny manifest.json into dist/ that the webapp fetches from its own origin.
ARG UNM_BUILD_TAG=

FROM node:20-alpine AS build

WORKDIR /app

# VITE_API_URL is baked into the static bundle at build time (Vite replaces
# import.meta.env.VITE_* references during `vite build`), so it must be
# supplied as a build arg rather than a runtime container environment
# variable, which would have no effect on the already-built assets.
ARG VITE_API_URL=http://localhost:3000/v1
ENV VITE_API_URL=${VITE_API_URL}

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

FROM node:20-alpine

WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist ./dist
# Bake the build tag into a manifest the UI can read (same origin, no API needed).
ARG UNM_BUILD_TAG=
RUN node -e "require('fs').writeFileSync('/app/dist/manifest.json', JSON.stringify({ buildTag: process.env.UNM_BUILD_TAG || '' }))"

EXPOSE 5173

# Unprivileged runtime user (uid/gid 1001) — the entrypoint wrapper drops to it.
RUN addgroup -g 1001 unm && adduser -u 1001 -G unm -D app \
    && chown -R 1001:1001 /app/dist

# UNM entrypoint wrapper — optional macvlan default gateway (UNM_DEFAULT_GATEWAY),
# runtime data-dir chown (UNM_CHOWN_PATHS, skippable via UNM_SKIP_CHOWN=1) and the
# privilege drop to `app` (opt out with UNM_RUN_AS_ROOT=1). Inlined here because
# this image's build context is ./webapp, not the repo root — KEEP IN SYNC with
# scripts/docker-entrypoint.sh (the other images COPY that file directly).
COPY <<'UNM_ENTRYPOINT' /usr/local/bin/unm-entrypoint.sh
#!/bin/sh
set -u

APP_UID=1001
APP_GID=1001

if [ -n "${UNM_DEFAULT_GATEWAY:-}" ]; then
  IFACE="${UNM_GW_IFACE:-}"
  if [ -z "$IFACE" ]; then
    for d in /sys/class/net/*; do
      n=${d##*/}
      [ "$n" = "lo" ] && continue
      ip4=$(ip -4 addr show dev "$n" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
      [ -z "$ip4" ] && continue
      case "$ip4" in
        172.1[6-9].*|172.[23][0-9].*) continue ;; # Docker bridge range — not the VLAN interface
      esac
      IFACE="$n"
      break
    done
  fi

  if [ -z "$IFACE" ]; then
    echo "[unm] UNM_DEFAULT_GATEWAY=${UNM_DEFAULT_GATEWAY} set but no suitable interface found (set UNM_GW_IFACE to force one) — skipping default route" >&2
  elif ip route replace default via "$UNM_DEFAULT_GATEWAY" dev "$IFACE" >/dev/null 2>&1; then
    echo "[unm] default route: via ${UNM_DEFAULT_GATEWAY} on ${IFACE}"
  else
    echo "[unm] WARN: could not set default gateway (needs CAP_NET_ADMIN) — continuing without it" >&2
  fi
fi

if [ "${UNM_SKIP_CHOWN:-0}" = "1" ]; then
  echo "[unm] UNM_SKIP_CHOWN=1 — skipping data-dir ownership fixup"
elif [ -n "${UNM_CHOWN_PATHS:-}" ]; then
  for p in $UNM_CHOWN_PATHS; do
    if [ -e "$p" ]; then
      if chown -R "$APP_UID:$APP_GID" "$p" >/dev/null 2>&1; then
        echo "[unm] chowned $p -> ${APP_UID}:${APP_GID}"
      else
        echo "[unm] WARN: could not chown $p (continuing)" >&2
      fi
    fi
  done
fi

if [ "${UNM_RUN_AS_ROOT:-0}" = "1" ]; then
  echo "[unm] UNM_RUN_AS_ROOT=1 — running as root (no privilege drop)"
  exec "$@"
else
  exec node /usr/local/lib/unm-privdrop.js "$@"
fi
UNM_ENTRYPOINT

# Privilege-drop helper — KEEP IN SYNC with scripts/unm-privdrop.js.
COPY <<'UNM_PRIVDROP' /usr/local/lib/unm-privdrop.js
#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');

const APP_USER = 'app';
const DEFAULT_UID = 1001;
const PRIMARY_GID = 1001; // group "unm"

function env(name) {
  return process.env[name] || '';
}

let targetUid = DEFAULT_UID;
if (/^\d+$/.test(env('UNM_DOCKER_UID'))) {
  const u = parseInt(env('UNM_DOCKER_UID'), 10);
  if (u > 0 && u < 65536) {
    targetUid = u;
    try {
      const pw = fs.readFileSync('/etc/passwd', 'utf8').split('\n');
      let changed = false;
      for (let i = 0; i < pw.length; ++i) {
        const p = pw[i].split(':');
        if (p[0] === APP_USER && parseInt(p[2], 10) !== targetUid) {
          p[2] = String(targetUid);
          pw[i] = p.join(':');
          changed = true;
        }
      }
      if (changed) fs.writeFileSync('/etc/passwd', pw.join('\n'));
    } catch (e) {
      process.stderr.write(`[unm] WARN: could not set app uid to ${targetUid}: ${e.message}\n`);
    }
  } else {
    process.stderr.write(`[unm] WARN: UNM_DOCKER_UID=${env('UNM_DOCKER_UID')} out of range — using ${DEFAULT_UID}\n`);
  }
}

const dockerGid = env('UNM_DOCKER_GID');
if (/^\d+$/.test(dockerGid)) {
  try {
    const lines = fs.readFileSync('/etc/group', 'utf8').split('\n');
    let idx = -1;
    for (let i = 0; i < lines.length; ++i) {
      const p = lines[i].split(':');
      if (p.length >= 4 && p[2] === dockerGid) {
        idx = i;
        break;
      }
    }
    if (idx < 0) {
      fs.appendFileSync('/etc/group', `unm-docker:x:${dockerGid}:${APP_USER}\n`);
    } else {
      const p = lines[idx].split(':');
      const members = (p[3] || '').split(',').filter(Boolean);
      if (!members.includes(APP_USER)) members.push(APP_USER);
      p[3] = members.join(',');
      lines[idx] = p.join(':');
      fs.writeFileSync('/etc/group', lines.join('\n') + '\n');
    }
  } catch (e) {
    process.stderr.write(`[unm] WARN: could not set up docker group ${dockerGid}: ${e.message}\n`);
  }
}

try {
  try {
    process.initgroups(APP_USER, 'unm'); // supplementary groups from /etc/group (incl. docker gid)
  } catch (_) {
    /* non-fatal — primary group still set below */
  }
  process.setgid(PRIMARY_GID);
  process.setuid(targetUid);
} catch (e) {
  process.stderr.write(`[unm] WARN: privilege drop failed (${e.message}) — continuing as root\n`);
}

const args = process.argv.slice(2);
if (args.length === 0) {
  process.stderr.write('[unm] ERROR: no command to run after privilege drop\n');
  process.exit(1);
}

let exited = false;
const child = spawn(args[0], args.slice(1), { stdio: 'inherit', env: process.env });

child.on('error', (e) => {
  if (!exited) {
    process.stderr.write(`[unm] failed to start ${args[0]}: ${e.message}\n`);
    exited = true;
    process.exit(127);
  }
});

child.on('exit', (code, signal) => {
  if (exited) return;
  exited = true;
  if (signal) process.kill(process.pid, signal); // re-raise so our status reflects it
  else process.exit(code == null ? 0 : code);
});

for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  process.on(sig, () => {
    if (!exited && child.pid) {
      try {
        child.kill(sig);
      } catch (_) {
        /* already gone */
      }
    }
  });
}
UNM_PRIVDROP

RUN chmod +x /usr/local/bin/unm-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/unm-entrypoint.sh"]

CMD ["serve", "-s", "dist", "-l", "5173"]
