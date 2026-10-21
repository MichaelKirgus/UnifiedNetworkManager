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

# UNM entrypoint wrapper — optional macvlan default gateway (UNM_DEFAULT_GATEWAY);
# pure passthrough when the variable is unset. Inlined here because this image's
# build context is ./webapp, not the repo root — KEEP IN SYNC with
# scripts/docker-entrypoint.sh (the other images COPY that file directly).
COPY <<'UNM_ENTRYPOINT' /usr/local/bin/unm-entrypoint.sh
#!/bin/sh
set -u

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

exec "$@"
UNM_ENTRYPOINT
RUN chmod +x /usr/local/bin/unm-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/unm-entrypoint.sh"]

CMD ["serve", "-s", "dist", "-l", "5173"]
