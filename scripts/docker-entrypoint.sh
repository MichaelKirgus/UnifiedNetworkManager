#!/bin/sh
# UNM container entrypoint wrapper — baked into every image built from the repo
# root context (api, mcp, all plugins). Runs as PID 1 before the app starts.
#
# Optional macvlan default-gateway setup: Docker does NOT install a default
# route into macvlan interfaces — without one, a container only reaches its own
# VLAN subnet (no internet, no other subnets). When UNM_DEFAULT_GATEWAY is set,
# this wrapper installs `default via <gw>` on the container's non-Docker
# interface before exec'ing the app. Unset/empty = pure passthrough, so normal
# bridge deployments are completely unaffected.
#
#   UNM_DEFAULT_GATEWAY  IPv4 to use as default gateway (e.g. 192.168.50.1).
#                        Empty/unset → the wrapper does nothing but exec "$@".
#   UNM_GW_IFACE         Optional: force the interface name instead of auto-detect.
#
# Auto-detect picks the first non-lo interface with a global IPv4 OUTSIDE
# Docker's bridge range (172.16/12) — i.e. the macvlan interface in both hybrid
# (bridge + macvlan) and macvlan-only setups. `ip route replace` is idempotent;
# in a hybrid setup it deliberately STEALS the bridge default route, so all
# outbound traffic then flows through your VLAN gateway.
#
# The wrapper NEVER blocks startup: if no suitable interface is found or the
# route cannot be written (missing CAP_NET_ADMIN), it logs to stderr and
# continues with the app anyway.

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
