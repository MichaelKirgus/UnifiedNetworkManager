#!/bin/sh
# UNM container entrypoint wrapper — baked into every image built from the repo
# root context (api, mcp, all plugins). Runs as PID 1 (root) before the app.
#
# It performs three OPTIONAL, root-only steps in order, then hands off to the app:
#
#   1. Default gateway (macvlan): when UNM_DEFAULT_GATEWAY is set, install
#      `default via <gw>` on the container's non-Docker interface. Docker does not
#      add a default route to macvlan interfaces — without it a container only
#      reaches its own VLAN subnet. Unset/empty = no-op (bridge deployments).
#
#   2. Data-dir ownership: when UNM_CHOWN_PATHS is set, chown each listed path to
#      the unprivileged user so EXISTING persistent volumes (created while running
#      as root) are writable after the drop below. Skip with UNM_SKIP_CHOWN=1
#      (e.g. huge byte stores you pre-chowned once). Fresh/ephemeral dirs are
#      already created owned by `app` at build time, so they need no runtime chown.
#
#   3. Privilege drop: unless UNM_RUN_AS_ROOT=1, exec the app through
#      /usr/local/lib/unm-privdrop.js (a dependency-free Node helper) which joins
#      any host docker group (UNM_DOCKER_GID), drops to `app` (uid/gid 1001), and
#      runs the real command with stdio inherited + signal forwarding. Set
#      UNM_RUN_AS_ROOT=1 to skip the drop entirely (the explicit "run as root"
#      opt-out, e.g. for rollback).
#
# Every step is best-effort: a failure logs to stderr and NEVER blocks startup.

set -u

APP_UID=1001
APP_GID=1001

# --- 1. Optional macvlan default gateway --------------------------------------
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

# --- 2. Optional runtime chown of persistent data dirs ------------------------
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

# --- 3. Privilege drop (or explicit root) -------------------------------------
if [ "${UNM_RUN_AS_ROOT:-0}" = "1" ]; then
  echo "[unm] UNM_RUN_AS_ROOT=1 — running as root (no privilege drop)"
  exec "$@"
else
  # The Node helper does the group join + setuid/setgid and re-execs the app with
  # stdio inherited and SIGTERM/SIGINT forwarded, exiting with the app's code.
  exec node /usr/local/lib/unm-privdrop.js "$@"
fi

