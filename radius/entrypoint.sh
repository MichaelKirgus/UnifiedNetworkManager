#!/bin/sh
# UNM RADIUS service supervisor (FreeRADIUS 3.x, runs as root inside the image).
#
# Responsibilities:
#   1. Keep the local raddb (/etc/freeradius/3.0) in sync with the config the
#      UNM API renders into the shared volume /data/radius. FreeRADIUS 3.x loads
#      module instances ONLY from mods-enabled/ and sites ONLY from
#      sites-enabled/, so each rendered file is copied to its exact destination:
#        clients.conf       -> raddb/clients.conf            (NAS list)
#        eap.conf           -> raddb/mods-enabled/eap         (EAP-TLS module —
#                                                       REPLACES the stock instance;
#                                                       rlm_eap requires an Auth-Type
#                                                       dict value named after the
#                                                       INSTANCE, and only "EAP" exists,
#                                                       so a custom name can't instantiate)
#        exec-unm.conf      -> raddb/mods-enabled/exec-unm.conf (revocation check program)
#        sql-unm.conf       -> raddb/mods-enabled/sql-unm.conf  (rlm_sql acct/auth)
#        site-eaptls.conf   -> raddb/sites-enabled/eap-tls    (REPLACES `default`)
#        radius-user-profile.sh -> raddb/radius-user-profile.sh (per-auth: revocation
#                                                       check + per-user reply attributes)
#        radius-auth-log.sh     -> raddb/radius-auth-log.sh      (post-auth audit:
#                                                       one radpostauth row per attempt)
#      Files are COPIED (not symlinked) so freerad's ownership stays correct no
#      matter who wrote the source. A fresh volume still boots: missing files are
#      skipped and the package defaults remain in place.
#   2. Keep root_ca.crt in sync from the CA shared volume (/data/ca, read-only)
#      into the raddb — EAP-TLS validates client certs against UNM's own CA.
#   3. Generate a self-signed RADIUS server cert/key on first boot (persisted on
#      /var/lib/unm-radius so container recreation keeps the same identity). The
#      API renders eap.conf to point at these paths.
#   4. Watch the rendered files' mtimes and SIGHUP radiusd to hot-apply changes
#      without a container restart (verified: FR3's HUP handler re-reads every
#      config file whose mtime changed — "HUP - Re-reading configuration files").
#   5. Forward SIGTERM/SIGINT for graceful shutdown.
set -eu

RADD="${FREERADIUS_DIR:-/etc/freeradius/3.0}"
CFG=/data/radius
CA_CFG=/data/ca
CERTDIR=/var/lib/unm-radius
BIN=/usr/sbin/freeradius

log() { echo "[unm-radius] $*"; }

# --- 1. Server cert/key (self-signed, persisted) ------------------------------
mkdir -p "$CERTDIR"
if [ ! -f "$CERTDIR/server.crt" ] || [ ! -f "$CERTDIR/server.key" ]; then
  log "no RADIUS server cert — generating a self-signed one…"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
    -subj "/CN=unm-radius/O=UnifiedNetworkManager" \
    -addext "subjectAltName=DNS:unm-radius,DNS:localhost" </dev/null >/dev/null 2>&1
fi
# Ownership: the entrypoint runs as ROOT, but radiusd DROPS to freerad before
# instantiating modules — rlm_eap_tls reads server.key AS FREERAD (verified:
# "Failed reading private key file … Permission denied" crash-loop otherwise).
# The key stays 600 and freerad-owned: no other user in the container can read
# it. Re-chown on every boot so a pre-existing root-owned key (e.g. from an
# older image) self-heals without manual intervention.
chown -R freerad:freerad "$CERTDIR" 2>/dev/null || true
chmod 600 "$CERTDIR/server.key"
chmod 644 "$CERTDIR/server.crt"

# --- 2. Sync rendered config into the raddb ----------------------------------
sync_config() {
  # CA root bundle (public cert only — no keys ever leave /pki). The stock raddb
  # has no ca/ dir (it uses certs/) — create it so the eap instance's ca_file
  # target exists.
  mkdir -p "$RADD/ca"
  if [ -f "$CA_CFG/root_ca.crt" ]; then
    cp "$CA_CFG/root_ca.crt" "$RADD/ca/root_ca.crt"
    chmod 644 "$RADD/ca/root_ca.crt"
  else
    log "WARN: no root_ca.crt in $CA_CFG yet — EAP-TLS cannot validate clients until the CA has bootstrapped"
  fi

  # Rendered files -> their exact raddb destinations (see header). FreeRADIUS 3.x
  # loads module instances ONLY from mods-enabled/ and sites ONLY from
  # sites-enabled/, so the API renders each file for its final location. Missing
  # source files are skipped so a fresh volume still boots with package defaults.
  # if/then (not `[ -f ] && cp`): under `set -e` a bare AND-list that fails as
  # the function's last command would kill the entrypoint on first boot, when no
  # rendered files exist yet.
  copy_if() { if [ -f "$CFG/$1" ]; then cp "$CFG/$1" "$2"; fi; }
  copy_if clients.conf        "$RADD/clients.conf"
  # The rendered eap instance REPLACES the stock one (same name, our TLS config).
  # A stale custom-named file from an older render is removed so it can't shadow.
  rm -f "$RADD/mods-enabled/eap-unm.conf"
  copy_if eap.conf            "$RADD/mods-enabled/eap"
  copy_if exec-unm.conf       "$RADD/mods-enabled/exec-unm.conf"
  copy_if sql-unm.conf        "$RADD/mods-enabled/sql-unm.conf"
  # A stale script from an older render is removed so it can't shadow the new one.
  rm -f "$RADD/revoked-check.sh"
  copy_if radius-user-profile.sh "$RADD/radius-user-profile.sh"
  copy_if radius-auth-log.sh     "$RADD/radius-auth-log.sh"

  # The EAP-TLS site REPLACES the stock `default` site (which would also accept
  # PAP/CHAP/EAP-MD5). inner-tunnel stays as-is — it only runs inside an outer
  # EAP tunnel, which our topology never opens.
  if [ -f "$CFG/site-eaptls.conf" ]; then
    rm -f "$RADD/sites-enabled/default"
    cp "$CFG/site-eaptls.conf" "$RADD/sites-enabled/eap-tls"
  fi

  # Permissions: freerad reads everything; the secrets (clients.conf carries NAS
  # shared secrets, sql-unm.conf + radius-user-profile.sh carry the DB password) are
  # group-readable by gid 1001 (the API) for debugging but not world-accessible.
  # The revocation script must be executable by freerad. chmod_if uses if/then —
  # a bare `[ -f ] && chmod` as this function's LAST command would make the
  # function return non-zero on first boot (no rendered files yet) and kill the
  # entrypoint under `set -e` (same trap as copy_if above).
  chmod_if() { if [ -f "$1" ]; then chmod "$2" "$1"; fi; }
  chown -R freerad:freerad "$RADD" 2>/dev/null || true
  chmod_if "$RADD/clients.conf" 640
  chmod_if "$RADD/mods-enabled/eap" 640
  chmod_if "$RADD/mods-enabled/exec-unm.conf" 640
  chmod_if "$RADD/mods-enabled/sql-unm.conf" 640
  chmod_if "$RADD/sites-enabled/eap-tls" 644
  chmod_if "$RADD/radius-user-profile.sh" 750
  chmod_if "$RADD/radius-auth-log.sh" 750
}

# --- 3. Start radiusd ----------------------------------------------------------
sync_config
# Validate BEFORE starting: `freeradius -C` exits non-zero on a broken config but
# writes the error to its log file (not the console), so surface it explicitly —
# otherwise an invalid render would crash-loop with no visible cause.
if ! "$BIN" -C >/dev/null 2>&1; then
  log "ERROR: freeradius config validation FAILED — not starting. Last log lines:"
  tail -n 30 /var/log/freeradius/radius.log 2>/dev/null || true
  exit 1
fi
log "config valid — starting freeradius…"
# -f = foreground: WITHOUT it radiusd daemonizes (double-forks) and the PID we
# capture is a short-lived parent that exits immediately — the watch loop below
# then sees a dead process, the entrypoint exits 0, and docker restart-loops the
# container forever. With -f, $! IS the real radiusd: kill -0 / SIGHUP / SIGTERM
# all reach it directly.
"$BIN" -f &
FR_PID=$!
log "freeradius started (pid $FR_PID)"

shutdown() {
  log "shutting down — forwarding SIGTERM to freeradius ($FR_PID)"
  kill -TERM "$FR_PID" 2>/dev/null || true
  wait "$FR_PID" 2>/dev/null || true
  exit 0
}
trap shutdown TERM INT

# --- 4. Config watch (mtime of every rendered file + the CA root) --------------
last_sig=""
signature() {
  local out="" f
  for f in clients.conf eap.conf exec-unm.conf sql-unm.conf radius-user-profile.sh radius-auth-log.sh site-eaptls.conf; do
    [ -f "$CFG/$f" ] && out="$out $(stat -c %Y "$CFG/$f")"
  done
  [ -f "$CA_CFG/root_ca.crt" ] && out="$out $(stat -c %Y "$CA_CFG/root_ca.crt")"
  echo "$out"
}

LAST=$(signature)
while kill -0 "$FR_PID" 2>/dev/null; do
  sleep 2
  SIG=$(signature) || continue
  if [ "$SIG" != "$LAST" ]; then
    LAST=$SIG
    log "rendered config changed — re-syncing + SIGHUP freeradius"
    sync_config
    kill -HUP "$FR_PID" 2>/dev/null || true
  fi
done
