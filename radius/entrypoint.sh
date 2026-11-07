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
#        trusted-ca.pem         -> merged into raddb/ca/bundle.pem with the local
#                                   root (RADIUS failover slaves trust their
#                                   replication source's CA — see sync_config)
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
#      Every reload is VERIFIED against radius.log; if the re-read fails, the
#      supervisor gracefully RESTARTS radiusd instead of leaving it stale (see
#      the watch loop below for why a failed HUP must never be left unhandled).
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
  # CA trust for EAP-TLS client validation (public certs only — no keys ever
  # leave /pki). The eap instance's ca_file points at a BUNDLE: the local UNM
  # root (when bootstrapped) + the replicated/trusted roots the API renders into
  # $CFG/trusted-ca.pem from its radiusTrustedCaPem setting — that is what makes
  # a RADIUS failover slave trust client certs issued by its replication source's
  # CA. The stock raddb has no ca/ dir (it uses certs/) — create it so the
  # bundle target exists. root_ca.crt is kept in sync too (legacy path, harmless).
  mkdir -p "$RADD/ca"
  if [ -f "$CA_CFG/root_ca.crt" ]; then
    cp "$CA_CFG/root_ca.crt" "$RADD/ca/root_ca.crt"
    chmod 644 "$RADD/ca/root_ca.crt"
  fi
  local bundle_tmp="$RADD/ca/bundle.pem.tmp"
  : > "$bundle_tmp"
  if [ -f "$CA_CFG/root_ca.crt" ]; then cat "$CA_CFG/root_ca.crt" >> "$bundle_tmp"; fi
  if [ -f "$CFG/trusted-ca.pem" ]; then cat "$CFG/trusted-ca.pem" >> "$bundle_tmp"; fi
  if [ -s "$bundle_tmp" ]; then
    mv "$bundle_tmp" "$RADD/ca/bundle.pem"
    chmod 644 "$RADD/ca/bundle.pem"
  else
    rm -f "$bundle_tmp" "$RADD/ca/bundle.pem"
    log "WARN: no CA root (local or trusted) — EAP-TLS cannot validate clients until a CA exists"
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
  for f in clients.conf eap.conf exec-unm.conf sql-unm.conf radius-user-profile.sh radius-auth-log.sh site-eaptls.conf trusted-ca.pem; do
    [ -f "$CFG/$f" ] && out="$out $(stat -c %Y "$CFG/$f")"
  done
  [ -f "$CA_CFG/root_ca.crt" ] && out="$out $(stat -c %Y "$CA_CFG/root_ca.crt")"
  echo "$out"
}

# Graceful in-place restart of radiusd — the fallback when a hot reload fails.
# A fresh full load re-reads every file and re-instantiates every module from
# scratch, which sidesteps whatever in-process state made the HUP re-read fail
# (a fresh load of the same on-disk config is verified to succeed: `freeradius -C`
# at boot + observed live). TERM+wait keeps it graceful; LAST_HUP resets because
# a fresh process has no 5s HUP window to respect.
restart_radiusd() {
  log "restarting freeradius (pid $FR_PID) to apply config…"
  kill -TERM "$FR_PID" 2>/dev/null || true
  wait "$FR_PID" 2>/dev/null || true
  "$BIN" -f &
  FR_PID=$!
  LAST_HUP=0
  log "freeradius restarted (pid $FR_PID)"
}

LAST=$(signature)
PENDING=""   # signature seen but not yet reloaded (debounce window)
LAST_HUP=0   # epoch of the last SIGHUP sent to radiusd
while kill -0 "$FR_PID" 2>/dev/null; do
  sleep 2
  SIG=$(signature) || continue
  if [ "$SIG" != "$LAST" ]; then
    LAST=$SIG
    PENDING=$SIG
    # Debounce: a render burst (e.g. the API re-rendering several files in one
    # mutation) must produce ONE reload, not one per file — and only after the
    # last file has landed, so the reload always sees the FINAL state.
    continue
  fi
  if [ -n "$PENDING" ] && [ "$SIG" = "$PENDING" ]; then
    PENDING=""
    log "rendered config changed — re-syncing + SIGHUP freeradius"
    sync_config
    # FreeRADIUS silently DROPS any HUP arriving less than 5s after the previous
    # one ("Ignoring HUP (less than 5s since last one)" in radius.log). A burst of
    # renders whose final reload lands inside that window leaves radiusd running a
    # STALE config forever — observed live: clients.conf re-rendered at :20/:27/:47,
    # the final copy's HUP dropped at :51, probes rejected as "unknown client" for
    # hours. Space sends >=6s apart so every reload is guaranteed to be accepted.
    NOW=$(date +%s)
    WAIT=$((LAST_HUP + 6 - NOW))
    if [ "$WAIT" -gt 0 ]; then sleep "$WAIT"; fi
    # Line count BEFORE the HUP so we only inspect log lines written by THIS reload.
    RLOG=/var/log/freeradius/radius.log
    MARK=$(wc -l < "$RLOG" 2>/dev/null || echo 0)
    kill -HUP "$FR_PID" 2>/dev/null || true
    LAST_HUP=$(date +%s)
    # VERIFY the reload actually happened. On success FR3 logs one "Loaded virtual
    # server …" line per site; on a failed re-read it logs "Cannot read
    # configuration files. Ignoring". A single failed re-read must never be left
    # unhandled: observed live (FR 3.2.x), after ONE failed HUP the process keeps
    # rejecting EVERY later HUP with the same error — even once all files are
    # valid again — until it is restarted, so an unverified failure leaves radiusd
    # serving a STALE config indefinitely (probes then time out / reject as
    # "unknown client"). Fallback: graceful restart = fresh full load of the
    # current on-disk config.
    if kill -0 "$FR_PID" 2>/dev/null; then
      sleep 4
      NEW=$(tail -n +"$((MARK + 1))" "$RLOG" 2>/dev/null || true)
      case "$NEW" in
        *"Cannot read configuration files"*|*"Ignoring HUP (less than 5s"*)
          log "WARN: hot reload FAILED — falling back to a graceful restart"
          restart_radiusd ;;
        *"Loaded virtual server"*)
          :   # reloaded cleanly
          ;;
        *)
          log "WARN: no reload confirmation in radius.log — restarting to be safe"
          restart_radiusd ;;
      esac
    fi
  fi
done
# Reaching here means radiusd died on its own (a broken config makes it exit
# immediately after a failed restart). Exit NON-ZERO so the container's restart
# policy recycles it and the boot-time `freeradius -C` surfaces the real error.
log "freeradius exited unexpectedly — exiting so the container is restarted"
exit 1
