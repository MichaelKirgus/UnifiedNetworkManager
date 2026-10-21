#!/bin/bash
# UNM CA service supervisor (runs as `step` user inside smallstep/step-ca image).
#
# Responsibilities — NO crypto logic here, only process supervision:
#   1. First boot: generate the PKI (root + intermediate) non-interactively via
#      `step ca init --pki` and move it to /pki (the CA-only volume). The root
#      key stays in /pki too — nothing outside this container ever sees it.
#   2. Ensure a default ca.json exists in the shared config volume (/data/ca) so
#      step-ca can start even before the UNM API renders its first one. The API
#      re-renders this file from global settings on boot and after every change;
#      we watch its mtime and SIGHUP step-ca to hot-apply (verified: step-ca
#      reloads provisioners/claims/policy/tls on SIGHUP without dropping state).
#   3. Forward SIGTERM/SIGINT to step-ca for graceful shutdown.
set -eo pipefail

export STEPPATH=/home/step
PKI_DIR=/pki
CFG_DIR=/data/ca
CA_JSON="$CFG_DIR/ca.json"
BOOTSTRAP_PW="$PKI_DIR/.bootstrap-password"   # CA-only volume; decrypts nothing today (keys are unencrypted) but mirrors the official image's runtime contract

log() { echo "[unm-ca] $*"; }

# --- 1. PKI bootstrap ---------------------------------------------------------
need_pki=0
for f in root_ca.crt intermediate_ca.crt intermediate_ca_key; do
  [ -f "$PKI_DIR/$f" ] || need_pki=1
done
if [ "$need_pki" = "1" ]; then
  log "no complete PKI in $PKI_DIR — generating (root + intermediate)…"
  # A partial state is treated as corrupt: regenerate everything so the chain
  # always matches. Wipe only our three files, never the config volume.
  rm -f "$PKI_DIR/root_ca.crt" "$PKI_DIR/intermediate_ca.crt" "$PKI_DIR/intermediate_ca_key"
  mkdir -p /tmp/unm-ca-bootstrap
  if [ ! -f "$BOOTSTRAP_PW" ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$BOOTSTRAP_PW"
    chmod 600 "$BOOTSTRAP_PW"
  fi
  # --pki = keys + certs only, no ca.json (we own that file). Non-interactive:
  # the password file suppresses the tty prompt.
  step ca init --pki \
    --name "UNM CA" \
    --dns unm-ca,localhost \
    --password-file "$BOOTSTRAP_PW" >/dev/null
  cp "$STEPPATH/certs/root_ca.crt" "$PKI_DIR/"
  cp "$STEPPATH/certs/intermediate_ca.crt" "$PKI_DIR/"
  cp "$STEPPATH/secrets/intermediate_ca_key" "$PKI_DIR/"
  log "PKI ready (root fingerprint: $(step certificate inspect --fingerprint "$PKI_DIR/root_ca.crt"))"
else
  log "existing PKI found in $PKI_DIR — reusing"
fi

# The UNM API (uid/gid 1001) renders ca.json into this shared volume, so its top
# dir must be group-writable for gid 1001. Fresh volumes get that from the image
# build; volumes created by OLDER images were step-owned 755 and need a one-time
# root fixup (this container runs as `step` and cannot chgrp to a foreign group):
#   docker run --rm -v <ca-cfg-volume>:/mnt alpine sh -c 'chgrp 1001 /mnt && chmod 2775 /mnt'
if [ "$(stat -c %G "$CFG_DIR" 2>/dev/null)" != "1001" ]; then
  log "WARN: $CFG_DIR is not group-owned by gid 1001 — the API cannot write ca.json. Fix once (as root): chgrp 1001 + chmod 2775 on the volume's top dir."
fi

# The PUBLIC root cert is mirrored into the shared config volume so the UNM API
# (which mounts /data/ca but never /pki) can use it as its TLS trust anchor and
# surface the fingerprint/expiry. Only the certificate — no keys ever leave /pki.
cp "$PKI_DIR/root_ca.crt" "$CFG_DIR/root_ca.crt"
# The UNM API runs unprivileged (uid 1001); make this PUBLIC cert world-readable
# so it can read its mTLS trust anchor regardless of who created the file.
chmod 644 "$CFG_DIR/root_ca.crt"

# --- 2. Default ca.json (only if the API has not rendered one yet) ------------
if [ ! -f "$CA_JSON" ]; then
  log "no ca.json yet — writing defaults (the UNM API overwrites this from global settings)"
  cat > "$CA_JSON" <<'JSON'
{
  "root": "/pki/root_ca.crt",
  "crt": "/pki/intermediate_ca.crt",
  "key": "/pki/intermediate_ca_key",
  "address": ":9000",
  "dnsNames": ["unm-ca", "localhost"],
  "logger": { "format": "text" },
  "db": { "type": "badgerv2", "dataSource": "/data/ca/db" },
  "authority": {
    "claims": {
      "minTLSCertDuration": "168h",
      "maxTLSCertDuration": "8760h",
      "defaultTLSCertDuration": "2160h"
    },
    "policy": {
      "x509": {
        "allow": { "dns": ["unm-ca", "localhost"] },
        "allowWildcardNames": false
      }
    },
    "provisioners": [
      { "type": "ACME", "name": "acme", "challenges": ["http-01"] }
    ]
  },
  "tls": { "minVersion": 1.2, "maxVersion": 1.3 }
}
JSON
fi

# --- 3. Run step-ca + config watch --------------------------------------------
step-ca "$CA_JSON" --password-file "$BOOTSTRAP_PW" &
STEPCA_PID=$!
log "step-ca started (pid $STEPCA_PID)"

shutdown() {
  log "shutting down — forwarding SIGTERM to step-ca ($STEPCA_PID)"
  kill -TERM "$STEPCA_PID" 2>/dev/null || true
  wait "$STEPCA_PID" 2>/dev/null || true
  exit 0
}
trap shutdown TERM INT

LAST_MTIME=$(stat -c %Y "$CA_JSON")
while kill -0 "$STEPCA_PID" 2>/dev/null; do
  sleep 2
  MTIME=$(stat -c %Y "$CA_JSON" 2>/dev/null) || continue
  if [ "$MTIME" != "$LAST_MTIME" ]; then
    LAST_MTIME=$MTIME
    log "ca.json changed — SIGHUP step-ca to reload"
    kill -HUP "$STEPCA_PID"
  fi
done
