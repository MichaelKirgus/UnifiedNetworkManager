#!/bin/bash
# UNM CA service supervisor (runs as `step` user inside smallstep/step-ca image).
#
# Responsibilities:
#   1. First boot: generate the PKI (root + intermediate) non-interactively via
#      `step ca init --pki` and move it to /pki (the CA-only volume). The root
#      key is copied into /pki as well — step-ca keeps it in its EPHEMERAL home
#      dir (/home/step/secrets), which dies with the container, so without this
#      copy a recreated container could never renew the intermediate again.
#   2. Ensure a default ca.json exists in the shared config volume (/data/ca) so
#      step-ca can start even before the UNM API renders its first one. The API
#      re-renders this file from global settings on boot and after every change;
#      we watch its mtime and SIGHUP step-ca to hot-apply (verified: step-ca
#      reloads provisioners/claims/policy/tls on SIGHUP without dropping state).
#   3. Intermediate renewal (chain-integrity guard): the intermediate is renewed
#      with its EXISTING key when it expires within 90 days, or immediately when
#      the UNM API drops a renew-trigger file into /data/ca (POST /v1/ca/
#      renew-intermediate). The new cert keeps subject + key and gets CA:TRUE
#      pathlen:0 + CertSign/CRLSign critical — verified live against step 0.30.2.
#      Its validity is clamped to the ROOT's expiry minus a 7-day margin, so the
#      chain can never break because the intermediate outlives its root. After an
#      atomic replace we SIGHUP step-ca (verified: SIGHUP rebuilds the whole
#      authority from disk — ca/signal.go + authority.go).
#   4. Forward SIGTERM/SIGINT to step-ca for graceful shutdown.
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
  # the password file suppresses the tty prompt. NOTE: step-ca 0.30.x has NO
  # duration flags on `step ca init` — its defaults are root AND intermediate
  # 10 years each (verified live), which matches UNM's long-lived client-cert
  # model. If a future step version changes those defaults, pin them here and
  # re-verify the chain guard in api/src/ca/enroll.ts still holds.
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

# Persist the ROOT KEY into /pki. step-ca keeps it only in its ephemeral home
# dir (/home/step/secrets/root_ca_key) — lost on container recreation, which
# would make intermediate renewal impossible (renewal signs with the root key).
# Idempotent: re-copied on every boot so a volume restored from backup without
# the key self-heals. The key is encrypted with $BOOTSTRAP_PW (also in /pki),
# and /pki is mounted on this container ONLY — nothing else ever sees it.
if [ -f "$STEPPATH/secrets/root_ca_key" ]; then
  cp "$STEPPATH/secrets/root_ca_key" "$PKI_DIR/root_ca_key"
  chmod 600 "$PKI_DIR/root_ca_key"
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

# --- 3. Intermediate renewal (chain-integrity guard) --------------------------
# The intermediate is renewed with its EXISTING key when it expires within 90
# days, or immediately when the UNM API drops $RENEW_TRIGGER into /data/ca
# (POST /v1/ca/renew-intermediate). Verified live against step 0.30.2:
#   - `openssl req -new -key <encrypted> -passin file:` builds a CSR from the
#     existing key with NO tty prompt and no decrypted temp key on disk;
#   - `step certificate sign` (arg order: csr crt key) is non-interactive with
#     --password-file, but IGNORES CSR extensions — so a JSON template forces
#     CA:TRUE pathlen:0 + CertSign/CRLSign critical (the leaf defaults would
#     produce a broken intermediate);
#   - the renewed cert keeps subject + key and chains to the same root.
RENEW_TRIGGER="$CFG_DIR/renew-trigger"
RENEW_WORK=/tmp/unm-ca-renew
RENEW_COOLDOWN=300        # seconds between retry attempts after a failure
RENEW_LAST_FAIL=0

renew_intermediate() {
  local reason="$1"
  log "renewing intermediate CA (reason: $reason)…"
  if [ ! -f "$PKI_DIR/root_ca_key" ]; then
    log "ERROR: no root key in $PKI_DIR — cannot renew the intermediate. Restore /pki from backup or re-bootstrap."
    RENEW_LAST_FAIL=$(date +%s)
    return 1
  fi
  mkdir -p "$RENEW_WORK"

  # Subject of the current intermediate (O + CN), preserved verbatim so every
  # already-issued leaf keeps validating against the renewed cert. Read from the
  # flat `subject_dn` string ("O=…, CN=…") — far more robust than parsing the
  # nested subject object, which has an identically-shaped issuer block above it.
  local dn o cn
  dn=$(step certificate inspect --format json "$PKI_DIR/intermediate_ca.crt" \
    | sed -n 's/.*"subject_dn": *"\([^"]*\)".*/\1/p') || return 1
  if [ -z "$dn" ]; then
    log "ERROR: could not read the intermediate subject — aborting renewal"
    RENEW_LAST_FAIL=$(date +%s)
    return 1
  fi
  o=${dn%%, CN=*}; o=${o#O=}
  cn=${dn##*CN=}

  # CHAIN GUARD: the renewed intermediate must never outlive its root. Clamp
  # the requested 10-year window to (root expiry − 7 days). Without this, a
  # future step version with different defaults could hand us an intermediate
  # that expires AFTER the root — breaking every leaf in the fleet.
  local root_end conv epoch now target hours
  root_end=$(step certificate inspect --format json "$PKI_DIR/root_ca.crt" \
    | sed -n '/"validity"/,/^  }/p' | sed -n 's/.*"end": *"\([^"]*\)".*/\1/p')
  conv=${root_end/T/ }; conv=${conv%Z}
  epoch=$(date -u -d "$conv" +%s) || { log "ERROR: cannot parse root expiry '$root_end'"; RENEW_LAST_FAIL=$(date +%s); return 1; }
  now=$(date +%s)
  target=$((now + 10 * 365 * 24 * 3600))
  if [ $((epoch - 7 * 86400)) -lt "$target" ]; then target=$((epoch - 7 * 86400)); fi
  hours=$(( (target - now) / 3600 ))
  if [ "$hours" -le 24 ]; then
    log "ERROR: the ROOT CA expires within a day — renewing the intermediate cannot keep the chain valid. Rotate the root PKI."
    RENEW_LAST_FAIL=$(date +%s)
    return 1
  fi

  # CSR from the EXISTING (encrypted) key — no tty, no decrypted temp file.
  local subj="/CN=$cn"
  [ -n "$o" ] && subj="/O=$o$subj"
  if ! openssl req -new -key "$PKI_DIR/intermediate_ca_key" -passin "file:$BOOTSTRAP_PW" \
      -subj "$subj" -out "$RENEW_WORK/renew.csr" </dev/null; then
    log "ERROR: CSR generation failed — aborting renewal"
    RENEW_LAST_FAIL=$(date +%s)
    return 1
  fi

  # step sign IGNORES CSR extensions (applies its leaf template), so force the
  # intermediate's CA extensions via a JSON certificate template. The subject
  # MUST be in the template too — without it step signs an EMPTY subject, which
  # would break every already-issued leaf (verified live). O/CN come from our
  # own bootstrap (`step ca init --name "UNM CA"`), so they are plain ASCII;
  # escape backslashes/quotes anyway for robustness.
  local o_json cn_json org_field=""
  if [ -n "$o" ]; then
    o_json=${o//\\/\\\\}; o_json=${o_json//\"/\\\"}
    org_field="\"organization\": [\"$o_json\"], "
  fi
  cn_json=${cn//\\/\\\\}; cn_json=${cn_json//\"/\\\"}
  cat > "$RENEW_WORK/ca.tpl" <<TPL
{
  "subject": { $org_field"commonName": "$cn_json" },
  "basicConstraints": { "isCA": true, "maxPathLen": 0 },
  "keyUsage": ["certSign", "crlSign"]
}
TPL

  if ! step certificate sign --template "$RENEW_WORK/ca.tpl" \
      "$RENEW_WORK/renew.csr" "$PKI_DIR/root_ca.crt" "$PKI_DIR/root_ca_key" \
      --not-after "${hours}h" --password-file "$BOOTSTRAP_PW" </dev/null \
      > "$RENEW_WORK/new_intermediate.crt"; then
    log "ERROR: signing the renewed intermediate failed — aborting renewal"
    RENEW_LAST_FAIL=$(date +%s)
    return 1
  fi

  # Never install a cert that does not chain to our root.
  if ! openssl verify -CAfile "$PKI_DIR/root_ca.crt" "$RENEW_WORK/new_intermediate.crt" >/dev/null; then
    log "ERROR: renewed intermediate does NOT chain to the root — refusing to replace"
    RENEW_LAST_FAIL=$(date +%s)
    return 1
  fi

  # Atomic replace (same filesystem), then SIGHUP so step-ca re-reads its cert.
  mv "$RENEW_WORK/new_intermediate.crt" "$PKI_DIR/intermediate_ca.crt"
  chmod 600 "$PKI_DIR/intermediate_ca.crt"
  rm -f "$RENEW_TRIGGER"
  log "intermediate renewed — now valid until $(openssl x509 -in "$PKI_DIR/intermediate_ca.crt" -noout -enddate | cut -d= -f2)"
  kill -HUP "$STEPCA_PID" 2>/dev/null || true
  return 0
}

# --- 4. Run step-ca + config/renewal watch ------------------------------------
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

  # Renewal check (cheap): manual trigger file, or intermediate expires <90d.
  # A failed attempt sets RENEW_LAST_FAIL; the cooldown prevents a hot retry
  # loop while the failure persists (the trigger file stays until success).
  NOW=$(date +%s)
  if [ $((NOW - RENEW_LAST_FAIL)) -ge "$RENEW_COOLDOWN" ]; then
    if [ -f "$RENEW_TRIGGER" ]; then
      renew_intermediate "manual trigger from the UNM API" || true
    elif ! openssl x509 -in "$PKI_DIR/intermediate_ca.crt" -noout -checkend $((90 * 86400)) >/dev/null 2>&1; then
      renew_intermediate "intermediate expires within 90 days" || true
    fi
  fi
done
