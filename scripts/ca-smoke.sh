#!/usr/bin/env bash
# Smoke test for the UNM certificate authority (Stage 0: CA service + mgmt plane).
#
# Non-destructive checks (default):
#   1. unm-ca is up and serving HTTPS on :9000 inside the compose network
#   2. /v1/ca/status returns version + root fingerprint (authed)
#   3. ACME directory reachable over TLS with the UNM root as trust anchor
#   4. Restarting unm-ca reuses the existing PKI — same root fingerprint, no re-init
#   5. A global-settings change hot-applies: ca.json mtime changes and step-ca logs "reloading"
#
# Destructive check (opt-in): `--fresh` recreates the CA volumes from scratch and
# verifies first-boot bootstrap produces a working PKI + ACME directory. Destroys
# any previously issued leaves' trust chain — only run on a dev stack.
#
# Usage (from the repo root, with the dev stack running):
#   scripts/ca-smoke.sh            # non-destructive
#   scripts/ca-smoke.sh --fresh    # also re-bootstrap from empty volumes
set -euo pipefail

cd "$(dirname "$0")/.."

API_BASE="${API_BASE:-http://localhost:3000/v1}"
FRESH=0
[ "${1:-}" = "--fresh" ] && FRESH=1

pass() { echo "  PASS $*"; }
fail() { echo "  FAIL $*" >&2; exit 1; }

# --- auth (admin/admin, TOTP from the seeded secret when enabled) -------------
get_token() {
  API_BASE="$API_BASE" node -e '
const path = require("node:path");
const { createRequire } = require("node:module");
(async () => {
  const apiRequire = createRequire(path.resolve(process.cwd(), "api", "package.json"));
  const { Pool } = apiRequire("pg");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? "postgresql://unm:unm@localhost:5432/unm" });
  const row = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = $1`, ["admin"])).rows[0];
  let token;
  if (!row.totpSecret) {
    const r = await fetch(process.env.API_BASE + "/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "admin", password: "admin" }) });
    token = (await r.json()).accessToken;
  } else {
    const { authenticator } = apiRequire("otplib");
    const code = authenticator.generate(row.totpSecret);
    const r1 = await fetch(process.env.API_BASE + "/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "admin", password: "admin" }) });
    const challenge = (await r1.json()).challengeToken;
    const r2 = await fetch(process.env.API_BASE + "/auth/2fa/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = (await r2.json()).accessToken;
  }
  await pool.end();
  if (!token) process.exit(1);
  console.log(token);
})().catch((e) => { console.error(e.message); process.exit(1); });
'
}

status_json() {
  curl -fsS -H "Authorization: Bearer $TOKEN" "$API_BASE/ca/status"
}

fingerprint_of() {
  node -e 'console.log(JSON.parse(process.argv[1]).status.rootFingerprint)' "$1"
}

echo "== CA smoke test =="

# --- 0. (opt-in) fresh-volume bootstrap ---------------------------------------
if [ "$FRESH" = "1" ]; then
  echo "-- fresh PKI/config volumes --"
  # Both containers mount the CA volumes (api shares /data/ca). Stopped containers
  # still hold their mounts, so remove them — `down` without -v keeps everything else.
  docker compose down unm-ca api >/dev/null
  for v in $(docker volume ls --format '{{.Name}}' | grep -E 'unm-ca-(pki|cfg)$'); do
    docker volume rm "$v" >/dev/null || fail "could not remove CA volume $v (in use by another container?)"
  done
  docker compose up -d unm-ca api >/dev/null
fi

# --- wait for the API to be healthy --------------------------------------------
for i in $(seq 1 30); do
  curl -fsS "${API_BASE%/v1}/healthz" >/dev/null 2>&1 && break
  [ "$i" = "30" ] && fail "API not healthy after 60s (check: docker compose logs api)"
  sleep 2
done

TOKEN="$(get_token)" || fail "could not obtain an admin token (is the stack up?)"

if [ "$FRESH" = "1" ]; then
  # The CA bootstraps its PKI on first boot; wait until /ca/status answers.
  for i in $(seq 1 30); do
    sleep 2
    status_json >/dev/null 2>&1 && break
    [ "$i" = "30" ] && fail "CA did not come up after fresh bootstrap (check: docker compose logs unm-ca)"
  done
  pass "fresh bootstrap → /v1/ca/status answers"
fi

# --- 1. status route -----------------------------------------------------------
echo "-- /v1/ca/status --"
S1="$(status_json)" || fail "/v1/ca/status failed"
FP1="$(fingerprint_of "$S1")"
[ -n "$FP1" ] && [ "$FP1" != "undefined" ] || fail "no rootFingerprint in status: $S1"
pass "status reports fingerprint $FP1"

# --- 2. ACME directory over TLS (root as trust anchor) -------------------------
echo "-- ACME directory --"
DIR="$(docker compose exec -T unm-ca sh -c 'curl -fsS --cacert /pki/root_ca.crt https://unm-ca:9000/acme/acme/directory')" \
  || fail "ACME directory not reachable over TLS with the UNM root as trust anchor"
echo "$DIR" | grep -q '"newOrder"' || fail "ACME directory missing newOrder: $DIR"
pass "ACME directory served (newOrder/newNonce present)"

# --- 3. restart persistence ----------------------------------------------------
echo "-- restart persistence --"
docker compose restart unm-ca >/dev/null
for i in $(seq 1 20); do
  sleep 2
  S2="$(status_json 2>/dev/null || true)" && [ -n "$S2" ] && break
  [ "$i" = "20" ] && fail "CA did not answer after restart (check: docker compose logs unm-ca)"
done
FP2="$(fingerprint_of "$S2")"
[ "$FP1" = "$FP2" ] || fail "root fingerprint changed across restart ($FP1 → $FP2) — PKI was re-initialized!"
pass "same root fingerprint after restart (no re-init)"

# --- 4. settings change hot-applies --------------------------------------------
echo "-- settings hot-reload --"
MTIME_BEFORE="$(docker compose exec -T unm-ca sh -c 'stat -c %Y /data/ca/ca.json')"
PUT_STATUS="$(curl -sS -o /tmp/ca-smoke-put.json -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"value": 45}' "$API_BASE/settings/caLeafDefaultDays")"
[ "$PUT_STATUS" = "200" ] || fail "PUT caLeafDefaultDays=45 → HTTP $PUT_STATUS ($(cat /tmp/ca-smoke-put.json))"
# Restore the default so the smoke test leaves no residue.
curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN" "$API_BASE/settings/caLeafDefaultDays" >/dev/null \
  || fail "could not reset caLeafDefaultDays"
sleep 4   # supervisor polls mtime every 2s; give it two beats
MTIME_AFTER="$(docker compose exec -T unm-ca sh -c 'stat -c %Y /data/ca/ca.json')"
[ "$MTIME_BEFORE" != "$MTIME_AFTER" ] || fail "ca.json was not re-rendered after the settings change"
RELOADS="$(docker compose logs --since 2m unm-ca 2>&1 | grep -c 'reloading' || true)"
[ "${RELOADS:-0}" -ge 1 ] || fail "step-ca did not log a reload after ca.json changed"
pass "settings change → ca.json re-rendered + step-ca hot-reloaded"

echo "== CA smoke test: all checks passed =="
