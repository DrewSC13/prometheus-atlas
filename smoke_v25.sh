#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-atlas-bootstrap-admin}"
TARGET="${TARGET:-example.com}"
SUBJECT="${SUBJECT:-claudio}"
TENANT_ID="${TENANT_ID:-local}"
PROJECT_ID="${PROJECT_ID:-default}"
ROLE="${ROLE:-admin}"
ATLAS_BIN="${ATLAS_BIN:-cargo run -q -p atlas --}"

if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq no está instalado"
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log() {
  printf '\n[INFO] %s\n' "$1"
}

ok() {
  printf '[OK] %s\n' "$1"
}

fail() {
  printf '[ERROR] %s\n' "$1"
  exit 1
}

json_get() {
  local file="$1"
  local expr="$2"
  jq -er "$expr" "$file"
}

call() {
  local name="$1"
  shift
  local out="$TMPDIR/${name}.json"
  local status
  status=$(curl -sS -o "$out" -w "%{http_code}" "$@")
  echo "$status" > "$TMPDIR/${name}.status"
  printf '%s' "$out"
}

assert_status() {
  local name="$1"
  local expected="$2"
  local got
  got="$(cat "$TMPDIR/${name}.status")"
  if [ "$got" != "$expected" ]; then
    echo "[ERROR] HTTP inesperado en $name: esperado=$expected obtenido=$got"
    cat "$TMPDIR/${name}.json" || true
    exit 1
  fi
  ok "$name HTTP $expected"
}

assert_jq() {
  local file="$1"
  local expr="$2"
  local label="$3"
  if jq -e "$expr" "$file" >/dev/null 2>&1; then
    ok "$label"
  else
    echo "[ERROR] Falló validación jq: $label"
    echo "[ERROR] Expresión: $expr"
    cat "$file" || true
    exit 1
  fi
}

log "1. Health / Ready / Version"

f="$(call health "$BASE_URL/health")"
assert_status health 200
assert_jq "$f" '.data.status == "ok"' "health ok"

f="$(call ready "$BASE_URL/ready")"
assert_status ready 200
assert_jq "$f" '.data.status == "ready"' "ready ok"

f="$(call version "$BASE_URL/version")"
assert_status version 200
assert_jq "$f" '.data.api_version == "v1"' "version api=v1"

log "2. Bootstrap token"

f="$(call bootstrap \
  -X POST "$BASE_URL/v1/admin/bootstrap-token" \
  -H "content-type: application/json" \
  -H "x-atlas-bootstrap-token: $BOOTSTRAP_TOKEN" \
  -d "{\"subject\":\"$SUBJECT\",\"tenant_id\":\"$TENANT_ID\",\"project_id\":\"$PROJECT_ID\",\"role\":\"$ROLE\"}")"
assert_status bootstrap 200
assert_jq "$f" '.data.access_token | length > 20' "token emitido"

TOKEN="$(json_get "$f" '.data.access_token')"
ok "TOKEN capturado"

AUTH=(-H "authorization: Bearer $TOKEN")

log "3. Scan"

f="$(call scan \
  -X POST "$BASE_URL/v1/scan" \
  "${AUTH[@]}" \
  -H "content-type: application/json" \
  -d "{\"target\":\"$TARGET\"}")"
assert_status scan 200
assert_jq "$f" '.data.target == "'"$TARGET"'"' "scan target correcto"

log "4. Crear snapshots persistidos con CLI"

eval "$ATLAS_BIN snapshot $TARGET --persist" >/dev/null
sleep 1
eval "$ATLAS_BIN snapshot $TARGET --persist" >/dev/null
ok "snapshots creados"

log "5. List snapshots"

f="$(call snapshots "$BASE_URL/v1/snapshots/$TARGET" "${AUTH[@]}")"
assert_status snapshots 200
assert_jq "$f" '.items | length >= 2' "hay al menos 2 snapshots"
assert_jq "$f" '.items[0].snapshot_version >= 2' "snapshot_version válido"

OLDER_PATH="$(json_get "$f" '.items[1].path')"
NEWER_PATH="$(json_get "$f" '.items[0].path')"
ok "paths de snapshot obtenidos"

log "6. Drift persistido"

f="$(call drift \
  -X POST "$BASE_URL/v1/drift" \
  "${AUTH[@]}" \
  -H "content-type: application/json" \
  -d "{\"target\":\"$TARGET\",\"persist\":true}")"
assert_status drift 200
assert_jq "$f" '.data.target == "'"$TARGET"'"' "drift target correcto"
assert_jq "$f" '.data.summary.total_score >= 0' "drift summary presente"

log "7. Generar graph persistido con CLI"

eval "$ATLAS_BIN graph $TARGET --persist" >/dev/null
ok "graph persistido"

log "8. Obtener graph"

f="$(call graph "$BASE_URL/v1/graphs/$TARGET" "${AUTH[@]}")"
assert_status graph 200
assert_jq "$f" '.graph.target == "'"$TARGET"'"' "graph target correcto"
assert_jq "$f" '.graph.node_count > 0' "graph tiene nodos"
assert_jq "$f" '.graph.edge_count > 0' "graph tiene edges"

log "9. Reports"

f="$(call reports "$BASE_URL/v1/reports/$TARGET" "${AUTH[@]}")"
assert_status reports 200
assert_jq "$f" '.summary.snapshots > 0' "report snapshots > 0"
assert_jq "$f" '.summary.graphs > 0' "report graphs > 0"

log "10. Saved query create/list/get/run"

f="$(call save_query \
  -X POST "$BASE_URL/v1/queries" \
  "${AUTH[@]}" \
  -H "content-type: application/json" \
  -d '{"name":"risky-admin","expression":"services label~admin"}')"
assert_status save_query 200

f="$(call list_queries "$BASE_URL/v1/queries" "${AUTH[@]}")"
assert_status list_queries 200
assert_jq "$f" '.data | length >= 1' "queries listadas"

f="$(call get_query "$BASE_URL/v1/queries/risky-admin" "${AUTH[@]}")"
assert_status get_query 200
assert_jq "$f" '.data.name == "risky-admin"' "query recuperada"

f="$(call run_saved_query "$BASE_URL/v1/queries/risky-admin/run/$TARGET" "${AUTH[@]}")"
assert_status run_saved_query 200
assert_jq "$f" '.data.saved_query.name == "risky-admin"' "saved query ejecutada"

log "11. Jobs create/list/get/disable/enable/run"

f="$(call create_job \
  -X POST "$BASE_URL/v1/jobs" \
  "${AUTH[@]}" \
  -H "content-type: application/json" \
  -d "{\"target\":\"$TARGET\",\"profile\":\"standard\",\"interval_seconds\":3600,\"enabled\":true}")"
assert_status create_job 200
JOB_ID="$(json_get "$f" '.data.job.job_id')"
ok "job creado: $JOB_ID"

f="$(call list_jobs "$BASE_URL/v1/jobs" "${AUTH[@]}")"
assert_status list_jobs 200
assert_jq "$f" '.data | length >= 1' "jobs listados"

f="$(call get_job "$BASE_URL/v1/jobs/$JOB_ID" "${AUTH[@]}")"
assert_status get_job 200
assert_jq "$f" '.data.job.job_id == "'"$JOB_ID"'"' "job recuperado"

f="$(call disable_job \
  -X POST "$BASE_URL/v1/jobs/$JOB_ID/disable" \
  "${AUTH[@]}")"
assert_status disable_job 200
assert_jq "$f" '.data.job.enabled == false' "job deshabilitado"

f="$(call enable_job \
  -X POST "$BASE_URL/v1/jobs/$JOB_ID/enable" \
  "${AUTH[@]}")"
assert_status enable_job 200
assert_jq "$f" '.data.job.enabled == true' "job habilitado"

f="$(call run_job \
  -X POST "$BASE_URL/v1/jobs/$JOB_ID/run" \
  "${AUTH[@]}" \
  -H "content-type: application/json" \
  -d '{"persist":true}')"
assert_status run_job 200
assert_jq "$f" '.data.job_id == "'"$JOB_ID"'"' "run_job respondió"

log "12. Findings current"

f="$(call current_findings "$BASE_URL/v1/findings/$TARGET/current" "${AUTH[@]}")"
assert_status current_findings 200
assert_jq "$f" '.data | type == "array"' "current findings devuelve array"

FINDING_ID="$(jq -r '.data[0].finding_id // empty' "$f")"

if [ -n "$FINDING_ID" ]; then
  ok "finding disponible: $FINDING_ID"

  log "13. Findings ack/assign/note/resolve"

  f="$(call finding_ack \
    -X POST "$BASE_URL/v1/findings/by-id/$FINDING_ID/ack" \
    "${AUTH[@]}")"
  assert_status finding_ack 200

  f="$(call finding_assign \
    -X POST "$BASE_URL/v1/findings/by-id/$FINDING_ID/assign" \
    "${AUTH[@]}" \
    -H "content-type: application/json" \
    -d "{\"owner\":\"$SUBJECT\"}")"
  assert_status finding_assign 200

  f="$(call finding_note \
    -X POST "$BASE_URL/v1/findings/by-id/$FINDING_ID/note" \
    "${AUTH[@]}" \
    -H "content-type: application/json" \
    -d '{"notes":"smoke test v0.25.0"}')"
  assert_status finding_note 200

  f="$(call finding_resolve \
    -X POST "$BASE_URL/v1/findings/by-id/$FINDING_ID/resolve" \
    "${AUTH[@]}")"
  assert_status finding_resolve 200

  f="$(call current_findings_after "$BASE_URL/v1/findings/$TARGET/current" "${AUTH[@]}")"
  assert_status current_findings_after 200
  assert_jq "$f" '.data[] | select(.finding_id == "'"$FINDING_ID"'") | .operational_state == "resolved"' "finding quedó resolved"
else
  log "13. No hubo findings actuales; se omite patch de findings"
fi

log "14. Telemetry"

f="$(call telemetry "$BASE_URL/v1/telemetry?limit=50" "${AUTH[@]}")"
assert_status telemetry 200
assert_jq "$f" '.items | length >= 1' "telemetry disponible"

log "15. Audit"

f="$(call audit "$BASE_URL/v1/audit?limit=50" "${AUTH[@]}")"
assert_status audit 200
assert_jq "$f" '.items | length >= 1' "audit disponible"

f="$(call admin_audit "$BASE_URL/v1/admin/audit?limit=50" "${AUTH[@]}")"
assert_status admin_audit 200
assert_jq "$f" '.data | length >= 1' "admin audit disponible"

log "16. Pruebas negativas"

f="$(call bad_finding_ack \
  -X POST "$BASE_URL/v1/findings/by-id/no-existe/ack" \
  "${AUTH[@]}")" || true
BAD_STATUS="$(cat "$TMPDIR/bad_finding_ack.status")"
if [ "$BAD_STATUS" = "500" ] || [ "$BAD_STATUS" = "404" ] || [ "$BAD_STATUS" = "400" ]; then
  ok "finding inexistente devuelve error controlado ($BAD_STATUS)"
else
  fail "finding inexistente devolvió HTTP inesperado: $BAD_STATUS"
fi

f="$(call bad_query \
  -X POST "$BASE_URL/v1/queries" \
  "${AUTH[@]}" \
  -H "content-type: application/json" \
  -d '{"name":"bad-query","expression":"services AND OR"}')" || true
BAD_STATUS="$(cat "$TMPDIR/bad_query.status")"
if [ "$BAD_STATUS" = "400" ]; then
  ok "query inválida devuelve 400"
else
  fail "query inválida devolvió HTTP inesperado: $BAD_STATUS"
fi

log "17. Resumen"

cat <<EOF
Smoke test v0.25.0 completado correctamente.

Variables usadas:
- BASE_URL=$BASE_URL
- TARGET=$TARGET
- TENANT_ID=$TENANT_ID
- PROJECT_ID=$PROJECT_ID
- SUBJECT=$SUBJECT
EOF
