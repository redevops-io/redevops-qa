#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# End-to-end check of the standalone image through Compose, from an empty directory that holds ONLY the two documented files (compose.yaml and a .env made from .env.example):
# refuses without a token, health and readiness, 401 without and with a wrong token, real runs through the API (each plan x defect given), the report and the evidence bundle,
# `redevops-qa verify` of the downloaded bundle in a second container, and data that survives a restart and a down/up. Nothing leaves the machine.
#
#   QA_SMOKE_IMAGE=redevops-qa QA_SMOKE_TAG=local deploy/standalone/smoke.sh
#   QA_SMOKE_RUNS="demo:none demo:discount demo:settings" ...   (default; on a host that cannot provide the Robot lane's kernel layers use "browser:none browser:settings robot-not-enforced:none")
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd -P)"
image="${QA_SMOKE_IMAGE:?set QA_SMOKE_IMAGE}"; tag="${QA_SMOKE_TAG:?set QA_SMOKE_TAG}"
runs="${QA_SMOKE_RUNS:-demo:none demo:discount demo:settings}"
project="qa-smoke-$$"
work="$(mktemp -d)"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
token="$(openssl rand -hex 32)"
cleanup() { docker compose -p "$project" -f "$work/compose.yaml" --env-file "$work/.env" down -v >/dev/null 2>&1 || true; rm -f "$work"/compose.yaml "$work"/.env "$work"/bundle.tar "$work"/report.html; rmdir "$work" 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "SMOKE FAIL: $*" >&2; docker compose -p "$project" -f "$work/compose.yaml" --env-file "$work/.env" logs --no-color 2>&1 | tail -30 >&2 || true; exit 1; }

cp "$here/compose.yaml" "$here/.env.example" "$work/"
cp "$work/.env.example" "$work/.env"; chmod 600 "$work/.env"
dc() { docker compose -p "$project" -f "$work/compose.yaml" --env-file "$work/.env" "$@"; }

echo "== compose refuses to start without a token and without a tag"
if QA_IMAGE="$image" dc config >/dev/null 2>&1; then fail "compose accepted an empty .env"; fi
{ echo "QA_IMAGE=$image"; echo "QA_IMAGE_TAG=$tag"; echo "QA_PORT=$port"; echo "QA_SERVICE_TOKEN="; } > "$work/.env"
if dc config >/dev/null 2>&1; then fail "compose accepted an empty token"; fi
sed -i.bak "s/^QA_SERVICE_TOKEN=.*/QA_SERVICE_TOKEN=$token/" "$work/.env"; rm -f "$work/.env.bak"

echo "== up"
dc up -d --wait --wait-timeout 120 >/dev/null 2>&1 || fail "compose up --wait"
base="http://127.0.0.1:$port"
api() { curl -sS --max-time 60 -H "Authorization: Bearer $token" "$@"; }
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
[ "$(code "$base/healthz")" = 200 ] || fail "healthz"
[ "$(code "$base/readyz")" = 200 ] || fail "readyz"
[ "$(code "$base/v1/info")" = 401 ] || fail "info without a token is not 401"
[ "$(code -H "Authorization: Bearer ${token}x" "$base/v1/info")" = 401 ] || fail "wrong token is not 401"
[ "$(code -H "Authorization: Bearer $token" "$base/v1/info")" = 200 ] || fail "right token is not 200"
echo "ok: probes open, every other path 401 without the token"

json() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
last_id=""
for spec in $runs; do
  plan="${spec%%:*}"; defect="${spec##*:}"
  echo "== run plan=$plan defect=$defect"
  id="$(api -X POST -d "{\"plan\":\"$plan\",\"defect\":\"$defect\"}" "$base/v1/runs" | json 'd["id"]')" || fail "start $spec"
  for _ in $(seq 1 120); do
    state="$(api "$base/v1/runs/$id" | json 'd["state"]')"; [ "$state" = running ] || break; sleep 3
  done
  outcome="$(api "$base/v1/runs/$id" | json 'str(d["outcome"])+" exit="+str(d["exit_code"])')"
  want="VERIFIED exit=0"; [ "$defect" = none ] || want="FAILED exit=1"
  [ "$outcome" = "$want" ] || { api "$base/v1/runs/$id/output" >&2 || true; fail "$spec ended $outcome, wanted $want"; }
  echo "ok: $spec -> $outcome"
  last_id="$id"; last_defect="$defect"
done

echo "== report, bundle, verification in a second container"
[ "$(code -H "Authorization: Bearer $token" "$base/v1/runs/$last_id/report?format=html")" = 200 ] || fail "html report"
api "$base/v1/runs/$last_id/report?format=html" -o "$work/report.html"; grep -q "QA evidence bundle" "$work/report.html" || fail "report content"
api "$base/v1/runs/$last_id/bundle.tar" -o "$work/bundle.tar"
vol="$(mktemp -d)"
tar -xf "$work/bundle.tar" -C "$vol"
# verify exits like the run did (0 VERIFIED, 1 FAILED) when it accepts the evidence; exit 5 would mean the evidence itself was rejected
want_exit=0; [ "$last_defect" = none ] || want_exit=1
status=0; verdict="$(docker run --rm --network none -v "$vol:/ev:ro" "$image:$tag" redevops-qa verify "/ev/$last_id")" || status=$?
[ "$status" = "$want_exit" ] && echo "$verdict" | grep -q "ACCEPTED" || { echo "$verdict" >&2; fail "offline verify of the downloaded bundle (exit $status, wanted $want_exit with ACCEPTED)"; }
echo "$verdict" | head -3
rm -r "$vol"

echo "== persistence"
before="$(api "$base/v1/runs" | json 'len(d["runs"])')"
dc restart >/dev/null 2>&1; dc up -d --wait --wait-timeout 120 >/dev/null 2>&1 || fail "restart"
[ "$(api "$base/v1/runs" | json 'len(d["runs"])')" = "$before" ] || fail "runs lost after restart"
dc down >/dev/null 2>&1; dc up -d --wait --wait-timeout 120 >/dev/null 2>&1 || fail "down/up"
[ "$(api "$base/v1/runs" | json 'len(d["runs"])')" = "$before" ] || fail "runs lost after down/up"
echo "ok: $before run(s) kept across restart and down/up"
echo "SMOKE OK"
