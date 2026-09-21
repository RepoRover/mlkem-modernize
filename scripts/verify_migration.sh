#!/usr/bin/env bash
# Verify end to end that the migration actually holds.
#
# Brings up a stack, lets the device transmit, then runs the passive attacker
# over the captured traffic and asserts the expected verdict for each link.
#
#   ./scripts/verify_migration.sh baseline   -> both links must be readable
#   ./scripts/verify_migration.sh modern     -> only the device link may be
#
# Deliberately avoids bash 4 syntax so it runs on a stock macOS shell.

set -euo pipefail

MODE="${1:-modern}"
RUN_SECONDS="${2:-20}"
cd "$(dirname "$0")/.."

case "$MODE" in
  baseline) COMPOSE="deploy/docker-compose.baseline.yml" ;;
  modern)   COMPOSE="deploy/docker-compose.yml" ;;
  *) echo "usage: $0 [baseline|modern] [seconds]" >&2; exit 2 ;;
esac

EVIDENCE_DIR="$(mktemp -d)"
cleanup() {
  docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
  rm -rf "$EVIDENCE_DIR"
}
trap cleanup EXIT

echo "==> building images"
# The attacker sits in the "attack" profile, so `up --build` skips it and a
# stale harvester image would silently be used.
docker compose -f "$COMPOSE" --profile attack build >/dev/null 2>&1

echo "==> starting the $MODE stack"
docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
docker compose -f "$COMPOSE" up -d >/dev/null 2>&1

echo "==> letting the device transmit for ${RUN_SECONDS}s"
sleep "$RUN_SECONDS"

echo "==> collecting strict attack and cloud-storage evidence"
docker compose -f "$COMPOSE" --profile attack run --rm -T harvester --format json \
    >"$EVIDENCE_DIR/attack.json" 2>/dev/null
python3 - <<'PY' >"$EVIDENCE_DIR/cloud.json"
import urllib.request
with urllib.request.urlopen("http://127.0.0.1:8000/readings?limit=1", timeout=5) as response:
    print(response.read().decode("utf-8"))
PY
python3 scripts/check_attack_report.py \
    "$MODE" "$EVIDENCE_DIR/attack.json" "$EVIDENCE_DIR/cloud.json"
