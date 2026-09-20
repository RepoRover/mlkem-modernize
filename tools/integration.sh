#!/bin/sh
# Exercises the local demo stack, preserving its database. Run from repo root.
set -eu
export LOCAL_UID="${LOCAL_UID:-$(id -u)}" LOCAL_GID="${LOCAL_GID:-$(id -g)}"
unset MLKEM_KEY_ID
mkdir -p .local/material .local/integration
if [ -e .local/material/active/cloud-kem-002.pem ] || [ -e .local/material/rotation-backup.pem ]; then
  echo 'Start with only cloud-kem-001 active; restore any interrupted manual rotation first.' >&2
  exit 1
fi
docker compose build bootstrap integration device gateway cloud > .local/integration/build.log 2>&1
if [ ! -f .local/material/device.key ]; then
  docker compose run --rm bootstrap
fi
if docker compose run --rm bootstrap > .local/integration/bootstrap-refusal.log 2>&1; then
  echo 'Bootstrap unexpectedly overwrote existing secrets' >&2; exit 1
fi
docker compose config --format json | docker compose run --rm --no-deps -T --entrypoint python integration tools/check_deployment.py
docker compose stop device
docker compose up -d --wait gateway
docker compose run --rm integration
# Also test both TLS client paths against untrusted, expired and wrong-host certs.
docker compose run --rm --no-deps --entrypoint python integration -m pytest -q -p no:cacheprovider tests/test_tls.py

query="SELECT count(*) FROM observations WHERE device_id='weather-station-001' AND observed_on BETWEEN '2024-01-01' AND '2025-12-31'"
count_rows() { docker compose exec -T postgres psql -U weather -d weather -Atc "$query"; }
docker compose run --rm --no-deps -e MAX_CYCLES=2 -e SEND_INTERVAL_SECONDS=0 device > .local/integration/cycles.log 2>&1
test "$(count_rows)" = 731
docker compose run --rm --no-deps -e MAX_CYCLES=1 -e SEND_INTERVAL_SECONDS=0 device > .local/integration/replay.log 2>&1
test "$(count_rows)" = 731
for service in postgres cloud gateway; do
  docker compose restart "$service"
  docker compose up -d --wait gateway
  test "$(count_rows)" = 731
done

cloud_id=$(docker compose ps -q cloud)
cloud_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cloud_id")
docker compose run --rm --no-deps device python -c "import socket; s=socket.socket(); s.settimeout(2); assert s.connect_ex(('$cloud_ip',8443)) != 0; print('Device cannot route directly to Cloud')"

# A real Device stays alive across a Cloud outage, then completes without duplicates.
outage_id=''
restore() {
  if [ -n "$outage_id" ]; then docker rm -f "$outage_id" >/dev/null 2>&1 || true; fi
  if [ -f .local/material/rotation-backup.pem ]; then
    mv .local/material/rotation-backup.pem .local/material/active/cloud-kem-001.pem
  fi
  rm -f .local/material/active/cloud-kem-002.pem
  unset MLKEM_KEY_ID
  docker compose up -d --wait cloud gateway >/dev/null 2>&1 || true
  docker compose restart cloud >/dev/null 2>&1 || true
  docker compose up -d --wait gateway >/dev/null 2>&1 || true
}
trap restore EXIT
trap 'exit 1' INT TERM
docker compose stop cloud
outage_id=$(docker compose run -d --no-deps -e MAX_CYCLES=1 -e SEND_INTERVAL_SECONDS=0 device)
# Wait for bounded retries to reach Device; capped to avoid a hanging test.
tries=0
until docker logs "$outage_id" 2>&1 | grep -q event=delivery_retry; do
  tries=$((tries+1)); test "$tries" -lt 45; sleep 1
done
docker compose up -d --wait cloud
tries=0
while [ "$(docker inspect --format '{{.State.Running}}' "$outage_id")" = true ]; do
  tries=$((tries+1)); test "$tries" -lt 90; sleep 1
done
docker wait "$outage_id" > .local/integration/outage-exit.txt
test "$(docker inspect --format '{{.State.ExitCode}}' "$outage_id")" = 0
docker logs "$outage_id" > .local/integration/outage.log 2>&1
docker rm "$outage_id" >/dev/null
outage_id=''
test "$(count_rows)" = 731

cp .local/material/staged/cloud-kem-002.pem .local/material/active/cloud-kem-002.pem
docker compose restart cloud
docker compose up -d --wait gateway
docker compose run --rm --no-deps -e ROTATION_STAGE=overlap integration -k rotation
export MLKEM_KEY_ID=cloud-kem-002
docker compose up -d --wait gateway
docker compose run --rm --no-deps -e ROTATION_STAGE=overlap integration -k 'rotation or real_device'
mv .local/material/active/cloud-kem-001.pem .local/material/rotation-backup.pem
docker compose restart cloud
docker compose up -d --wait gateway
docker compose run --rm --no-deps -e ROTATION_STAGE=retired integration -k 'rotation or real_device'
docker compose logs --no-color gateway cloud > .local/integration/services.log
if grep -q AUDIT_SECRET_SENTINEL .local/integration/services.log; then
  echo 'Secret sentinel leaked to logs' >&2; exit 1
fi
printf 'Integration checks passed: 731 rows, replay, restarts, outage, TLS, rotation, isolation, logs.\n'
