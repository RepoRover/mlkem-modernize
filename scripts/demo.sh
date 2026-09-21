#!/usr/bin/env bash
# Live demonstration of the post-quantum migration.
#
#   ./scripts/demo.sh            narrated, pauses between acts
#   ./scripts/demo.sh --no-pause runs straight through
#
# Build the images before presenting: ./scripts/demo.sh --warmup

set -euo pipefail
cd "$(dirname "$0")/.."

BASELINE=deploy/docker-compose.baseline.yml
MODERN=deploy/docker-compose.yml
PAUSE=1
TRANSMIT=14

for arg in "$@"; do
  case "$arg" in
    --no-pause) PAUSE=0 ;;
    --warmup)
      echo "Building every image so the demo does not wait on Docker..."
      docker compose -f "$BASELINE" --profile attack build
      docker compose -f "$MODERN" --profile attack build
      echo "Ready. Run ./scripts/demo.sh when the meeting starts."
      exit 0 ;;
  esac
done

banner() {
  printf '\n\033[1m%s\033[0m\n' "════════════════════════════════════════════════════════════════"
  printf '\033[1m  %s\033[0m\n' "$1"
  printf '\033[1m%s\033[0m\n\n' "════════════════════════════════════════════════════════════════"
}
step() { printf '\033[36m→ %s\033[0m\n' "$1"; }
hold() { [ "$PAUSE" = "1" ] && { printf '\n\033[2m   [Enter to continue]\033[0m'; read -r _; } || true; }

cleanup() {
  docker compose -f "$BASELINE" down -v >/dev/null 2>&1 || true
  docker compose -f "$MODERN"   down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

pretty_device_logs() {
  docker compose -f "$1" logs legacy-device 2>&1 | python3 -c "
import sys, json
for line in sys.stdin:
    _, _, payload = line.partition('| ')
    try: r = json.loads(payload)
    except ValueError: continue
    if 'mlkem_available' in r:
        print('   python {}  cryptography {}  ML-KEM available: {}'.format(
            r['python_version'], r['cryptography_version'], r['mlkem_available']))
    elif r['level'] == 'WARNING':
        print('   WARNING  {}'.format(r['message'][:78]))
    elif 'seq' in r and r['seq'] < 4:
        print('   sent reading  seq={}  date={}'.format(r['seq'], r.get('date')))
" | head -8
}

# ---------------------------------------------------------------- ACT 1
banner "ACT 1 — The legacy system we started with"
step "Starting the baseline: device, gateway, cloud. Every link uses RSA."
docker compose -f "$BASELINE" up -d >/dev/null 2>&1
sleep "$TRANSMIT"

step "What the device says about itself at boot:"
pretty_device_logs "$BASELINE"

step "What reached the cloud:"
curl -s 'http://127.0.0.1:8000/readings?limit=1' | python3 -c "
import sys, json; d = json.load(sys.stdin)
print('   readings stored:', d['total'])
for suite, n in d['by_suite'].items(): print('   suite in use  :', suite, '->', n, 'frames')
print('   quantum-vulnerable frames:', d['quantum_vulnerable_frames'])
r = d['readings'][0]
print('   latest reading:', r['date'], r['temp_max_c'], 'C max,', r['precipitation_mm'], 'mm rain')
"
hold

# ---------------------------------------------------------------- ACT 2
banner "ACT 2 — The attack, against the legacy system"
step "A wiretap recorded both links. The attacker is now handed the RSA private"
step "keys, which is what a working quantum computer would eventually produce."
docker compose -f "$BASELINE" --profile attack run --rm -T harvester 2>/dev/null | tail -28
hold
cleanup

# ---------------------------------------------------------------- ACT 3
banner "ACT 3 — The same device, talking to a modernized gateway"
step "Starting the modernized stack. The device image is byte-for-byte identical."
docker compose -f "$MODERN" up -d >/dev/null 2>&1
sleep "$TRANSMIT"

step "The gateway is now brokering between two different suites:"
curl -s http://127.0.0.1:8080/capabilities | python3 -c "
import sys, json; d = json.load(sys.stdin)
print('   device  -> gateway :', d['downstream_suite'])
print('   gateway -> cloud   :', d['upstream_suite'])
print('   brokering between suites:', d['brokering'])
"

step "And the cloud now refuses the old suite entirely:"
printf '   GET /legacy/pubkey -> HTTP '
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/legacy/pubkey
curl -s 'http://127.0.0.1:8000/readings?limit=1' | python3 -c "
import sys, json; d = json.load(sys.stdin)
print('   readings stored:', d['total'])
for suite, n in d['by_suite'].items(): print('   suite in use  :', suite, '->', n, 'frames')
print('   quantum-vulnerable frames:', d['quantum_vulnerable_frames'])
"
hold

# ---------------------------------------------------------------- ACT 4
banner "ACT 4 — The identical attack, against the modernized system"
step "Same wiretap, same attacker, same keys handed over."
docker compose -f "$MODERN" --profile attack run --rm -T harvester 2>/dev/null | tail -26

banner "What this showed"
cat <<'SUMMARY'
   Baseline    edge      COMPROMISED   100% of frames read
               backbone  COMPROMISED   100% of frames read

   Modernized  edge      COMPROMISED   100% of frames read  <- unchanged, by design
               backbone  RESISTED        0% of frames read

   The device was never touched. The gateway terminates its obsolete session and
   opens a separate ML-KEM-768 + X25519 session to the cloud.

   The edge link stays readable because the device is frozen firmware with no
   update path. That is the honest limit of brokered migration, and the test
   suite asserts it rather than hiding it.
SUMMARY
echo
