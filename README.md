# mlkem-modernize

PQC migration of a legacy edge–cloud weather system.

**Current state: the legacy baseline ("before").** Three services — a simulated
non-upgradeable device, an edge gateway, and a cloud service — passing real
weather readings over classical crypto. ML-KEM is not integrated yet.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component diagram,
message formats, handshake sequences and the weakness list (W1–W19),
[docs/TESTING.md](docs/TESTING.md) for the test and measurement baseline, and
[docs/DECISIONS.md](docs/DECISIONS.md) for why each choice was made.

## Run it

```bash
docker compose up --build
```

`keygen` writes development keys to a shared volume, then cloud → gateway →
device start in order. The device replays 366 daily readings from
`data/weather_data.csv`, one every 2 seconds, looping.

Read the data back:

```bash
curl http://127.0.0.1:8000/readings?limit=5
curl http://127.0.0.1:8000/stats
```

Fast run — the whole year in about 20 seconds, then stop:

```bash
docker compose -f docker-compose.yml -f docker-compose.fast.yml up --build
```

## Run the tests

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt   # Windows
# .venv/bin/pip install -r requirements-dev.txt               # Linux/macOS

.venv/Scripts/python -m pytest                  # 200 fast tests (~7 s), no Docker
.venv/Scripts/python -m pytest -m docker        # 9 integration tests on real containers
.venv/Scripts/python -m pytest -m ""            # all 209
.venv/Scripts/python -m pytest --cov=services --cov-report=term-missing
```

209 tests, 91% line coverage. Docker tests are opt-in and skip automatically if
Docker is unavailable. See [docs/TESTING.md](docs/TESTING.md) for what is
covered and — importantly — what is hard to test and why.

## Benchmark

```bash
.venv/Scripts/python scripts/benchmark.py
```

Writes `results/legacy-baseline-latest.json` and `.md`: handshake latency,
per-message latency and message-size overhead, so the PQC version can be
compared against it. Re-run it on the same machine that will produce the
after-measurement.

## Run without Docker

```bash
python scripts/gen_keys.py --out keys

KEYS_DIR=keys DB_PATH=/tmp/readings.db PORT=8000 python -m services.cloud.main
KEYS_DIR=keys CLOUD_URL=http://127.0.0.1:8000 PORT=8001 python -m services.gateway.main
KEYS_DIR=keys GATEWAY_URL=http://127.0.0.1:8001 REPLAY_INTERVAL_SECONDS=0.1 \
  MAX_RECORDS=20 LOOP_FOREVER=false python -m services.device.main
```

## Configuration

| Variable | Default | Applies to |
|---|---|---|
| `REPLAY_INTERVAL_SECONDS` | `2.0` | device |
| `LOOP_FOREVER` | `true` | device |
| `MAX_RECORDS` | `0` (unlimited) | device |
| `MAX_RECORDS_PER_SESSION` | `100` | gateway, cloud |
| `SESSION_TTL_SECONDS` | `600` | gateway, cloud |
| `LOG_LEVEL` | `info` | all |
| `KEYS_DIR` | `/keys` | all |

## Layout

```
data/weather_data.csv     Open-Meteo daily export (two CSV blocks, 366 records)
services/common/          wire format, crypto, handshakes, parsing, validation
services/device/          simulated legacy firmware — hop 1 client
services/gateway/         hop 1 server + hop 2 client
services/cloud/           hop 2 server + storage + read API
scripts/gen_keys.py       development key generation
scripts/benchmark.py      latency and message-size baseline
tests/                    209 tests (200 fast + 9 Docker)
results/                  benchmark baseline (*-latest.* committed for comparison)
docs/                     architecture, testing report, decision log
```

## Security note

The device hop deliberately has no forward secrecy and an unauthenticated
ServerHello. That is the point — it is the legacy state being migrated away
from. Do not copy it into anything new. Development keys are generated, never
committed.
