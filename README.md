# mlkem-modernize

PQC migration of a legacy edge–cloud weather system.

**Current state: hop 2 (gateway → cloud) does hybrid post-quantum key
establishment with X25519 + ML-KEM-768.** Hop 1 (device → gateway) is still
classical, because the device is treated as non-upgradeable firmware.

> **The system as a whole is not post-quantum secure.** Hop 2 is. Traffic
> recorded on hop 1 today stays decryptable by a future quantum computer, and
> authentication on both hops is still ECDSA P-256. See
> [docs/MIGRATION.md](docs/MIGRATION.md) §2 for exactly what is and is not
> protected.

| Doc | Covers |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, message formats, handshake sequences, weaknesses W1–W20 |
| [MIGRATION.md](docs/MIGRATION.md) | migration phases, sunset criteria, the gateway as trust boundary |
| [TESTING.md](docs/TESTING.md) | test and measurement baseline, and what is hard to test |
| [CICD.md](docs/CICD.md) | pipeline stages, what each catches, secrets handling, known gaps |
| [DECISIONS.md](docs/DECISIONS.md) | every significant decision, with alternatives and known weaknesses |

## Crypto at a glance

| | Hop 1: device → gateway | Hop 2: gateway → cloud |
|---|---|---|
| Protocol | `wx-legacy/1` | `wx-hybrid/2` |
| Key establishment | static-static ECDH P-256 | **X25519 + ML-KEM-768** |
| Post-quantum | **no** | **yes** |
| Forward secrecy | none | yes |
| Authentication | implicit (pinned static key) | mutual ECDSA P-256 |
| Suite negotiation | none | yes, with downgrade protection |
| AEAD | AES-256-GCM | AES-256-GCM, separate key per direction |

ML-KEM is used for **key establishment only**, never to encrypt payloads.

## Run it

```bash
docker compose up --build
```

`keygen` writes development keys to a shared volume, then cloud → gateway →
device start in order. The device replays 366 daily readings from
`data/weather_data.csv`, one every 2 seconds, looping.

```bash
curl http://127.0.0.1:8000/readings?limit=5
curl http://127.0.0.1:8000/stats     # includes pqc.pqc_fraction
```

Fast run — the whole year in about 20 seconds, then stop:

```bash
docker compose -f docker-compose.yml -f docker-compose.fast.yml up --build
```

### PQC policy

`PQC_POLICY` controls hop 2 key establishment on each service.

| Value | Behaviour |
|---|---|
| `require` | Hybrid only. Classical peers get `403 downgrade_refused`. **Cloud default.** |
| `prefer` | Hybrid when possible; classical logged at WARNING and counted. **Gateway default.** |
| `classical-only` | Explicit opt-out. Logs a startup banner. |

Fallback to classical is never silent: it is logged, counted, and visible as
`pqc.pqc_fraction` on `/stats`.

```bash
# Phase 1 of the migration: observe, do not enforce
CLOUD_PQC_POLICY=prefer GATEWAY_PQC_POLICY=prefer docker compose up --build
```

### See what the backend actually does

```bash
python scripts/visualize_web.py          # local page on http://127.0.0.1:8420
python scripts/visualize.py              # same thing in the terminal, 7 steps
python scripts/visualize.py --step 3     # just the post-quantum handshake
```

Runs the real services in-process with every HTTP call tapped, and walks the
data path: both handshakes, the key schedule, one reading travelling end to end,
what gets rejected and why, and the resulting cloud state. Every byte count is
measured from that run, not quoted from the docs.

Both front-ends read the same `collect_trace()`, so they cannot disagree. The
page also serves the raw measurements at `/api/trace`. It binds to 127.0.0.1
only — it is a local diagnostic, not something to expose.

### See each migration phase

```bash
python scripts/demo_phases.py            # all phases
python scripts/demo_phases.py --phase 2a # the downgrade attack
```

Runs the real services in-process and prints what actually happens at each
phase — which suite is negotiated, what gets refused, what the metrics say.

## CI/CD

GitHub Actions: [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
Full rationale in [docs/CICD.md](docs/CICD.md).

| Stage | Tool | Catches |
|---|---|---|
| Lint | ruff | unused code, import drift, naive datetimes, insecure patterns |
| Type check | mypy | wrong types across same-shaped `bytes` parameters |
| Static security | bandit | insecure primitives, shell injection, SQL concatenation |
| Dependency scan | pip-audit | CVEs in the tree, including transitive |
| Tests | pytest | regressions; **fails under 85% coverage** |
| Build | buildx → GHCR | one SHA-tagged image for all three services |
| Image scan | trivy | vulnerable OS/library packages in the image |
| Integration | docker compose | keygen ordering, volumes, healthchecks, service DNS |
| Deploy | kind | missing Secret, bad env, probe never ready, DNS |
| Smoke test | `scripts/smoke_test.py` | **silent downgrade to classical** |

Run the same gates locally:

```bash
ruff check . && mypy && bandit -c pyproject.toml -r services scripts -ll
pip-audit -r requirements.txt
pytest --cov=services --cov-report=term-missing
python scripts/smoke_test.py --cloud-url http://127.0.0.1:8000
```

All tool configuration lives in `pyproject.toml`.

**Secrets:** no key material is committed. CI generates ephemeral keys at deploy
time into a Kubernetes Secret; they die with the cluster. Registry auth uses the
per-run `GITHUB_TOKEN`.

## Run the tests

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt   # Windows
# .venv/bin/pip install -r requirements-dev.txt               # Linux/macOS

.venv/Scripts/python -m pytest                  # 264 fast tests (~7 s), no Docker
.venv/Scripts/python -m pytest -m docker        # 11 integration tests on real containers
.venv/Scripts/python -m pytest -m ""            # all 275
.venv/Scripts/python -m pytest --cov=services --cov-report=term-missing
```

275 tests, 92% line coverage. Docker tests are opt-in and skip automatically if
Docker is unavailable.

## Benchmark

```bash
.venv/Scripts/python scripts/benchmark.py --label pqc-hybrid \
    --compare results/phase2-classical-baseline.json
```

Writes `results/pqc-hybrid-latest.{json,md}` with a before/after table.
Re-run it on whichever machine will produce the report's numbers — comparing
across machines is meaningless.

Measured cost of adding ML-KEM-768:

| | Classical | Hybrid | Delta |
|---|---:|---:|---:|
| hop 2 key establishment (crypto only) | 0.746 ms | 1.158 ms | +55% |
| hop 2 handshake bytes | 710 B | 3959 B | +458% |
| **per-message bytes** | **416 B** | **416 B** | **0%** |

The per-message row is the invariant: the KEM establishes a key and never
touches the payload.

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
| `PQC_POLICY` | `require` (cloud) / `prefer` (gateway) | gateway, cloud |
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
services/common/          wire format, crypto, handshakes, suites, parsing, validation
services/device/          simulated legacy firmware — hop 1 client (frozen)
services/gateway/         hop 1 server + hop 2 client
services/cloud/           hop 2 server + storage + read API
scripts/gen_keys.py       development key generation
scripts/benchmark.py      latency and message-size measurement
scripts/demo_phases.py    migration phase demonstration
scripts/visualize.py      step-by-step trace of the live data path (terminal)
scripts/visualize_web.py  the same trace as a local web page
scripts/smoke_test.py     post-deploy verification (asserts PQC, not just 200 OK)
deploy/k8s/               Kubernetes manifests for the test environment
.github/workflows/ci.yml  the CI/CD pipeline
pyproject.toml            ruff / mypy / bandit / coverage configuration
tests/                    275 tests (264 fast + 11 Docker)
results/                  benchmark baselines (*-latest.* committed for comparison)
docs/                     architecture, migration, testing, CI/CD, decision log
```

## Dependencies

`pip-audit` runs on every build and weekly on a schedule.

`cryptography` is **pinned exactly** (50.0.1). It is the only crypto dependency
and now supplies ML-KEM-768 as well as X25519, ECDH, ECDSA, HKDF and AES-GCM, so
an unreviewed upgrade could silently change primitive behaviour. ML-KEM needs
`cryptography >= 48` with an OpenSSL >= 3.5 backend; the 50.0.1 wheels ship
OpenSSL 4.0.2.

## Security note

The device hop deliberately has no forward secrecy and an unauthenticated
ServerHello. That is the point — it is the legacy state being migrated away
from. Do not copy it into anything new. Development keys are generated, never
committed.
