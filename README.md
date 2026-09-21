# ML-KEM Modernize

Educational Device → trusted Gateway → Cloud → PostgreSQL weather simulation.
Device uses AES-256-GCM over TLS 1.2; Gateway forwards an ML-KEM-768/HKDF/AES-GCM
envelope over TLS 1.3. Gateway sees plaintext by design. This is **not** end-to-end
post-quantum encryption or a production-security claim.

## Start with Docker

Run from this directory as a non-root user. Only Docker with Compose and a POSIX
shell are required; Python and uv are installed inside the images.

Create the gitignored, machine-local Compose environment once; Compose loads
`.env` automatically:

```sh
printf 'LOCAL_UID=%s\nLOCAL_GID=%s\n' "$(id -u)" "$(id -g)" > .env
mkdir -p .local/material
docker compose run --build --rm bootstrap
docker compose up --build -d --wait
docker compose logs -f device gateway cloud
```

Bootstrap prints paths, not secrets, and refuses to overwrite an existing material
directory. `--force` explicitly **replaces all contents** of that directory and
invalidates previous credentials. Do not use it against a running stack or an
existing database volume: stop the stack and explicitly reset disposable demo data
first, or retain the original database credentials. Certificates last 30 days;
re-bootstrap is a development reset, not an automated renewal procedure.

Generated material, reports, and logs live under gitignored `.local/` and are
excluded from Docker build contexts. The directory is private (0700), private keys
and tokens are 0600. PostgreSQL's password file is readable by its distinct container
UID, but protected by the enclosing private directory on the host.

Runtime services receive only their own read-only secret mounts. CA signing and
staged rotation keys are never mounted into runtime services. Python containers
run as your non-root UID/GID (image default: 10001), with read-only root filesystems,
dropped capabilities, and no-new-privileges. PostgreSQL's official entrypoint drops
to its database user. **No ports are published to the host.** Two internal networks
prevent Device from routing directly to Cloud or PostgreSQL.

Useful commands:

```sh
# Inspect committed data without adding a public read API.
docker compose exec postgres psql -U weather -d weather -c 'SELECT count(*) FROM observations'
# Finite replay, useful for demonstrations. Stop the continuous Device first.
docker compose stop device
docker compose run --rm -e MAX_CYCLES=2 -e SEND_INTERVAL_SECONDS=0 device
# Stop containers; named PostgreSQL volume and local secrets are retained.
docker compose down
```

Normal pacing defaults to five minutes. Set `SEND_INTERVAL_SECONDS` in `.env`
to override the 300-second interval.
A finite cycle replays 366 observations for 2024, then 365 for 2025. Restarts begin
at cycle zero; first accepted write wins and replay does not add duplicate rows.
Device is limited to 0.25 CPU and 128 MiB. This does not emulate ESP8266 hardware.

Application logs are JSON Lines on container stdout/stderr. Each line has a stable
`timestamp`, `service`, `level`, `logger`, and `message`; application events also
carry allowlisted fields such as `event`, `observation_id`, and `result`. For
example:

```sh
docker compose logs --no-log-prefix gateway | jq -Rr 'fromjson? | select(.event == "observation_accepted")'
```

## Optional live observability

The opt-in Compose overlay runs OpenTelemetry collectors and Grafana's local LGTM
demo image (Loki logs, Grafana dashboards, Tempo traces, and Prometheus metrics).
It auto-instruments FastAPI, HTTPX, and asyncpg and adds safe spans around the
cryptographic and storage stages. Start it instead of the base `up` command:

```sh
docker compose -f docker-compose.yml -f docker-compose.observability.yml up --build -d
```

Open <http://127.0.0.1:3000> and sign in with `admin` / `admin`. The provisioned
**ML-KEM Live Pipeline** dashboard refreshes every two seconds. Search live logs
by `observation_id`; select a `trace_id` or use **Explore → Tempo** to inspect the
Device → Gateway → Cloud waterfall and service graph. Generate a short, clear demo
with:

```sh
docker compose -f docker-compose.yml -f docker-compose.observability.yml stop device
docker compose -f docker-compose.yml -f docker-compose.observability.yml run --rm \
  -e MAX_CYCLES=1 -e SEND_INTERVAL_SECONDS=0 device
```

The two segment-local collectors preserve the application's Device/Cloud network
separation. The LGTM backend bridges the internal observability network to a
separate dashboard network; only Grafana is published, and only on loopback.
Telemetry is fail-open and carries
bounded identifiers, outcomes, timings, and algorithm names—not payloads,
ciphertext, credentials, or key material. The overlay is a development/demo tool,
not a production observability deployment.

Stop the observable stack with the same file set. Add `-v` only when you intend
to delete both PostgreSQL and observability data:

```sh
docker compose -f docker-compose.yml -f docker-compose.observability.yml down
```

## Verification

```sh
# End-to-end checks against the local demo stack (stops the continuous Device).
sh tools/integration.sh
# Informational timings, peak process RSS, and Docker image sizes.
sh tools/benchmark.sh
```

The integration script requires an initially unrotated key directory. It builds the
images, checks bootstrap refusal, validates rendered deployment boundaries and
request-deadline margin, then exercises real TLS and PostgreSQL: 731 observations,
replay, independent restarts, database lock/pool exhaustion recovery, Cloud outage
and Device retry, certificate failures on both hops, key overlap/switch/retirement,
network isolation, and log sanitization. Rotation state is restored on exit; the
stack and database remain available. Test records dated 2050 are separate from the
731 source-year records. Logs are in `.local/integration/`.

For local development with Python 3.14.7+ and uv:

```sh
uv sync --all-packages --all-groups --locked
uv run --no-sync pytest -q
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync pyright .
```

The normal pytest command skips Docker-dependent integration tests; it includes
real loopback TLS certificate-failure tests. `sh tools/integration.sh` runs the
Docker tests explicitly. The `tools` Compose profile contains only one-shot tools,
not additional continuously running services. Its integration container deliberately
has wider test-only secret access to exercise rotation.

## Bounds and operational behavior

- Request bodies: 32 KiB, five-second upload deadline, checked before JSON parsing.
- Uvicorn: at most 64 concurrent connections/tasks, backlog 128, ten-second graceful
  shutdown deadline. Upload timeouts return generic 400; overload returns 503.
- Outbound responses: streamed, at most 32 KiB for every status. Compressed responses
  are rejected before decoding, preventing decompression-based memory amplification.
- Gateway: eight seconds per Cloud attempt, 30 seconds total forwarding deadline.
  Device: 35-second request deadline. `tools/check_deployment.py` verifies a margin
  of at least five seconds in the rendered Compose configuration.
- Cloud: asyncpg pool of at most four connections; two-second connection/acquisition
  and lock limits; three-second SQL command/statement and health limits; five-second
  total insert deadline including commit; three-second pool shutdown grace before
  forced termination. Gateway/Device retries recover from transient database errors.
- Bearer credentials are ASCII token syntax, compared timing-safely. Validation logs
  contain bounded error codes, not attacker-controlled field names or values.

The installed service commands are `mlkem-device`, `mlkem-gateway`, and
`mlkem-cloud`; the equivalent module entry points are `python -m device.main`,
`python -m gateway.main`, and `python -m cloud.main`. Each workspace member is an
independently buildable package, so service execution does not depend on `PYTHONPATH`
or the current directory. `create_app()` is the explicit ASGI factory; the supported
main commands configure TLS and connection limits. Gateway's `cloud_aad()` helper
intentionally supports independent protocol-verification tests.

## Manual ML-KEM rotation

Bootstrap places only `cloud-kem-001.pem` in `active/`; the next private key is in
`staged/`. Keep your UID/GID exports from startup.

```sh
cp .local/material/staged/cloud-kem-002.pem .local/material/active/
docker compose restart cloud
docker compose up -d --wait gateway
docker compose run --rm -e ROTATION_STAGE=overlap integration -k rotation
export MLKEM_KEY_ID=cloud-kem-002
docker compose up -d --wait gateway
# After verifying new-key traffic, retire the old key (keep an offline backup).
mv .local/material/active/cloud-kem-001.pem .local/material/retired-cloud-kem-001.pem
docker compose restart cloud
docker compose up -d --wait gateway
docker compose run --rm -e ROTATION_STAGE=retired integration -k rotation
```

Keep `MLKEM_KEY_ID=cloud-kem-002` in the environment for subsequent Compose commands.
Never remove the last active key. Rotation requires restarts; there is no mutable
key-management endpoint.

See [requirements](docs/FRD.md), [benchmark sample](docs/BENCHMARK.md), and
[AI usage and verification record](docs/AI_USAGE.md).
