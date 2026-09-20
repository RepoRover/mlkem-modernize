# AI Usage Log

## Strict Pyright remediation

### Prompt

> I just introduced strict pyright mode. This causes things to fail. Make sure all files pass with the strict mode. Dont use ignore comments fix the actuall issues, no bandaids

### Result and decisions

- Preserved strict mode and all-file coverage without exclusions or relaxed diagnostics. Added `asyncpg-stubs` as a development-only dependency and updated the lockfile.
- Replaced opaque file/key objects with concrete `Path` and supported private-key types, annotated fixtures/callbacks and benchmark collections, and used `AsyncGenerator` for lifespan context managers.
- Replaced response-body `Any`/untyped dictionary access with exhaustive structural matching of untrusted objects.
- Removed all existing type-ignore comments. Settings now expose an explicit `from_environment()` factory that validates an environment snapshot through Pydantic and the existing aliases; no required-field defaults, unchecked constructors, or casts were added.
- Reworked tests to use real forwarding dependencies, fully validated settings, public HTTP endpoints, actual pool lifecycle methods, and concurrent database inserts rather than private helper/pool access or incomplete model construction. Added environment tests proving required fields, invalid identifiers, nonexistent files, and defaults are still validated.

### Verification

- `uvx pyright`: zero errors, warnings, or informational diagnostics in strict mode.
- `.venv/bin/python -m pytest -q`: **45 passed, 5 skipped**; Docker-dependent tests run separately.
- `sh tools/integration.sh`: passed, including all real-stack tests, six real TLS rejection tests, 731 rows, replay, restarts, outage recovery, rotation, and isolation checks. While converting the pool test to a black-box concurrency test, detected PostgreSQL's transaction-cached activity snapshot and explicitly refreshed it before each observation; the corrected test passed against PostgreSQL.
- Ruff lint/format and `git diff --check`: passed.
- Source scan: no type-ignore comments, `Any` annotations, casts, or `model_construct` calls remain.
- Stopped verification containers without deleting the retained local database or credentials.

## 2026-09-20 — Audit remediation

### Prompt

> Perform a through audit of the current implementation. Identify security issues, performance issues, dead code and implementation issues. Report back any findings ranking them based on priority from 1-10.

> Record this prompt and fix all the issues

### Relevant result

Addressed all 13 audit findings:

1. Added Compose deployment, dependency health checks, PostgreSQL schema initialization/persistent volume, separate internal networks, per-service secret mounts, Device limits, and a self-contained bootstrap image. Documented startup and recovery.
2. Bounded database connection acquisition, commands/statements, locks, total inserts, readiness, and shutdown. Added pool lifecycle management.
3. Replaced attacker-controlled validation locations with bounded library error codes.
4. Added five-second upload deadlines and Uvicorn concurrency/backlog/shutdown limits; checked chunks before appending.
5. Added security regressions, real loopback TLS rejection tests, and Docker integration automation for PostgreSQL, full finite Device cycles, replay, independent restarts, outage recovery, rotation, network boundaries, and sanitized logs.
6. Streamed and bounded all Device/Gateway upstream responses before parsing. Explicitly rejected compression before decoding.
7. Reused a bounded four-connection asyncpg pool rather than opening a connection for each observation/health check.
8. Validated ASCII bearer syntax at provisioning load and safely compared supplied credentials; malformed non-ASCII headers now return 401.
9. Excluded generated material and build/test artifacts with `.gitignore` and `.dockerignore`.
10. Added non-root image users; Compose uses the invoking user's non-root UID/GID, read-only application filesystems, dropped capabilities, and no-new-privileges. PostgreSQL uses its official privilege-dropping entrypoint.
11. Added repeatable crypto/RSS/image-size benchmarking and a checked-in sample report.
12. Applied the ASCII protocol identifier constraint to private-key filenames.
13. Removed redundant module-level application instances and an unreachable JSONDecodeError handling branch. Retained and explicitly documented the two compatibility launchers and protocol-verification AAD helper rather than deleting useful entry points/test support.

### Decisions

- Used asyncpg's built-in pool: no new runtime dependency or shared framework package.
- Kept secrets in a private gitignored directory. Bootstrap refuses overwrite unless `--force`; force is documented as a destructive development credential reset, not a migration.
- Kept CA signing and staged keys out of runtime mounts. Only the explicit integration tool has wider test-only access.
- Used fixed conservative database/server resource bounds for this single-device PoC. Rendered deployment validation checks the Device/Gateway timeout margin and isolation settings.
- Recorded the original audit request and this remediation request verbatim above. Implementation was performed directly without delegation.

### Verification

- `.venv/bin/python -m pytest -q`: **42 passed, 5 skipped**; skipped tests require the explicit Compose integration stack.
- `uvx ruff check .`, `uvx ruff format --check .`, and `uvx pyright`: passed; Pyright reports zero errors/warnings.
- `git diff --check`: passed.
- Built all three runtime application images and the bootstrap/integration/benchmark tools.
- `sh tools/integration.sh`: passed twice after deployment fixes, including the final script. Five real-stack pytest checks plus six real TLS rejection checks passed; explicit overlap/new-key/retired-key tests passed. Verified **731 source-year rows**, no increase on replay, persistence across PostgreSQL/Cloud/Gateway restarts, Device completion after a Cloud outage, database lock/pool exhaustion recovery, no direct Device-to-Cloud route, deadline/configuration/secret-mount checks, and absence of the injected secret sentinel in service logs.
- `sh tools/benchmark.sh`: passed with 1,000 measured operations per primitive/envelope after 20 warm-ups. Sample environment/results are in `docs/BENCHMARK.md`; raw output is under `.local/benchmarks/`.
- Initial verification found a rendered Compose memory value represented as a string; adjusted the deployment check to normalize it before comparison. Formatting/type errors in new tests were corrected before final checks.

### Limitations and retained state

This remains an educational PoC, not a production security certification. Benchmarks exclude network/database latency and do not emulate ESP8266 timing. No dependency-CVE scan or sustained adversarial load test was performed. Generated credentials, test logs, and the named PostgreSQL demo volume are local and untracked; runtime containers were stopped after verification without deleting data.

## 2026-09-20 — Cloud service implementation

### Prompt

> `@GOAL.md @docs/PRD.md @docs/FRD.md` The legacy and gateway should now have been implemented. Go ahead and implement the cloud service.

### Relevant result

Implemented the Cloud HTTPS application with bearer authentication before parsing or cryptographic work, bounded strict envelope validation, ML-KEM-768 key selection/decapsulation, HKDF-SHA-256 and AES-256-GCM decryption, plaintext observation validation, and idempotent PostgreSQL persistence. Added database-aware health reporting, current/previous key-directory loading for manual rotation, TLS 1.3 service startup, schema SQL, a standalone Docker image, and Cloud protocol tests.

### Decisions

- Used PEM PKCS#8 ML-KEM private keys named by validated key ID and loaded all active keys at startup to support rotation overlap.
- Used short-lived asyncpg connections and one transaction per request, avoiding an additional pool dependency for this PoC.
- Kept Cloud protocol models independent from Gateway models; cross-service tests generate envelopes through Gateway code and consume them through Cloud.
- Returned generic errors and logged only allowlisted identifiers/outcomes rather than payloads or cryptographic details.

### Verification

- `uv run pytest -q`: 14 passed after `uv sync --all-packages`.
- `uvx ruff check .` and `uvx ruff format --check .`: passed.
- `uvx pyright`: passed with zero errors.
- Built `cloud/Dockerfile` successfully.

## 2026-09-20 — Gateway implementation and Device integration

### Prompt

> `@GOAL.md @docs/PRD.md @docs/FRD.md`. The legacy device should now be implemented, implement the gateway and make sure its integration works with the legacy device.

### Relevant result

Implemented the Gateway HTTPS application with bounded request parsing, strict Device-envelope validation, AES-256-GCM authentication/decryption, plaintext Observation validation, fresh ML-KEM-768 encapsulation and HKDF/AES-256-GCM Cloud envelopes, bearer-authenticated Cloud forwarding, bounded retry/deadline behavior, health reporting, sanitized logs, validated startup material, and a standalone Docker image.

Added an integration test that invokes the existing Device delivery code against the Gateway ASGI application, decrypts the forwarded envelope with a test Cloud ML-KEM private key, and verifies that a transient Cloud failure causes a fresh encapsulation before successful Device acknowledgement. Additional checks cover Device ciphertext tampering and permanent Cloud rejection propagation.

### Decisions

- Kept Gateway code in a dedicated `gateway` package with focused configuration, model, cryptography, forwarding, API, and process-entry modules.
- Loaded a raw 1,184-byte pinned ML-KEM-768 public key and failed startup when ML-KEM or local key/TLS material is invalid.
- Kept Device and Gateway models separate, as the requirements prohibit introducing a shared framework package; wire-level integration tests enforce compatibility.
- Used dependency-injected HTTPX transports for deterministic integration coverage without implementing the still-separate Cloud service in this change.

### Verification

- `uv run pytest -q`: 11 passed.
- `uvx ruff check .` and `uvx ruff format --check .`: passed.
- `uvx pyright`: passed with zero errors.
- Built `gateway/Dockerfile` successfully.
- Ran an ML-KEM-768 encapsulation/decapsulation self-check and imported the Gateway application inside the built image.

## 2026-09-20 — Legacy Device modularization

### Prompt

> We should not code application logic inside of `__init__.py`; create a file `main.py` and modular, maintainable code where possible.

### Relevant result

Moved the process entry point and orchestration to `main.py`; separated settings, models, CSV/calendar processing, cryptography, delivery/retry behavior, and safe errors into focused modules. `__init__.py` now contains only the package docstring, and the console entry point targets `device.main:main`.

### Verification

- `uv run prek run --all-files`: passed.
- `uv run pytest -q`: 7 passed.
- Rebuilt the Device image and verified both the console script and `python -m device.main` entry points.

## 2026-09-20 — Legacy Device implementation

### Prompt

> `@docs/FRD.md @docs/PRD.md @GOAL.md` Implement the Legacy device.

### Relevant result

Implemented the Device CLI with validated environment settings, two-section CSV parsing, calendar-year cycling, AES-256-GCM envelopes, TLS-1.2-only HTTP delivery, retry/permanent-failure handling, safe lifecycle logging, unit tests, and a standalone Docker image.

### Decisions

- Used the standard `csv`, `ssl`, `asyncio`, and `zoneinfo` modules plus the required Pydantic, HTTPX, and `cryptography` dependencies.
- Kept retries in memory and regenerated envelopes, as Gateway/Cloud idempotency is based on observation ID.
- Added no checkpoint, queue, device server, or shared framework package.

### Verification

- `uv run pytest -q`: 7 passed.
- Ruff format/lint and Pyright: passed.
- Parsed all 366 supplied source rows; cycle one produced 365 rows after skipping February 29.
- Built `device/Dockerfile`; the resulting container runs Python 3.14.7 and fails safely when required settings are absent.

## PRD and FRD review corrections

### Prompt

> Review the @docs/PRD.md and @docs/FRD.md
> Fix it.

### Relevant result

Updated both requirements documents to distinguish permanent upstream and TLS verification failures from transient retries, reject datasets without valid observations, coordinate request deadlines, restrict secret mounts by service, preserve source timezone metadata explicitly, sanitize exception logs, and define containerized bootstrap. Extended the FRD verification plan for these requirements.

### Verification

Checked the edited requirements for consistency and the Markdown for whitespace errors. These are documentation changes; implementation and runtime verification remain pending.

## 2026-09-20 — PRD and FRD

### Prompt

> `@GOAL.md` This is the task. Lets convert the idea into a PRD and FRD to be developed. Have a discussion fill in the technical and knowledge gaps.

### Relevant result

AI-assisted discussion and research produced:

- [`PRD.md`](PRD.md): product scope, requirements, success criteria, and limitations.
- [`FRD.md`](FRD.md): architecture, data contracts, cryptographic flow, persistence, deployment, and verification plan.

The resulting design uses a trusted Gateway to translate Device AES-256-GCM traffic into an ML-KEM-768-derived AES-256-GCM envelope for Cloud.

### Decisions

**Accepted**

- One simulated Device using TLS 1.2 and a provisioned AES-256-GCM key.
- Verified HTTPS and bearer authentication from Gateway to Cloud.
- Pinned ML-KEM public keys, manual current/previous key rotation, and gitignored generated secrets.
- At-least-once delivery with idempotent PostgreSQL insertion.
- JSON envelopes with base64-encoded binary fields.
- Continuous dataset replay with the year incremented each cycle; invalid shifted February 29 dates are skipped.
- Informational Docker/resource benchmarks rather than hardware-equivalence claims.

**Modified**

- Reduced the scope from production-shaped infrastructure to a well-built educational PoC.
- Replaced proposed mTLS with bearer authentication over verified HTTPS.
- Reframed ESP8266 results as supporting evidence, not proof from faithful emulation.

**Rejected or deferred**

- `liboqs-python` in favor of the standardized `cryptography` ML-KEM API.
- Multiple devices, durable queues, PKI/KMS infrastructure, automated rotation, and analytics/read APIs.

### Verification

- Reviewed `GOAL.md`, workspace manifests, lockfile, repository structure, and the 366-row 2024 weather dataset.
- Checked ML-KEM-768 parameters against [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) and the [`cryptography` ML-KEM API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/).
- Checked backend support against [OpenSSL 3.5 documentation](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/).
- Checked ESP8266 constraints against the [Espressif datasheet](https://documentation.espressif.com/0a-esp8266ex_datasheet_en.pdf).
- Verified PRD-to-FRD requirement traceability and Markdown structure. No implementation or runtime tests were performed.
