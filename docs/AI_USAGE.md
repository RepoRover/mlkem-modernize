# AI Usage Log

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
