# Baseline analysis (`v0-legacy`)

Measurements in this document were captured from immutable commit `7a467db`
before any post-quantum work began. Reproduce them from a detached checkout with:

```bash
git checkout --detach 7a467db
uv run python -m bench v0-legacy 200
uv run pytest tests/unit --cov=packages --cov=services
docker compose -f deploy/docker-compose.baseline.yml up --build
```

## 1. What the baseline does

A simulated weather station replays 366 daily readings (Berlin, 2024,
Open-Meteo archive) to an edge gateway, which relays them to a cloud service
that stores them in SQLite and exposes a query API.

```
legacy-device ──(legacy suite)──> gateway ──(legacy suite)──> cloud
 py3.9, 48 MB                     broker                      FastAPI + SQLite
 read-only, no egress
```

Every hop uses `LEGACY-RSA2048-OAEP-AESGCM`: the device draws a random 32-byte
secret, wraps it under the peer's long-term RSA-2048 public key with OAEP-SHA256,
and protects each reading with AES-256-GCM. The gateway decrypts and re-encrypts
onto an independent upstream session, so the two links are separate
cryptographic contexts even though they currently run the same suite.

## 2. Measured performance

Captured on arm64, Python 3.13.11, cryptography 50.0.1. The benchmark command
requested 200 iterations. The harness used all 200 for the short operations,
but deliberately reduced expensive RSA key generation to `200 / 20 = 10`
samples and the full handshake path to `200 / 4 = 50` samples. Full data is in
[`bench/results/v0-legacy.json`](../bench/results/v0-legacy.json).

| Operation | Samples | Median | p95 | Max |
|---|---:|---:|---:|---:|
| RSA-2048 keygen | 10 | 62.0959 ms | 187.2772 ms | 187.2772 ms |
| Handshake, client side (RSA-OAEP encrypt) | 200 | 0.0247 ms | 0.0311 ms | 0.0357 ms |
| Handshake, server side (RSA-OAEP decrypt) | 200 | 0.8776 ms | 0.9955 ms | 1.8696 ms |
| Seal one reading (AES-256-GCM) | 200 | 0.0017 ms | 0.0020 ms | 0.0127 ms |
| Full handshake + seal + open | 50 | 0.9193 ms | 1.0237 ms | 2.0883 ms |

Wire sizes: 103 B plaintext reading, 344 B handshake payload (base64 of a 256 B
RSA ciphertext), 119 B data frame, 16 B AEAD tag overhead.

Two observations matter for the migration. RSA private-key operations cost
roughly **36x** the public-key ones, so the responder, not the device, carries
the handshake cost. And keygen is both slow and highly variable — a ~3.0x spread
between median and p95 — because RSA key generation searches for primes. ML-KEM
has no such search, which should make its keygen both faster and far more
predictable. Those are the specific predictions the post-migration benchmark
will check.

## 3. Cryptographic weaknesses

Three defects are deliberate, and are marked as such in
[`cryptosuite/legacy.py`](../packages/pqcsuite/src/pqcsuite/legacy.py).

| # | Defect | Consequence |
|---|---|---|
| 1 | The transported secret is used directly as the AES key, with no KDF | No domain separation. The secret could not safely be reused for any other purpose, and nothing binds the key to its context. |
| 2 | The RSA ciphertext is not bound to the session identifier | A captured handshake can be replayed under a different session label to obtain a session with the same key. |
| 3 | Key transport under a *static* long-term RSA key — no forward secrecy | **The quantum-relevant one.** Recovering that single key retroactively decrypts every archived session. |

Defect 3 is what makes harvest-now-decrypt-later work: an adversary records
traffic today and waits for a cryptographically relevant quantum computer to
recover the RSA key by Shor's algorithm. Defects 1 and 2 are classical hygiene
failures that the migration also repairs.

## 4. What actually constrains the device

The real target device is hardware-limited by the project premise and cannot
perform ML-KEM. This repository runs a host/container simulation, not that
hardware; host timing, memory use, and container quotas therefore cannot prove
or disprove feasibility on the target.

One narrower finding is reproducible: Python 3.9 alone does not establish
incapability. `cryptography>=48` installs on Python 3.9 and ML-KEM-768 works in
that host/container environment, as asserted by
`test_python_version_alone_would_not_have_blocked_mlkem`. That result corrects a
software-version claim; it is not hardware evidence.

The simulation models additional field constraints that prevent a software
upgrade even where the host can execute ML-KEM:

1. The crypto dependency is **pinned** to an August 2021 build inside an
   immutable image.
2. The container sits on an `internal: true` network with **no route to a
   package index**, so it cannot fetch a newer build.
3. The root filesystem is **read-only**, so nothing can be installed at runtime.

Each is asserted in
[`tests/integration/test_device_constraints.py`](../tests/integration/test_device_constraints.py).
Together, the target-hardware premise and the modeled immutable deployment make
gateway brokering the migration strategy. The simulation validates the protocol
and deployment shape, but real target-hardware feasibility remains outside its
evidence.

## 5. Operational gaps at baseline

These are real and deliberate; each is the subject of later work.

| Gap | Current state |
|---|---|
| Test coverage | 49% overall. The protocol and crypto packages are covered; **all three services are at 0%**. |
| Negative-path testing | None. No tests for tampered ciphertext, replayed frames, or suite confusion. |
| Known-answer tests | None. Correctness rests on round-trip tests only, which would pass even against a consistently wrong implementation. |
| Metrics | None. No `/metrics` endpoint, no way to ask how much traffic is still quantum-vulnerable. |
| CI/CD | None. |
| Key management | Keys are generated on first boot and stored unencrypted on a volume. No rotation, no KMS. |
| Alerting | None. |

## 6. Baseline test inventory

30 unit tests pass, covering frame encoding and AAD injectivity, sequence and
replay handling, the telemetry loader, the legacy round trip, and capability
reporting. Four Docker-backed integration tests assert the device constraints.

The gap that matters most is the absence of known-answer tests: every current
correctness check is a round trip, and a round trip passes whenever both sides
are wrong in the same way. Closing that is a prerequisite for trusting the
ML-KEM integration.
