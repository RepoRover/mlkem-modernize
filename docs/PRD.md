# Product Requirements Document: Legacy Weather Station PQ Gateway

| Field           | Value                        |
| --------------- | ---------------------------- |
| Status          | Draft for review             |
| Version         | 0.1                          |
| Product type    | Educational proof of concept |
| Primary runtime | Local Docker Compose         |

## 1. Summary

Build a continuously running simulation of one hardware-constrained ESP8266 weather station. The simulated Device sends AES-256-GCM-protected weather observations over TLS 1.2 to a trusted Gateway. The Gateway decrypts and validates each observation, then re-encrypts it using a fresh ML-KEM-768-established key and forwards it over HTTPS to a Cloud service. The Cloud decrypts, validates, and stores each observation in PostgreSQL.

The product demonstrates a migration boundary for a legacy symmetric-capable device. It is not end-to-end encryption: the Gateway is trusted and handles plaintext.

## 2. Problem

Some deployed devices can perform symmetric encryption and TLS 1.2 but cannot practically adopt the desired post-quantum key-establishment stack. Replacing otherwise useful devices creates cost and e-waste. A trusted edge Gateway can preserve the existing Device-facing protocol while modernizing the Gateway-to-Cloud cryptographic boundary.

This PoC must make that boundary observable and testable without claiming to faithfully emulate ESP8266 hardware or provide production security assurance.

## 3. Goals

1. Demonstrate the full Device → Gateway → Cloud → PostgreSQL flow.
2. Show symmetric decryption and post-quantum re-encryption at an explicit trusted boundary.
3. Use ML-KEM-768 as standardized by NIST FIPS 203.
4. Validate authentication failures, tampering, replay/idempotency, outages, certificate failures, malformed input, restart behavior, and ML-KEM key rotation.
5. Run all services as separate uv workspace packages and Docker images under Docker Compose.
6. Provide reproducible, informational evidence of the Device/Gateway capability split.
7. Keep the design small enough to understand as a PoC.

## 4. Non-goals

- Production deployment or formal security assurance.
- Protection after Device, Gateway, Cloud, database, or secret-store compromise.
- End-to-end Device-to-Cloud encryption; the Gateway sees plaintext by design.
- A physical ESP8266 test or cycle-accurate ESP8266 emulation.
- Proof that ML-KEM cannot execute on every ESP8266 implementation.
- Multiple devices, enrollment, fleet management, or device administration.
- A user-facing analytics view or read API.
- Durable Gateway queues, high availability, horizontal scaling, or disaster recovery.
- Mutual TLS, a PKI service, KMS/HSM integration, or automatic credential rotation.
- Post-quantum TLS or post-quantum signatures.
- An over-the-air firmware update mechanism.

## 5. Users and stakeholders

- **Evaluator:** starts the PoC, observes the data flow, runs tests, and reviews stored data through test assertions or PostgreSQL tooling.
- **Developer:** implements and maintains the three services and protocol contracts.
- **Security learner/reviewer:** examines trust boundaries, crypto operations, failure behavior, and limitations.

## 6. Product flow

1. A bootstrap command creates local development certificates, credentials, and ML-KEM keys outside Git.
2. Docker Compose starts PostgreSQL, Cloud, Gateway, and Device in dependency order.
3. Device parses and validates `device/data/weather_data.csv`.
4. Device emits observations at a configurable interval.
5. Device encrypts each observation with its provisioned AES-256-GCM key and sends the envelope to Gateway over certificate-verified TLS 1.2.
6. Gateway authenticates the Device by successful AES-GCM verification, decrypts the payload, and validates it.
7. Gateway encapsulates a fresh shared secret to the pinned Cloud ML-KEM-768 public key, derives an AES-256-GCM key, encrypts the observation, and sends it to Cloud over certificate-verified HTTPS using a bearer credential.
8. Cloud authenticates Gateway, decapsulates, derives the same AES key, decrypts, validates, and inserts the observation into PostgreSQL.
9. Cloud treats a repeated observation ID as an idempotent success rather than inserting a duplicate.
10. After the CSV ends, Device starts another cycle with every source date shifted forward by one calendar year. February 29 is skipped in non-leap target years.

## 7. Functional requirements

### PRD-FR-001 — Local bootstrap and startup

The repository shall provide documented commands to:

- generate local development secrets and certificates;
- build and start all services with Docker Compose;
- run automated checks; and
- run the informational resource benchmark.

Bootstrap shall run through a documented one-shot Docker Compose command that builds its image when needed; only Docker with Compose is required on the host. Bootstrap shall refuse to overwrite existing secret material unless explicitly requested.

### PRD-FR-002 — Dataset parsing

Device shall:

- read the supplied location metadata and daily observations;
- validate metadata and every row with Pydantic;
- log and skip malformed observation rows; and
- stop with an error when required headers or location metadata are unusable, or no valid source observations remain.

Timezone fields shall preserve source metadata, not claim the actual UTC offset or abbreviation of each shifted date.

### PRD-FR-003 — Continuous calendar simulation

Device shall:

- process observations in source order;
- use the source dates during cycle zero;
- add one to the source year for every subsequent cycle;
- skip February 29 when the target year is not a leap year;
- derive a stable observation ID from Device identity and shifted observation date;
- repeat until stopped or the supported calendar year range is exhausted; and
- allow a finite cycle count in automated tests.

### PRD-FR-004 — Configurable pacing

The normal delay between successful observations shall be configurable without rebuilding the image. Retry backoff shall be independent of the normal observation interval.

### PRD-FR-005 — Device protection and transport

Device shall:

- support only TLS 1.2 for its Gateway connection to demonstrate the legacy transport constraint;
- verify the Gateway certificate and hostname;
- encrypt each observation with AES-256-GCM using its provisioned 32-byte key and a fresh 96-bit nonce; and
- authenticate routing metadata as AES-GCM additional authenticated data.

### PRD-FR-006 — Trusted Gateway boundary

Gateway shall:

- accept Device envelopes over HTTPS;
- reject malformed, unknown-key, or authentication-failed envelopes;
- decrypt and validate accepted Device payloads;
- avoid writing plaintext observations or secret values to logs; and
- synchronously forward accepted observations to Cloud before acknowledging success to Device.

### PRD-FR-007 — Post-quantum Cloud envelope

For every forwarding attempt, Gateway shall:

- use the configured, pinned ML-KEM-768 public key and key ID;
- create a fresh ML-KEM encapsulation;
- derive a 32-byte AES key with HKDF-SHA-256;
- encrypt the validated observation with AES-256-GCM and a fresh 96-bit nonce; and
- send the ML-KEM ciphertext and encrypted observation to Cloud over verified HTTPS.

### PRD-FR-008 — Gateway authentication to Cloud

Gateway shall send a provisioned bearer credential over HTTPS. Cloud shall reject missing or invalid credentials before ML-KEM decapsulation. This is a PoC authentication mechanism, not a production identity system.

### PRD-FR-009 — Cloud processing and persistence

Cloud shall:

- select the ML-KEM private key by key ID;
- decapsulate, derive, decrypt, and validate the observation;
- insert new observations into PostgreSQL in a transaction; and
- return a successful duplicate result when the observation ID already exists.

No product read API is required.

### PRD-FR-010 — Retry and idempotency

- Device shall retry transient connection errors, timeouts, rate limits, and transient server errors with capped exponential backoff.
- Certificate trust/hostname failures and permanent Gateway-to-Cloud configuration rejections shall stop Device rather than trigger infinite retries.
- Device's request deadline shall exceed Gateway's bounded total forwarding deadline, including retry delays.
- Device shall retain the current observation in memory until it receives a success or a permanent rejection.
- Gateway shall make a small bounded number of retries for transient Cloud failures, then return a retryable failure to Device.
- Cloud shall use the observation ID as the idempotency key.
- No Gateway disk queue is required.
- A Device restart may replay earlier observations; replay shall not create duplicate rows.

### PRD-FR-011 — ML-KEM key rotation exercise

The PoC shall support and test manual ML-KEM key rotation:

1. Cloud accepts the current and previous private keys during an overlap window.
2. Gateway is changed to the new public key and key ID.
3. New envelopes use the new key.
4. Old envelopes remain decryptable during overlap.
5. Old envelopes are rejected after the previous private key is removed.

Dynamic reload and automated rotation are not required; service restart is acceptable.

### PRD-FR-012 — Failure demonstrations

Automated checks shall cover:

- happy-path persistence;
- altered Device ciphertext or authenticated metadata;
- altered Cloud ciphertext or authenticated metadata;
- unknown Device key or invalid Cloud bearer credential;
- replay/idempotent duplicate handling;
- ML-KEM key rotation and unknown key IDs;
- Cloud outage followed by retry and recovery;
- invalid TLS trust or hostname on both hops without infinite retries;
- malformed CSV rows and datasets with no valid observations;
- Device, Gateway, and Cloud restart behavior; and
- database uniqueness under repeated delivery.

### PRD-FR-013 — Health and logs

- Gateway and Cloud shall expose HTTPS health endpoints suitable for Compose health checks.
- Services shall log significant lifecycle, validation, forwarding, retry, rotation, and persistence outcomes to standard output.
- Logs shall include service/event names and observation/key IDs where relevant.
- Logs shall not include AES keys, ML-KEM private material, bearer credentials, nonces paired with plaintext, or decrypted payload bodies.

### PRD-FR-014 — Resource evidence

The repository shall provide an informational benchmark that reports:

- AES-GCM operation timing for the Device path;
- ML-KEM encapsulation and decapsulation timing for the Gateway/Cloud path;
- process peak memory where supported;
- resulting Docker image sizes; and
- runtime environment details needed to interpret results.

The Device container shall run with documented CPU and memory limits. Benchmark values shall not be pass/fail gates because host hardware and container runtimes vary.

## 8. Non-functional requirements

### Security correctness

- Use maintained library implementations; do not implement cryptographic primitives.
- Use authenticated encryption and strict certificate verification.
- Use cryptographically secure randomness.
- Keep generated private material out of Git and mount only each service's required material read-only. Never mount the CA private key into runtime services; keep staged rotation keys outside Cloud's active-key directory.
- Sanitize logs and exception output so validation errors cannot disclose plaintext or secrets.
- Reject extra fields and malformed base64 at HTTP trust boundaries.
- Bound request and decoded-field sizes before expensive operations.
- Treat Gateway as the explicit plaintext trust boundary.

These are implementation-quality requirements for a demonstration, not a security certification or production-readiness claim.

### Reliability

- PostgreSQL data shall survive service-container restarts through a named volume.
- Gateway shall remain stateless.
- Retry behavior shall not create duplicate database rows.
- Permanent input failures shall not trigger infinite retries.

### Deployability

- Each service shall remain a separate uv workspace package, executable, and Docker image.
- `docker compose up --build` shall start the bootstrapped system without manually installing service dependencies on the host.
- Device and Cloud shall be placed on separate Docker networks, with Gateway attached to both, so Device has no direct Cloud route.

### Maintainability

- Use Google-style docstrings for non-trivial public code.
- Use Pydantic for runtime data and configuration validation.
- Keep dependencies and abstractions minimal.
- Record significant AI assistance in `docs/AI_USAGE.md`.

## 9. Success criteria

The PoC is complete when:

1. A documented bootstrap plus Docker Compose command starts all four runtime containers.
2. A valid observation crosses both encrypted hops and is stored once in PostgreSQL.
3. A second delivery of the same observation returns success without another row.
4. A later simulation cycle stores observations under the next calendar year, skipping invalid February 29 dates.
5. The failure checks in PRD-FR-012 pass.
6. The ML-KEM rotation exercise passes without a key-management service.
7. Device cannot route directly to Cloud on the Compose network.
8. The benchmark produces an informational report and clearly states its hardware-emulation limitations.
9. No generated private keys or credentials are tracked by Git.

## 10. Product decisions

| Topic                | Decision                                                               |
| -------------------- | ---------------------------------------------------------------------- |
| Scope                | Well-built educational PoC                                             |
| Threat posture       | Demonstrate mechanics and failures; make no production assurance claim |
| Device count         | Exactly one simulated Device                                           |
| Device transport     | Verified TLS 1.2 plus an application AES-256-GCM envelope              |
| Cloud authentication | Bearer credential over verified HTTPS; no mTLS                         |
| ML-KEM trust         | Public key pinned through a read-only mounted file                     |
| Delivery             | At-least-once retry with idempotent Cloud insertion                    |
| Dataset lifecycle    | Repeat forever, shifting the source year by one each cycle             |
| Wire encoding        | JSON with standard padded base64 for binary values                     |
| Analytics/read API   | Out of scope                                                           |
| Secret setup         | Explicit bootstrap script; generated material ignored by Git           |
| Executable rotation  | ML-KEM keys only                                                       |
| Hardware evidence    | Docker limits and informational benchmarks, explicitly not proof       |

## 11. Risks and limitations

- A Python container is not a faithful ESP8266 emulator and requires far more memory than the physical device.
- The Python crypto backend used by the simulator may contain ML-KEM code even though Device never invokes it; this PoC demonstrates an architectural restriction, not physical impossibility.
- Bearer authentication, local file-based secrets, and manual rotation are intentionally limited to this PoC.
- Classical TLS certificates authenticate the HTTPS endpoints; the PoC does not demonstrate post-quantum authentication.
- Gateway compromise exposes plaintext and both forwarding credentials by design.
- Random AES-GCM nonces depend on a correct operating-system CSPRNG.
- Continuously shifted years cause unbounded database growth until the operator stops or resets the demo volume; the simulation stops rather than wrapping after calendar year 9999.
- ML-KEM support requires a compatible `cryptography` release and backend; startup must fail clearly when unavailable.

## 12. Future considerations

Only pursue these after the PoC is accepted:

- analytics or visualization over stored observations;
- multiple-device enrollment and per-device key management;
- durable edge buffering;
- mTLS or workload identity for Gateway;
- managed secret storage and automated rotation;
- metrics and tracing;
- physical-device or emulator measurements; and
- a hybrid or fully post-quantum authenticated transport profile.
