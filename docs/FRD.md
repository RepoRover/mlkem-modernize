# Functional Requirements Document: Legacy Weather Station PQ Gateway

| Field | Value |
| --- | --- |
| Status | Draft for review |
| Version | 0.1 |
| Parent | [`PRD.md`](PRD.md) |

## 1. Purpose

This document defines the implementable behavior, interfaces, cryptographic processing, persistence, configuration, deployment, and verification for the PoC described in the PRD.

Normative terms **shall**, **should**, and **may** indicate required, recommended, and optional behavior.

## 2. Architecture

```text
                                      trusted plaintext boundary
                                                   │
 device network                                    │                    cloud network
                                                   │
┌──────────────┐  TLS 1.2 + Device AES-GCM  ┌──────▼──────┐  HTTPS + ML-KEM/AES-GCM  ┌────────────┐
│ Device       ├────────────────────────────►│ Gateway     ├─────────────────────────►│ Cloud      │
│ CSV simulator│                             │ decrypts and│                          │ decrypts   │
└──────────────┘                             │ re-encrypts │                          └─────┬──────┘
                                             └─────────────┘                                │
                                                                                     ┌──────▼──────┐
                                                                                     │ PostgreSQL │
                                                                                     └─────────────┘
```

Docker Compose shall define two internal networks:

- `device_net`: Device and Gateway only;
- `cloud_net`: Gateway, Cloud, and PostgreSQL only.

Gateway is the only application attached to both networks. Device shall not have a route to Cloud or PostgreSQL.

## 3. Technology profile

| Concern | Selection |
| --- | --- |
| Language/workspace | Python `>=3.14.7`, uv workspace |
| HTTP APIs | FastAPI with Uvicorn |
| HTTP clients | HTTPX |
| Runtime validation | Pydantic v2 and pydantic-settings |
| Cryptography | `cryptography` 47+ with ML-KEM-capable backend |
| Database driver | asyncpg, parameterized SQL |
| Database | PostgreSQL |
| Tests | pytest plus Docker Compose integration tests |
| Serialization | UTF-8 JSON; RFC 4648 padded base64 for bytes |
| Time zones | Python `zoneinfo`; container includes IANA timezone data |
| Logging | Python standard logging to stdout |

Do not add an ORM, migration framework, reverse proxy, message broker, cache, metrics stack, or shared framework package for this PoC.

At process startup, Gateway and Cloud shall verify that ML-KEM-768 is available. Failure shall produce a clear fatal error rather than silently changing algorithms.

## 4. Component requirements

### 4.1 Device

Device is a command-line process, not an HTTP server.

It shall:

1. Load validated settings and the 32-byte Device AES key.
2. Parse the two-section weather CSV using the Python `csv` module.
3. Validate location metadata once.
4. Iterate daily rows in file order.
5. Shift each source date by the current cycle index in calendar years.
6. Log and omit February 29 when the target year is not a leap year.
7. Validate the resulting observation.
8. Encrypt it into a Device envelope.
9. POST it to Gateway.
10. Advance only after Gateway accepts it or permanently rejects that observation.
11. Sleep for the configured interval after accepted observations.
12. Start the next yearly cycle after reaching the end of the CSV.
13. Stop after `max_cycles` when configured for a test; otherwise repeat indefinitely.

A malformed daily row shall be logged with its CSV line number and skipped. Device shall validate source rows before starting delivery. Invalid required headers, invalid location metadata, or zero valid source observations shall fail startup rather than enter an empty cycle loop.

### 4.2 Gateway

Gateway shall expose:

- `POST /v1/observations`
- `GET /healthz`

It shall:

1. Terminate HTTPS and permit TLS 1.2 clients.
2. Bound and parse the Device envelope.
3. Select the single configured Device key after matching Device and key IDs.
4. Authenticate/decrypt the ciphertext with AES-256-GCM.
5. Validate the plaintext observation and cross-field identities.
6. Create a new Cloud envelope with a fresh ML-KEM encapsulation.
7. Send it synchronously to Cloud with the bearer credential.
8. Retry transient Cloud failures a bounded number of times.
9. Map the Cloud stored/duplicate result into the Device response.

Gateway shall be stateless. It shall not write observations, envelopes, or retry items to disk.

### 4.3 Cloud

Cloud shall expose:

- `POST /v1/observations`
- `GET /healthz`

It shall:

1. Terminate HTTPS.
2. Authenticate the bearer credential before ML-KEM processing.
3. Bound and parse the Cloud envelope and require the configured Gateway ID.
4. Select a private key from the ML-KEM key directory by key ID.
5. Decapsulate, derive, and decrypt.
6. Validate the plaintext observation and cross-field identities.
7. Insert it with idempotent SQL.
8. Return whether it was stored or already present.

Cloud shall not expose an observation read API.

### 4.4 PostgreSQL

PostgreSQL shall use a named Docker volume. Schema creation shall use one checked-in SQL file; Alembic or another migration framework is not required for this one-table PoC.

## 5. Data model

### 5.1 Observation

The plaintext on both application-encryption hops shall use the same logical schema:

```json
{
  "schema_version": 1,
  "observation_id": "weather-station-001:2024-01-01",
  "device_id": "weather-station-001",
  "observed_on": "2024-01-01",
  "latitude": 52.54833,
  "longitude": 13.407822,
  "elevation_m": 38.0,
  "utc_offset_seconds": 7200,
  "timezone": "Europe/Berlin",
  "timezone_abbreviation": "GMT+2",
  "temperature_max_c": 7.4,
  "temperature_min_c": 3.4,
  "precipitation_mm": 1.8,
  "wind_speed_max_kmh": 19.7
}
```

Validation shall enforce:

- `schema_version == 1`;
- identifier strings match `[A-Za-z0-9._:-]+` and contain no control characters;
- `observation_id == "{device_id}:{observed_on}"`;
- latitude is between -90 and 90;
- longitude is between -180 and 180;
- numbers are finite;
- `temperature_min_c <= temperature_max_c`;
- precipitation and wind speed are non-negative;
- timezone is accepted by `zoneinfo.ZoneInfo`;
- `utc_offset_seconds` is between -43,200 and 50,400; and
- unknown JSON fields are rejected.

The timezone, UTC offset, and timezone abbreviation fields preserve the CSV's location metadata unchanged across cycles. They are not computed offsets or abbreviations for `observed_on`; in particular, the source `GMT+2` metadata does not describe Berlin's winter offset. `observed_on` is a calendar date, not a timestamp.

### 5.2 Calendar-cycle transformation

For source date `(year, month, day)` and zero-based cycle `n`, Device shall attempt:

```text
target_date = date(year + n, month, day)
```

If this is invalid because the source is February 29 and the target year is not a leap year, Device shall log `calendar_day_skipped` and continue. It shall not clamp or roll the date because either choice would collide with another daily observation. If the target year would exceed Python/PostgreSQL's supported year 9999, Device shall log a fatal `calendar_range_exhausted` error and stop rather than silently wrap to duplicate dates.

A restart begins again at cycle zero. Existing rows make the replay idempotent; no Device checkpoint is required.

## 6. Device envelope protocol

### 6.1 JSON request

```json
{
  "version": 1,
  "device_id": "weather-station-001",
  "key_id": "device-key-001",
  "observation_id": "weather-station-001:2024-01-01",
  "nonce": "base64-encoded 12 bytes",
  "ciphertext": "base64-encoded ciphertext followed by 16-byte GCM tag"
}
```

### 6.2 Encryption

- Algorithm: AES-256-GCM.
- Key: exactly 32 bytes loaded from a read-only file.
- Nonce: 12 random bytes from the operating-system CSPRNG for every encryption attempt.
- Plaintext: compact UTF-8 JSON encoding of the validated Observation.
- Tag: the 16-byte tag remains appended to ciphertext, matching `AESGCM.encrypt` output.
- Maximum decoded ciphertext: 16 KiB.

Additional authenticated data shall be the following UTF-8 values joined by a zero byte, in order:

```text
device-envelope | 1 | device_id | key_id | observation_id
```

Here `|` illustrates field separation; the encoded separator is `0x00`, not the pipe character.

Gateway shall require the decrypted Observation values for `device_id` and `observation_id` to equal the authenticated envelope values.

### 6.3 Device authentication meaning

A valid GCM tag demonstrates possession of the configured Device key and authenticates the envelope metadata. TLS authenticates Gateway to Device. There is no Device client certificate or separate Device bearer token.

## 7. Cloud envelope protocol

### 7.1 JSON request

```json
{
  "version": 1,
  "gateway_id": "gateway-001",
  "kem": "ML-KEM-768",
  "kem_key_id": "cloud-kem-001",
  "observation_id": "weather-station-001:2024-01-01",
  "kem_ciphertext": "base64-encoded 1088 bytes",
  "nonce": "base64-encoded 12 bytes",
  "ciphertext": "base64-encoded ciphertext followed by 16-byte GCM tag"
}
```

The request shall include:

```http
Authorization: Bearer <gateway-token>
Content-Type: application/json
```

### 7.2 ML-KEM and key derivation

For each forwarding attempt, Gateway shall:

1. Load the pinned ML-KEM-768 public key identified by `kem_key_id`.
2. Call encapsulation to obtain a 32-byte shared secret and 1,088-byte KEM ciphertext.
3. Derive 32 bytes using HKDF-SHA-256 with no salt and this zero-byte-separated `info`:

```text
mlkem-modernize | cloud-envelope | 1 | kem_key_id
```

4. Encrypt the compact Observation JSON with AES-256-GCM and a new random 12-byte nonce.

Cloud shall select the matching private key, decapsulate, perform the identical HKDF operation, and decrypt.

ML-KEM-768 values shall have these exact lengths before cryptographic processing:

| Value | Length |
| --- | ---: |
| Raw public key | 1,184 bytes |
| KEM ciphertext | 1,088 bytes |
| Shared secret | 32 bytes |

### 7.3 Authenticated metadata

Cloud-envelope additional authenticated data shall be these UTF-8 values joined by `0x00`:

```text
cloud-envelope | 1 | gateway_id | ML-KEM-768 | kem_key_id | observation_id
```

Cloud shall require the decrypted Observation `observation_id` to equal the authenticated envelope value.

### 7.4 Public-key trust

Gateway shall not discover the ML-KEM public key over HTTP. Bootstrap shall provision a pinned public-key file and its key ID through a read-only mount. HTTPS certificate verification and the pinned file are separate controls.

## 8. HTTP behavior

### 8.1 Common constraints

- Requests shall use `application/json`.
- HTTP bodies shall be limited to 32 KiB before JSON parsing.
- Base64 shall be validated strictly before decoding.
- Pydantic models shall reject unknown fields.
- Error responses shall not contain exception traces, secrets, decrypted payloads, or cryptographic failure details.

### 8.2 Gateway endpoint

`POST /v1/observations`

| Outcome | Status | Response status |
| --- | ---: | --- |
| Cloud inserted observation | 201 | `stored` |
| Cloud already had observation | 200 | `duplicate` |
| Malformed envelope/encoding | 400 | `rejected` |
| Unknown Device/key ID or invalid GCM tag | 401 | `rejected` |
| Decrypted payload fails validation | 422 | `rejected` |
| Cloud unavailable after Gateway retries | 503 | `retry` |
| Cloud rejects Gateway configuration/envelope, or Cloud certificate verification fails | 502 | `upstream_rejected` |

A permanent upstream failure shall return `502` with the generic body `{"status":"upstream_rejected"}` and no underlying cryptographic or configuration details. Device shall treat this result as fatal, not retryable.

Successful response:

```json
{
  "observation_id": "weather-station-001:2024-01-01",
  "status": "stored"
}
```

### 8.3 Cloud endpoint

`POST /v1/observations`

| Outcome | Status | Response status |
| --- | ---: | --- |
| Inserted | 201 | `stored` |
| Primary key already exists | 200 | `duplicate` |
| Malformed envelope/length/encoding | 400 | `rejected` |
| Missing or invalid bearer credential | 401 | `rejected` |
| Unknown ML-KEM key ID | 400 | `rejected` |
| Decapsulation-derived decryption fails | 400 | `rejected` |
| Decrypted payload fails validation | 422 | `rejected` |
| Database unavailable | 503 | `retry` |

Bearer comparison shall use a timing-safe comparison. Authentication shall occur before base64 decoding and ML-KEM work.

### 8.4 Health endpoints

`GET /healthz` shall return status 200 only when:

- Gateway has loaded settings, Device key, Cloud public key, TLS material, and bearer token;
- Cloud has loaded settings, at least one ML-KEM private key, TLS material, bearer token, and can execute `SELECT 1` against PostgreSQL.

Gateway health shall not depend on current Cloud reachability; otherwise a Cloud outage would cascade into a misleading Gateway liveness failure.

## 9. TLS requirements

### 9.1 Device to Gateway

- Device client context: minimum TLS 1.2 and maximum TLS 1.2.
- Gateway server: supports TLS 1.2.
- Device verifies the bootstrap CA and `gateway` service hostname.
- Certificate verification shall never be disabled by a runtime convenience flag.

### 9.2 Gateway to Cloud

- Gateway client context: minimum TLS 1.3.
- Gateway verifies the bootstrap CA and `cloud` service hostname.
- Cloud does not request a client certificate.
- The classical server certificate authenticates Cloud during the live connection; this PoC does not claim post-quantum authentication.

TLS private keys and bearer/PSK material shall be mounted read-only. The CA certificate and ML-KEM public key are not secret but shall also be mounted read-only to prevent accidental mutation.

## 10. Persistence

### 10.1 Schema

```sql
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    observed_on DATE NOT NULL,
    latitude DOUBLE PRECISION NOT NULL CHECK (latitude BETWEEN -90 AND 90),
    longitude DOUBLE PRECISION NOT NULL CHECK (longitude BETWEEN -180 AND 180),
    elevation_m DOUBLE PRECISION NOT NULL,
    utc_offset_seconds INTEGER NOT NULL CHECK (
        utc_offset_seconds BETWEEN -43200 AND 50400
    ),
    timezone TEXT NOT NULL,
    timezone_abbreviation TEXT NOT NULL,
    temperature_max_c DOUBLE PRECISION NOT NULL,
    temperature_min_c DOUBLE PRECISION NOT NULL,
    precipitation_mm DOUBLE PRECISION NOT NULL CHECK (precipitation_mm >= 0),
    wind_speed_max_kmh DOUBLE PRECISION NOT NULL CHECK (wind_speed_max_kmh >= 0),
    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (temperature_min_c <= temperature_max_c)
);
```

Cloud shall use parameterized SQL. Insert behavior shall be equivalent to:

```sql
INSERT INTO observations (...) VALUES (...)
ON CONFLICT (observation_id) DO NOTHING
RETURNING observation_id;
```

A returned row means `stored`; no returned row means `duplicate`. First accepted write wins. The PoC does not update or version an existing observation.

### 10.2 Transactions

Each request shall use one short transaction. Cloud shall acknowledge `stored` only after commit. A database error shall roll back and return a retryable response.

## 11. Retry and recovery

### 11.1 Device

Device shall retry the same logical observation indefinitely for:

- connection and DNS errors;
- TLS connection interruptions other than certificate verification failures;
- timeout;
- HTTP 408 or 429; and
- HTTP 5xx, except `502` with response status `upstream_rejected`.

Certificate trust, expiry, or hostname verification failures shall fail Device immediately, including failures after a previously successful connection. `502 upstream_rejected` shall also fail Device because operator intervention is required. A generic or malformed 502 response remains retryable.

Backoff shall be exponential with configurable initial and maximum delays and bounded jitter. It shall reset after success.

Behavior for permanent responses:

- 400 or 422: log the observation as permanently rejected and continue;
- 401 or 403: fail the process because credentials/configuration are invalid;
- other 4xx: log and skip unless explicitly classified as retryable.

A regenerated retry envelope may use a new nonce. Its observation ID shall remain unchanged.

### 11.2 Gateway

Gateway shall retry transient Cloud connection errors, timeouts, 408, 429, and 5xx responses a configurable small number of times. HTTP 408 and 429 are exceptions to the rule that Cloud 4xx responses are not retried. Other Cloud 4xx responses and certificate trust, expiry, or hostname verification failures shall return `502 upstream_rejected` without retries. After transient retries are exhausted, Gateway returns 503 so Device owns the longer retry loop.

`CLOUD_FORWARD_DEADLINE_SECONDS` shall bound the complete forwarding operation, including all attempts and retry delays; expiry returns 503. `CLOUD_TIMEOUT_SECONDS` shall bound each complete attempt, not merely individual socket inactivity. Device shall enforce `GATEWAY_TIMEOUT_SECONDS` as a total request deadline. Compose shall default the forwarding deadline to 30 seconds and Device's request deadline to 35 seconds, and deployment checks shall require the latter to exceed the former by at least 5 seconds.

Gateway shall create a fresh ML-KEM encapsulation for each Cloud attempt. Idempotency depends on the stable observation ID, not ciphertext reuse.

### 11.3 Restart behavior

- Device restart: begins cycle zero and safely replays existing observations.
- Gateway restart: loses no durable state because Device retries.
- Cloud restart: reloads keys and reconnects to persistent PostgreSQL.
- PostgreSQL restart: retains rows in its named volume.

## 12. Configuration and secret material

Settings shall be validated at startup. Environment variables may point to files; secret values shall not be supplied as command-line arguments.

### 12.1 Device settings

| Setting | Purpose |
| --- | --- |
| `DEVICE_ID` | Fixed simulated Device identifier |
| `DEVICE_KEY_ID` | AES key identifier |
| `DEVICE_KEY_FILE` | Read-only raw 32-byte key |
| `GATEWAY_URL` | HTTPS observation endpoint |
| `GATEWAY_TIMEOUT_SECONDS` | Total request deadline; default 35 seconds |
| `CA_CERT_FILE` | CA used to verify Gateway |
| `WEATHER_CSV_FILE` | Input dataset path |
| `SEND_INTERVAL_SECONDS` | Delay after accepted observations |
| `RETRY_INITIAL_SECONDS` | Initial transient retry delay |
| `RETRY_MAX_SECONDS` | Retry-delay cap |
| `MAX_CYCLES` | Optional finite test run; absent means unlimited |

### 12.2 Gateway settings

| Setting | Purpose |
| --- | --- |
| `DEVICE_ID` | Only accepted Device ID |
| `DEVICE_KEY_ID` | Only accepted Device key ID |
| `DEVICE_KEY_FILE` | Matching raw 32-byte key |
| `GATEWAY_ID` | Authenticated Cloud-envelope identity |
| `CLOUD_URL` | HTTPS Cloud endpoint |
| `CLOUD_CA_CERT_FILE` | CA used to verify Cloud |
| `CLOUD_API_TOKEN_FILE` | Read-only bearer credential |
| `MLKEM_KEY_ID` | Current Cloud key ID |
| `MLKEM_PUBLIC_KEY_FILE` | Pinned current public key |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | Gateway server identity |
| `CLOUD_RETRY_ATTEMPTS` | Bounded forwarding attempts |
| `CLOUD_TIMEOUT_SECONDS` | Total per-attempt timeout |
| `CLOUD_FORWARD_DEADLINE_SECONDS` | Total forwarding deadline including retries and delays; default 30 seconds |

### 12.3 Cloud settings

| Setting | Purpose |
| --- | --- |
| `GATEWAY_ID` | Accepted Gateway identity |
| `GATEWAY_API_TOKEN_FILE` | Expected bearer credential |
| `MLKEM_PRIVATE_KEYS_DIR` | Private keys named by key ID |
| `DATABASE_URL_FILE` | PostgreSQL connection string |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | Cloud server identity |

Private-key filenames shall use the validated key ID, for example `cloud-kem-001.pem`. Cloud loads all valid keys in the directory at startup. Gateway uses exactly one current public key.

### 12.4 Bootstrap output

Bootstrap shall run as a one-shot Compose service through the documented command `docker compose run --build --rm bootstrap`; the service shall be assigned a `tools` profile so normal `docker compose up` excludes it, shall have no runtime-service dependencies, and shall build/install its own dependencies. Only Docker with Compose is required on the host. It is not a fifth continuously running service.

The explicit bootstrap script shall create a gitignored local directory containing:

- one local CA certificate and private key;
- Gateway and Cloud server certificates with correct Compose DNS SANs;
- one 32-byte Device AES key;
- one random Gateway bearer token with at least 256 bits of entropy;
- PostgreSQL credentials and Cloud's matching database connection-string file;
- current and next ML-KEM-768 keypairs for the rotation exercise; and
- public-key copies for Gateway.

The script shall use secure file permissions, print created paths but never secret values, and require `--force` to replace material. Only the current ML-KEM private key shall initially be placed in Cloud's active-key directory; the next keypair shall be staged separately until the rotation exercise.

## 13. ML-KEM rotation procedure

Given `cloud-kem-001` as current and `cloud-kem-002` as next:

1. Add `cloud-kem-002.pem` to Cloud's private-key directory while retaining `cloud-kem-001.pem`.
2. Restart Cloud and verify both key IDs load.
3. Change Gateway's `MLKEM_KEY_ID` and public-key mount to `cloud-kem-002`.
4. Restart Gateway.
5. Verify new observations use and are accepted with `cloud-kem-002`.
6. Verify a test envelope using `cloud-kem-001` is still accepted during overlap.
7. Remove `cloud-kem-001.pem`, restart Cloud, and verify the old key ID is rejected.

No endpoint shall mutate active keys.

## 14. Logging

Use stdout/stderr and stable event names. Recommended fields are:

```text
service, level, event, observation_id, device_id, key_id, attempt, result
```

Required events include:

- settings/keys loaded without values;
- service ready/stopping;
- CSV row skipped;
- non-leap February 29 skipped;
- observation accepted/rejected;
- forwarding retry/exhaustion;
- observation stored/duplicate;
- key ID selected/unknown; and
- benchmark environment/results.

Tracebacks may be logged for unexpected internal errors only after sanitizing exception messages and omitting local variables. Validation logs shall use allowlisted field names and error codes, never rejected values or raw exception strings. Response bodies shall remain generic. Do not log plaintext Observation JSON or cryptographic secret values.

## 15. Docker requirements

- Each workspace package shall have its own Dockerfile and command.
- Containers shall run the matching package entry point.
- Device shall be limited to `0.25` CPU and `128 MiB`; implementation measurements may justify updating the documented memory value before acceptance.
- PostgreSQL shall use a named data volume.
- Generated secrets shall be excluded by `.gitignore`. Runtime mounts shall be read-only and restricted to the following material; no runtime service shall receive the entire bootstrap directory:
  - Device: its AES key and Gateway CA certificate.
  - Gateway: Device AES key, bearer token, pinned current ML-KEM public key, Cloud CA certificate, and its own TLS certificate/private key.
  - Cloud: active ML-KEM private-key directory, bearer token, database connection-string file, and its own TLS certificate/private key.
  - PostgreSQL: only its required database credentials.
- The CA private key and staged rotation keys shall not be mounted into runtime services.
- Compose health-based dependencies shall start Cloud after PostgreSQL, Gateway after Cloud, and Device after Gateway.
- Gateway and Cloud APIs shall use HTTPS directly; no reverse-proxy container is required.

The Device limit is a demonstration constraint only. It does not approximate the ESP8266's roughly sub-50-KB application memory.

## 16. Verification plan

### 16.1 Unit checks

1. CSV metadata and daily-row parsing.
2. Calendar shifting across leap and non-leap years.
3. Observation cross-field validation.
4. Device AES-GCM round trip and failure after changing every authenticated field.
5. ML-KEM/HKDF/AES-GCM round trip and failure after changing every authenticated field.
6. Strict base64, field-size, and extra-field rejection.
7. Retry classification, including retryable 408/429, fatal certificate verification failures, and fatal `502 upstream_rejected` versus retryable generic 502.
8. Idempotent SQL result mapping.

Use official ML-KEM known-answer or library self-checks where the selected API exposes them; do not create custom algorithm test vectors.

### 16.2 Integration checks

1. **Happy path:** one finite Device cycle stores all 366 source-year observations.
2. **Next year:** a second cycle adds 365 observations and skips shifted February 29.
3. **Replay:** restart Device at cycle zero; row count does not increase for the replayed year.
4. **Device tamper:** change nonce, ciphertext, and AAD-covered metadata; Gateway rejects each.
5. **Cloud tamper:** change KEM ciphertext, AES ciphertext, and AAD-covered metadata; Cloud rejects each.
6. **Credentials:** wrong Device key ID and wrong bearer token are rejected.
7. **Rotation:** execute the overlap/add/switch/remove flow in section 13.
8. **Outage:** stop Cloud, observe Device retry through Gateway 503, restart Cloud, and verify one insert.
9. **TLS:** test untrusted CA, expired certificate, and trusted certificate with a wrong hostname on each hop; Device fails without infinite retries, and Gateway maps Cloud verification failures to `502 upstream_rejected`.
10. **Malformed CSV:** supply one bad row; it is skipped while later rows arrive. Header-only and all-invalid datasets fail startup without cycling.
11. **Restarts:** restart each service and PostgreSQL independently; accepted rows remain unique and durable.
12. **Network boundary:** verify Device cannot connect directly to Cloud.
13. **Permanent upstream failure:** invalid Cloud bearer token or unknown ML-KEM key causes Gateway `502 upstream_rejected` and Device exits without retrying.
14. **Deadlines:** verify the configured deadline margin; a stalled Cloud exhausts Gateway's total forwarding deadline and Device receives 503 before its own deadline.
15. **Secret isolation:** inspect runtime mounts for the per-service allowlist and verify CA private and staged rotation keys are absent.
16. **Log sanitization:** trigger plaintext validation and internal errors containing sentinel secret values; captured logs and responses shall not contain those values.
17. **Bootstrap:** from an empty generated-material directory, run the documented containerized bootstrap command; verify current/staged key separation and refusal to overwrite without `--force`.

Integration tests shall use a near-zero send interval and finite cycles. They shall not depend on the normal demo interval.

### 16.3 Informational benchmark

A repeatable command shall report, after warm-up:

- median and p95 AES-256-GCM encrypt/decrypt duration for a representative observation;
- median and p95 ML-KEM-768 encapsulation/decapsulation duration;
- median and p95 complete Gateway/Cloud envelope duration;
- peak resident memory where the platform exposes it;
- operation counts and runtime versions;
- host CPU/platform details; and
- Docker image sizes.

Use Python's standard timing/statistics facilities. Do not fail CI based on benchmark values. The report shall state that container results neither reproduce ESP8266 instruction timing nor prove algorithm infeasibility on that hardware.

## 17. Requirement traceability

| PRD requirement | FRD sections |
| --- | --- |
| PRD-FR-001 | 12.4, 15, 16 |
| PRD-FR-002 | 4.1, 5, 16.1 |
| PRD-FR-003 | 4.1, 5.2 |
| PRD-FR-004 | 11, 12.1 |
| PRD-FR-005 | 6, 9.1 |
| PRD-FR-006 | 4.2, 8.2 |
| PRD-FR-007 | 7 |
| PRD-FR-008 | 7.1, 8.3 |
| PRD-FR-009 | 4.3, 10 |
| PRD-FR-010 | 10, 11 |
| PRD-FR-011 | 12.3, 13 |
| PRD-FR-012 | 16 |
| PRD-FR-013 | 8.4, 14 |
| PRD-FR-014 | 15, 16.3 |

## 18. References

- NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
- `cryptography`, [ML-KEM API documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/).
- OpenSSL, [EVP_PKEY-ML-KEM](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/).
- Espressif, [ESP8266EX Datasheet](https://documentation.espressif.com/0a-esp8266ex_datasheet_en.pdf).
