# Architecture — Legacy Baseline ("before" state)

This document describes the **pre-PQC** weather telemetry system: a simulated
legacy device, an edge gateway, and a cloud service. Every cryptographic choice
here is classical, and most of them are broken by a cryptographically relevant
quantum computer. That is intentional — this is the state we migrate *from*.

**Status:** working end to end. Not production software. Do not copy the hop 1
design into anything new.

---

## 1. Components

```mermaid
flowchart LR
    subgraph edge["Field site"]
        DEV["<b>Legacy device</b><br/>services/device<br/><i>simulated firmware</i><br/>replays data/weather_data.csv<br/>NON-UPGRADEABLE"]
    end

    subgraph dmz["Edge"]
        GW["<b>Edge gateway</b><br/>services/gateway<br/>validates + re-encrypts<br/><i>PQC starts here later</i>"]
    end

    subgraph cloudzone["Cloud"]
        CLD["<b>Cloud service</b><br/>services/cloud<br/>validates + stores"]
        DB[("SQLite<br/>readings.db")]
    end

    OPS(["Operator / API consumer"])

    DEV -- "hop 1 — HTTP + AES-256-GCM<br/><b>static-static ECDH P-256</b><br/>no forward secrecy" --> GW
    GW  -- "hop 2 — HTTP + AES-256-GCM<br/><b>ephemeral ECDHE P-256 + mutual ECDSA</b><br/>forward secrecy" --> CLD
    CLD --> DB
    OPS -- "GET /readings (no auth)" --> CLD

    classDef weak fill:#fde8e8,stroke:#c53030,stroke-width:2px,color:#1a202c
    classDef ok fill:#e6f4ea,stroke:#2f855a,stroke-width:2px,color:#1a202c
    classDef neutral fill:#edf2f7,stroke:#4a5568,stroke-width:1px,color:#1a202c
    class DEV weak
    class GW,CLD ok
    class DB,OPS neutral
```

| Component | Role | Crypto | Upgradeable? |
|---|---|---|---|
| `services/device` | Replays 366 daily readings | static-static ECDH P-256 + AES-256-GCM | **No** — treated as frozen firmware |
| `services/gateway` | Validates, re-encrypts, forwards | hop 1 server + hop 2 client | Yes |
| `services/cloud` | Validates, stores, serves read API | hop 2 server | Yes |

The gateway is a **decrypt/re-encrypt point**. Plaintext readings exist in its
memory. This is not end-to-end confidentiality — and it is precisely what makes
a staged PQC migration possible, because the device never has to change.

---

## 2. Why the two hops differ

This is the central design decision of the baseline.

| | Hop 1 (device → gateway) | Hop 2 (gateway → cloud) |
|---|---|---|
| Key agreement | static-static ECDH P-256 | **ephemeral-ephemeral** ECDH P-256 |
| Forward secrecy | **none** | yes |
| Client auth | implicit (static ECDH key *is* the identity) | explicit (ECDSA P-256 signature) |
| Server auth | implicit (pinned static key) | **explicit** (ECDSA signature over transcript) |
| ServerHello authenticated | **no** | yes |
| KDF transcript binding | nonces only — **public keys not bound** | full transcript |
| AEAD | AES-256-GCM | AES-256-GCM |

**Hop 1 is deliberately cruftier.** It models non-upgradeable firmware honestly:
a key burned in at manufacture, no ephemerals, no signatures, no negotiation.
Every session between this device and this gateway derives from the *same* ECDH
shared secret `Z`; only the HKDF salt varies.

**Hop 2 is a clean classical baseline.** It is the closest classical analogue of
what replaces it, so the before/after comparison isolates the cost of adding
ML-KEM-768 and nothing else.

---

## 3. Message formats

All messages are JSON over HTTP. Binary fields are base64 (standard alphabet,
padded, strictly validated on decode).

Transcripts that are hashed or signed use **length-prefixed concatenation**
(`services/common/wire.py::lp`): each part is a 4-byte big-endian length
followed by its bytes. Without this, `("ab","c")` and `("a","bc")` would produce
identical bytes and a signature over one would verify over the other.

### 3.1 Hop 1 — ClientHello (`POST /handshake` on the gateway)

```json
{
  "protocol": "wx-legacy/1",
  "hop": "device-gateway",
  "client_id": "device-berlin-01",
  "client_nonce": "<b64, 16 bytes>"
}
```

No ephemeral key and no signature. The device is identified by `client_id` and
authenticated *implicitly* — the gateway looks up that device's static ECDH
public key, and only the genuine device can derive the matching session key.

### 3.2 Hop 1 — ServerHello

```json
{
  "protocol": "wx-legacy/1",
  "session_id": "<b64, 16 bytes>",
  "server_nonce": "<b64, 16 bytes>",
  "nonce_prefix": "<b64, 4 bytes>",
  "expires_at": "2026-09-21T10:05:00Z",
  "max_records": 100
}
```

**Unauthenticated.** An on-path attacker can forge this. The device accepts it
without checking anything, and only discovers a wrong gateway when its first
message comes back with a tag failure.

### 3.3 Hop 2 — ClientHello (`POST /handshake` on the cloud)

```json
{
  "protocol": "wx-legacy/1",
  "hop": "gateway-cloud",
  "client_id": "gw-01",
  "client_nonce": "<b64, 16 bytes>",
  "eph_pub": "<b64, X9.62 uncompressed P-256 point, 65 bytes>",
  "sig": "<b64, ECDSA-P256-SHA256, DER>"
}
```

`sig` covers:

```
lp( "wx-legacy/1", "gateway-cloud", "client-hello",
    client_id, client_nonce, eph_pub )
```

### 3.4 Hop 2 — ServerHello

```json
{
  "protocol": "wx-legacy/1",
  "session_id": "<b64, 16 bytes>",
  "server_nonce": "<b64, 16 bytes>",
  "eph_pub": "<b64, 65 bytes>",
  "nonce_prefix": "<b64, 4 bytes>",
  "expires_at": "2026-09-21T10:05:00Z",
  "max_records": 100,
  "sig": "<b64, ECDSA-P256-SHA256, DER>"
}
```

`sig` covers the **full transcript**, including the client's contribution:

```
lp( "wx-legacy/1", "gateway-cloud", "server-hello",
    client_id, client_nonce, client_eph_pub,
    session_id, server_nonce, server_eph_pub,
    nonce_prefix, expires_at, max_records )
```

Because the client's nonce and ephemeral key are inside the signature, a captured
ServerHello cannot be replayed into a different session. This is the explicit
server authentication that substitutes for what TLS would otherwise provide.

### 3.5 Data message (`POST /ingest`, both hops)

```json
{
  "session_id": "<b64, 16 bytes>",
  "seq": 0,
  "nonce": "<b64, 12 bytes = nonce_prefix(4) || seq_be(8)>",
  "ct": "<b64, AES-256-GCM ciphertext || 16-byte tag>"
}
```

- **AAD** = `session_id || seq_be(8)` — so the sequence number is authenticated
  and a ciphertext cannot be moved to a different position in the stream.
- **Nonce uniqueness** is structural: a random 4-byte prefix per session plus a
  counter that never repeats within that session. The receiver requires
  `seq` to be strictly increasing and recomputes the expected nonce itself.

### 3.6 Hop 1 plaintext — one reading

```json
{
  "device_id": "device-berlin-01",
  "station": { "lat": 52.54833, "lon": 13.407822, "elev_m": 38.0, "tz": "Europe/Berlin" },
  "sent_at": "2026-09-21T10:00:02Z",
  "date": "2024-01-01",
  "temp_max_c": 7.4,
  "temp_min_c": 3.4,
  "precip_mm": 1.80,
  "wind_max_kmh": 19.7
}
```

### 3.7 Hop 2 plaintext — gateway envelope

```json
{
  "gateway_id": "gw-01",
  "device_id": "device-berlin-01",
  "reading": { "date": "2024-01-01", "temp_max_c": 7.4, "temp_min_c": 3.4,
               "precip_mm": 1.80, "wind_max_kmh": 19.7 },
  "station": { "lat": 52.54833, "lon": 13.407822, "elev_m": 38.0, "tz": "Europe/Berlin" },
  "received_at": "2026-09-21T10:00:02Z",
  "device_hop": { "verified": true, "suite": "ECDH-P256-static-static+AES-256-GCM" }
}
```

`device_hop.verified` is the gateway **asserting** that hop 1 authenticated. The
cloud has no independent way to check this — see weakness W7.

### 3.8 Responses

```json
{ "status": "accepted", "seq": 0, "outcome": "stored" }
{ "status": "rejected", "seq": 0, "reason": "validation_failed" }
```

Reasons: `malformed_message`, `malformed_payload`, `malformed_envelope`,
`session_expired`, `replay`, `bad_tag`, `validation_failed`, `device_id_mismatch`.

Responses are **plaintext and unauthenticated** on both hops (W5).

---

## 4. Handshake sequences

### 4.1 Hop 1 — device → gateway (static-static, no forward secrecy)

```mermaid
sequenceDiagram
    autonumber
    participant D as Legacy device
    participant G as Edge gateway

    Note over D: has: own static ECDH privkey<br/>gateway static pubkey (pinned at "manufacture")
    Note over G: has: own static ECDH privkey<br/>registry device_id → device static pubkey

    D->>G: ClientHello { protocol, hop, client_id, client_nonce }
    Note over G: reject unknown client_id<br/>reject reused client_nonce

    Note over G: Z = ECDH(gw_static_priv, device_static_pub)
    Note over D: Z = ECDH(device_static_priv, gw_static_pub)
    rect rgb(253, 232, 232)
        Note over D,G: Z is IDENTICAL for every session.<br/>No ephemeral anywhere → no forward secrecy.
    end

    G-->>D: ServerHello { session_id, server_nonce, nonce_prefix,<br/>expires_at, max_records }
    rect rgb(253, 232, 232)
        Note over D: ServerHello is NOT authenticated.<br/>Device accepts it blindly.
    end

    Note over D,G: K = HKDF-SHA256(<br/>  ikm  = Z,<br/>  salt = client_nonce ‖ server_nonce,<br/>  info = lp("wx-legacy/1", "device-gateway") )
    rect rgb(253, 232, 232)
        Note over D,G: info does NOT bind the public keys.
    end

    loop seq = 0 .. max_records-1
        D->>G: Ingest { session_id, seq, nonce, ct }
        Note over G: seq must exceed the highest seen<br/>AES-GCM open, AAD = session_id ‖ seq<br/>validate ranges, check device_id matches session
        G-->>D: { status, seq } (plaintext)
    end

    Note over D,G: budget or TTL exhausted → new ClientHello
```

### 4.2 Hop 2 — gateway → cloud (ephemeral ECDHE + mutual ECDSA)

```mermaid
sequenceDiagram
    autonumber
    participant G as Edge gateway
    participant C as Cloud service

    Note over G: has: own ECDSA privkey<br/>cloud ECDSA pubkey (pinned)
    Note over C: has: own ECDSA privkey<br/>registry gateway_id → gateway ECDSA pubkey

    Note over G: generate FRESH ephemeral ECDH keypair
    G->>C: ClientHello { protocol, hop, client_id,<br/>client_nonce, eph_pub, sig }

    Note over C: reject unknown client_id<br/>reject reused client_nonce<br/>VERIFY sig over client transcript<br/>reject eph_pub not on P-256
    Note over C: generate FRESH ephemeral ECDH keypair

    Note over C: Z = ECDH(cloud_eph_priv, gw_eph_pub)
    C-->>G: ServerHello { session_id, server_nonce, eph_pub,<br/>nonce_prefix, expires_at, max_records, sig }

    rect rgb(230, 244, 234)
        Note over G: VERIFY sig over the FULL transcript<br/>→ explicit server authentication<br/>→ ServerHello cannot be replayed
    end
    Note over G: Z = ECDH(gw_eph_priv, cloud_eph_pub)

    Note over G,C: K = HKDF-SHA256(<br/>  ikm  = Z,<br/>  salt = client_nonce ‖ server_nonce,<br/>  info = lp(protocol, hop, gw_eph_pub,<br/>            cloud_eph_pub, client_nonce, server_nonce) )
    rect rgb(230, 244, 234)
        Note over G,C: Full transcript binding.<br/>Ephemerals discarded after use → forward secrecy.
    end

    loop seq = 0 .. max_records-1
        G->>C: Ingest { session_id, seq, nonce, ct }
        Note over C: replay check, AES-GCM open,<br/>re-validate reading, store
        C-->>G: { status, seq, outcome } (plaintext)
    end

    Note over G,C: budget or TTL exhausted → new ClientHello
```

### 4.3 The migration delta

Only `hop2_derive` and the hop 2 ClientHello/ServerHello change:

```
  ikm  = Z_ecdh                    →   ikm  = Z_x25519 ‖ ss_mlkem768
  info = lp(..., eph_pubs, nonces) →   info = lp(..., eph_pubs, nonces,
                                                  mlkem_pubkey, mlkem_ciphertext)
```

Hop 1, the device, the AEAD framing, validation, storage and the read API do not
move. That is the point of splitting the hops this way.

---

## 5. Session lifetime and rekeying

A session is the scope of one AEAD key. It ends at whichever comes first:

| Limit | Default | Env var |
|---|---|---|
| Records sent | 100 | `MAX_RECORDS_PER_SESSION` |
| Wall-clock age | 600 s | `SESSION_TTL_SECONDS` |

The client re-handshakes proactively when it hits either limit; if the server has
already dropped the session it answers `409 session_expired` and the client
re-handshakes and retries once.

Rekeying bounds how much data one derived key protects. On hop 1 it does **not**
bound the damage from a compromised static key, because every session key is
recomputable from `Z` plus the nonces, which travel in the clear.

Counter exhaustion is not a practical concern: the 8-byte counter allows 2⁶⁴
messages per session against a budget of 100.

---

## 6. Data flow and validation

`data/weather_data.csv` is an Open-Meteo daily export with **two CSV blocks**
separated by a blank line — a station block and a record block. Handing the whole
file to `csv.DictReader` produces nonsense, so `services/common/weather.py`
splits it explicitly and reads it as UTF-8 (the headers carry `°C`).

366 daily records, 2024-01-01 → 2024-12-31, Berlin, no gaps, no missing values.

Validation runs **twice** — at the gateway and again at the cloud:

| Rule | Bound |
|---|---|
| `date` | parseable ISO 8601 calendar date |
| `temp_max_c`, `temp_min_c` | −90 … 60 °C |
| `temp_min_c ≤ temp_max_c` | cross-field consistency |
| `precip_mm` | 0 … 2000 mm |
| `wind_max_kmh` | 0 … 500 km/h |
| all measurements | real numbers; `bool` explicitly rejected |

Rejection reasons name the offending **field**, never its value, so plaintext
does not leak into logs.

Storage is SQLite with primary key `(device_id, date)`. Re-sending a date updates
it, which is what we want because the device loops over the same year.

---

## 7. Read API

Unauthenticated (W9). Published on `127.0.0.1:8000` only.

| Endpoint | Purpose |
|---|---|
| `GET /readings?limit=&since=&device_id=` | most recent readings, newest first |
| `GET /readings/{date}` | one date, 404 if absent |
| `GET /stats` | row counts, active sessions, message counters |
| `GET /health` | liveness + advertised suite |

---

## 8. Weaknesses of this baseline

The reason the system exists. Ordered by how much they matter.

### Quantum exposure

- **W1 — Both hops fall to Shor's algorithm.** ECDH P-256 *and* ECDSA P-256 are
  broken by a cryptographically relevant quantum computer. Every handshake in
  this system is quantum-vulnerable.
- **W2 — Harvest-now-decrypt-later, and hop 1 is catastrophic.** Recorded traffic
  can be decrypted retroactively once a CRQC exists. On hop 1 this is far worse
  than usual: because the ECDH is static-static, recovering *one* private key
  yields `Z`, and `Z` plus the cleartext nonces yields **every session key the
  device has ever used**. Hop 2's ephemerals limit the damage to sessions whose
  ephemeral keys are individually attacked.
- **W3 — Signatures are not migrated either.** Replacing the KEM fixes
  confidentiality, not authentication. ECDSA P-256 remains quantum-broken, so a
  future attacker could impersonate the gateway or the cloud. **ML-DSA
  (FIPS 204) is out of scope for this project and is a stated remaining risk.**

### Protocol design

- **W4 — No forward secrecy on hop 1.** Compromise of either static key exposes
  all past and future traffic on that hop. Rekeying does not help.
- **W5 — ServerHello and all responses are unauthenticated on hop 1**, and
  responses are unauthenticated on both hops. An on-path attacker can forge
  `accepted`, causing silent data loss, or forge `rejected`, causing the device
  to discard good readings.
- **W6 — Hop 1's KDF does not bind the public keys.** `info` is a fixed label and
  only the nonces are salted in, so the derived key does not commit to the
  identities involved. Asserted by a test so it cannot change unnoticed.
- **W7 — No algorithm negotiation and no downgrade protection.** The `protocol`
  field is trusted and, on hop 1, unauthenticated. There is no cipher-suite
  agility at all, which is itself why this migration is hard.
- **W8 — The cloud trusts the gateway's word.** `device_hop.verified` is an
  assertion. Readings are not signed by the device, so a compromised gateway can
  fabricate readings that the cloud accepts as device-authenticated.
- **W9 — Nonce-collision fragility on hop 1.** If both handshake nonces ever
  repeated, the session key would repeat, and since the AEAD counter restarts at
  0 that is a catastrophic (key, nonce) reuse. 16 random bytes per side makes it
  negligible in practice, but nothing in the design *prevents* it.

### Transport and operations

- **W10 — No TLS.** Metadata — device ids, message timing, message sizes — is in
  the clear, and there is no protection against traffic analysis.
- **W11 — Key management is a placeholder.** Keys are unencrypted PEM files on a
  shared volume, generated by a container. No HSM or secure element, no
  attestation, no rotation path, no revocation. The device's pinned gateway key
  cannot be changed without reflashing — which by premise cannot happen.
- **W12 — Read API has no authentication and no rate limiting.** Anyone who can
  reach the port can read everything.
- **W13 — No store-and-forward.** If the cloud is unreachable the gateway returns
  `502` and the reading is dropped. The device logs and moves on. There is no
  queue, no retry budget and no backoff.
- **W14 — Sessions are in-memory and per-replica.** A restart drops every session,
  and the design does not survive horizontal scaling.
- **W15 — SQLite single-writer, no backups, no migrations.**

### Testing and observability

- **W16 — No CI.** 209 tests exist and pass, with 91% line coverage, but nothing
  runs automatically on push. See `docs/TESTING.md`.
- **W17 — ~~The Docker build and compose stack are unverified.~~ RESOLVED
  2026-09-21.** `docker compose up` builds and runs; all 366 readings flow
  device → gateway → cloud with zero rejections, verified by 9 integration tests
  in `tests/test_docker_integration.py`.
- **W18 — No fuzzing or property-based testing** of the parser or the wire
  format, and no load testing. Negative tests are hand-written cases; a
  `b64d(None)` crash-to-500 bug found during this work suggests generated input
  would find more. See `docs/TESTING.md` §5.
- **W19 — Logging only, no metrics.** No counters exported, no tracing, no
  dashboards, no alerting. `GET /stats` is the closest thing and must be polled
  by hand. This is what the observability work replaces.

---

## 9. What a human must verify

Flagged explicitly, per the project's working rules.

1. ~~The Docker build and `docker compose up` have not been run.~~ **Done
   2026-09-21** — build, keygen ordering, volume permissions, healthchecks and a
   full 366-reading replay all verified. See `tests/test_docker_integration.py`.
2. **Review the hop 1 design as deliberate.** The missing forward secrecy,
   unauthenticated ServerHello and weak KDF binding are intentional and
   documented. Confirm the group agrees they are the right "before" state rather
   than accidents.
3. **Check the transcript definitions** in `services/common/handshake.py` against
   the sequences in §4. A mismatch between what is signed and what is used is the
   classic way this kind of protocol breaks.
4. **Python version.** The code targets 3.12 in the container but is written to
   run on 3.10 so it can be tested on machines without 3.12. Decide whether to
   keep that.
5. **`0.0.0.0` bind.** Correct inside a container, wrong if anyone runs these
   services directly on a host.
