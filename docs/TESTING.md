# Testing and Measurement Baseline

The "before" measurement for the PQC migration. Every number here was produced
by running the suite, not estimated.

**Status:** 209 tests, all passing. 91% line coverage on `services/`.

---

## 1. How to run

```bash
pytest                          # 200 fast tests (~7 s), no Docker
pytest -m docker                # 9 integration tests against real containers (~60 s)
pytest -m ""                    # everything
pytest --cov=services --cov-report=term-missing
python scripts/benchmark.py     # writes results/
```

Docker tests are opt-in (`addopts = -q -m "not docker"` in `pytest.ini`) because
they build images and replay a full year. They skip automatically if Docker is
unavailable rather than failing.

---

## 2. What is tested

| Module | Tests | Focus |
|---|---:|---|
| `test_negative.py` | 89 | hostile input on both hops — rejected, not crashed |
| `test_config.py` | 40 | env parsing, device startup |
| `test_weather.py` | 26 | two-block CSV parsing, validation bounds |
| `test_crypto.py` | 21 | ECDH/ECDSA/HKDF wrappers, AEAD framing |
| `test_sessions.py` | 13 | session lifetime, rekeying, log hygiene |
| `test_end_to_end.py` | 11 | in-process device → gateway → cloud |
| `test_docker_integration.py` | 9 | the real docker-compose stack |
| **Total** | **209** | 200 fast + 9 Docker |

### 2.1 Parsing and validation

The export is two CSV blocks separated by a blank line, so the parser is a
genuine source of bugs rather than a formality. Covered: the real 366-record
file end to end; a single-block file; truncated rows; missing columns in either
block; empty cells; bad dates; non-numeric measurements; a station row shorter
than its header; UTF-8 handling for the `°C` headers; and the replay iterator
in both looping and non-looping modes.

Validation is checked at both bounds of every field, plus the cross-field rule
`temp_min ≤ temp_max`, string-instead-of-number, `None`, `NaN`, `Inf`, and
`bool` (which is an `int` subclass in Python and would otherwise slip through as
`1.0`).

### 2.2 Crypto wrappers

Both hops derive matching keys from both directions. Signature verification
fails for the wrong key and for the wrong message. Public-key encoding
round-trips, and an off-curve point is rejected — the invalid-curve defence.
Non-P-256 keys are refused at load time.

Two tests deliberately assert **weaknesses** so they cannot be silently
"fixed", which would destroy the before/after comparison:

- `test_hop1_has_no_forward_secrecy` — the same `Z` every session.
- `test_hop1_kdf_does_not_bind_public_keys` — both directions derive the same
  key, because nothing in the KDF distinguishes the roles.

AEAD framing: round trip, nonce uniqueness across 100 messages, tampering at
four byte positions, replay, reordering, wrong key, and the sequence number
being bound into the AAD.

### 2.3 Negative tests — the "rejected, not crash" contract

This is the largest group. Every case asserts three things: a 4xx with a reason
code (never a 5xx, which would mean an unhandled exception), nothing stored,
and **the service still serves the next request**. A service that rejects an
attack and then falls over has still been denied.

| Category | Cases |
|---|---|
| Tampered ciphertext | bit flips at 4 positions, truncation, empty, cross-session replay — both hops |
| Replayed message | byte-identical replay, out-of-order, replayed ClientHello — both hops |
| Malformed reading | 12 implausible-value mutations, 5 missing fields, non-JSON, JSON that is not an object |
| Wrong key | wrong device key, wrong pinned gateway key, unknown device id, forged gateway signature, signature over a different transcript |
| Malformed frames | empty body, bad base64, negative/string/bool/oversized `seq`, JSON `null` fields, unknown session, 1 MB blob |
| Handshake abuse | wrong protocol, wrong hop, short nonce, non-string client id, off-curve ephemeral key |
| Read API | 404s, out-of-range `limit`, non-numeric `limit`, garbage `since` |

**This found a real bug.** `b64d(None)` raised `AttributeError`, which was not in
the handlers' caught exception tuple, so a JSON `null` in any base64 field
produced a **500 instead of a 400** — exactly the crash-instead-of-reject case.
Fixed in `services/common/wire.py` by making `b64d` raise `ValueError` for
non-string input, hardening the wrapper rather than patching each call site.

### 2.4 Integration

Two levels, deliberately:

- **In-process** (`test_end_to_end.py`) — both FastAPI apps on Starlette
  `TestClient`. Fast, runs anywhere, good for logic.
- **Real containers** (`test_docker_integration.py`) — the only tests that touch
  the actual deployment artefact. They verify the image build, keygen init
  ordering, the shared keys volume, healthchecks, `depends_on` conditions,
  service DNS, that all 366 readings arrive with zero rejections and ≥4
  rekeys, that containers run as non-root `appuser`, that keys live on the
  volume and not in image layers, that the gateway's ingest port is **not**
  published to the host, and one tamper case executed inside the network.

---

## 3. Coverage

```
Name                                Stmts   Miss  Cover
-----------------------------------------------------------------
services/cloud/main.py                136      3    98%
services/cloud/storage.py              42      3    93%
services/common/config.py              39      0   100%
services/common/cryptoutil.py          99      5    95%
services/common/handshake.py           24      0   100%
services/common/sessions.py            60      1    98%
services/common/weather.py            136      1    99%
services/common/wire.py                29      2    93%
services/device/gateway_client.py      72      8    89%
services/device/main.py                64     39    39%
services/gateway/cloud_client.py       84     12    86%
services/gateway/main.py              124     11    91%
-----------------------------------------------------------------
TOTAL                                 909     85    91%
```

**Important caveat:** this is measured on the fast suite only. Coverage is not
collected inside containers, so the Docker tests contribute nothing to these
numbers even though they exercise a great deal of code.

`services/device/main.py` at 39% is the clearest example. Its replay loop is
fully exercised by the Docker integration test — 366 readings through it every
run — but none of that is counted. Only `wait_for_gateway` is unit-tested. The
uncovered lines are the `main()` loop body, which is a `while` over a generator
with `time.sleep` in it; testing it in-process would mean either mocking the
clock and the HTTP client until the test asserts nothing real, or duplicating
the Docker test badly.

The remaining uncovered lines are mostly `if __name__ == "__main__"` blocks,
`build_default_app()` factories that only run from env vars in a container, and
network-error branches in the two client classes.

---

## 4. Benchmark

`python scripts/benchmark.py` writes three files to `results/`:

- `legacy-baseline-<timestamp>.json` — archived run
- `legacy-baseline-latest.json` — stable name for diffing after PQC
- `legacy-baseline-latest.md` — human-readable summary

Three layers, because they answer different questions:

1. **Primitives** — ECDH, ECDSA, HKDF, AES-GCM in isolation. This is where
   ML-KEM's cost will actually appear, with no HTTP or JSON noise.
2. **Key establishment** — the complete handshake computation for each hop,
   both sides, crypto only.
3. **Protocol and sizes** — full round trips including framing, and exact
   serialised byte counts.

### 4.1 Baseline numbers

Median, 300 iterations, Python 3.10 on Windows AMD64, in-process.

| Measurement | Median |
|---|---:|
| `ecdh_p256` | 0.067 ms |
| `ecdsa_sign_p256` | 0.041 ms |
| `ecdsa_verify_p256` | 0.094 ms |
| **hop 1 key establishment** (static-static) | **0.093 ms** |
| **hop 2 key establishment** (ECDHE + mutual ECDSA) | **0.795 ms** |
| hop 1 handshake round trip (incl. HTTP) | 4.80 ms |
| hop 2 handshake round trip (incl. HTTP) | 6.21 ms |
| reading, both hops end to end | 7.35 ms |

| Size | Bytes |
|---|---:|
| P-256 public key (X9.62 uncompressed) | 65 |
| ECDSA P-256 signature (DER) | 71 |
| hop 1 handshake total | 310 |
| hop 2 handshake total | 710 |
| reading plaintext (JSON) | 233 |
| hop 1 ingest frame on the wire | 416 |
| **AEAD expansion** (the GCM tag) | **16** |
| **Framing overhead** (base64 + JSON) | **167** |
| **Wire/plaintext ratio** | **1.785x** |

Latency is reported as median and p95. Means are dominated by outliers and are
not a useful thing to compare across runs.

### 4.2 Reading these numbers honestly

Everything runs **in-process**, on purpose: the numbers must be comparable
across machines and CI runners, and a real socket would measure the network far
more than the crypto. The ~5 ms floor on every round trip is ASGI and JSON
serialisation, not cryptography — note that hop 1 key establishment is 0.09 ms
inside a 4.8 ms handshake. **Absolute values are not production latencies.**
The delta is the deliverable.

### 4.3 What to expect after ML-KEM

ML-KEM-768 changes the handshake, not the message path:

- **hop 2 handshake should grow**, in both latency and size. An ML-KEM-768
  encapsulation key is 1184 B and a ciphertext 1088 B, against 65 B for a P-256
  public key — roughly +2.2 KB before base64, ~3 KB after.
- **hop 1 should be unchanged.** The device is non-upgradeable.
- **Per-message latency and size should be unchanged.** The KEM establishes a
  key and never touches the payload. **If per-message numbers move, something is
  wrong** — most likely ML-KEM being misused to encrypt data, which
  `CLAUDE.md` forbids.

---

## 5. What is hard to test, and why

Stated plainly so nobody mistakes a green suite for a security guarantee.

### 5.1 Not testable, even in principle

**Quantum vulnerability (W1, W2, W3).** The central risk of the whole project
cannot be demonstrated by a test. No CRQC exists. The suite proves the crypto
works, which is orthogonal to whether it will still be safe. This is an argument
from published cryptanalysis, not from evidence we can generate. *Mitigation:
none available. It is why the migration is happening.*

**Absence of forward secrecy (W4).** "An attacker who later obtains the static
key can decrypt everything recorded" is a statement about a capability we cannot
grant a test. `test_hop1_has_no_forward_secrecy` asserts the *structural* cause —
`Z` is identical every session — which is the closest a test can get. The actual
consequence is reasoning, not observation.

**Nonce-collision catastrophe (W9).** If both 16-byte handshake nonces ever
repeated, key+nonce reuse would break AES-GCM completely. Triggering that
requires a ~2⁻¹²⁸ event. We test that nonces are *structurally* unique within a
session; we cannot test the collision path without weakening the RNG, which
would test a different system.

### 5.2 Testable only with tooling we do not have

**Timing side-channels.** Nothing here measures whether signature verification
or tag comparison is constant-time. We rely on `cryptography`/OpenSSL for that
and have not verified it. Would need `dudect` or similar statistical testing.

**On-path attacker forging responses (W5).** ACKs are unauthenticated on both
hops, so an attacker could forge `accepted` (silent data loss) or `rejected`
(discarding good readings). Demonstrating this needs an intercepting proxy
between containers, not a unit test. **The vulnerability is real and currently
unproven by any test** — the most significant gap in this suite.

**Concurrency.** `SessionStore` is a plain dict mutated from uvicorn's
threadpool. There is no test for concurrent handshakes racing on the same
session, or for the nonce table under load. Would need a proper concurrency
harness; `pytest` alone cannot make these deterministic.

**Resource exhaustion.** We test a 1 MB ciphertext is refused, but there is no
load testing, no memory-pressure testing, and no test of the nonce table growing
under sustained handshake volume. `test_nonce_table_is_pruned...` documents that
pruning also makes very old ClientHellos replayable again — a real trade-off
that is recorded rather than solved.

### 5.3 Approximated, not proven

**"Never log keys or plaintext."** `test_handshake_logs_do_not_contain_key_material`
scans captured log records for the session key in hex, base64 and byte-list
form, and for the private key PEM. This can only catch secrets that appear *in
that run's log lines*. It cannot prove the property for code paths the test did
not take, for a future `log.debug` someone adds, or for an exception traceback
that happens to carry key material. It is a regression guard, not a proof.

**Rejection reasons not leaking values.** Same shape: we assert one specific
value does not appear in one specific response.

### 5.4 Deliberately out of scope

**The device's `main()` loop** — see §3. Covered by the Docker test, invisible to
coverage.

**Cloud restart / session recovery.** The client re-handshakes on
`session_expired` and that path is tested in-process, but we do not restart the
cloud container mid-run to prove it end to end.

**Store-and-forward (W13).** There is nothing to test — the gateway drops
readings when the cloud is unreachable. The `forward_failed` counter is
incremented and the `502` path exists, but no test exercises it, because the
behaviour under test would be "data is lost", which is the documented weakness
rather than a bug.

**Clock skew.** TTL expiry is tested by mutating `expires_at` directly. Real
clock drift between containers is untested.

---

## 6. Recommended next steps

1. **CI** — run `pytest` on every push and `pytest -m docker` on merge. The
   fast suite is ~7 s; there is no excuse for it not being automatic.
2. **An intercepting proxy test** for W5, the largest unproven weakness.
3. **Property-based testing** (Hypothesis) on the parser and the wire format —
   the negative tests are hand-written cases and will miss shapes nobody
   thought of. The `b64d(None)` bug is evidence that this class of input is
   where the bugs are.
4. **Concurrency harness** for `SessionStore`.
5. **Re-run `scripts/benchmark.py` immediately before starting the PQC work**,
   on the machine that will run the after-measurement. Comparing across
   machines is meaningless.
