# Testing and Measurement Baseline

The "before" measurement for the PQC migration. Every number here was produced
by running the suite, not estimated.

**Status:** 275 tests, all passing. 92% line coverage on `services/`.

Covers the classical baseline **and** the hybrid post-quantum hop 2. PQC-specific
tests live in `tests/test_pqc.py`; see §2.5.

---

## 1. How to run

```bash
pytest                          # 264 fast tests (~7 s), no Docker
pytest -m docker                # 11 integration tests against real containers (~60 s)
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
| `test_negative.py` | 94 | hostile input on both hops — rejected, not crashed |
| `test_pqc.py` | 59 | hybrid PQC: handshake, negotiation, downgrade, rotation |
| `test_config.py` | 40 | env parsing, device startup |
| `test_weather.py` | 26 | two-block CSV parsing, validation bounds |
| `test_crypto.py` | 21 | ECDH/ECDSA/HKDF wrappers, AEAD framing |
| `test_sessions.py` | 13 | session lifetime, rekeying, log hygiene |
| `test_end_to_end.py` | 11 | in-process device → gateway → cloud |
| `test_docker_integration.py` | 11 | the real docker-compose stack |
| **Total** | **275** | 264 fast + 11 Docker |

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

### 2.5 Hybrid post-quantum (hop 2)

`tests/test_pqc.py`. The six behaviours the design has to get right:

**1. Hybrid handshake succeeds.** Both sides derive matching keys; data flows;
`pqc_fraction` reaches 1.0. Plus three structural properties: the IKM puts the
ML-KEM secret first (swapping the halves must change the key), changing *either*
half changes the key (so an attacker must break both), and the KDF binds the
ML-KEM ciphertext and both public keys.

**2. Tampered ML-KEM ciphertext.** Tested at both defence layers, because they
fail differently and the inner one is the subtle part:

- *Outer* — in the real protocol the ServerHello signature covers the
  ciphertext, so tampering in flight fails verification before decapsulation
  ever runs.
- *Inner* — bypassing the signature to isolate ML-KEM itself:
  **decapsulation does not raise**. FIPS 203 §7.3 implicit rejection returns a
  *different pseudorandom secret*, and the failure surfaces as an **AEAD tag
  failure** on the first message. A test asserting an exception here would be
  wrong, and this is the classic ML-KEM integration bug.

  This layering matters because the outer defence is ECDSA, which a CRQC can
  forge; the inner one still holds.

**3. Encapsulation-key validation (FIPS 203 §7.2).** The modulus check is
verified at the q boundary: coefficient 3328 accepted, 3329 rejected, all-0xFF
rejected — and **all-zeros accepted**, because that is a *valid* encoding.

> An earlier probe used "all-zeros was accepted" as evidence that validation was
> missing. That was wrong: all-zeros must be accepted, so the probe tested
> nothing. A negative test that cannot fail proves nothing. Recorded in
> DECISIONS.md because the mistake is instructive.

**4. Version and suite negotiation.** Both protocol versions are served; unknown
versions rejected; unknown suite names ignored rather than refused (forward
compatibility); a legacy `wx-legacy/1` gateway still works under `prefer` and is
refused under `require`.

**5. Downgrade protection**, all three layers independently:

| Attack | Defence | Result |
|---|---|---|
| Strip `hybrid` from `offered_suites` | signature over the offer | 403, signature fails |
| Reorder `offered_suites` | signature | 403 |
| Genuine classical-only offer | policy | 403 `downgrade_refused`, counted |
| Classical under `prefer` | logged + counted | 200, never silent |
| Signed classical ServerHello, gateway on `require` | client-side policy | refused |
| Cloud selects a suite we never offered | client-side check | refused |

**6. Key rotation and direction separation.** A fresh ML-KEM keypair every
handshake (5 handshakes → 5 distinct encapsulation keys and ciphertexts); the
record budget forces rekeys; rotated sessions have distinct keys; no ephemeral
private key is retained on the client after the handshake.

Direction separation: `key_c2s != key_s2c` for both suites, sending on the wrong
direction key is rejected with `bad_tag`, and separation comes from the KDF
label rather than from distinct nonce prefixes. Hop 1 keeps one key and
`test_hop1_is_strictly_one_way` asserts its responses are plaintext — if that
ever changes, `DerivedSession` must become directional first.

---

## 3. Coverage

```
Name                                Stmts   Miss  Cover
-----------------------------------------------------------------
services/cloud/main.py                251     17    93%
services/cloud/storage.py              42      3    93%
services/common/config.py              39      0   100%
services/common/cryptoutil.py         141      5    96%
services/common/handshake.py           73      1    99%
services/common/sessions.py            61      1    98%
services/common/suites.py              52      0   100%
services/common/weather.py            136      1    99%
services/common/wire.py                33      2    94%
services/device/gateway_client.py      72      8    89%
services/device/main.py                64     39    39%
services/gateway/cloud_client.py      148     13    91%
services/gateway/main.py              127     12    91%
-----------------------------------------------------------------
TOTAL                                1239    102    92%
```

The PQC work added ~330 statements and coverage went **up**, from 91% to 92%.
`suites.py` — negotiation and policy, the downgrade-protection logic — is at
100%.

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

- `<label>-<timestamp>.json` — archived run
- `<label>-latest.json` — stable name for diffing
- `<label>-latest.md` — human-readable summary

`--compare <baseline.json>` adds a before/after table. The Phase 2 → Phase 4
comparison was produced with:

```bash
python scripts/benchmark.py --label pqc-hybrid \
    --compare results/phase2-classical-baseline.json
```

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

### 4.3 Result after ML-KEM — the predictions held

The Phase-2 prediction was: hop 2 handshake grows by roughly 3 KB after base64,
hop 1 unchanged, per-message unchanged. Measured (`results/pqc-hybrid-latest.md`,
300 iterations, same machine):

| Measurement | Classical | Hybrid | Delta |
|---|---:|---:|---:|
| hop 2 key establishment (crypto only) | 0.746 ms | 1.158 ms | **+55%** |
| hop 2 ClientHello | 316 B | 2095 B | +563% |
| hop 2 ServerHello | 394 B | 1864 B | +373% |
| **hop 2 handshake total** | **710 B** | **3959 B** | **+458%** |
| hop 1 handshake total (control) | 310 B | 310 B | 0% |
| hop 1 key establishment (control) | 0.092 ms | 0.082 ms | −11% |
| **reading plaintext** | **233 B** | **233 B** | **0%** |
| **reading ciphertext + tag** | **249 B** | **249 B** | **0%** |
| **ingest frame on the wire** | **416 B** | **416 B** | **0%** |

The +3249 B growth matches the prediction: ek 1184 B + ct 1088 B = 2272 B raw,
≈3029 B base64'd, plus the suite list and second key share.

**The per-message rows are the invariant that matters.** All exactly 0% — ML-KEM
establishes a key and never touches the payload, as `CLAUDE.md` requires. Any
movement there would mean the KEM had leaked onto the data path.

#### Read the latency rows sceptically

**The hop 1 control row moved −11% despite nothing about hop 1 changing.** That
is pure run-to-run noise, and it is the honest measure of how much the
in-process round-trip figures can drift between runs. The same applies to the
round-trip latencies, which are dominated by ASGI and JSON rather than crypto.

Trustworthy at this sample size: the **crypto-only** latencies and the **byte
counts** (which are deterministic). Treat the round-trip numbers as indicative
only, and re-measure both sides on one machine in one sitting before quoting
them.

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
