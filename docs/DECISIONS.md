# Decisions

Append-only. Newest entry last. Each entry records what was done, what else was
considered, what is known to be weak, and what a human must check.

---

## 2026-09-21 — Legacy baseline: device → gateway → cloud

### What was done

Built the complete pre-PQC baseline: three containerised Python services, a
shared crypto/wire library, 47 tests, docker-compose, and `docs/ARCHITECTURE.md`.

- `data/` — `weather_data.csv` moved here from the repo root (`git mv`) to match
  the layout in `CLAUDE.md`. Open-Meteo daily export, two CSV blocks separated by
  a blank line, 366 records for 2024, Berlin, no gaps or missing values.
- `services/common/` — wire encoding, crypto primitives, both handshakes, session
  store, CSV parsing, validation, config/logging.
- `services/device/` — replays readings; hop 1 client.
- `services/gateway/` — hop 1 server, hop 2 client, validation, forwarding.
- `services/cloud/` — hop 2 server, SQLite storage, read API.

**Suite:** ECDH P-256, ECDSA P-256 + SHA-256, HKDF-SHA256, AES-256-GCM. All via
`cryptography`; no primitive implemented by hand.

### Decision 1 — Application-layer crypto over plain HTTP, not TLS

**Chosen** so the key establishment is ours to see, test and replace. Putting it
inside TLS would hide the handshake in OpenSSL and make the ML-KEM integration a
matter of linking a different library rather than an exercise in safe migration.
It also makes the before/after measurement possible at all.

*Alternatives:* TLS 1.3 with a PQC-capable provider (hides the thing we are
studying); mTLS (same); raw TCP with a custom framing layer (more code, no gain).

**Production would not do this.** A real deployment of this system should use
**TLS 1.3 with the `X25519MLKEM768` hybrid group** (the IETF/NIST-aligned named
group now widely deployed) and keep application-layer crypto only if it needs
end-to-end protection *through* the gateway. This project's structure is a
teaching and measurement artefact, not a recommendation.

**Condition met:** the user required that the handshake authenticate the server.
Hop 2 does this explicitly — the cloud signs the full transcript with ECDSA and
the gateway verifies before deriving. Hop 1 authenticates the gateway only
*implicitly*, via the pinned static ECDH key; see Decision 3.

### Decision 2 — Keep ECDSA, and place it on hop 2

ECDSA is kept because it makes "the gateway validates readings" mean something,
and because it is *also* quantum-broken — giving the final report a concrete
remaining-risk statement (ML-DSA / FIPS 204 not implemented; see W3).

It is placed on **hop 2 only**. On hop 1 the device's static ECDH key already
*is* its identity, so a signature on top would be redundant crypto that no real
constrained firmware ships. On hop 2 the gateway uses ephemeral keys and
therefore needs an explicit signature to prove who it is.

### Decision 3 — Split the hops (this is the important one)

| | Hop 1 | Hop 2 |
|---|---|---|
| ECDH | static-static | ephemeral-ephemeral |
| Forward secrecy | none | yes |
| Auth | implicit both ways | explicit, mutual, ECDSA |
| ServerHello signed | no | yes |
| KDF binds public keys | **no** | yes |

**Hop 1 is deliberately weak.** It models non-upgradeable firmware honestly.
**Hop 2 is a clean classical baseline** so that swapping in X25519 + ML-KEM-768
isolates the cost of the KEM and nothing else.

*Alternative considered:* identical structure on both hops — simpler to test, but
it would have made the "before" state look better than real legacy systems do,
and it would have muddied the benchmark.

### Decision 4 — HKDF transcript binding differs by hop, on purpose

- Hop 1: `salt = client_nonce ‖ server_nonce`, `info = lp(protocol, hop)`.
  The peers' **public keys are not bound**. This is a real and common legacy
  shortcut, not an oversight.
- Hop 2: `info = lp(protocol, hop, both ephemeral pubkeys, both nonces)` — full
  binding, as `CLAUDE.md` requires on the PQC path.

Both are asserted by tests (`test_hop1_kdf_does_not_bind_public_keys`,
`test_hop2_kdf_binds_the_full_transcript`) so neither can change silently.

### Decision 5 — AEAD nonce construction

Nonce = 4-byte random per-session prefix ‖ 8-byte big-endian counter.
AAD = `session_id ‖ counter`. The receiver requires strictly increasing sequence
numbers and recomputes the expected nonce itself, so a ciphertext cannot be
replayed, reordered or moved to a different sequence position.

*Alternative:* fully random 96-bit nonces — simpler, but birthday-bounded and it
gives no replay protection for free. *Alternative:* a sliding replay window —
more robust to reordering, more state; unnecessary over HTTP.

### Decision 6 — Session lifetime

Rekey after **100 records or 600 seconds**, whichever comes first; both are env
vars. Bounds the data protected by one key. Does **not** bound hop 1 static-key
compromise, since all of its session keys are recomputable from `Z` and the
cleartext nonces.

### Decision 7 — Key provisioning

A `keygen` service runs once at compose startup and writes four P-256 keypairs to
a shared volume; existing keys are kept so a restart does not brick the pinned
device. `keys/` and `*.pem` are gitignored — **no private keys in the repo**.

*Alternative:* commit dev keys (simpler, but normalises a bad habit);
*alternative:* a key-distribution service (out of scope for a baseline).

### Decision 8 — Python 3.10-compatible source, 3.12 in the container

`CLAUDE.md` specifies 3.12 and the image uses `python:3.12-slim`. The source
avoids 3.11+ syntax so the suite also runs on 3.10, which is what was available
for testing. Nothing in the project needs a 3.12-only feature. **Flagged for the
group to confirm** — if 3.12 everywhere is preferred, say so and the constraint
can be dropped.

### Known weaknesses

The full list is §8 of `docs/ARCHITECTURE.md` (W1–W19). Headline items:

- W1/W2 — both hops fall to Shor; on hop 1, one recovered static key yields
  *every* session key the device has ever used.
- W3 — **ML-DSA is not implemented; ECDSA stays quantum-broken.** Stated
  remaining risk for the final report.
- W5 — responses are unauthenticated on both hops; forged ACKs cause silent loss.
- W8 — the cloud cannot independently verify that hop 1 authenticated.
- W13 — no store-and-forward; readings are dropped if the cloud is unreachable.
- W16/W19 — no CI, no metrics. Next phases.

### What was verified

- **47 tests pass** on Python 3.10 (`pytest`): parser against the real 366-record
  file, both handshakes deriving matching keys, AEAD tamper/replay/reorder/
  wrong-key rejection, validation bounds, and in-process device → gateway → cloud
  flow including forced rekeying and the read API.
- **Real multi-process run**: cloud and gateway under uvicorn on real sockets,
  device replaying 8 readings — 8 accepted on both hops, stored, and returned by
  `GET /readings`. Gateway and cloud `/stats` agreed.

### What a human must verify

1. **The Docker build and `docker compose up` were never executed** — no Docker
   in the authoring environment. Image build, volume ownership for the non-root
   `appuser`, healthchecks and `depends_on` ordering are **unverified**.
2. That the hop 1 weaknesses read as deliberate rather than as mistakes.
3. That the signed transcripts in `handshake.py` match §3–4 of ARCHITECTURE.md.
4. Decision 8 (Python version floor).
5. `0.0.0.0` bind is correct for containers, wrong for direct host execution.

---

## 2026-09-21 — Testing and measurement baseline

### What was done

Established the "before" measurement for the PQC migration: 209 tests (up from
47), 91% line coverage, a Docker integration suite, and a benchmark script that
writes comparable results to `results/`. Full report in `docs/TESTING.md`.

- `tests/test_negative.py` (new, 89 tests) — the "rejected, not crash" contract.
- `tests/test_docker_integration.py` (new, 9 tests) — the real compose stack.
- `tests/test_sessions.py` (new, 13 tests) — session lifetime, rekeying, log hygiene.
- `tests/test_config.py` (new, 40 tests) — env parsing, device startup helpers.
- `tests/test_weather.py`, `tests/test_crypto.py` — extended to cover parser and
  wrapper error paths.
- `scripts/benchmark.py` (new) — three-layer benchmark, JSON + Markdown output.
- `docs/TESTING.md` (new) — coverage, methodology, and what is hard to test.

### W17 resolved: the container path is verified

`docker compose up --build` works. All 366 readings flow device → gateway →
cloud with zero rejections and ≥4 rekeys. Also verified: keygen runs once and
exits 0, containers run as non-root `appuser`, private keys live on the volume
and not in image layers, the gateway's ingest port is **not** published to the
host, and a tampered message is rejected inside the real network.

This was the outstanding item from the previous entry. ARCHITECTURE.md §8 and §9
have been updated.

### Bug found and fixed

`b64d(None)` raised `AttributeError`, which was not in the request handlers'
caught exception tuple. A JSON `null` in any base64 field therefore produced a
**500 instead of a 400** — precisely the crash-instead-of-reject failure the
negative tests were written to find.

Fixed in `services/common/wire.py`: `b64d` now raises `ValueError` for
non-string input. **Hardening the wrapper rather than each call site** was
chosen deliberately — there are eight call sites across two services and adding
`AttributeError` to each `except` tuple would leave the next one to be written
vulnerable again. `UnicodeEncodeError` is also folded into `ValueError` for the
same reason.

*Known weakness:* this makes `b64d` accept a slightly wider contract than its
name suggests. Reviewers should confirm that raising `ValueError` for a type
error is acceptable here; the justification is that every input to this function
comes off the wire, so a wrong type is hostile data, not a programming error.

### Decision 9 — Docker tests are opt-in, not default

`pytest.ini` sets `addopts = -m "not docker"`. The fast suite is ~7 s and should
be run constantly; the Docker suite builds images and replays a year (~60 s).
Marked `docker`, run with `pytest -m docker`, and skipped automatically when
Docker is absent rather than failing.

*Alternative:* one suite, always. Rejected — a 60 s suite stops being run.

### Decision 10 — The benchmark runs in-process, not over sockets

Numbers must be comparable across machines and CI runners. A real socket would
measure the network far more than the crypto, and the comparison we need is
before/after on the same machine.

**Consequence, stated plainly:** absolute values are not production latencies.
The ~5 ms floor on every round trip is ASGI and JSON serialisation, not
cryptography — hop 1 key establishment is 0.09 ms inside a 4.8 ms handshake.
The three-layer split (primitives / key establishment / protocol) exists so the
crypto cost can be read without that floor.

*Alternative:* benchmark against the running compose stack. Rejected as the
default because container scheduling noise would swamp a sub-millisecond
difference, but it remains the right thing to do for an end-user-latency claim.

### Decision 11 — Two tests assert weaknesses on purpose

`test_hop1_has_no_forward_secrecy` and `test_hop1_kdf_does_not_bind_public_keys`
assert that hop 1 is weak. If someone "fixes" hop 1, these fail loudly. That is
intended: hop 1 is the legacy control in the experiment, and silently improving
it would invalidate the before/after comparison.

### Baseline numbers recorded

`results/legacy-baseline-latest.json` and `.md` (300 iterations, Python 3.10,
Windows AMD64, in-process):

| Measurement | Median |
|---|---:|
| hop 1 key establishment (static-static ECDH) | 0.093 ms |
| hop 2 key establishment (ECDHE + mutual ECDSA) | 0.795 ms |
| hop 1 handshake round trip (incl. HTTP) | 4.80 ms |
| hop 2 handshake round trip (incl. HTTP) | 6.21 ms |
| reading, both hops end to end | 7.35 ms |
| hop 2 handshake size | 710 B |
| wire/plaintext ratio per reading | 1.785x |

After ML-KEM-768, hop 2 handshake size should grow by ~3 KB (base64'd) and hop 2
handshake latency should rise. **Per-message latency and size must not change.**
If they do, the KEM is being misused on the payload path.

### Known weaknesses of this testing baseline

Full treatment in `docs/TESTING.md` §5. The ones that matter:

- **Quantum vulnerability is not testable at all.** No test in this suite says
  anything about W1–W3. That is an argument from published cryptanalysis.
- **W5 (forged ACKs) is real and unproven by any test.** Demonstrating it needs
  an intercepting proxy between containers. Largest gap in the suite.
- **Coverage excludes the containers.** `services/device/main.py` reads 39% but
  its replay loop runs 366 times in every Docker test; coverage is not collected
  inside containers. The number understates what is exercised.
- **"Never log secrets" is approximated, not proven.** The test scans one run's
  log records for one session key in three encodings. It cannot cover paths the
  test did not take or a `log.debug` added later.
- **No concurrency testing.** `SessionStore` is a plain dict mutated from
  uvicorn's threadpool. Untested under races.
- **No timing side-channel analysis.** We trust `cryptography`/OpenSSL and have
  not verified constant-time behaviour.

### What a human must verify

1. That `b64d` raising `ValueError` on a type error is the right call (above).
2. That the benchmark's in-process methodology is acceptable for the report, and
   re-run it on the machine that will produce the after-measurement — comparing
   across machines is meaningless.
3. That Decision 11's weakness-asserting tests are understood by the whole group
   before anyone "fixes" hop 1.
4. Set up CI (W16). The fast suite is 7 s; there is no reason it is not automatic.
