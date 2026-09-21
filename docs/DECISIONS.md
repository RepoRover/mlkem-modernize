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

---

## 2026-09-21 — Hybrid post-quantum key establishment on hop 2

### What was done

Hop 2 (gateway → cloud) now does hybrid **X25519 + ML-KEM-768** key
establishment with suite negotiation, three-layer downgrade protection, and
per-direction key separation. Hop 1 is untouched and classical, by design.

- `services/common/suites.py` (new) — suite IDs, `Policy`, `negotiate()`.
- `services/common/handshake.py` — `wx-hybrid/2` transcripts and `hop2_v2_derive`.
- `services/common/cryptoutil.py` — X25519 and ML-KEM-768 wrappers.
- `services/cloud/main.py` — protocol dispatch, negotiation, policy enforcement.
- `services/gateway/cloud_client.py` — offers suites, verifies, enforces policy.
- `scripts/demo_phases.py` (new) — runs each migration phase.
- `docs/MIGRATION.md` (new) — phases, sunset criteria, trust-boundary risks.

**Full design, including all 20 security assumptions, was reviewed and approved
before implementation.**

### Decision 12 — Library: pyca/cryptography, pinned to 50.0.1

Compared three candidates by installing them:

| | pyca/cryptography | liboqs-python | PQClean wrappers |
|---|---|---|---|
| Install | binary wheel, ~10 s | **failed** — CMake-builds liboqs at import | build toolchain |
| Docker cost | none, already a dependency | cmake+ninja+gcc+git, source fetch at build | toolchain |
| Maintenance | 50.0.1 (2026-08-25), wheels ship OpenSSL 4.0.2 | active (OQS / PQCA) | thinner |
| FIPS 140-3 validated | **no** | **no** | **no** |

Chosen because it is already our only crypto dependency — one audit surface,
one CVE feed — and adds zero Docker build complexity. ML-KEM arrived in 48.0.0
(OpenSSL >= 3.5 backend; 47.0.0 was AWS-LC/BoringSSL only) and the
implementation is OpenSSL's.

*liboqs would win* if we needed agility across many PQC schemes. We need one KEM.

**Version pinned exactly.** Bumping 45.0.7 to 50.0.1 was done as a separate
first commit with the full suite as the gate: **200/200 fast tests and 9/9
Docker tests passed with no code changes.** No breakage to report.

*Verify independently:* the version and provenance claims above come from
upstream release notes and a local install; the reviewer asked to check them.

### Decision 13 — Hybrid construction: ML-KEM secret first

```
IKM  = ss_mlkem768 || ss_x25519
salt = client_nonce || server_nonce
info = lp(protocol, hop, selected_suite, client_id, offered_suites,
          nonces, both x25519 pubkeys, mlkem_ek, mlkem_ct, direction_label)
```

Order is not arbitrary: NIST SP 800-56C Rev2 permits HKDF over two shared
secrets **provided the FIPS-approved one leads**. TLS's `X25519MLKEM768` orders
it identically. Matching a construction with real scrutiny beats inventing one.

Asserted by `test_hybrid_ikm_puts_mlkem_first` — swapping the halves must change
the key, otherwise the ordering is not actually part of the construction.

### Decision 14 — Roles: gateway generates, cloud encapsulates

The gateway sends the encapsulation key; the cloud encapsulates to it. Same
direction as TLS 1.3 `key_share`, and it puts the expensive keygen on the edge
rather than on the shared cloud service.

### Decision 15 — Three-layer downgrade protection

1. **Signature** — the gateway signs its whole offer; the cloud signs the full
   transcript *including that offer*. Editing `offered_suites` in flight breaks
   both.
2. **KDF binding** — the offer list is in the HKDF info, so a mismatch yields
   different keys and fails at the AEAD.
3. **Policy** — `PQC_POLICY` in {`require`, `prefer`, `classical-only`}.
   Defaults: cloud `require`, gateway `prefer`. Classical selection is *never*
   silent: WARNING log plus `handshakes_classical` counter plus `pqc_fraction`
   on `/stats`. `classical-only` logs a startup banner.

Enforced on **both** ends: a gateway on `require` refuses a correctly signed
classical ServerHello, because either peer may be the one that was rolled back.

**Layers 1 and 2 rest on ECDSA and are therefore not post-quantum.** Only
layer 3 survives a CRQC. See the next entry.

### Decision 16 — ECDSA's weakness: active attacks only (per review feedback)

Stated precisely, because it is easy to over- or under-claim:

- **Recorded hybrid traffic stays confidential.** Session keys come from
  `ss_mlkem768 || ss_x25519`; breaking ECDSA reveals neither. An attacker who
  captures hop 2 traffic today and gets a CRQC later must still break
  ML-KEM-768. **HNDL protection on hop 2 is real and holds.**
- **ECDSA's weakness enables ACTIVE attacks, and only once a CRQC exists** —
  real-time impersonation, MITM, and forced downgrade, all requiring the
  attacker on-path *at handshake time* with a CRQC already in hand. None of this
  retroactively decrypts anything.

Even then, a cloud on `require` will not complete a classical session: a forged
signature buys a refused handshake, not a downgraded one.

Full treatment in `docs/MIGRATION.md` section 2. Residual risk: ML-DSA
(FIPS 204) is out of scope (W3).

### Decision 17 — Per-direction keys (per review feedback)

`DirectionalSession` derives `key_c2s` and `key_s2c` from the same IKM with
different direction labels (`gw->cloud`, `cloud->gw`) in the HKDF info.

Both directions share a session id and nonce prefix, so a shared key would mean
message N in each direction reused the same (key, nonce) pair — catastrophic for
AES-GCM. Only `key_c2s` carries data today (responses are still plaintext, W5),
but deriving both removes the failure mode instead of relying on the channel
staying one-way by convention.

**Hop 1 keeps a single key** and is documented and enforced as strictly one-way:
`test_hop1_is_strictly_one_way` asserts the gateway's responses are plaintext.
If encrypted responses are ever added there, `DerivedSession` must become
directional first.

### Correction — assumption 7 was based on a flawed probe

The pre-implementation design listed as an open assumption that
`MLKEM768PublicKey.from_public_bytes` performs FIPS 203 input validation,
citing as evidence that an **all-zero encapsulation key was accepted**.

**That evidence was wrong, and the reviewer was right to reject it.** An
all-zero ek is a *valid* encoding: every 12-bit coefficient is 0, which is
< q = 3329, so it must be accepted. It tested nothing.

The correct test is the FIPS 203 section 7.2 modulus check — a coefficient >= q
does not survive `ByteDecode12`/`ByteEncode12` round-tripping. Re-probed:

| Encapsulation key | Result |
|---|---|
| all zeros (coeffs = 0) | **accepted** — valid, as it should be |
| first coeff = 3328 (q-1) | **accepted** |
| first coeff = 3329 (= q) | **REJECTED** |
| all 0xFF (coeffs = 4095) | **REJECTED** |

The check is enforced, exactly at the q boundary. **Assumption 7 is now
verified rather than assumed**, and is locked in by
`test_encapsulation_key_with_coefficient_at_or_above_q_is_rejected`.

Lesson recorded deliberately: a negative test that cannot fail proves nothing,
and "the library accepted my malformed input" is worthless if the input was not
actually malformed.

*Note:* the library reports a modulus-check failure as `"An ML-KEM-768 public
key is 1184 bytes long"` even when the input *is* 1184 bytes. Misleading
upstream message; we wrap it in `InvalidEncapsulationKey` and never surface it.

### Decision 18 — Implicit rejection is load-bearing, and tested as such

FIPS 203 section 7.3: decapsulating a tampered ciphertext **does not fail**. It
returns a different pseudorandom secret, because distinguishing valid from
invalid ciphertexts would break IND-CCA security. **Verified empirically.**

Consequence: a tampered ML-KEM ciphertext surfaces as an **AEAD tag failure on
the first message**, never as a decapsulation exception. Code or tests expecting
an exception are wrong — this is the classic ML-KEM integration bug.

Both defence layers are tested separately:

- `test_tampered_mlkem_ciphertext_in_transit_fails_the_signature_first` — in the
  real protocol the ServerHello signature catches it *before* decapsulation.
- `test_tampered_mlkem_ciphertext_causes_aead_tag_failure` — bypasses the
  signature to isolate ML-KEM's own behaviour, which matters because the outer
  layer is ECDSA and a CRQC can forge it.

### Decision 19 — `classical-p256` fallback keeps P-256, not X25519

The fallback *is* the Phase-2 baseline, so the benchmark comparison isolates the
cost of adding ML-KEM and nothing else. Approved at review.

### Measured cost (Phase 2 to Phase 4)

300 iterations, in-process, same machine. Full table in
`results/pqc-hybrid-latest.md`.

| | Classical | Hybrid | Delta |
|---|---:|---:|---:|
| hop 2 key establishment (crypto only) | 0.746 ms | 1.158 ms | **+55%** |
| hop 2 handshake bytes | 710 B | 3959 B | **+458%** |
| hop 1 key establishment (control) | 0.092 ms | 0.082 ms | -11% (noise) |
| per-message size | 416 B | 416 B | **0%** |

The per-message row is the invariant that matters: **ML-KEM establishes a key
and never touches the payload**, as `CLAUDE.md` requires.

**Read the latency rows with care.** The hop 1 control row moved -11% despite
nothing changing, which is how much run-to-run noise the in-process round-trip
measurements carry. Only the crypto-only and byte-count rows are trustworthy at
this sample size; the round-trip figures are dominated by ASGI and JSON.

### Known weaknesses

- ECDSA remains quantum-broken (W3). Downgrade protection layers 1-2 fall with it.
- Hop 1 is still classical; the **system as a whole is not post-quantum**.
- Hybrid handshakes are trivially fingerprintable by size (~4 KB vs ~700 B).
- No FIPS 140-3 validated implementation is in use.
- Sunset criterion 3 (device inventory) cannot currently be satisfied — no
  firmware-version reporting exists. Blocks Phase 4.
- `SessionStore` concurrency remains untested (carried over).

### What a human must verify

1. **The library version and provenance claims** in Decision 12 — the reviewer
   asked to check these independently.
2. That the transcript definitions in `handshake.py` match `ARCHITECTURE.md`
   section 4. A mismatch between what is signed and what is used is how this
   class of protocol breaks.
3. That Decision 13's IKM ordering matches SP 800-56C Rev2 as you read it.
4. That the ECDSA framing in Decision 16 and `MIGRATION.md` section 2 is neither
   overstated nor understated for the final report.
5. Re-run `scripts/benchmark.py --compare` on the machine that will produce the
   report's numbers; cross-machine comparison is meaningless.


---

## 2026-09-21 — CI/CD pipeline

### What was done

GitHub Actions pipeline in `.github/workflows/ci.yml`: lint, type check, static
security analysis, dependency CVE scan, tests with a coverage gate, image build
and push, container scan, compose integration, and a kind deployment with a
post-deploy smoke test. Full stage-by-stage rationale in `docs/CICD.md`.

New files: `.github/workflows/ci.yml`, `pyproject.toml` (all tool config),
`deploy/k8s/*.yaml`, `scripts/smoke_test.py`, `docs/CICD.md`.

Platform was not guessed: the repo's own remote is
`github.com/RepoRover/mlkem-modernize`, so GitHub Actions it is.

### Decision 20 — Gates are hard from day one, so the code was fixed first

A pipeline whose gates are advisory is decoration. Rather than land the workflow
with `continue-on-error` and a backlog, every existing finding was resolved
before the gates went in:

- **ruff:** 73 findings. 43 auto-fixed; the rest either fixed properly or given
  *scoped* per-file ignores with a written reason.
- **bandit:** 12 findings, each assessed individually (table in `docs/CICD.md`).
  Five production `assert`s became explicit `raise`s — asserts are stripped under
  `python -O`, so they were not actually enforcing anything in a `-O` deployment.
- **mypy:** `services/` was already clean; tests and scripts were annotated until
  all 32 files pass.

*Alternative considered:* ship the workflow with warnings-only gates and fix
later. Rejected — nobody fixes later, and a permanently-yellow pipeline teaches
the team to ignore it.

### Decision 21 — Coverage threshold: 85%

Actual is ~91%. The 6-point gap is deliberate: `services/device/main.py` reads
39% because its replay loop is exercised only by the Docker suite, where
coverage is not collected. A gate pinned at 91% would fail correct changes for
reasons unrelated to them; 85% still fails if a test module is deleted or a
feature lands untested.

*Alternative:* per-file thresholds. Rejected as premature for this size.

### Decision 22 — One image for all three services

`SERVICE` selects the module at runtime, so cloud/gateway/device are the same
bytes with different env. Verified: all three modules import from a single built
image. One thing to build, scan, sign and roll back.

This also changed the k8s design for the better — no shared `keys` volume across
pods (which would need ReadWriteMany), just a Secret each pod mounts.

### Decision 23 — Deploy target: kind on the runner

Chosen at review from three options (kind / compose-on-runner / SSH to a real
host). kind gives a genuine deployment target — real Deployments, Services,
probes, Secrets and rollout semantics — with no infrastructure to own and no
long-lived credentials. The cluster is created and destroyed per run.

*Rejected:* compose-on-the-runner (not really a deploy, just a second
integration test); SSH to a test host (most realistic, but needs a machine the
group maintains and a static SSH key in CI).

### Decision 24 — Secrets are generated per run, never stored

CI runs `gen_keys.py`, creates a Kubernetes Secret from the output, and deletes
the local copy. Keys live only for the job. Registry auth uses the automatic
`GITHUB_TOKEN`. The workflow defaults to `contents: read`; only the build job
gets `packages: write`.

**Stated limitation:** a production pipeline would not generate its own keys. It
would fetch them from a KMS/HSM via an OIDC-federated identity, with no static
credential in CI. This is a test-environment shortcut and is recorded as such.

### Decision 25 — The smoke test asserts PQC, not just liveness

A 200 from `/health` proves the process started. It does not prove the keys were
mounted, the gateway can reach the cloud, or that hop 2 negotiated hybrid PQC
rather than silently falling back to classical.

`scripts/smoke_test.py` runs 10 checks across liveness, data flow, post-quantum
negotiation and the read API. **Both failure modes were verified, not assumed:**

- nothing deployed → exits 1 at the health check;
- **stack fully up but classical-only → exits 1**, despite 288 readings stored,
  zero rejections and a healthy `/health`. A conventional health check passes
  that; this one fails it. That is the check worth having.

### Bug found: 12 CVEs in a transitive dependency

`pip-audit` on its first run found **12 known vulnerabilities in starlette
0.48.0** (PYSEC-2026-161, -248, -249, -1942, -2280, -2281), pulled in
transitively by a stale `fastapi>=0.110,<0.120` pin. Nothing in our code was
wrong; the pin was simply old.

Fixed by moving to `fastapi>=0.141,<0.142` and pinning `starlette>=1.3.1`
directly so a transitive downgrade is caught too. **All 264 tests passed
unchanged** across that 22-minor-version jump, and the 11 Docker tests still
pass.

This is the clearest justification for the weekly cron: a CVE can be published
against code nobody has touched, so a green build last week is not evidence of a
safe build today.

### Known weaknesses of this pipeline

Full list in `docs/CICD.md` §7. The ones that matter:

- **The workflow has never run on GitHub.** Every stage was reproduced locally,
  but runner-specific behaviour (kind startup, GHCR auth, the trivy action,
  SARIF upload) is **unverified**. Expect to iterate on the first real run.
- **No persistent environment**, no rollback procedure, no release versioning
  beyond image tags.
- **No SBOM and no image signing** (cosign/sigstore) — natural next steps for a
  project adjacent to supply-chain security.
- **`ruff format` is not enforced**; it would reformat 18 hand-aligned files and
  bury real review in noise. Deferred to its own deliberate commit.
- **Trivy runs with `ignore-unfixed`**, so an unfixable HIGH does not block. It
  appears in the SARIF report, but nothing forces anyone to read it.
- **Coverage is an absolute gate, not a trend** — slow erosion from 91% to 85%
  would pass unnoticed.
- `sed` substitution of the image tag is the crudest possible templating.

### What a human must verify

1. **Run the workflow.** It is unverified on real runners; that is the single
   biggest caveat.
2. That the per-file ruff ignores and every `# nosec` in `pyproject.toml` and the
   source are agreed to be correct assessments, not conveniences. Each names a
   specific check and gives a reason; they should be read rather than trusted.
3. That 85% is the threshold the group wants.
4. That the `fastapi` 0.119 → 0.141 jump is acceptable. The suite passes, but
   the group should know a major dependency moved a long way in one step.
5. Set up branch protection on `main` requiring the `ci-passed` check.


---

## 2026-09-21 — Backend visualisation script

### What was done

`scripts/visualize.py`: runs the real device, gateway and cloud apps in-process
and prints a step-by-step trace of the data path — the two handshakes, the key
schedule, one reading travelling end to end, the rejection behaviour, and the
resulting cloud state.

No service code was changed. This is a reading aid for the report and for
reviewers who want to see the system work without standing up Docker.

### Decision 26 — Measure, do not narrate

Every number printed is taken from a live run through an httpx event-hook tap on
both TestClients, not hard-coded from the docs. A visualisation that restates
`ARCHITECTURE.md` can drift away from the code silently; one that reads the wire
cannot. The ML-KEM sizes (ek 1184 B, ct 1088 B) and the per-message byte counts
shown are therefore evidence, not claims.

*Alternative considered:* a static Mermaid diagram. Rejected — `ARCHITECTURE.md`
already has one, and a diagram cannot show that `pqc_fraction` is actually 1.0.

### Decision 27 — Keys are shown only as one-way fingerprints

CLAUDE.md forbids logging keys, shared secrets and plaintext payloads. Step 4
needs to demonstrate that `key_c2s != key_s2c`, which requires *comparing* two
keys without revealing either, so it prints truncated SHA-256 fingerprints.
Shared secrets are reported by length only. Step 1 prints the weather reading
from the CSV the script itself parsed — source data, never a decrypted payload.

### Bug found in my own probe: wrong defence demonstrated

The first version of the tampered-ciphertext probe incremented `seq` but reused
the original nonce. `AeadReceiver.decrypt` derives the expected nonce from
`prefix ‖ counter` and checks it *before* opening the AEAD, so the probe was
rejected as `replay` — the label said "bit flipped" while the backend was
actually catching a counter mismatch. Fixed by recomputing the nonce for the new
`seq`, which now produces the intended `bad_tag`. Both cases are shown side by
side, since the difference between them is the point.

Same lesson as the Assumption 7 correction earlier in this log: **a negative test
that passes for the wrong reason proves nothing.** A probe has to be checked
against *which* defence fired, not merely that something was refused.

### Decision 28 — A local web page over the terminal dump

`scripts/visualize_web.py` renders the same run as a page on `127.0.0.1:8080`,
with the byte-size bars, flow and metric tiles the terminal cannot show. It also
exposes `/api/trace` for the raw measurements.

Both front-ends read one shared `collect_trace()`, and the CLI's step 4 and step 6
were refactored onto the shared `sample_key_schedule()` and
`run_rejection_probes()` helpers. Two front-ends measuring independently would
eventually disagree, and the one that disagreed would still look authoritative.

*Alternative considered:* emit a static HTML file. Rejected — a file gets stale
and then gets quoted. The page re-runs the stack, so it is always current or it
is not there at all.

**Bound to 127.0.0.1, never 0.0.0.0.** It performs handshakes with development
keys and reports internal byte counts; it is a local diagnostic.

### Known weaknesses

- **No tests.** Both are diagnostic scripts, consistent with `demo_phases.py` and
  `benchmark.py`; it exercises the services but asserts nothing, so it will not
  catch a regression. The suite in `tests/` is what does that.
- Runs in-process, so it shows protocol behaviour, not container, network or
  concurrency behaviour. The Docker suite and `smoke_test.py` cover those.
- The hop 2 handshake-byte figure quoted in step 5 is from the benchmark
  baseline, not measured in that run; the ClientHello/ServerHello sizes printed
  in step 3 *are* measured.
- ANSI colour is unconditional — no `--no-color` and no TTY detection.
- The web page holds one cached trace in module state with a lock around the
  run. It is single-user by construction; concurrent "Run again" clicks
  serialise rather than queue sensibly.
- The page is served from a Python string. Fine at this size, but it is not a
  template system and will not stay pleasant if it grows.

### What a human must verify

1. That the narration in each step matches what the code actually does. The
   numbers are measured; the *explanations* around them are mine and are exactly
   the kind of plausible-sounding prose this project treats as untrusted.
2. That printing truncated key fingerprints is agreed to be acceptable under the
   "never log keys" rule. It is one-way and the argument is given above, but it
   is a judgement call the group should confirm rather than inherit.
