# Cryptographic design

Both suites are KEM-DEM constructions: a key encapsulation mechanism
establishes a 32-byte session key, and a data encapsulation mechanism protects
each reading under it. Only the KEM half changes between them. The record layer
is shared code, which is what makes the before/after comparison isolate one
variable.

## 1. The legacy suite — `LEGACY-RSA2048-OAEP-AESGCM`

```
device                                             gateway
  k  <- random 32 bytes
  c  <- RSA-2048-OAEP-SHA256(pk_gw, k)
  ---------------- {suite, session_id, c} ---------------->
                                             k <- RSA-Decrypt(sk_gw, c)
  frame_i = AES-256-GCM(k, nonce=i, aad=A_i, reading_i)
```

Three defects are deliberate. They are marked in
[`pqcsuite/legacy.py`](../packages/pqcsuite/src/pqcsuite/legacy.py) and are the
subject of the baseline analysis.

**No key derivation.** The transported secret becomes the AES key directly.
There is no domain separation, so `k` could not safely be reused for any other
purpose, and nothing binds the key to the context it was established in.

**No transcript binding.** The RSA ciphertext commits to nothing but `k`. A
captured handshake replayed under a different `session_id` yields a working
session with the same key. This is asserted by
`test_legacy_handshake_is_not_bound_to_its_session_id`, which documents the flaw
rather than hiding it.

**No forward secrecy.** `pk_gw` is long-lived. One recovered private key
retroactively opens every archived session — the harvest-now-decrypt-later
exposure, and the defect a quantum adversary converts into a break.

## 2. The modernized suite — `MLKEM768-X25519-HKDF-AESGCM`

Before this exchange, each side receives a separate ML-DSA-65 identity out of
band: the gateway holds its private seed plus the cloud public pin, while the
cloud holds its private seed plus the gateway public pin. Four separate volumes
are mounted read-only into only the service that needs each secret or pin. The
`/pqc/identity` response is diagnostic only: the gateway does not request it and
it cannot replace the pin.

```
gateway                                                        cloud
  pk_cloud <- local pin                              pk_gateway <- local pin
  <------------ GET /pqc/offer ----------------------------------
  offer = {version, suite, key_id, ek_mlkem, pk_x25519, sigma_cloud}
  sigma_cloud = ML-DSA-65-Sign(sk_cloud, LP(all offer fields))

  verify sigma_cloud with pk_cloud
  (ss_pq, ct) <- ML-KEM-768.Encaps(ek_mlkem)
  (sk_e, pk_e) <- X25519.KeyGen()
  ss_ec       <- X25519(sk_e, pk_x25519)
  sigma_gateway <- ML-DSA-65-Sign(sk_gateway, LP(ctx, transcript))
  -- {version, suite, session_id, key_id, ct, pk_e, sigma_gateway} -->
                                      verify sigma_gateway with pk_gateway
                                            ss_pq <- Decaps(dk_mlkem, ct)
                                            ss_ec <- X25519(sk_x, pk_e)
```

Session key, both sides:

```
transcript = SHA-256( LP(ctx) ‖ LP(request_version) ‖ LP(request_suite)
                    ‖ LP(offer_version) ‖ LP(offer_suite) ‖ LP(session_id)
                    ‖ LP(key_id) ‖ LP(ek_mlkem) ‖ LP(pk_x25519)
                    ‖ LP(ct) ‖ LP(pk_e) )

k = HKDF-SHA256( ikm  = ss_pq ‖ ss_ec,
                 salt = transcript,
                 info = "MLKEM768-X25519-HKDF-AESGCM",
                 L    = 32 )
```

### Why each piece is there

**Hybrid, not pure ML-KEM.** ML-KEM is young. X25519 has two decades of
cryptanalysis but falls to Shor. Concatenating both secrets before the KDF means
the session key stays secure as long as *either* the module-lattice problem or
the elliptic-curve discrete log problem holds. Adopting a new primitive costs
nothing against classical adversaries. The ordering `ss_pq ‖ ss_ec` matches the
`X25519MLKEM768` group as deployed in TLS.

**Concatenate-then-KDF.** Feeding both secrets as HKDF input keying material and
extracting once is the standard hybrid combiner. XOR would be wrong: it lets an
attacker who controls one component cancel the other.

**Transcript as HKDF salt.** Every public value in the handshake is hashed into
the salt, so the session key is bound to the exact exchange that produced it. A
shared secret cannot be transplanted into another context, and the
handshake cannot be spliced with values from a different session.

**Length-prefixed encoding.** `LP(x) = len(x)‖x` with a 4-byte big-endian
length. Delimiter joining would be ambiguous — `("a|b", "c")` and `("a", "b|c")`
would hash identically, letting an attacker reinterpret field boundaries. The
encoding's injectivity is a property test, not a claim
(`test_aad_encoding_is_injective`).

**Ephemeral responder keys.** The cloud generates a fresh ML-KEM and X25519 key
pair per session and discards it after one use. This is what gives the link
forward secrecy, and it is the property the legacy suite most conspicuously
lacks. Offers are single-use and expire, so a captured handshake cannot be
replayed against the same ephemeral key.

**ML-DSA-65 over the offer.** Ephemeral keys are useless if an active attacker
can substitute its own, so the offer is signed by the cloud's long-term identity
key. Signing post-quantum too avoids a chain that is only as strong as its
weakest link. The verifier key must itself be trusted: fetching it from the same
unauthenticated network as the offer would let a MITM substitute both and sign a
fully self-consistent forgery. The out-of-band pin closes that bootstrap gap;
missing, malformed, or non-matching trust material fails closed.

**ML-DSA-65 over the gateway request.** A signed server offer authenticates the
cloud but says nothing about who encapsulated to it. The gateway therefore signs
the same complete transcript used by HKDF. The cloud checks its pinned gateway
key before consuming the offer or decapsulating. Session-id, ciphertext,
X25519-key, version, and suite substitution all invalidate this signature. This
is post-quantum initiator authentication for one provisioned gateway identity;
it is not device authentication and it is not dynamic gateway enrollment.

## 3. The record layer, shared by both suites

```
nonce_i = i as 12 bytes, big-endian
A_i     = LP("mlkem-modernize/aad/v1") ‖ LP(version) ‖ LP(suite)
          ‖ LP(session_id) ‖ LP(i)
frame_i = AES-256-GCM(k, nonce_i, A_i, plaintext)
```

The nonce is derived from the sequence number rather than transmitted: a fresh
key per session plus a strictly increasing counter means a nonce is never
reused, and the counter refuses to pass 2³²−1 so that argument stays
enforceable. Binding the suite into the AAD blocks downgrade-by-relabelling;
binding the session id blocks splicing; binding the sequence number blocks
reordering and replay.

The replay guard commits its high-water mark **after** tag verification, so a
forged frame carrying a high sequence number cannot desynchronise a session.
Each record session also has an age ceiling and permits at most 10,000 seals
and 10,000 authenticated opens. Service session stores add configurable TTLs
and retain used identifiers in bounded replay history, preventing a replayed
handshake from resetting this high-water mark while that process remains alive.

## 4. Implicit rejection, and why it shapes the protocol

This is the single most important behavioural fact about ML-KEM for anyone
building on it.

FIPS 203 decapsulation **does not fail** on a corrupted ciphertext. It returns a
deterministic pseudo-random secret derived from the private key. Our tests
confirm both `cryptography` and `kyber-py` return the *same* such value, so this
is standards-conformant behaviour rather than an implementation quirk.

The consequence: a handshake carrying a tampered ML-KEM ciphertext **completes**.
The responder derives a key, believes it has a session, and nothing signals a
problem until the first AEAD tag fails. Any protocol treating "decapsulation
succeeded" as "the peer is authentic" is broken by construction. Our suite never
does — authentication comes from both pinned ML-DSA signatures, and record
integrity from the AEAD tag over a transcript-bound key. Network ciphertext
mutation fails the gateway signature first. The explicit implicit-rejection test
re-signs the mutation as the legitimate gateway to isolate ML-KEM behavior, then
proves the divergent key fails at the first AEAD frame.

## 5. Validation

Round-trip tests cannot establish correctness: they pass whenever both sides are
wrong in the same way. The ML-KEM backend is therefore cross-checked against
`kyber-py`, an independently written pure-Python FIPS 203 implementation:

- both derive byte-identical 1184-byte encapsulation keys from the same 64-byte
  seed, across four fixed seeds;
- ciphertexts produced by either decapsulate correctly under the other;
- parameter sizes match FIPS 203 Table 2 exactly;
- both implicitly reject a corrupted ciphertext to the same value.

`kyber-py` is a test-only dependency and never reaches a runtime image.

## 6. Measured cost

The timing rows below are the original 300-iteration arm64 measurement from
before mutual gateway authentication and are therefore lower bounds for the
current handshake. The benchmark harness now measures the added gateway
ML-DSA sign/verify operations and reports both signature sizes; its checked-in
historical result is not relabelled as a fresh measurement.

| Operation | Legacy | Modernized | Change |
|---|---:|---:|---|
| Key generation (median) | 41.84 ms | 0.26 ms | **164x faster** |
| Key generation (p95) | 165.15 ms | 0.26 ms | 640x faster, and predictable |
| Handshake, initiator | 0.025 ms | 0.770 ms | 31x slower |
| Handshake, responder | 0.897 ms | 0.278 ms | 3.2x faster |
| Seal one reading | 0.0017 ms | 0.0017 ms | unchanged |
| Raw handshake cryptographic fields | 256 B | ~9.0 kB | 35x larger |

Three things worth drawing out.

**Key generation stops being a problem.** RSA keygen searches for primes, so it
is both slow and wildly variable — a 3.9x spread from median to p95. ML-KEM
keygen is deterministic work over a lattice: 0.256 ms median against 0.258 ms
p95. That predictability matters more than the raw speedup, because it makes
per-session ephemeral keys affordable, and ephemeral keys are what buy forward
secrecy.

**The cost moved to the initiator.** RSA is cheap to encrypt and expensive to
decrypt, so the legacy responder carried the load. The hybrid gateway verifies
one ML-DSA signature, encapsulates, performs X25519 and HKDF, then creates its
own ML-DSA signature. The cloud performs the matching signature verification.
The old 31x initiator figure excludes that new sign operation and must not be
quoted as a current benchmark.

**Bandwidth is the real trade.** Raw cryptographic handshake fields grow from
256 B to roughly 9.0 kB, dominated by two 3309-byte ML-DSA signatures and the
1184-byte encapsulation key. JSON/base64 adds further wire overhead. Data frames
are unchanged at 119 B because the record layer is shared. On a constrained
radio link the handshake cost, not the compute, would be the thing to engineer
around.
