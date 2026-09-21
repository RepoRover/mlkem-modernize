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

Before this exchange, the gateway is provisioned out of band with the cloud's
raw ML-DSA-65 public key. In the Compose deployment a networkless one-shot
provisioner writes that pin to a dedicated volume, which is mounted read-only at
`CLOUD_IDENTITY_PUBLIC_KEY_PATH`. The `/pqc/identity` response is diagnostic
only: the gateway does not request it and it cannot replace the pin.

```
gateway                                                        cloud
  pk_id <- read-only local pin
  <------------ GET /pqc/offer ----------------------------------
  offer = {key_id, ek_mlkem, pk_x25519, sigma}                 (ephemeral, per session)
  sigma = ML-DSA-65-Sign(sk_id, LP(ctx, key_id, ek_mlkem, pk_x25519))

  verify sigma with pk_id
  (ss_pq, ct) <- ML-KEM-768.Encaps(ek_mlkem)
  (sk_e, pk_e) <- X25519.KeyGen()
  ss_ec       <- X25519(sk_e, pk_x25519)
  ------------- {suite, session_id, key_id, ct, pk_e} ----------->
                                            ss_pq <- Decaps(dk_mlkem, ct)
                                            ss_ec <- X25519(sk_x, pk_e)
```

Session key, both sides:

```
transcript = SHA-256( LP(ctx) ‖ LP(version) ‖ LP(suite) ‖ LP(session_id)
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
does — authentication comes from the ML-DSA signature over the offer, and
integrity from the AEAD tag over a transcript-bound key. This is pinned by
`test_tampering_with_the_kem_ciphertext_surfaces_at_the_first_frame`.

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

300 iterations, arm64, Python 3.13.11, cryptography 50.0.1. Full data in
[`bench/results/comparison.json`](../bench/results/comparison.json).

| Operation | Legacy | Modernized | Change |
|---|---:|---:|---|
| Key generation (median) | 41.84 ms | 0.26 ms | **164x faster** |
| Key generation (p95) | 165.15 ms | 0.26 ms | 640x faster, and predictable |
| Handshake, initiator | 0.025 ms | 0.770 ms | 31x slower |
| Handshake, responder | 0.897 ms | 0.278 ms | 3.2x faster |
| Seal one reading | 0.0017 ms | 0.0017 ms | unchanged |
| Handshake bytes on the wire | 344 B | ~5.6 kB | 16x larger |

Three things worth drawing out.

**Key generation stops being a problem.** RSA keygen searches for primes, so it
is both slow and wildly variable — a 3.9x spread from median to p95. ML-KEM
keygen is deterministic work over a lattice: 0.256 ms median against 0.258 ms
p95. That predictability matters more than the raw speedup, because it makes
per-session ephemeral keys affordable, and ephemeral keys are what buy forward
secrecy.

**The cost moved to the initiator.** RSA is cheap to encrypt and expensive to
decrypt, so the legacy responder carried the load. The hybrid initiator verifies
a signature, encapsulates, does an X25519 exchange, and runs HKDF — 31x more
than an RSA public-key operation, though still under a millisecond. For a
gateway holding long-lived sessions this is irrelevant; for a device opening a
session per reading it would not be.

**Bandwidth is the real trade.** The handshake grows from 344 B to roughly
5.6 kB, dominated by the 3309-byte ML-DSA signature and the 1184-byte
encapsulation key. Data frames are unchanged at 119 B because the record layer
is shared. On a constrained radio link the handshake cost, not the compute,
would be the thing to engineer around.
