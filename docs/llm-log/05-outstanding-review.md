# 05 — What still needs independent human review

This log was written by the same model that produced the code, so it is a record
of decisions and evidence, not an independent audit. Treating it as sufficient
review would reproduce exactly the failure mode the assignment is testing for.

The items below are where group verification would have most value, roughly in
order.

## 1. The hybrid key combiner

`_combine()` in `pqcsuite/hybrid.py` derives the session key as:

```
HKDF-SHA256(ikm = ss_pq ‖ ss_ec, salt = transcript_hash, info = suite_id)
```

Only round-trip tests cover this, and a round trip passes whenever both sides are
wrong in the same way. The ML-KEM *primitive* is cross-validated against
`kyber-py`; the combiner built on top of it is not validated against anything.

**Check against:** the IETF hybrid design draft and the `X25519MLKEM768`
construction as deployed in TLS. Specifically: is concatenate-then-extract with
the transcript as *salt* (rather than as `info`, or hashed into the IKM) the
right placement? The choice here is defensible but was not derived from a
specification.

## 2. Secret ordering

`ss_pq ‖ ss_ec` was chosen to match TLS's `X25519MLKEM768`. Worth confirming
against the actual specification rather than the claim in this log — it is the
kind of detail that is easy to state confidently and get backwards.

## 3. ML-DSA usage

Signing and verification are exercised only by round-trip tests within one
implementation. There is no independent cross-check equivalent to the ML-KEM
one, and no known-answer test against FIPS 204 vectors.

Worth checking: that the signed message (`LP(ctx, key_id, ek_mlkem, pk_x25519)`)
covers everything an attacker could profitably substitute. The `key_id` is
included; confirm nothing security-relevant is outside the signature.

## 4. The nonce argument

The record layer derives AES-GCM nonces from the sequence number and relies on
one-key-per-session for uniqueness. The counter refuses to pass 2³²−1.

Confirm there is no path where two `RecordSession` objects could share a key —
in particular, that the legacy suite's unbound handshake (a known defect) cannot
be used to induce key reuse across two sessions with different labels. This was
reasoned about but not proven.

## 5. Benchmark methodology

`bench/suites.py` measures the two suites differently in one respect: the hybrid
server's `accept` consumes a single-use offer, so it is measured over a
pre-built pool while the legacy server's `accept` is measured by repetition.

Confirm the pool construction is not attributing cost to the wrong operation,
and that the comparison in `crypto-design.md` is like-for-like.

## 6. Whether the defects are pedagogically right

The legacy suite has three deliberate defects. Confirm they are the ones the
group wants to discuss, and that the *absence* of others is intentional — for
example, there is no padding-oracle exposure, because RSA-OAEP decryption
failures and malformed-secret-length failures are not distinguished to the
caller. That was not a designed property.

## 7. Everything in `docs/risks.md`

The risk register is a set of judgements about what is acceptable. Those are the
group's to make, not the model's. R1 in particular — accepting that the device
link stays quantum-vulnerable — is the project's central trade-off and should be
an explicit group decision rather than an inherited one.
