# 01 — Architecture and library selection

## Context provided

The course brief, an empty repository, and one constraint from the group: the
legacy device must be genuinely unable to run ML-KEM, so a gateway is needed.
The report perspective chosen was *cryptography and mathematics*, which shifted
emphasis toward construction detail and test vectors.

## Decision 1 — ML-KEM library

**Proposed:** `cryptography>=48`, with `liboqs-python` and `kyber-py` as
alternatives.

**Challenged by the group:** the recommendation was justified with "I verified
it works on this machine", and the reply was that the project has to run
elsewhere. That objection was correct and the original evidence was too weak.

**Re-verified:** ML-KEM-768 was exercised inside `linux/amd64` and `linux/arm64`
containers. The wheel statically bundles its own OpenSSL, so the host provides
nothing. **Accepted** on that basis, not the original one.

**Modified later:** `kyber-py` was added as a *test-only* dependency for
cross-validation. A single implementation agreeing with itself is not evidence
of correctness, and the crypto/math perspective makes independent verification
worth the dependency. It never reaches a runtime image.

**Rejected:** `liboqs-python`. Stronger provenance, but a cmake build in every
image, and the cross-check against `kyber-py` already provides independent
verification at far lower cost.

## Decision 2 — Package structure

**First proposal:** two packages, `wire` and a crypto package.

**Rejected on inspection.** The device also needs RSA and AES, so it would have
had to import the crypto package — which would have pulled post-quantum code
onto a node that must not have it.

**Second proposal:** three packages split by Python version.

**Rejected as over-engineering.** Replaced by a single crypto package whose
ML-KEM import is *optional at runtime*. The device installs the same code
against an old backend, and the hybrid suite reports itself unavailable instead
of failing at import.

This turned out better than either alternative: the device's limitation became a
queryable property (`probe().mlkem_available`) rather than a packaging trick,
and the degradation path is tested on real Python 3.9 in CI.

## Decision 3 — Baseline before migration

The group chose to build and tag a working legacy system first, then migrate.

Midway through, the hybrid suite had already been written before the baseline
was committed. Committing it would have put post-quantum code inside
`v0-legacy`, contaminating every "before" measurement. The file was parked and
restored at the migration commit instead.

Worth recording because the shortcut was tempting and the damage would have been
invisible — the numbers would still have looked plausible.

## Decision 4 — Forward secrecy, added beyond the plan

The approved plan specified a hybrid suite with transcript binding, which is
satisfied by encapsulating to a static responder key. That was **rejected during
implementation** in favour of per-session ephemeral keys authenticated with
ML-DSA-65.

Reason: without forward secrecy the sharpest contrast with the legacy suite
disappears. The legacy defect that matters is not "RSA" but "one long-term key
opens all archived traffic", and a static ML-KEM key would have reproduced that
shape with a different primitive.

Cost: an extra round trip, an offer store with TTL and single-use semantics, and
3.3 kB of signature per handshake. Judged worth it; the bandwidth cost is
recorded in the risk discussion rather than glossed.

## Decision 5 — Secret ordering, changed against the written plan

The approved plan specified the combiner input as `ss_ec ‖ ss_pq`. The
implementation uses `ss_pq ‖ ss_ec`.

**Reason:** the deployed `X25519MLKEM768` group in TLS places the ML-KEM secret
first, and matching a shipping standard is worth more than matching a plan
written before the standard was checked. The suite name already implies that
order.

**Risk:** this was changed on the basis of recalled convention. Either ordering
is cryptographically sound provided both ends agree, so nothing is broken
either way — but the *justification* is only as good as the recollection, and it
has not been read back against the specification. Flagged for verification in
[entry 05](05-outstanding-review.md).

Recorded because deviating from an approved plan during implementation is
exactly the kind of change that disappears if it is not written down.
