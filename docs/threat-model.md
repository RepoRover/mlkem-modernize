# Threat model

## Adversary

The modelled attacker is **passive and on the public network**. It observes every
byte on both links, stores traffic indefinitely, and later acquires a
cryptographically relevant quantum computer. This is the weakest realistic
network attacker, chosen deliberately: the legacy suite already loses to it.

The `tap` service implements exactly this. It forwards traffic untouched and
records a copy. A capture write failure is swallowed and counted rather than
propagated, because a wiretap that breaks the link it observes is not passive —
an earlier version returned HTTP 500 to the device when its disk write failed,
which was a modelling bug as much as a code bug.

## What "Shor succeeded" means here

The `harvester` is **handed** the RSA private keys. No factoring is performed.
This models the end state of running Shor's algorithm against the captured
public keys, and the tool's own output says so rather than implying an attack
was executed. What is demonstrated is the *consequence* — one recovered
long-term key retroactively opens every archived session — not the method.

## In scope

| Capability | Result |
|---|---|
| Record all traffic on both links | Succeeds. This is the tap. |
| Later recover long-term RSA private keys | Reads 100% of legacy traffic, retroactively. |
| Same, against the modernized backbone | Reads nothing. ML-KEM ciphertexts carry no classically recoverable secret, and the responder's KEM keys were ephemeral and discarded. |
| Modify, reorder, replay, or splice frames | Rejected. Suite, session id, and sequence number are all bound into the AEAD tag. Covered in `tests/negative/`. |
| Substitute its own ephemeral KEM keys | Rejected. The offer is ML-DSA-65 signed by the cloud's long-term identity. |
| Substitute both `/pqc/identity` and a self-signed offer | Rejected. The gateway verifies against an out-of-band read-only pin and does not fetch `/pqc/identity` for trust. |
| Replay a captured post-quantum handshake | Rejected. Offers are single-use and expire. |
| Replay a captured *legacy* handshake under a new label | **Succeeds.** The legacy suite does not bind the handshake to its session id. Documented, tested, and unfixed — it is a property of the baseline. |
| Exhaust memory by opening sessions | Bounded. Session stores cap both age and count. |

## Out of scope

**Host compromise.** Keys are stored unencrypted on a volume. If the attacker
can read the filesystem, everything is lost. A production deployment would use a
KMS or HSM; this is recorded in [risks.md](risks.md) rather than solved.

**The device's own integrity.** A compromised device is trusted by the gateway.
There is no device attestation or per-device identity — the legacy handshake
authenticates nobody.

**Transport security below the application layer.** There is no TLS. All
confidentiality comes from the application-layer suites, which is what makes the
comparison legible; a real deployment would run both.

**Traffic analysis.** Frame sizes, timing, and counts leak. A reading is ~119 B
at a fixed cadence, so an observer learns the sampling rate regardless of suite.

**Active downgrade at the gateway's configuration layer.** An attacker who can
set `UPSTREAM_SUITE=legacy` has already compromised the deployment.

## The residual exposure

The device link is readable by the modelled attacker, before and after the
migration. This is the honest cost of brokered migration and the central
limitation of the whole design.

`scripts/verify_migration.sh modern` asserts the edge link is **still
compromised**. The test would fail if that stopped being true — which keeps the
limitation from quietly disappearing from the narrative.
