# Threat model

## Adversary

The modelled attacker is **passive and on the public network**. It observes every
byte on both links, stores traffic indefinitely, and later acquires a
cryptographically relevant quantum computer. This is the weakest realistic
network attacker, chosen deliberately: the legacy suite already loses to it.

The `tap` service implements this for normal protocol traffic. It relays the
same application body and records a copy, with explicit request/response,
wall-clock, recorded-field, and capture-file ceilings so the teaching component
cannot buffer without bound. Oversized, compressed, or timed-out traffic is
rejected. A capture write failure or full capture budget is counted and stops
recording without interrupting otherwise valid relay, because a wiretap whose
disk fills should not take the victim link down.

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
| Impersonate a gateway to the hybrid cloud endpoint | Rejected. The complete request transcript is ML-DSA-65 signed and checked against the cloud's read-only gateway pin. |
| Mutate version, suite, session id, KEM ciphertext, or X25519 share | Rejected by structural version checks, signed transcripts, or transcript-bound AEAD keys. |
| Replay a captured post-quantum handshake | Rejected. Offers are authenticated, single-use, expiring, and hard bounded. |
| Replay a captured legacy handshake with the same id | Rejected while the process retains its fail-closed replay marker; succeeds after restart because history is not durable. |
| Relabel a captured legacy handshake | The unauthenticated handshake can establish the wrapped key under a new canonical id, but captured frames cannot be relabelled because their original id is AEAD-bound. |
| Exhaust memory by opening sessions or offers | Retained keys and offers are bounded. History saturation fails closed; CPU, request bodies at the endpoints, bandwidth, and availability are not fully protected. |

## Out of scope

**Host compromise.** Keys are stored unencrypted on a volume. If the attacker
can read the filesystem, everything is lost. A production deployment would use a
KMS or HSM; this is recorded in [risks.md](risks.md) rather than solved.

**The device's own integrity.** A compromised device is trusted by the gateway.
There is no device attestation or per-device identity — the legacy handshake
authenticates nobody.

**Transport security below the application layer.** There is no TLS. Backbone
payload confidentiality and mutual gateway/cloud authentication come from the
application-layer hybrid suite, but HTTP metadata and availability do not. This
keeps the comparison legible; a real deployment would run both layers.

**Traffic analysis.** Frame sizes, timing, and counts leak. A reading is ~119 B
at a fixed cadence, so an observer learns the sampling rate regardless of suite.

**Active downgrade at the gateway's configuration layer.** An attacker who can
set `UPSTREAM_SUITE=legacy` has already compromised the deployment. Neither the
network nor the retained `auto` spelling can select legacy.

**Restart-spanning replay.** Active and recent session identifiers are tracked
only in bounded process memory. Restart clears that history. A captured legacy
handshake and its frames can therefore be replayed after restart; hybrid offer
private keys disappear on restart, so its captured handshake cannot complete.
Durable anti-replay state is out of scope.

## The residual exposure

The device link is readable by the modelled attacker, before and after the
migration. This is the honest cost of brokered migration and the central
limitation of the whole design.

`scripts/verify_migration.sh modern` asserts the edge link is **still
compromised**. The test would fail if that stopped being true — which keeps the
limitation from quietly disappearing from the narrative.
