# 07 — Selective hardening after identity bootstrap

## Context provided

The model limited this second pass to replay/session safety, bounded ephemeral
state, version/policy enforcement, gateway initiator authentication, small HTTP
operational controls, and targeted negative evidence. Two other worktrees were
provided as idea sources, not as code to merge.

## Ideas accepted from `matheus`

The gateway now applies the small controls with the highest value for this
architecture: response-size bounds, `Accept-Encoding: identity`, rejection of
compressed responses before decoding, finite per-attempt timeout, total GET
deadline, bounded retry count and capped backoff. Liveness and readiness are
separate. Configuration values are range checked and identity secrets/pins use
separate read-only mounts.

**Modified:** retries apply only to GET. The donor retries forwarding POSTs, but
this protocol uses single-use offers and sequence numbers. Retrying after an
ambiguous response could replay state, so handshake and frame POSTs make one
bounded attempt.

**Rejected:** PostgreSQL, TLS certificate infrastructure, bearer-token envelope
encryption, tracing, and the donor device model. They would replace the system
being measured or widen this hardening phase rather than secure its existing
seams.

## Ideas accepted from `Sebastiaan`

The pass added FIPS 203 encapsulation-key coefficient boundary evidence (`q-1`
accepted, `q` and above rejected), retained explicit implicit-rejection testing,
bound version and suite into the signed offer/transcript, authenticated the
initiator transcript, and added session age/record ceilings. Session identifiers
remain remembered after expiry in bounded state so replay cannot reset a live
record high-water mark.

**Modified:** this branch keeps responder-generated, per-session ephemeral
ML-KEM-768 and X25519 offers. It does not adopt the donor's gateway-generated
ML-KEM recipient key or negotiation structure. ML-DSA-65 is used in both
handshake directions rather than adding a classical-only signature chain.

**Rejected:** the donor's static recipient direction, alternate constrained
device model, redundant ML-KEM round-trip tests already covered by independent
`kyber-py` cross-validation, and broad handshake redesign.

## New authentication decision

The gateway receives a dedicated ML-DSA private seed and the cloud receives its
public pin through the same networkless provisioning boundary used for the
cloud identity. The gateway signs the complete hybrid request transcript; the
cloud verifies before consuming the offer or decapsulating. No identity is sent
for discovery and no HTTP response can replace a pin.

This gives post-quantum mutual authentication for the provisioned gateway/cloud
pair. It does **not** authenticate the legacy device, hide HTTP metadata, provide
TLS, or enroll gateways dynamically.

## Significant prompts preserved from the workflow

This phase implemented the second half of the user's prompt:

> With what we have learned, create a new branch `frankenstein` based on Iurii's branch. Fix the cloud identity bootstrap; once it's fixed, commit your changes. Then continue by adopting the operational hardening from Matheus's branch and the handshake/negative tests from Sebastiaan's branch. Once everything is complete, commit your changes and push the branch to the remote.

The user gave no further implementation instructions during this phase. The
model decomposed the prompt into delegated tasks and review gates; the scope
limits and blocker list described here are the model's own, not the user's.
Before commit, review required canonical 16-character lowercase-hex session
IDs, fail-closed replay-history capacity, sender-side record age/count limits,
one bounded device re-handshake and current-reading retry, Compose readiness
via `/readyz`, strict migration verification with cloud-storage evidence, and
tap byte/time/capture-storage bounds.

## Representative review output and disposition

The review reported these concrete findings (excerpts retained verbatim):

> the current deployment eventually stops transmitting, replay state can be
> churned out, the migration gate can pass without proving a migration, and
> attacker-controlled identifiers undermine memory-bound claims.

> “Bounded gateway responses” is locally true but operationally incomplete
> because the in-path tap buffers unbounded bodies first.

Accepted and implemented: canonical identifiers, fail-closed replay history,
sender limits, one bounded re-handshake/retry, strict migration and cloud
receipt evidence, `/readyz` deployment wiring, tap ceilings, and localhost-only
direct development ports. Modified: deterministic fake-clock coverage replaces
a literal 900-second soak; replay protection remains bounded and process-local
rather than becoming a database. Rejected as out of phase: durable distributed
replay storage, TLS/PKI, PostgreSQL, tracing, KMS/HSM, production capture
rotation, and a wholesale proxy redesign. Image-digest and hash-locked artifact
pinning remain explicitly recorded supply-chain debt.

## Residual risk

Replay history is bounded in process memory and disappears on restart. A
captured legacy handshake can therefore be replayed after restart. At capacity,
new handshakes fail closed until a marker expires, creating a deliberate denial
trade-off instead of weakening replay protection. Identity rotation still
supports one pin at a time and requires coordinated replacement. Readiness
proves local configuration plus upstream reachability, not transport privacy or
durable availability. The tap is a bounded teaching component, not a production
proxy. The added gateway signature also makes the Phase 1 handshake timing a
lower bound; the benchmark harness now measures both signatures, but historical
result files are not presented as a fresh run.
