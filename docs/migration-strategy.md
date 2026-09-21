# Migration strategy

## The constraint that shapes everything

The device cannot be updated. Not "is expensive to update" — the image is
immutable, it has no route to a package index, and its filesystem is read-only.
Any strategy that begins "roll out new firmware" is not available. See
[architecture.md](architecture.md) for why, and why the obvious explanation is
wrong.

So the migration protects the hop that *can* change, and is honest about the one
that cannot.

## Phases

### Phase 0 — baseline, tagged `v0-legacy`

Every link uses `LEGACY-RSA2048-OAEP-AESGCM`. Measurements captured before any
post-quantum work: see [baseline-analysis.md](baseline-analysis.md). Reproduce
with `docker compose -f deploy/docker-compose.baseline.yml up --build`.

Verified exposure: a passive attacker handed the RSA keys reads 100% of frames
on both links.

### Phase 1 — dual-stack cloud and identity bootstrap

The cloud gains `/pqc/*` endpoints while `/legacy/*` keeps working. Before a
gateway can use them, the cloud's ML-DSA public identity must be delivered out
of band and configured as `CLOUD_IDENTITY_PUBLIC_KEY_PATH`. It must not be
learned from `/pqc/identity`, because a MITM could replace both that response and
the signed offer. The modern Compose stack models provisioning with a
networkless one-shot service and separate private/public volumes; long-running
services mount their half read-only. A second independently generated pair
pins the gateway at the cloud; hybrid rollout requires both directions before
traffic is accepted.

Nothing changes for existing legacy gateways. This is deployable independently
and is the step that makes suite rollback free: a gateway can move to the
post-quantum suite and back without any cloud code change.

### Phase 2 — gateway cutover

`UPSTREAM_SUITE` moves from `legacy` to `hybrid`, one gateway at a time. The
device sees nothing different — it is still speaking the only suite it has.
Mixed fleets are staged through explicit per-gateway configuration. The retained
`auto` value is only a backward-compatible alias for `hybrid`; it does not query
cloud capabilities or fall back. The modern Compose deployment pins `hybrid`;
the separately runnable baseline pins `legacy`. Operators that previously
relied on dynamic `auto` negotiation must now select `legacy` explicitly during
rollback.

Watch `pqc_frames_total{suite=...}` per gateway to confirm each cutover, and
`pqc_suite_in_use` to see the configured posture of every link. A gateway is
ready only when its validated local secure configuration can reach cloud
readiness; Compose gates dependencies on `/readyz`, while `/healthz` remains a
separate diagnostic liveness check. Device sessions automatically re-handshake
on local age/count exhaustion or a gateway HTTP 409 and retry that reading once,
so loop-forever traffic remains live across bounded session lifetimes.

### Phase 3 — completion

Once every gateway reports the post-quantum suite, the cloud sets
`ALLOW_LEGACY_SUITE=false` and refuses quantum-vulnerable traffic outright.
Legacy requests then return HTTP 403 and are logged, so a straggler is loud
rather than silently accepted. `pqc_quantum_vulnerable_frames_total{service="cloud"}`
should be flat at zero from this point.

The service label is load-bearing. The same counter at the *gateway* keeps
rising for as long as the device transmits, because the gateway has to accept a
suite the device cannot replace. Aggregating the two hides the completion signal
behind the residual exposure.

This is the state in `deploy/docker-compose.yml`.

### Phase 4 — the part that is not solved

The device link stays on RSA and stays readable. This is not a gap in the
implementation; it is the residual risk of brokered migration, and it is
reported rather than hidden — `verify_migration.sh modern` asserts the edge link
is *still compromised*, so the limitation cannot be forgotten.

Closing it requires one of: replacing the hardware; a firmware update channel
that does not currently exist; or physically shortening the legacy segment so it
runs only inside a trusted boundary. That last option is the cheapest real
mitigation — co-locating the gateway with the device means the quantum-vulnerable
traffic never crosses a public network, which is a deployment decision rather
than a cryptographic one.

## Fallback

Every phase is reversible by configuration alone.

| Failure | Response |
|---|---|
| Gateway cannot complete a post-quantum handshake | Set `UPSTREAM_SUITE=legacy` and restart. Requires `ALLOW_LEGACY_SUITE=true` on the cloud, so phase 3 is the point of no easy return. |
| Cloud rejects post-quantum traffic | Gateway surfaces a 502 and the frame is dropped, not silently downgraded. |
| ML-KEM flaw discovered | The hybrid construction already covers this: X25519 alone still protects the session, and the suite can be retired without touching the record layer. |
| Cloud or gateway identity key compromised | Ephemeral KEM keys mean past sessions stay secret. Provision both replacement secret and peer pin out of band, then restart cloud and gateways as a coordinated operation. |

The decision to keep the legacy suite implemented rather than deleting it is
deliberate. It costs a little complexity and buys a working rollback path plus a
reproducible baseline.

## Identity rotation

A pin makes rotation explicit rather than automatic. This implementation accepts
one ML-DSA identity at a time and has no overlap set: replacing only the cloud
key makes every gateway reject its offers, while replacing only the gateway pin
makes it reject the old cloud. Rotation therefore requires a maintenance window
(or an external blue/green rollout): stop the modern stack, replace both
identity volumes through the trusted provisioning path, and restart cloud and
gateways together. Do not copy a key from `/pqc/identity` during an incident;
that recreates the network bootstrap vulnerability. Existing session secrecy is
not affected because KEM keys are ephemeral, but new sessions remain unavailable
until both sides agree on the new pin. The same limitation applies independently
to the gateway initiator identity.

## Operational bounds

`MAX_PENDING_OFFERS` bounds cloud ephemeral state; expiry and authenticated use
release capacity. Gateway upstream GETs enforce `UPSTREAM_TIMEOUT_SECONDS`,
`UPSTREAM_TOTAL_DEADLINE_SECONDS`, `UPSTREAM_RETRY_ATTEMPTS`, capped backoff, and
`UPSTREAM_MAX_RESPONSE_BYTES`. Compressed responses are rejected before body
decoding. State-changing POSTs are not retried because their outcome may be
ambiguous and the protocol deliberately makes offers and frame sequences
single-use.

Canonical fixed-length session identifiers remain in bounded in-memory history
after active sessions expire, preventing handshake replay from resetting record
replay state. Once full, history admission fails closed until markers expire;
it never silently evicts an unexpired marker. This can cause handshake denial
under churn and is preferable to shortening the promised replay window. The
history is not durable: after a gateway or cloud restart, captured legacy
handshakes can be accepted again and all clients must re-handshake. Persistent
or distributed replay state is deferred rather than implied.

The demonstration gate requires both links, nonzero traffic, exact suites,
complete decryption on deliberately readable links, zero modern-backbone
decryption, and matching cloud storage. The teaching taps cap request and
response bodies, relay duration, recorded fields, and total capture size;
capture saturation stops recording without stopping valid relay.

## Crypto-agility

Adding a third suite means: a `SuiteSpec` entry in `pqcwire/protocol.py`, a
client/server pair in `pqcsuite`, and an `UPSTREAM_SUITE` value. The record
layer, framing, AAD, replay handling, metrics, and storage are all
suite-agnostic. Every frame carries its `suite_id`, so traffic is attributable
by suite for as long as it is retained — which is what makes "how much of this
is still vulnerable?" answerable rather than a guess.
