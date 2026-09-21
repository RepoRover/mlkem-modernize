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

### Phase 1 — dual-stack cloud

The cloud gains `/pqc/*` endpoints while `/legacy/*` keeps working. Nothing
changes for existing gateways. This is deployable independently and is the step
that makes rollback free: a gateway can move to the post-quantum suite and back
without any cloud change.

### Phase 2 — gateway cutover

`UPSTREAM_SUITE` moves from `legacy` to `hybrid`, one gateway at a time. The
device sees nothing different — it is still speaking the only suite it has. With
`auto`, a gateway negotiates against the cloud's advertised `accepted_suites`,
which is how a mixed fleet runs during a staged rollout.

Watch `pqc_frames_total{suite=...}` per gateway to confirm each cutover, and
`pqc_suite_in_use` to see the configured posture of every link.

### Phase 3 — completion

Once every gateway reports the post-quantum suite, the cloud sets
`ALLOW_LEGACY_SUITE=false` and refuses quantum-vulnerable traffic outright.
Legacy requests then return HTTP 403 and are logged, so a straggler is loud
rather than silently accepted. `pqc_quantum_vulnerable_frames_total` at the
cloud should be flat at zero from this point.

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
| Cloud identity key compromised | Ephemeral KEM keys mean past sessions stay secret. Rotate the ML-DSA key; gateways pick up the new identity on their next offer fetch. |

The decision to keep the legacy suite implemented rather than deleting it is
deliberate. It costs a little complexity and buys a working rollback path plus a
reproducible baseline.

## Crypto-agility

Adding a third suite means: a `SuiteSpec` entry in `pqcwire/protocol.py`, a
client/server pair in `pqcsuite`, and an `UPSTREAM_SUITE` value. The record
layer, framing, AAD, replay handling, metrics, and storage are all
suite-agnostic. Every frame carries its `suite_id`, so traffic is attributable
by suite for as long as it is retained — which is what makes "how much of this
is still vulnerable?" answerable rather than a guess.
