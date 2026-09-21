# Risks and technical debt

Ordered by severity. Each entry states what is actually true now, not what a
production system would do.

## R1 — The device link remains quantum-vulnerable (accepted)

**Exposure.** All device-to-gateway traffic uses RSA key transport with no
forward secrecy. An attacker recording it today reads it retroactively once RSA
falls. Verified: 100% of frames decrypted, before and after the migration.

**Why accepted.** The device cannot be updated — immutable image, no package
index route, read-only filesystem. This is the residual risk of brokered
migration.

**Mitigation available.** Shorten the legacy segment physically. Co-locating the
gateway with the device keeps quantum-vulnerable traffic off any public network.
That is a deployment decision, not a cryptographic one, and it is the cheapest
real fix.

**Tracked by.** `scripts/verify_migration.sh modern` asserts this link is still
compromised, so the limitation cannot silently drop out of the story.

## R2 — The device ships 13 known vulnerabilities (accepted, monitored)

`pip-audit` reports 13 advisories against `cryptography==3.4.8`, including
PYSEC-2023-254, PYSEC-2026-3553, and GHSA-537c-gmf6-5ccf. Several are remotely
reachable in principle.

This is the realistic cost of frozen firmware and is exactly what the project is
about. CI audits the device's pins on every run but does not fail the build on
them, because failing on a deliberately frozen dependency would train everyone
to ignore the job. The modern nodes' dependencies **do** fail the build.

## R3 — Keys are stored unencrypted on disk

RSA private keys and both ML-DSA identity seeds are written to separate mounted
volumes with mode 0600 and no encryption at rest. Long-running services receive
only the secret or public pin they need, read-only, but host compromise still
loses everything.

Deliberate: the threat model is a network adversary, and the harvester demo
needs a readable key file to stand in for Shor's algorithm. A production system
would use a KMS or HSM and never materialise the private key in process memory.

## R4 — Identity rotation requires coordinated downtime

Long-term RSA and ML-DSA keys are generated once and have no automatic rotation
schedule or revocation path. Cloud and gateway now pin each other's ML-DSA
public keys out of band, closing network bootstrap substitution, but only one
pin is supported in either direction. Rotating either identity requires
replacing its private key and peer pin as a coordinated maintenance operation;
mismatched sides fail closed and cannot open new sessions. Ephemeral KEM keys
preserve past-session secrecy, but a compromised identity can impersonate its
owner until that manual rotation completes.

## R5 — No device authentication

The legacy handshake authenticates nobody. Anything that can reach the gateway
can open a session and inject readings. The gateway accepts them and the cloud
stores them. Canonical identifier lengths and bounded session stores cap
retained session-state memory, but they do not prevent CPU, bandwidth, request
body, or handshake-capacity denial and do not stop fabricated telemetry.

Out of scope as modelled, but it would be the first thing to fix in a real
deployment — and it is unrelated to post-quantum work.

## R6 — No transport security

There is no TLS on any link. Payload confidentiality and gateway/cloud mutual
authentication come from the application-layer hybrid suite, but HTTP metadata,
endpoint privacy, and availability do not. This makes the comparison legible —
the harvester sees exactly the bytes the suite produced — but a real system
would run TLS underneath, ideally with a post-quantum key exchange there too.

## R7 — Uneven test coverage

Core protocol, device re-handshake, tap bounds, and deployment evidence have
focused unit/integration tests. CLI entrypoints and many logging/error branches
remain less directly covered than the cryptographic and state-machine paths.
Coverage is useful regression evidence, not a proof that every operational
failure has been modelled.

## R8 — Benchmarks are single-machine

All numbers come from one arm64 laptop. They are internally consistent and
reproducible, but absolute figures will differ elsewhere, and the device's
0.1 CPU quota is not reflected in them at all — the benchmarks run unconstrained.
Comparative claims (ML-KEM keygen versus RSA keygen) are sound; absolute
throughput claims would not be. Checked-in Phase 1 timings predate mutual
ML-DSA gateway authentication and are historical lower bounds, not current
Phase 2 measurements.

## R9 — SQLite and in-memory session/replay state

The cloud stores readings in SQLite with a process-level lock. Sessions, recent
identifier history, and pending offers remain in process memory. A restart drops
every session and replay marker; clients must re-handshake, and a captured
legacy handshake can be accepted again after restart. Canonical identifiers
bound retained key size, and unexpired replay markers fail admission closed when
the history cap is reached rather than being evicted. That preserves the stated
in-process replay window but deliberately permits handshake denial under churn.
It does not provide durable or cross-replica replay protection. Fine at this
scale; horizontal scaling would need shared persistent state.

## R10 — The tap is not a production proxy

The teaching tap now has request/response, relay-time, field, and capture-file
ceilings and rejects compressed upstream responses. Capture saturation drops
observations while continuing valid relay. It still is not hardened as an
Internet-facing reverse proxy, and internal actors can reach services without
passing through it; host-published gateway/cloud ports are development-only and
bind to `127.0.0.1`.

## R11 — Supply-chain artifacts are not fully pinned

Container base images are tag-pinned rather than digest-pinned and runtime
exports do not carry a complete hash-locked supply chain. Addressing registry
immutability and signed artifact provenance is valid production debt but outside
this focused PoC security pass.

## R12 — Package names collided with PyPI (resolved)

The original package names `wire` and `nodekit` both exist on PyPI. Installs
here are path-based with `--no-deps`, so nothing resolved wrongly, but the
collision was a dependency-confusion hazard one typo away from mattering.
Renamed to `pqcwire`, `pqcnode`, and `pqcsuite`, none of which are claimed.

Recorded because the class of problem is easy to reintroduce: any new local
package needs a name check before it is used.

## R13 — Grafana exposed a default admin account (resolved)

The observability overlay disabled Grafana's login form and presented the stack
as anonymous and read-only. It was not: the form flag leaves HTTP basic auth
enabled, so the built-in `admin` account stayed reachable over the API with its
default password on a port published to the host. Verified exploitable —
`GET /api/admin/settings` returned HTTP 200 with `admin:admin`.

Resolved by disabling basic auth as well. The admin account now has no
authentication path, and nothing requires one, since all Grafana configuration
is provisioned from files.

**Residual:** the overlay is a local demo stack. Exposing it beyond localhost
would still leave anonymous read access to every metric, which reveals traffic
rates and suite posture. Acceptable for a test environment; not for anything
reachable from a network you do not control.
