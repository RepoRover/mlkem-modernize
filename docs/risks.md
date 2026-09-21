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

RSA private keys and the ML-DSA identity seed are written to a mounted volume
with mode 0600 and no encryption at rest. Host compromise loses everything.

Deliberate: the threat model is a network adversary, and the harvester demo
needs a readable key file to stand in for Shor's algorithm. A production system
would use a KMS or HSM and never materialise the private key in process memory.

## R4 — No key rotation

Long-term RSA and ML-DSA keys are generated once and never rotated. There is no
rotation schedule, no overlap window, and no revocation path. Ephemeral KEM keys
limit the blast radius for the post-quantum link, but a compromised ML-DSA
identity would let an attacker forge offers until it is manually replaced.

## R5 — No device authentication

The legacy handshake authenticates nobody. Anything that can reach the gateway
can open a session and inject readings. The gateway accepts them and the cloud
stores them. Bounded session stores prevent memory exhaustion, but not
fabricated telemetry.

Out of scope as modelled, but it would be the first thing to fix in a real
deployment — and it is unrelated to post-quantum work.

## R6 — No transport security

There is no TLS on any link. All confidentiality comes from the application-layer
suites. This makes the comparison legible — the harvester sees exactly the bytes
the suite produced — but a real system would run TLS underneath, ideally with a
post-quantum key exchange there too.

## R7 — Uneven test coverage

72% overall. The remaining gaps are concentrated in `legacy_device/device.py`,
`tap/app.py`, and the `__main__` entrypoints, all at 0%. The device and tap are
covered end to end by the Docker integration tests but not by unit tests, so a
refactor of their internals would not be caught quickly.

## R8 — Benchmarks are single-machine

All numbers come from one arm64 laptop. They are internally consistent and
reproducible, but absolute figures will differ elsewhere, and the device's
0.1 CPU quota is not reflected in them at all — the benchmarks run unconstrained.
Comparative claims (ML-KEM keygen versus RSA keygen) are sound; absolute
throughput claims would not be.

## R9 — SQLite and in-memory session state

The cloud stores readings in SQLite with a process-level lock and holds sessions
in memory. A restart drops every session, and connected gateways get HTTP 409
until they re-handshake — observed during development. Fine at this scale;
neither would survive horizontal scaling.

## R10 — Package names collided with PyPI (resolved)

The original package names `wire` and `nodekit` both exist on PyPI. Installs
here are path-based with `--no-deps`, so nothing resolved wrongly, but the
collision was a dependency-confusion hazard one typo away from mattering.
Renamed to `pqcwire`, `pqcnode`, and `pqcsuite`, none of which are claimed.

Recorded because the class of problem is easy to reintroduce: any new local
package needs a name check before it is used.
