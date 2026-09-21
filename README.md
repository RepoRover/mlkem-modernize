# ML-KEM legacy modernization

A small edge–cloud telemetry system migrated to post-quantum cryptography, built
for the SDMO course project. A simulated legacy weather station streams daily
readings to a cloud service through an edge gateway. The device cannot be
changed, so the gateway brokers the post-quantum link on its behalf.

The point of the project is not that the system runs. It is that the migration
can be **measured**: a passive attacker reads 100% of the baseline traffic and
0% of the modernized backbone, and both numbers are produced by a script.

```
                 Link A: LEGACY                       Link B: POST-QUANTUM
            RSA-2048-OAEP + AES-256-GCM        ML-KEM-768 + X25519 + AES-256-GCM
              (quantum-vulnerable)                  (quantum-resistant)

  ┌───────────────┐      ┌─────┐      ┌──────────┐      ┌─────┐      ┌────────┐
  │ legacy-device │─────>│ tap │─────>│ gateway  │─────>│ tap │─────>│ cloud  │
  │ py3.9 · 48 MB │      └──┬──┘      │ (broker) │      └──┬──┘      │ FastAPI│
  │ read-only     │         │         └──────────┘         │         │ SQLite │
  └───────────────┘         └───────────┬─────────────────┘         └────────┘
                                 capture.jsonl
                                        │
                                ┌───────▼────────┐
                                │   harvester    │  handed the RSA keys,
                                │ offline attack │  models Shor succeeding
                                └────────────────┘
```

## Quick start

```bash
uv sync --all-extras && uv run pytest
```

Run the modernized stack and watch a year of weather readings flow:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

The one-shot `identity-provisioner` creates the cloud ML-DSA private seed and a
separate gateway public-key pin before either network service starts. The cloud
and gateway then receive only their half in read-only volumes. The gateway will
not start in `hybrid` or `auto` mode if
`CLOUD_IDENTITY_PUBLIC_KEY_PATH` is absent or malformed; `/pqc/identity` is
informational and is never a trust bootstrap. The same provisioner gives the
gateway a separate ML-DSA signing key and mounts its public pin at the cloud, so
the hybrid handshake is mutually authenticated. `hybrid` is the default; `auto`
is a fail-closed compatibility alias, and rollback requires explicit
`UPSTREAM_SUITE=legacy` configuration.

Then query what arrived, and note that nothing quantum-vulnerable reached it:

```bash
curl -s localhost:8000/readings?limit=3 | python3 -m json.tool
```

## Operational security controls

The modern deployment sets a hard pending-offer cap and bounded gateway HTTP
responses, retry attempts, per-attempt timeout, and total GET deadline. The tap
also bounds request/response bytes, relay duration, recorded fields, and capture
storage. GETs may retry with capped backoff; state-changing handshake and frame
POSTs do not, because an ambiguous response cannot safely be replayed. `/healthz`
reports only process liveness, while the Compose gateway health gate uses
`/readyz` and requires a reachable configured upstream. Local identity parsing
happens at startup and fails closed.

Canonical 16-character lowercase-hex session identifiers cannot replace active
sessions and remain blocked for 30 minutes from admission in the configured
in-memory history. If that history fills before markers expire, admission fails
closed rather than
evicting replay protection. Both history and active sessions are lost on
restart; see [docs/risks.md](docs/risks.md). Sender and receiver record keys
have age and count limits; the device re-handshakes and retries the current
reading once when its session is exhausted or the gateway returns HTTP 409.

What is post-quantum protected is deliberately narrow: backbone payload
confidentiality uses ML-KEM-768 plus X25519, and both handshake directions use
pinned ML-DSA-65 identities. The device link remains RSA-based, and HTTP
metadata, timing, and availability are not hidden.

## The demonstration

One script proves the migration actually changed something. It requires both
links, nonzero frames, exact expected suites, complete decryption on readable
links, zero backbone decryption in modern mode, and a cloud-stored reading under
the expected backbone suite:

```bash
./scripts/verify_migration.sh baseline   # both links readable
```

```bash
./scripts/verify_migration.sh modern     # only the device link readable
```

| Link | Baseline | Modernized |
|---|---|---|
| edge (device → gateway) | COMPROMISED, 100% of frames | COMPROMISED, 100% of frames |
| backbone (gateway → cloud) | COMPROMISED, 100% of frames | **RESISTED, 0% of frames** |

The edge link stays readable, and that is reported rather than hidden: the
device is frozen firmware, so brokered migration protects the backbone and
leaves genuine last-mile exposure. See [docs/risks.md](docs/risks.md).

## Observability

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.observability.yml up --build
```

Grafana is at `localhost:3000`, Prometheus at `localhost:9090`.

The headline panel is `pqc_quantum_vulnerable_frames_total` **scoped to the
cloud**, which sits at zero once the migration is complete. A second panel
tracks the same counter at the *gateway*, which is deliberately non-zero: the
device can only speak the legacy suite, so the gateway must accept it. Reading
those two numbers separately is the whole point — summing them across the
deployment shows a healthy migration as a failure.

## Repository layout

| Path | Contents |
|---|---|
| `packages/pqcwire` | Protocol framing, canonical AAD, replay guard, telemetry schema. Standard library only, Python 3.9. |
| `packages/pqcsuite` | Both cipher suites and the shared AEAD record layer. |
| `packages/pqcnode` | Structured logging, configuration, bounded session storage. Standard library only, Python 3.9. |
| `services/` | `legacy_device`, `gateway`, `cloud`, `tap`, `harvester`. |
| `bench/` | Like-for-like measurement harness for both suites. |
| `deploy/` | Dockerfiles, both compose stacks, observability overlay. |
| `docs/` | Design, analysis, migration strategy, risks, and the LLM log. |

## Documentation

- [Architecture](docs/architecture.md) — components, links, and why a gateway exists
- [Cryptographic design](docs/crypto-design.md) — the KEM-DEM construction, hybrid combiner, and transcript binding
- [Baseline analysis](docs/baseline-analysis.md) — measurements from `v0-legacy` before any PQC work
- [Migration strategy](docs/migration-strategy.md) — rollout, fallback, and completion
- [Threat model](docs/threat-model.md) — what the attacker can do, and what is out of scope
- [Risks](docs/risks.md) — residual exposure and technical debt
- [LLM log](docs/llm-log/) — prompts, generated output, and what was accepted, changed, or rejected

## Reproducing the measurements

```bash
uv run python -m bench comparison 300
```

Results land in `bench/results/`. Checked-in and quoted timing numbers were
captured on arm64 with Python 3.13 and cryptography 50.0.1 before Phase 2 added
gateway ML-DSA authentication. They are immutable historical lower bounds, not
current mutual-authentication measurements; rerun the command for current data.
