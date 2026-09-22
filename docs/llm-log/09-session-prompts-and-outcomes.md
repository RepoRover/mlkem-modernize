# 09 — Significant session prompts and outcomes

This entry uses a report-oriented format: significant user prompts are preserved
verbatim, while the resulting discussion, implementation, review findings, and
file changes are summarized. Short progress requests, repeated continuation
messages, worktree housekeeping, and status questions are intentionally omitted.

## 1. Evaluate the three proposed PoCs

### Prompt — verbatim

> We were tasked to implement a PoC in order to secure a legacy device that cant handle ml-kem calculations and harden it so that its post-quantum safety. The device is limited by hardware and this is non negotiable. Study these PDFs @"Group work project 1 pdf.pdf" @"SDMO_Project (1).pdf"  presented by the professor. Based on thiese instructions 3 students have made their own implementation with the help of LLM see git branches. Your goal is to do a deep analysis and rank these PoC. We will proceed developing further from one of these branches so be critical and raise the pros/cons of each.

### Result and decisions

The professor's requirements were extracted from both PDFs and used as the
review rubric: real ML-KEM integration, preservation of the legacy boundary,
baseline evidence, critical LLM evaluation, CI/deployment, observability, and
honest treatment of remaining risks.

The three branches were inspected independently. The resulting order was:

1. **`iurii`** — best continuation base because it most clearly separated the
   ML-KEM-incapable device from the modern gateway/cloud runtime and had the
   strongest CI, attack demonstration, cross-validation, and LLM review record.
2. **`matheus`** — strongest operational implementation, but the simulated
   device remained ML-KEM-capable and the cloud used long-lived static ML-KEM
   recipient keys without forward secrecy.
3. **`Sebastiaan`** — strongest custom-handshake engineering and negative tests,
   but its shared image caused the simulated device to execute an ML-KEM
   self-test and the branch had no CI workflow.

The review also established the claim boundary used throughout later work: only
the gateway-to-cloud path can receive post-quantum protection. The legacy edge
link remains classical, the gateway sees plaintext, and the complete system must
not be described as end-to-end post-quantum secure.

The most important blocking issue in `iurii` was an unauthenticated cloud
identity bootstrap: the gateway downloaded the ML-DSA identity key over the same
HTTP path that the key was intended to authenticate.

### Files modified

No tracked project files were changed during the comparative review. Separate
Git worktrees were created outside the repository worktree for `iurii`,
`matheus`, and `Sebastiaan`; PDF extraction and review reports were temporary
analysis artifacts.

## 2. Select the continuation implementation

### Prompt — verbatim

> Okay proceed with the analysis, decide on which implementations best fit the project goal.

### Result and decisions

The decision was to continue from **`iurii`**, conditionally. Its device/runtime
boundary and assignment evidence best matched the project, but the branch was
not accepted unchanged. The required first change was an out-of-band pinned
cloud identity. Subsequent priorities were replay/session bounds, authenticated
initiators, fail-closed hybrid policy, bounded upstream I/O, stronger readiness,
and selected negative tests from `Sebastiaan`.

Operational controls worth borrowing from `matheus` were identified, but its
static ML-KEM recipient design, PostgreSQL expansion, and larger tracing stack
were deliberately rejected for this PoC. Likewise, `Sebastiaan` was treated as
a source of handshake and negative-test ideas rather than code to merge.

### Files modified

No tracked project files were changed by the selection decision.

## 3. Create and harden `frankenstein`

### Prompt — verbatim

> Understood. With the things we have learned. Create a new branch `frankenstein` based of Iuriss branch. Fix the cloud identity bootstrap, once fixed commit your changes and then continue working on adopting the operational-hardening from matheys branch and the handshake/negative-test from sebastiaan's branch. Once all are completed commit your changes and push the branch to remote

### Result and decisions

A new `frankenstein` branch and worktree were created from `iurii` commit
`0cd9642`.

The first isolated commit, `39da4f3` (`fix(security): pin cloud identity out of
band`), replaced HTTP identity discovery with networkless provisioning and a
required read-only gateway pin. Review found that the original `auto` mode still
allowed an unauthenticated capability response to trigger legacy fallback. The
mode was changed to a fail-closed hybrid alias; legacy rollback now requires an
explicit operator setting. Provisioner path-collision and incomplete-pair cases
were also fixed and tested.

The second commit, `71d8f0d` (`feat(security): harden hybrid migration`), added:

- pinned mutual ML-DSA gateway/cloud authentication bound to the complete
  hybrid transcript;
- bounded active/recent session state and fail-closed replay-history capacity;
- bounded, expiring, single-use ephemeral ML-KEM/X25519 offers;
- strict protocol versions and canonical session identifiers;
- sender/receiver record-count and age limits;
- one bounded device re-handshake and current-reading retry after expiry;
- bounded upstream bodies, compression rejection, timeouts, deadlines, and
  safe GET retries;
- readiness wiring, bounded teaching-tap behavior, and strict migration
  evidence requiring real frames and cloud storage;
- ML-KEM coefficient-boundary, implicit-rejection, transcript-mutation,
  downgrade, replay, and resource-limit tests.

Review questions materially changed the implementation. In particular, the
reviewers found unbounded session identifiers, replay-marker eviction, a device
that stopped after session expiry, a migration check that could pass with no
modern telemetry, and an in-path tap that defeated response bounds. These were
accepted and fixed. Durable distributed replay storage, TLS/PKI expansion,
PostgreSQL, tracing, and a production proxy redesign were rejected as outside
the approved PoC scope.

The configured signing agent refused both commits. After explicit approval,
commits were created with `--no-gpg-sign` without changing persistent Git
configuration. Provider usage limits interrupted some delegated review stages;
those were treated as orchestration failures, not test results, and the work was
resumed from the inspected worktree.

### Files modified

**Identity-bootstrap commit:**

```text
README.md
deploy/Dockerfile.service
deploy/docker-compose.yml
docs/architecture.md
docs/crypto-design.md
docs/llm-log/01-design-decisions.md
docs/migration-strategy.md
docs/risks.md
docs/threat-model.md
services/cloud/app.py
services/gateway/app.py
services/gateway/upstream.py
services/identity_provisioner.py
tests/integration/test_end_to_end.py
tests/unit/test_upstream_identity.py
```

**Phase 2 hardening commit:**

```text
README.md
bench/suites.py
deploy/Dockerfile.service
deploy/docker-compose.baseline.yml
deploy/docker-compose.yml
docs/architecture.md
docs/crypto-design.md
docs/llm-log/07-phase-2-hardening.md
docs/llm-log/README.md
docs/migration-strategy.md
docs/risks.md
docs/threat-model.md
packages/pqcnode/src/pqcnode/__init__.py
packages/pqcnode/src/pqcnode/sessions.py
packages/pqcsuite/src/pqcsuite/__init__.py
packages/pqcsuite/src/pqcsuite/hybrid.py
packages/pqcsuite/src/pqcsuite/legacy.py
packages/pqcsuite/src/pqcsuite/record.py
packages/pqcwire/src/pqcwire/frames.py
scripts/check_attack_report.py
scripts/verify_migration.sh
services/cloud/app.py
services/gateway/app.py
services/gateway/upstream.py
services/identity_provisioner.py
services/legacy_device/device.py
services/tap/app.py
tests/integration/test_end_to_end.py
tests/kat/test_mlkem_crossvalidation.py
tests/negative/test_tampering.py
tests/unit/test_attack_report.py
tests/unit/test_deployment_config.py
tests/unit/test_frames.py
tests/unit/test_hybrid_limits.py
tests/unit/test_legacy_device.py
tests/unit/test_session_limits.py
tests/unit/test_tap_limits.py
tests/unit/test_upstream_identity.py
```

## 4. Complete the final review and delivery

### Prompt — verbatim

> Finish the workflow if everything passes record the prompt/results in docs/ of that worktree. Then commit and push. Finally, give me a tldr of all files changed in the frankensteiin in comparisson to Iuriss branch

### Result and decisions

The final security gate passed the hybrid protocol and runtime hardening. The
delivery gate found three release blockers:

1. anonymous Grafana and Prometheus were published on all host interfaces;
2. baseline documentation referenced a nonexistent tag and disagreed with its
   committed JSON measurements;
3. several comments and documents incorrectly used host/container evidence to
   contradict the owner-supplied hardware limitation.

The final commit, `90b4533` (`fix(delivery): resolve final review blockers`),
bound observability ports to loopback, corrected baseline reproduction and
measurements, and rewrote the hardware narrative. The real device's inability
to perform ML-KEM is now treated as a project premise. The simulator only proves
software/deployment properties and cannot establish feasibility on the target
MCU.

The exact-head validation completed with 137 tests passing, Ruff, strict Mypy,
Bandit, four Compose renders, and both migration demonstrations. In baseline
mode, 87/87 edge and 87/87 backbone frames were recoverable. In modern mode,
88/88 edge frames remained recoverable while 0/88 backbone frames were
recoverable. Secret/artifact and whitespace checks passed. These are local
validation receipts; no hosted GitHub Actions result was observed.

The branch was pushed normally without force. Local and remote
`origin/frankenstein` both ended at `90b4533876c12b1e9f919f4ca536b4c9344833ee`.

### Files modified

```text
deploy/Dockerfile.device
deploy/docker-compose.baseline.yml
deploy/docker-compose.observability.yml
deploy/docker-compose.yml
docs/architecture.md
docs/baseline-analysis.md
docs/llm-log/02-a-false-claim-caught.md
docs/llm-log/08-final-workflow.md
docs/llm-log/README.md
docs/migration-strategy.md
tests/integration/test_device_constraints.py
tests/unit/test_deployment_config.py
```

## Resulting delivery state

The session produced three commits over `origin/iurii`:

```text
39da4f3  fix(security): pin cloud identity out of band
71d8f0d  feat(security): harden hybrid migration
90b4533  fix(delivery): resolve final review blockers
```

The resulting PoC provides ephemeral hybrid ML-KEM-768/X25519 confidentiality
and pinned ML-DSA mutual authentication on the gateway-to-cloud backbone. The
legacy device link remains intentionally classical and quantum-vulnerable, the
gateway remains a plaintext trust boundary, and target-hardware feasibility was
not measured in this session.
