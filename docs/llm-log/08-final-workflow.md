# 08 — Final review and delivery

## Prompt

> Finish the workflow. If everything passes, record the prompt and results in docs/ of that worktree, then commit and push. Finally, give me a TL;DR of all files changed in frankenstein compared with Iurii's branch.

The model held the commit and push until the final review gates passed.

## Review gates and disposition

The final security review passed the hybrid protocol and runtime hardening. This
was a model review, not a hosted-CI result. The delivery review then blocked
release on three concrete findings:

1. Prometheus and Grafana published ports on every host interface.
2. The baseline report named a nonexistent `v0-legacy` tag, misstated sample
   counts/results, and did not reproduce the checked-in result JSON.
3. The architecture narrative contradicted the owner's premise by treating
   host/container timing and quota observations as proof about the real target
   hardware.

These findings were fixed without changing the approved protocol or
architecture:

- the observability ports now publish as `127.0.0.1:9090:9090` and
  `127.0.0.1:3000:3000`, with rendered-Compose regression coverage for both the
  baseline and modern overlays;
- baseline reproduction now uses immutable commit `7a467db`, explains why a
  requested 200 iterations yields 10 RSA-keygen and 50 full-path samples, and
  reports the values in `bench/results/v0-legacy.json` exactly;
- the architecture and baseline documents now state that the real device is
  hardware-limited by premise, while the host/container simulation cannot prove
  or disprove its feasibility, and entry 02 carries a marked correction to the
  same effect. Python version alone is still correctly rejected as proof of
  incapability. Immutable software, an old pinned dependency, read-only
  deployment, and no egress remain explicit additional modeled constraints.

## Follow-up review

A follow-up review initially blocked release with one P1 and one P2 finding.
Both were valid and were fixed narrowly:

- **P1, resolved:** `deploy/Dockerfile.device`, both Compose files, and
  `tests/integration/test_device_constraints.py` no longer infer target-hardware
  capability from host/container quotas or timings. They preserve the
  owner-provided hardware limitation, identify Python 3.9 compatibility as only
  a software-version finding, and describe immutable software, no egress, and a
  read-only filesystem as modeled deployment constraints.
- **P2, resolved:** `docs/migration-strategy.md` now identifies the baseline by
  immutable commit `7a467db`, not by the nonexistent `v0-legacy` tag.

Direct searches found no remaining form of the challenged arithmetic/CPU claim
in the affected deployment and test files, and no remaining documentation claim
that `v0-legacy` is a tag. The affected tests and the full feasible validation
suite below passed after these edits. **Final review: PASS.**

## Validation evidence

The review verdicts above are model findings. The command results below were
run directly against the final tree, starting from commit `71d8f0d`; they are
not copied from review summaries.

| Command | Result |
|---|---|
| `uv run pytest -q tests/unit/test_deployment_config.py tests/integration/test_device_constraints.py` | PASS — 8 passed in 18.24s |
| `uv run pytest -q` | PASS — 137 passed, 2 dependency deprecation warnings in 23.21s |
| `uv run ruff check .` | PASS — `All checks passed!` |
| `uv run ruff format --check .` | PASS — 74 files already formatted |
| `uv run mypy packages services bench` | PASS — no issues in 39 source files |
| `uv run bandit -c pyproject.toml -r packages services bench -q` | PASS — exit 0, no findings printed |
| `docker compose -f deploy/docker-compose.yml config --quiet` | PASS — exit 0 |
| `docker compose -f deploy/docker-compose.baseline.yml config --quiet` | PASS — exit 0 |
| `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.observability.yml config --quiet` | PASS — exit 0 |
| `docker compose -f deploy/docker-compose.baseline.yml -f deploy/docker-compose.observability.yml config --quiet` | PASS — exit 0 |
| `./scripts/verify_migration.sh baseline 25` | PASS — edge 87/87 compromised, backbone 87/87 compromised, cloud-storage check OK |
| `./scripts/verify_migration.sh modern 25` | PASS — edge 88/88 compromised, backbone 0/88 readable (88 resisted), cloud-storage check OK |
| `git diff --check` | PASS — no whitespace errors |
| secret/generated-artifact checks documented below | PASS — no matching secret material or tracked runtime/key artifacts |

The two migration scripts built and ran local Docker Compose stacks. These are
local receipts only. No hosted CI run was triggered or observed, so this entry
does **not** claim hosted CI passed.

The final hygiene checks used:

```bash
! git grep -nE 'BEGIN ([A-Z0-9]+ )*PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}' -- . ':!uv.lock' ':!docs/llm-log/08-final-workflow.md'
test -z "$(git ls-files '*.pem' '*.key' 'run/**' 'capture/**' '.env' '.env.*')"
git status --short --ignored | grep -E '(^|/)(run|capture)/|\.pem$|\.key$|\.env($|\.)|__pycache__|\.coverage|coverage\.xml'
git diff --check
```

The first two commands exited zero. The status/grep inspection printed no
matching generated or secret-bearing artifacts (the grep itself therefore
exited one, as expected). `git diff --check` exited zero.

## Residual risks and delivery state

- The actual target hardware was not available. Its inability to perform ML-KEM
  remains a project premise, not a result established by this simulation.
- Local Docker and Python validation cannot substitute for hosted CI or an
  independent security audit; there is no hosted-CI receipt for this diff.
- The legacy device hop deliberately remains quantum-vulnerable, and the broader
  replay, key-management, supply-chain, and teaching-proxy limitations remain
  tracked in `docs/risks.md` and the earlier log entries.
