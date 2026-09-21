# 04 — Defects that only appeared when the system ran

Every defect below passed lint, type checking, and unit tests. None would have
been caught by reading the diff. They are grouped by what it took to find them.

## Found by starting the containers

### The wiretap was not passive

The `tap` forwards traffic and records a copy. When the capture write failed on
a permissions error, the exception propagated and the tap returned HTTP 500 to
the device — so the wiretap broke the link it existed only to observe.

This was a **modelling** bug as much as a code bug. A passive attacker whose
disk fills does not take the victim's network down; the correct failure mode is
losing the observation, not losing the traffic.

```python
except OSError as exc:
    _capture_errors += 1
    log.error("capture write failed; traffic still relayed", ...)
```

Unit tests would never have found this: it needs a *failing* capture write
during a *live* relay.

### Named volumes mount root-owned — twice

Services run as a non-root user. A Docker named volume mounted at a path that
does not exist in the image is created root-owned, so the service cannot write
its own database.

Hit once for `/var/lib/node`, fixed, then hit again for `/var/lib/capture`
because the fix was applied to the specific path rather than the pattern. The
second occurrence is the more instructive one: the first fix was correct and
still did not generalise.

## Found by wiring up monitoring

### Prometheus rejected every scrape

The metrics endpoint served the OpenMetrics content type with a body from the
plain-text generator:

```python
from prometheus_client import generate_latest
from prometheus_client.openmetrics.exposition import CONTENT_TYPE_LATEST
```

Both imports are real, both names are correct, and the combination is wrong.
OpenMetrics requires a `# EOF` terminator the text format does not emit, so
Prometheus reported `data does not end with # EOF` and both targets sat `down`.

The endpoint returned HTTP 200 with plausible-looking metrics throughout. Only
querying Prometheus for target health exposed it — and the temptation was to
verify by curling `/metrics`, which would have shown nothing wrong.

## Found by running the *other* deployment

### The baseline stack had silently broken

Adding the ML-DSA identity in the migration commit gave the cloud a new required
path. The modernized compose set `CLOUD_IDENTITY_PATH`; the baseline compose was
never updated, so its cloud crashed trying to write a relative path into a
read-only image.

The baseline had been working, was never touched, and broke anyway. It stayed
broken across two commits because only the modern stack was being exercised.

`scripts/verify_migration.sh` now runs **both** deployments in CI, which is the
structural fix — the baseline is a graded artifact and needs to keep working.

## Found by paying attention to exit codes

### A commit landed with a test suite that would not collect

```bash
uv run pytest -q 2>&1 | tail -3 && git commit ...
```

A pipeline's exit status is the *last* command's. `tail` succeeded, so the
commit proceeded even though `pytest` had failed to collect a module —
`services` was not on the test import path.

Fixed by adding `pythonpath = ["."]`, and by capturing exit codes explicitly
afterwards. Recorded because the mistake was in the *verification*, which is a
worse place to have one than in the code.

## Found by a scanner

### Local package names collided with real PyPI packages

`pip-audit` skipped `nodekit` and `cryptosuite` as unpublished but audited
`wire` — because a public package named `wire` exists. Checking directly
confirmed both `wire` and `nodekit` are taken.

Installs here are path-based with `--no-deps`, so nothing was resolving wrongly.
But the collision is a dependency-confusion hazard one typo away from mattering,
in a project specifically about supply-chain-adjacent security.

Renamed to `pqcwire`, `pqcnode`, `pqcsuite` — all verified unclaimed. Chosen
over documenting the hazard: a known-and-unfixed supply-chain issue in a
security project is a weaker outcome than a mechanical rename.

## Pattern

Static analysis found none of these. Type checking found none of these. Unit
tests found none of these.

What found them: starting the system, querying the monitoring rather than the
monitored, running the deployment nobody was looking at, and reading a scanner's
*skip* column rather than only its findings.
