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

## Found by a question about something else

### Grafana shipped with a working default admin account

A team member asked whether it was a problem that the repo has no `.env`. It
mostly is not — no configuration value is secret, and crypto keys are generated
at runtime rather than passed in. But auditing the question turned up the one
place a credential genuinely mattered.

The observability overlay set `GF_AUTH_DISABLE_LOGIN_FORM=true`, with a comment
presenting the stack as anonymous and read-only. That flag only **hides the web
form**. HTTP basic auth stayed enabled, so Grafana's built-in admin account
remained reachable over the API with its publicly known default password — on a
port published to the host.

```
GET /api/admin/settings   (admin:admin)  -> HTTP 200
authenticated as: admin | grafana admin: True
```

Fixed by also setting `GF_AUTH_BASIC_ENABLED=false`, leaving the admin account
with no way to authenticate. Verified in both directions, since the original
mistake was assuming a flag did more than it does:

```
admin endpoint, admin:admin   -> HTTP 403   (was 200)
dashboard, anonymous viewer   -> HTTP 200   (still works)
write attempt, anonymous      -> HTTP 403   (refused)
```

Setting an admin password was **rejected** as the fix. It would have meant a
hardcoded secret in a committed file, or a `.env` every teammate must create
before the demo runs. Nothing needs administering at runtime — the datasource
and dashboard are provisioned from files — so removing the access path is
strictly better than guarding it.

This is the same failure as [entry 02](02-a-false-claim-caught.md) in a
different domain: a confident assumption about what something does, written
into a comment that made it look deliberate, and never executed. The comment is
the aggravating part — it did not merely fail to catch the problem, it would
have reassured a reviewer that the problem had been considered.

## Smaller items, recorded for completeness

**Generated code called a method it never defined.** `HybridServer.make_offer()`
invoked `self._expire()`, which did not exist. Caught within seconds by the
first execution, and a textbook instance of a model writing a plausible call to
an imaginary helper. Harmless here only because the code was run immediately.

**A test failed for the wrong reason.** `test_tampering_with_the_kem_ciphertext...`
raised `FrameError: frame belongs to a different session`. The tempting reading
was that the code was wrong. The *test* was wrong — it sealed a frame with a
different session's key, so the session-id check fired before the AEAD ever ran,
and the behaviour under test was never reached.

Worth dwelling on: when the same model writes both the code and the tests, a
failing test is not evidence about which of the two is broken. A test that fails
for the wrong reason is only one edit away from a test that *passes* for the
wrong reason, and that one is invisible.

**A portability assumption in tooling.** `verify_migration.sh` used `${VAR@L}`,
a bash 4.4 parameter expansion, on a machine whose `/bin/bash` is 3.2. The
script was rewritten to move the logic into Python rather than patching the
expansion, since shell portability was not worth defending.

**`docker compose up --build` silently skipped the attacker.** The harvester sits
behind a `profiles: ["attack"]` guard, so `up --build` never rebuilt it and the
demo ran a stale image that rejected a newly added flag. Fixed by building the
profile explicitly. The failure mode is the dangerous kind — old code running
silently under a command that appears to rebuild everything.

**`pip-audit --strict` was wrong for this repo.** Strict mode fails on any
dependency it cannot resolve, which includes every local workspace package.
Caught before CI ran by checking what the flag actually did rather than assuming
stricter was better.

## Pattern

Static analysis found none of these. Type checking found none of these. Unit
tests found none of these.

What found them: starting the system, querying the monitoring rather than the
monitored, running the deployment nobody was looking at, and reading a scanner's
*skip* column rather than only its findings.
