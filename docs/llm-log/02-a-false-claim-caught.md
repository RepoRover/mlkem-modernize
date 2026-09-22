# 02 — A plausible, load-bearing, and false claim

The most useful thing that happened in this project was catching a wrong
software-version explanation for a premise the simulation cannot itself test.

## The claim

The project premise says the real target device is hardware-limited and cannot
perform ML-KEM. While building a host/container model of that device, the
reasoning substituted this software explanation:

> Python 3.9 reached end of life in October 2025 and cryptography 3.4.8 dates
> from August 2021 — it predates ML-KEM by three years. The device therefore
> cannot negotiate a post-quantum suite no matter how much CPU it is given; the
> primitive simply is not there.

This was written into `Dockerfile.device` as justification. It is fluent,
technically flavoured, and consistent with the deployment. It is also not a
valid explanation of the target hardware premise.

## How it was caught

Not by review — by running the thing the claim was about:

```bash
docker run --rm python:3.9-slim sh -c \
  "pip install -q 'cryptography>=48' && python -c \
   'from cryptography.hazmat.primitives.asymmetric import mlkem; print(\"available\")'"
```

Output: `available`. A current, PQC-capable `cryptography` installs on Python
3.9 without complaint, and ML-KEM-768 works in this host/container environment.
That proves Python version alone is not the blocker.

Host measurements also observed a 0.26 ms ML-KEM-768 keygen and 20.8 MiB idle
container use. Those numbers describe the development host under a container
configuration; neither its quota nor its timing is evidence about the real
target hardware. The simulation cannot prove or disprove target-hardware
feasibility.

## What was actually true

The real device's inability to perform ML-KEM is an owner-provided hardware
premise, not a conclusion produced by this simulation. Independently, the model
represents field software and deployment constraints that prevent upgrading its
available primitive:

1. the old crypto dependency is pinned inside an immutable image;
2. the container has no route to a package index;
3. the root filesystem is read-only.

Only the first was enforced at the time the claim was written. The second was a
comment; the third was partial. These constraints strengthen the migration
scenario, but they do not constitute a hardware benchmark.

## What changed

**Rejected:** the Python-version explanation, any use of container CPU/memory
observations as target-hardware evidence, and the Dockerfile comment asserting
them.

**Modified:** the deployment now *enforces* the modeled no-egress constraint.
The device sits on an `internal: true` Docker network with no default route, so
it genuinely cannot reach PyPI. Previously the isolation was described rather
than imposed.

**Added:** four tests in `test_device_constraints.py`, including one that exists
purely to prevent the comfortable version returning:

```python
def test_python_version_alone_would_not_have_blocked_mlkem():
    """Guards against the tempting but false claim that Python 3.9 is the limit.

    If this ever fails, the honest justification in the architecture docs needs
    revisiting -- not the docs quietly rewritten to match.
    """
```

## Why this is the important entry

The claim was not a hallucinated API or a syntax error — those fail loudly. It
was a *plausible causal story* that matched the observable setup, would have
survived code review, and would have read well in the report.

It also obscured two distinct facts. The owner premise supplies the physical
limit of the real device, while immutable software, old dependencies, read-only
deployment, and no egress model the operational barriers common to fielded
firmware. "Old Python lacks the primitive" establishes neither. Keeping those
claims separate makes gateway brokering a defensible simulated migration
strategy without overstating what the development host demonstrated.

The generalisable lesson: the dangerous outputs are the ones that sound like
domain knowledge and sit upstream of a design decision. The defence is not more
careful reading. It is executing the claim.
