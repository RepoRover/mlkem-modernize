# 02 — A plausible, load-bearing, and false claim

The most useful thing that happened in this project was catching a wrong claim
that the entire architecture rested on.

## The claim

Asked to simulate a device that cannot run ML-KEM, the reasoning went:

> Python 3.9 reached end of life in October 2025 and cryptography 3.4.8 dates
> from August 2021 — it predates ML-KEM by three years. The device therefore
> cannot negotiate a post-quantum suite no matter how much CPU it is given; the
> primitive simply is not there.

This was written into `Dockerfile.device` as justification. It is fluent,
technically flavoured, and consistent with the deployment. It is also false in
the way that mattered.

## How it was caught

Not by review — by running the thing the claim was about:

```bash
docker run --rm python:3.9-slim sh -c \
  "pip install -q 'cryptography>=48' && python -c \
   'from cryptography.hazmat.primitives.asymmetric import mlkem; print(\"available\")'"
```

Output: `available`. A current, PQC-capable `cryptography` installs on Python
3.9 without complaint, and ML-KEM-768 works there.

A second check removed the fallback explanation. ML-KEM-768 keygen takes
0.26 ms and the device idles at 20.8 MiB of its 48 MiB cap, so neither the CPU
quota nor the memory limit would have prevented it either.

Both of the obvious justifications for the project's central design decision
were wrong.

## What was actually true

The device is blocked by its **update path**:

1. the crypto dependency is pinned inside an immutable image;
2. the container has no route to a package index;
3. the root filesystem is read-only.

Only the first was real at the time the claim was written. The second was a
comment; the third was partial.

## What changed

**Rejected:** the Python-version and CPU-budget explanations, and the Dockerfile
comment asserting them.

**Modified:** the deployment now *enforces* the real constraint. The device sits
on an `internal: true` Docker network with no default route, so it genuinely
cannot reach PyPI. Previously the isolation was described rather than imposed.

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
survived code review, and would have read well in the report. Nothing in the
code would ever have contradicted it.

It also made the project weaker. "Old Python lacks the primitive" is a
contrivance. "Fielded firmware cannot be updated" is the actual reason PQC
migration is hard at scale, and it is what makes gateway brokering a real
strategy rather than a lab exercise.

The generalisable lesson: the dangerous outputs are the ones that sound like
domain knowledge and sit upstream of a design decision. The defence is not more
careful reading. It is executing the claim.
