# 06 — Found by a human reading the output

Everything in [entry 04](04-defects-found-by-running.md) was found by running
the system. This entry is about a defect that survived running it, because the
system ran correctly and reported itself incorrectly.

It was caught by a team member looking at Grafana and asking whether the number
was supposed to look like that.

## The defect

The dashboard's headline panel read:

```
Quantum-vulnerable frames accepted:  366
```

Red, and never falling. The migration appeared to have failed.

The panel's query was:

```promql
sum(pqc_quantum_vulnerable_frames_total)
```

Split by service, the same data says the opposite:

| Series | Value |
|---|---|
| `...{service="gateway"}` | 447 |
| `...{service="cloud"}` | series does not exist — zero |

The gateway **must** accept quantum-vulnerable frames. The device can only speak
the legacy suite, so brokering it is the entire design. That number can never
reach zero. The cloud's number is the one that means something, and it was zero
the whole time.

The panel aggregated a metric across two nodes where the same value carries
opposite meanings, and so displayed a completed migration as a failure.

Three separate errors in one panel:

1. **Not scoped by service.** The aggregation destroyed the distinction the
   metric existed to express.
2. **Cumulative counter used to answer a "right now" question.** A counter only
   rises. "Should fall to zero" is impossible once anything has been counted, so
   the stated success criterion could never be met by construction.
3. **Threshold inverted in practice.** Red above zero meant correct behaviour
   rendered as an alert.

## Why the existing safeguards did not catch it

They were all aimed one layer too low.

- Unit and integration tests assert the **metric increments correctly**. It did.
- CI asserts the **migration works**. It does.
- The M7 verification queried Prometheus **per service** and printed
  `gateway 67 / cloud 0` — the correct decomposition was on screen at the time
  the dashboard was written.

The commit message for that work even states it accurately: *"the gateway
accepting 67 vulnerable frames from the device and the cloud accepting none."*
The right data was in hand. The panel was built to sum it anyway.

So this was not a knowledge gap. It was a failure to ask what the visualisation
would **mean to someone reading it**, as distinct from whether the pipeline
technically worked. The metric was verified; the interpretation was not.

## A compounding defect, found by the same question

Following up revealed a second problem. The device sent its 366 readings and
stopped, so every rate on the dashboard decayed to zero once the dataset was
exhausted.

That is worse than it sounds for a demonstration: a rate falling to zero is
exactly what a *successful migration* would look like, so the dashboard would
have shown a convincing success for the wrong reason. `LOOP_FOREVER` now keeps
the year replaying so the displayed state reflects the system rather than the
end of the data.

## What changed

**Rejected:** the aggregate panel and its success criterion.

**Modified:** the headline is now `...{service="cloud"}`, which genuinely sits at
zero and for which a cumulative counter is the *right* instrument — "has
quantum-vulnerable traffic ever reached the cloud" is a question where one
occurrence matters and history should not decay.

**Added:** a separate gateway panel, coloured neutrally and titled *last-mile
exposure (expected)*, plus a rate view so "is it happening now" is answerable.
The residual risk is now visible on the dashboard by design rather than
aggregated out of sight.

**Corrected:** the metric's own docstring, which made the identical conflation
and instructed readers that the total should reach zero. Documentation that
teaches the wrong reading of a metric is worse than no documentation, because it
propagates.

## The lesson

The other entries in this log are about claims that were wrong. This one is
about a claim that was *right* — the metric was accurate, the system was
correct, the tests passed — presented in a way that communicated the opposite.

Tests verify that software does what it was built to do. They cannot tell you
whether what it displays means what a person will take it to mean. That gap
needs a human looking at the output and being willing to say "is this supposed
to look like this?"

Worth stating plainly: no amount of test coverage would have caught this, and
the model that wrote the panel also wrote the tests, the verification script,
and this log. The defect was found because someone else looked.
