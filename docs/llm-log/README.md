# LLM-assisted development log

The brief requires reporting the prompts used for significant tasks, the
relevant outputs, the context provided, and what the group changed — and for
each artifact, what was accepted, modified, or rejected, why, how problems were
found, and what risk remains.

The purpose is not to show the model produced good code. It is to show the work
was assessed rather than trusted.

## How this log is organised

| Entry | Subject |
|---|---|
| [01](01-design-decisions.md) | Architecture and library selection |
| [02](02-a-false-claim-caught.md) | A plausible, load-bearing, and false claim about the device |
| [03](03-cryptographic-subtleties.md) | Two API traps and one standards behaviour |
| [04](04-defects-found-by-running.md) | Defects that only appeared when the system ran |
| [05](05-outstanding-review.md) | What still needs human review before submission |

## Method used

Three habits did most of the work:

**Verify before asserting.** Every factual claim about a library was checked by
running it, not recalled. This caught the project's central architectural claim
being wrong (entry 02).

**Make constraints executable.** Where a claim mattered, it became a test or a
deployment property rather than a sentence in a comment. The device's isolation
is enforced by an `internal: true` network; the migration's effect is asserted
by a script CI runs.

**Prefer the measurement to the assertion.** "ML-KEM is faster" is worth little;
`bench/results/comparison.json` with 300 iterations is worth something, and it
also showed a 31x regression on the initiator that the optimistic version of the
sentence would have hidden.

## Honest limitation of this log

It was written by the same model that produced the code, so it is not an
independent review. It is a record of decisions and the evidence behind them.
Entry 05 lists what the group should check independently — treating this
document as sufficient review would reproduce exactly the failure mode the
assignment is testing for.
