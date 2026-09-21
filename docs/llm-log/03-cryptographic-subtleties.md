# 03 — Two API traps and one standards behaviour

## Trap 1 — `encapsulate()` returns `(shared_secret, ciphertext)`

Most KEM examples, and most generated code, assume `(ciphertext, shared_secret)`.
`cryptography` returns the reverse.

Found immediately, because the first exploratory call unpacked it the intuitive
way:

```python
ct, ss = pub.encapsulate()
ss2 = k.decapsulate(ct)
# ValueError: Invalid ML-KEM-768 ciphertext
```

The error is misleading. Nothing is wrong with the ciphertext — a 32-byte shared
secret was passed where a 1088-byte ciphertext belonged, and the length check
fired. A reader debugging this would reasonably start by suspecting key
mismatch, corruption, or a version problem.

**Accepted with guards.** A comment at the call site in `hybrid.py` and a
regression test asserting the ordering by length:

```python
def test_encapsulate_returns_the_secret_before_the_ciphertext():
    first, second = private_key.public_key().encapsulate()
    assert len(first) == 32
    assert len(second) == 1088
```

Worth keeping in the log because it is a realistic failure mode for AI-assisted
cryptographic work: the swap type-checks, runs, and fails somewhere else with an
error pointing at the wrong thing.

## Trap 2 — modernised syntax versus a Python 3.9 runtime

Ruff's autofix rewrote `Optional[str]` to `str | None` and `Dict` to `dict`
across packages the Python 3.9 device installs. PEP 604 unions are a 3.10
runtime feature.

**Not rejected** — verified instead. Because every module carries
`from __future__ import annotations`, annotations are never evaluated, so the
modernised syntax is safe on 3.9. Confirmed by installing the packages in a real
`python:3.9-slim` container and exercising a full legacy handshake.

One case genuinely was unsafe: `logging.LoggerAdapter[logging.Logger]` as a
**base class** is evaluated at runtime and only became subscriptable in 3.11.
Resolved with a `TYPE_CHECKING` guard rather than by loosening the type checker:

```python
if TYPE_CHECKING:
    _AdapterBase = logging.LoggerAdapter[logging.Logger]
else:
    _AdapterBase = logging.LoggerAdapter
```

The distinction matters: one was a false alarm, one was real, and only running
the code on 3.9 separated them. CI now runs that check on every push.

## Behaviour — FIPS 203 implicit rejection

The cross-validation against `kyber-py` surfaced the most consequential
cryptographic fact in the project.

Decapsulating a *corrupted but correctly sized* ML-KEM ciphertext does not
raise. It returns a deterministic pseudo-random 32-byte secret derived from the
private key. Both implementations return the **same** value, confirming this is
standards-conformant rather than an implementation quirk.

```
corrupted ct, same length (1088)
  cryptography: returned a secret, differs from real: True
  kyber-py    : returned a secret, differs from real: True
  both implicit-reject to the SAME value: True
```

The protocol consequence is significant: a handshake carrying a tampered KEM
ciphertext **completes**. The responder derives a key, believes it has a
session, and nothing signals a problem until the first AEAD tag fails. Any
design treating "decapsulation succeeded" as "the peer is authentic" is broken
by construction.

This was not designed around in advance — it was discovered by cross-validation
and the design was checked against it afterwards. The suite happened to be
correct already, because authentication comes from the ML-DSA signature and
integrity from the AEAD tag over a transcript-bound key. A test now pins the
behaviour so the reasoning is explicit rather than accidental:
`test_tampering_with_the_kem_ciphertext_surfaces_at_the_first_frame`.

**Risk remaining:** the cross-check covers ML-KEM only. ML-DSA-65 signing and
the HKDF combiner are exercised only by round-trip tests within a single
implementation, so a consistent-but-wrong combiner would not be detected. See
entry 05.
