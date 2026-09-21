"""Cipher suites, PQC policy, and suite negotiation for hop 2.

Hop 2 (gateway -> cloud) negotiates between:

  hybrid-x25519-mlkem768   X25519 ECDHE + ML-KEM-768   (post-quantum)
  classical-p256           P-256 ECDHE                 (the Phase 2 baseline)

Hop 1 (device -> gateway) does not negotiate anything. It is frozen legacy.

NO SILENT DOWNGRADE. Selecting the classical suite is always either refused or
logged and counted. The policy below is the enforcement point; the signature
and KDF bindings in handshake.py are the cryptographic backstops.
"""

from __future__ import annotations

from enum import Enum

# Suite identifiers as they appear on the wire.
SUITE_HYBRID = "hybrid-x25519-mlkem768"
SUITE_CLASSICAL = "classical-p256"

ALL_SUITES = (SUITE_HYBRID, SUITE_CLASSICAL)

#: Suites this build knows how to complete, in descending preference order.
SUPPORTED_SUITES = (SUITE_HYBRID, SUITE_CLASSICAL)


def is_post_quantum(suite: str) -> bool:
    return suite == SUITE_HYBRID


class Policy(str, Enum):
    """What a service will accept for hop 2 key establishment."""

    #: Hybrid only. A peer that cannot do PQC is refused, loudly.
    REQUIRE = "require"

    #: Hybrid when both sides can, classical otherwise -- logged and counted.
    PREFER = "prefer"

    #: Classical only. An explicit, deliberate opt-out for rollback or testing.
    CLASSICAL_ONLY = "classical-only"

    @classmethod
    def parse(cls, raw: str) -> Policy:
        value = (raw or "").strip().lower()
        try:
            return cls(value)
        except ValueError:
            allowed = ", ".join(p.value for p in cls)
            raise ValueError(
                f"invalid PQC policy {raw!r}; expected one of: {allowed}"
            ) from None


class NegotiationError(Exception):
    """Base class for a handshake that cannot proceed."""

    #: Short machine-readable reason, safe to put in a response body.
    reason = "negotiation_failed"


class DowngradeRefused(NegotiationError):
    """Peer offered no post-quantum suite while policy requires one.

    This is the "no silent downgrade" rule firing. It is an explicit, logged,
    counted refusal -- never a quiet fallback to classical.
    """

    reason = "downgrade_refused"


class NoCommonSuite(NegotiationError):
    """No overlap between what the peer offered and what policy permits."""

    reason = "no_common_suite"


def canonical_suites(suites: list[str] | tuple[str, ...]) -> str:
    """Stable string form of an offer list, for signing and for the KDF.

    Order is preserved because it expresses preference, and because an attacker
    reordering the list must not produce the same bytes. Deduplicating or
    sorting here would silently discard evidence of tampering.
    """
    return ",".join(suites)


def negotiate(offered: list[str] | tuple[str, ...], policy: Policy) -> str:
    """Pick a suite, or refuse.

    `offered` is untrusted input from the peer. Unknown suite names are ignored
    rather than rejected, so that a future peer offering
    ["hybrid-x25519-mlkem1024", "hybrid-x25519-mlkem768"] still interoperates.

    Raises DowngradeRefused or NoCommonSuite; never returns a classical suite
    when policy is REQUIRE.
    """
    if not isinstance(offered, (list, tuple)):
        raise NoCommonSuite("offered_suites is not a list")

    known = [s for s in offered if isinstance(s, str) and s in ALL_SUITES]

    if policy is Policy.REQUIRE:
        if SUITE_HYBRID in known:
            return SUITE_HYBRID
        # The peer could not or would not do PQC. Refuse rather than fall back.
        raise DowngradeRefused(
            f"policy=require but peer offered {canonical_suites(offered) or '(nothing)'}"
        )

    if policy is Policy.PREFER:
        if SUITE_HYBRID in known:
            return SUITE_HYBRID
        if SUITE_CLASSICAL in known:
            # Caller MUST log and count this. See cloud/main.py.
            return SUITE_CLASSICAL
        raise NoCommonSuite(f"no usable suite in {canonical_suites(offered) or '(nothing)'}")

    if policy is Policy.CLASSICAL_ONLY:
        if SUITE_CLASSICAL in known:
            return SUITE_CLASSICAL
        raise NoCommonSuite(
            f"policy=classical-only but peer offered {canonical_suites(offered) or '(nothing)'}"
        )

    raise NoCommonSuite(f"unhandled policy {policy!r}")  # pragma: no cover


def client_offer(policy: Policy) -> tuple[str, ...]:
    """Which suites a client advertises under a given policy.

    Under REQUIRE the client does not offer classical at all, so a stripped-down
    offer cannot be blamed on us.
    """
    if policy is Policy.REQUIRE:
        return (SUITE_HYBRID,)
    if policy is Policy.CLASSICAL_ONLY:
        return (SUITE_CLASSICAL,)
    return SUPPORTED_SUITES
