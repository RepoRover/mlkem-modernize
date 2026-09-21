import pytest

import pqcsuite as cs
from pqcsuite import hybrid as hybrid_module
from pqcwire.frames import FrameError


def _pair(*, ttl_seconds=60, max_pending_offers=2):
    cloud_identity = cs.generate_identity_key()
    gateway_identity = cs.generate_identity_key()
    server = cs.HybridServer(
        cloud_identity,
        gateway_identity.public_key(),
        ttl_seconds=ttl_seconds,
        max_pending_offers=max_pending_offers,
    )
    client = cs.HybridClient(cloud_identity.public_key(), gateway_identity)
    return server, client


def test_pending_offer_capacity_is_hard_bounded_and_recovers_after_use():
    server, client = _pair(max_pending_offers=2)
    first = server.make_offer()
    server.make_offer()

    with pytest.raises(cs.OfferCapacityError, match="capacity"):
        server.make_offer()
    assert server.pending_offers == 2

    request, _ = client.open_session(first)
    server.accept(request)
    server.make_offer()
    assert server.pending_offers == 2


def test_pending_offer_capacity_recovers_after_expiry(monkeypatch):
    clock = {"now": 10.0}
    monkeypatch.setattr(hybrid_module.time, "monotonic", lambda: clock["now"])
    server, client = _pair(ttl_seconds=5, max_pending_offers=1)
    expired = server.make_offer()

    clock["now"] = 16.0
    replacement = server.make_offer()
    assert replacement.key_id != expired.key_id
    assert server.pending_offers == 1

    expired_request, _ = client.open_session(expired)
    with pytest.raises(FrameError, match="unknown, expired, or already used"):
        server.accept(expired_request)


def test_offer_parser_rejects_unsupported_version_before_crypto():
    server, _ = _pair()
    raw = server.make_offer().to_dict()
    raw["v"] = 2

    with pytest.raises(FrameError, match="unsupported protocol version"):
        cs.Offer.from_dict(raw)


def test_offer_limits_reject_unsafe_configuration():
    cloud_identity = cs.generate_identity_key()
    gateway_identity = cs.generate_identity_key()

    with pytest.raises(ValueError, match="positive"):
        cs.HybridServer(
            cloud_identity,
            gateway_identity.public_key(),
            max_pending_offers=0,
        )
