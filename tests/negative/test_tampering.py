"""Failure-path tests: what happens when an attacker modifies traffic.

The tap in this project is passive, but a real public network permits an
active attacker. These tests establish that every field an active attacker
could reach is authenticated, and they pin down the one place where the legacy
suite genuinely fails.
"""

import pytest

import pqcsuite as cs
from pqcsuite.record import AuthenticationError
from pqcwire.frames import DataFrame, FrameError, b64d, b64e
from pqcwire.protocol import HYBRID_PQC, LEGACY_RSA, PROTOCOL_VERSION
from pqcwire.sequence import ReplayError


@pytest.fixture
def legacy_pair():
    server = cs.LegacyServer(cs.generate_private_key())
    client = cs.LegacyClient(server.public_key)
    request, client_session = client.open_session()
    return client, server, request, client_session, server.accept(request)


@pytest.fixture
def hybrid_pair():
    identity = cs.generate_identity_key()
    gateway_identity = cs.generate_identity_key()
    server = cs.HybridServer(identity, gateway_identity.public_key())
    client = cs.HybridClient(identity.public_key(), gateway_identity)
    offer = server.make_offer()
    request, client_session = client.open_session(offer)
    return client, server, offer, request, client_session, server.accept(request)


def _flip(frame: DataFrame, index: int = 0) -> DataFrame:
    corrupted = bytearray(frame.ciphertext)
    corrupted[index] ^= 0xFF
    return DataFrame(
        suite=frame.suite,
        session_id=frame.session_id,
        seq=frame.seq,
        ciphertext=bytes(corrupted),
    )


def test_unsupported_versions_are_rejected_before_cryptographic_use(legacy_pair):
    _, server, request, client_session, server_session = legacy_pair
    wrong_request = type(request)(
        suite=request.suite,
        session_id=request.session_id,
        kem_payload=dict(request.kem_payload),
        version=PROTOCOL_VERSION + 1,
    )
    frame = client_session.seal(b"reading")
    wrong_frame = type(frame)(
        suite=frame.suite,
        session_id=frame.session_id,
        seq=frame.seq,
        ciphertext=frame.ciphertext,
        version=PROTOCOL_VERSION + 1,
    )

    with pytest.raises(FrameError, match="unsupported protocol version"):
        server.accept(wrong_request)
    with pytest.raises(FrameError, match="unsupported protocol version"):
        server_session.open(wrong_frame)


def test_modified_ciphertext_is_rejected(legacy_pair):
    *_, client_session, server_session = legacy_pair
    with pytest.raises(AuthenticationError):
        server_session.open(_flip(client_session.seal(b"reading")))


def test_truncated_ciphertext_is_rejected(legacy_pair):
    *_, client_session, server_session = legacy_pair
    frame = client_session.seal(b"reading")
    truncated = DataFrame(
        suite=frame.suite,
        session_id=frame.session_id,
        seq=frame.seq,
        ciphertext=frame.ciphertext[:-1],
    )
    with pytest.raises(AuthenticationError):
        server_session.open(truncated)


def test_relabelling_the_suite_is_rejected(legacy_pair):
    """Downgrade-by-relabelling: the suite is bound into the AEAD tag."""
    *_, client_session, server_session = legacy_pair
    frame = client_session.seal(b"reading")
    relabelled = DataFrame(
        suite=HYBRID_PQC,
        session_id=frame.session_id,
        seq=frame.seq,
        ciphertext=frame.ciphertext,
    )
    with pytest.raises(FrameError):
        server_session.open(relabelled)


def test_moving_a_frame_to_another_session_is_rejected(legacy_pair):
    *_, client_session, server_session = legacy_pair
    frame = client_session.seal(b"reading")
    spliced = DataFrame(
        suite=frame.suite,
        session_id="0" * 16,
        seq=frame.seq,
        ciphertext=frame.ciphertext,
    )
    with pytest.raises(FrameError):
        server_session.open(spliced)


def test_renumbering_a_frame_is_rejected(legacy_pair):
    """The sequence number is in the AAD, so it cannot be rewritten."""
    *_, client_session, server_session = legacy_pair
    frame = client_session.seal(b"reading")
    renumbered = DataFrame(
        suite=frame.suite,
        session_id=frame.session_id,
        seq=frame.seq + 5,
        ciphertext=frame.ciphertext,
    )
    with pytest.raises(AuthenticationError):
        server_session.open(renumbered)


def test_replaying_a_frame_is_rejected(legacy_pair):
    *_, client_session, server_session = legacy_pair
    frame = client_session.seal(b"reading")
    assert server_session.open(frame) == b"reading"
    with pytest.raises(ReplayError):
        server_session.open(frame)


def test_a_rejected_frame_does_not_desynchronise_the_session(legacy_pair):
    """A forgery must not advance the replay high-water mark."""
    *_, client_session, server_session = legacy_pair
    genuine = [client_session.seal(f"reading-{i}".encode()) for i in range(3)]

    assert server_session.open(genuine[0]) == b"reading-0"
    with pytest.raises(AuthenticationError):
        server_session.open(_flip(genuine[2]))
    # The genuine frames that follow are still accepted.
    assert server_session.open(genuine[1]) == b"reading-1"
    assert server_session.open(genuine[2]) == b"reading-2"


def test_forged_offer_signature_is_rejected(hybrid_pair):
    client, _, offer, *_ = hybrid_pair
    forged = cs.Offer(
        key_id=offer.key_id,
        mlkem_pub=offer.mlkem_pub,
        x25519_pub=offer.x25519_pub,
        signature=bytes(len(offer.signature)),
    )
    with pytest.raises(FrameError, match="signature"):
        client.verify_offer(forged)


def test_substituted_ephemeral_keys_are_rejected(hybrid_pair):
    """An active attacker cannot swap in its own KEM key: the offer is signed."""
    client, _, offer, *_ = hybrid_pair
    attacker_key = cs.mlkem_module().MLKEM768PrivateKey.generate()
    substituted = cs.Offer(
        key_id=offer.key_id,
        mlkem_pub=attacker_key.public_key().public_bytes_raw(),
        x25519_pub=offer.x25519_pub,
        signature=offer.signature,
    )
    with pytest.raises(FrameError, match="signature"):
        client.verify_offer(substituted)


def test_signed_offer_with_out_of_range_mlkem_coefficient_is_rejected():
    cloud_identity = cs.generate_identity_key()
    gateway_identity = cs.generate_identity_key()
    server = cs.HybridServer(cloud_identity, gateway_identity.public_key())
    client = cs.HybridClient(cloud_identity.public_key(), gateway_identity)
    real = server.make_offer()
    invalid_key = bytearray(real.mlkem_pub)
    # ML-KEM packs two 12-bit coefficients into three bytes. q=3329 in the
    # first coefficient is structurally invalid under FIPS 203 section 7.2.
    invalid_key[0] = 3329 & 0xFF
    invalid_key[1] = (invalid_key[1] & 0xF0) | ((3329 >> 8) & 0x0F)
    unsigned = cs.Offer(
        key_id=real.key_id,
        mlkem_pub=bytes(invalid_key),
        x25519_pub=real.x25519_pub,
        signature=b"",
    )
    signed = cs.Offer(
        key_id=unsigned.key_id,
        mlkem_pub=unsigned.mlkem_pub,
        x25519_pub=unsigned.x25519_pub,
        signature=cloud_identity.sign(unsigned.signed_bytes()),
    )

    with pytest.raises(ValueError):
        client.open_session(signed)


def test_offer_signature_binds_protocol_version_and_suite(hybrid_pair):
    client, _, offer, *_ = hybrid_pair
    changed_version = cs.Offer(
        key_id=offer.key_id,
        mlkem_pub=offer.mlkem_pub,
        x25519_pub=offer.x25519_pub,
        signature=offer.signature,
        version=offer.version + 1,
        suite=offer.suite,
    )
    changed_suite = cs.Offer(
        key_id=offer.key_id,
        mlkem_pub=offer.mlkem_pub,
        x25519_pub=offer.x25519_pub,
        signature=offer.signature,
        version=offer.version,
        suite=LEGACY_RSA,
    )

    with pytest.raises(FrameError, match="protocol version"):
        client.verify_offer(changed_version)
    with pytest.raises(FrameError, match="offer suite"):
        client.verify_offer(changed_suite)
    assert changed_version.signed_bytes() != offer.signed_bytes()
    assert changed_suite.signed_bytes() != offer.signed_bytes()


def test_gateway_signature_binds_the_full_hybrid_request(hybrid_pair):
    client, server, *_ = hybrid_pair
    offer = server.make_offer()
    request, _ = client.open_session(offer)
    changed = type(request)(
        suite=request.suite,
        session_id="different-session",
        kem_payload=dict(request.kem_payload),
    )

    with pytest.raises(FrameError, match="gateway handshake signature"):
        server.accept(changed)
    # Unauthenticated garbage does not consume the bounded offer.
    server.accept(request)


def test_gateway_signature_rejects_kem_ciphertext_mutation(hybrid_pair):
    client, server, *_ = hybrid_pair
    offer = server.make_offer()
    request, _ = client.open_session(offer)
    ciphertext = bytearray(b64d(request.kem_payload["mlkem_ct"]))
    ciphertext[0] ^= 1
    changed = type(request)(
        suite=request.suite,
        session_id=request.session_id,
        kem_payload={**request.kem_payload, "mlkem_ct": b64e(bytes(ciphertext))},
    )

    with pytest.raises(FrameError, match="gateway handshake signature"):
        server.accept(changed)
    server.accept(request)


def test_unpinned_gateway_identity_is_rejected(hybrid_pair):
    _, server, *_ = hybrid_pair
    attacker = cs.HybridClient(server.identity_public_key, cs.generate_identity_key())
    offer = server.make_offer()
    request, _ = attacker.open_session(offer)

    with pytest.raises(FrameError, match="gateway handshake signature"):
        server.accept(request)


def test_an_offer_cannot_be_used_twice(hybrid_pair):
    _, server, _, request, *_ = hybrid_pair
    with pytest.raises(FrameError, match="unknown, expired, or already used"):
        server.accept(request)


def test_tampering_with_the_kem_ciphertext_surfaces_at_the_first_frame(hybrid_pair):
    """ML-KEM implicit rejection means the handshake still "succeeds".

    FIPS 203 decapsulation does not fail on a corrupted ciphertext; it returns
    a different pseudo-random secret. So the responder derives a key, believes
    it has a session, and only the AEAD tag on the first frame reveals the
    mismatch. This is why the suite must never treat handshake completion as
    authentication.
    """
    client, server, *_ = hybrid_pair
    offer = server.make_offer()
    request, initiator_session = client.open_session(offer)

    corrupted_ct = bytearray(b64d(request.kem_payload["mlkem_ct"]))
    corrupted_ct[0] ^= 0xFF
    tampered = type(request)(
        suite=request.suite,
        session_id=request.session_id,
        kem_payload={**request.kem_payload, "mlkem_ct": b64e(bytes(corrupted_ct))},
    )
    # A network attacker cannot update this signature. Re-sign as the legitimate
    # gateway to isolate ML-KEM's implicit-rejection behavior itself.
    tampered = client.authenticate_request(tampered, offer)

    # The handshake completes rather than raising -- that is the point.
    victim_session = server.accept(tampered)
    assert victim_session.session_id == initiator_session.session_id

    # Same session label, divergent keys. Only the AEAD tag catches it.
    with pytest.raises(AuthenticationError):
        victim_session.open(initiator_session.seal(b"reading"))


def test_legacy_handshake_is_not_bound_to_its_session_id(legacy_pair):
    """Documents defect 2 of the legacy suite, rather than hiding it.

    The RSA ciphertext carries no binding to the session identifier, so a
    captured handshake can be replayed under a different label and yields a
    working session with the same key. The hybrid suite closes this by folding
    the session id into the transcript hash; if this test ever starts failing,
    the legacy suite has been fixed and the baseline analysis needs updating.
    """
    _, server, request, _, _ = legacy_pair
    relabelled = type(request)(
        suite=LEGACY_RSA,
        session_id="deadbeefdeadbeef",
        kem_payload=dict(request.kem_payload),
    )
    hijacked = server.accept(relabelled)
    assert hijacked.session_id == "deadbeefdeadbeef"
