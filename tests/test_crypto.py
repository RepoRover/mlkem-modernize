"""Both hops must agree on a key, and the AEAD framing must reject tampering,
replay and nonce reuse."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from services.common import cryptoutil as cu
from services.common.handshake import hop1_derive, hop2_derive
from services.common.wire import b64d, b64e, counter_bytes, lp


# ------------------------------------------------------------------ encoding


def test_length_prefixing_is_unambiguous():
    # Without length prefixes these two would be identical bytes, and a
    # signature over one would verify over the other.
    assert lp(b"ab", b"c") != lp(b"a", b"bc")


def test_base64_roundtrip_and_strictness():
    raw = cu.random_bytes(32)
    assert b64d(b64e(raw)) == raw
    with pytest.raises(Exception):
        b64d("not valid base64!!")


def test_counter_bytes_is_big_endian_and_bounded():
    assert counter_bytes(1) == b"\x00" * 7 + b"\x01"
    with pytest.raises(ValueError):
        counter_bytes(-1)


# ------------------------------------------------------- hop 1: static-static


def test_hop1_both_sides_derive_the_same_key():
    device = cu.generate_private_key()
    gateway = cu.generate_private_key()
    client_nonce, server_nonce = cu.random_bytes(16), cu.random_bytes(16)
    session_id, prefix = cu.random_bytes(16), cu.random_bytes(4)

    device_side = hop1_derive(device, gateway.public_key(), client_nonce,
                              server_nonce, session_id, prefix)
    gateway_side = hop1_derive(gateway, device.public_key(), client_nonce,
                               server_nonce, session_id, prefix)

    assert device_side.key == gateway_side.key
    assert len(device_side.key) == 32


def test_hop1_wrong_peer_key_yields_a_different_key():
    """Implicit authentication: an impostor derives garbage, not a valid session."""
    device = cu.generate_private_key()
    gateway = cu.generate_private_key()
    impostor = cu.generate_private_key()
    args = (cu.random_bytes(16), cu.random_bytes(16), cu.random_bytes(16), cu.random_bytes(4))

    real = hop1_derive(device, gateway.public_key(), *args)
    fake = hop1_derive(impostor, gateway.public_key(), *args)

    assert real.key != fake.key


def test_hop1_has_no_forward_secrecy():
    """Documents the weakness rather than asserting a good property.

    Both sessions use different nonces so the derived keys differ, but the
    underlying ECDH secret Z is identical every time. Anyone who later obtains
    either static private key can recompute Z and then every session key, since
    the nonces travel in the clear.
    """
    device = cu.generate_private_key()
    gateway = cu.generate_private_key()

    z1 = cu.ecdh(device, gateway.public_key())
    z2 = cu.ecdh(device, gateway.public_key())
    assert z1 == z2  # <- the weakness

    s1 = hop1_derive(device, gateway.public_key(), cu.random_bytes(16),
                     cu.random_bytes(16), cu.random_bytes(16), cu.random_bytes(4))
    s2 = hop1_derive(device, gateway.public_key(), cu.random_bytes(16),
                     cu.random_bytes(16), cu.random_bytes(16), cu.random_bytes(4))
    assert s1.key != s2.key  # salt still varies, so keys differ per session


def test_hop1_kdf_does_not_bind_public_keys():
    """Intentional baseline weakness, asserted so it cannot regress silently.

    Two different key pairs that happen to produce the same Z would produce the
    same session key, because the peers' public keys are not in the transcript.
    We simulate that by deriving with identical inputs from both directions.
    """
    device = cu.generate_private_key()
    gateway = cu.generate_private_key()
    nonces = (cu.random_bytes(16), cu.random_bytes(16), cu.random_bytes(16), cu.random_bytes(4))

    forward = hop1_derive(device, gateway.public_key(), *nonces)
    backward = hop1_derive(gateway, device.public_key(), *nonces)

    # Same key from both directions: nothing in the KDF distinguishes the roles.
    assert forward.key == backward.key


# --------------------------------------------------- hop 2: ephemeral ECDHE


def test_hop2_both_sides_derive_the_same_key():
    client_eph = cu.generate_private_key()
    server_eph = cu.generate_private_key()
    client_pub = cu.public_key_to_bytes(client_eph.public_key())
    server_pub = cu.public_key_to_bytes(server_eph.public_key())
    cn, sn = cu.random_bytes(16), cu.random_bytes(16)
    sid, prefix = cu.random_bytes(16), cu.random_bytes(4)

    client_side = hop2_derive(client_eph, server_eph.public_key(), cn, sn,
                              client_pub, server_pub, sid, prefix)
    server_side = hop2_derive(server_eph, client_eph.public_key(), cn, sn,
                              client_pub, server_pub, sid, prefix)

    assert client_side.key == server_side.key


def test_hop2_has_forward_secrecy():
    """Fresh ephemerals each time means a fresh Z each time."""
    peer = cu.generate_private_key()
    a, b = cu.generate_private_key(), cu.generate_private_key()
    assert cu.ecdh(a, peer.public_key()) != cu.ecdh(b, peer.public_key())


def test_hop2_kdf_binds_the_full_transcript():
    client_eph = cu.generate_private_key()
    server_eph = cu.generate_private_key()
    client_pub = cu.public_key_to_bytes(client_eph.public_key())
    server_pub = cu.public_key_to_bytes(server_eph.public_key())
    cn, sn = cu.random_bytes(16), cu.random_bytes(16)
    sid, prefix = cu.random_bytes(16), cu.random_bytes(4)

    baseline = hop2_derive(client_eph, server_eph.public_key(), cn, sn,
                           client_pub, server_pub, sid, prefix)

    # Flip one bit of the recorded client public key: same Z, different key,
    # because the transcript is in the HKDF info.
    tampered_pub = bytes([client_pub[0]]) + bytes([client_pub[1] ^ 0x01]) + client_pub[2:]
    tampered = hop2_derive(client_eph, server_eph.public_key(), cn, sn,
                           tampered_pub, server_pub, sid, prefix)

    assert baseline.key != tampered.key


def test_signature_roundtrip_and_rejection():
    signer = cu.generate_private_key()
    other = cu.generate_private_key()
    message = b"transcript bytes"

    signature = cu.sign(signer, message)
    assert cu.verify(signer.public_key(), signature, message)
    assert not cu.verify(other.public_key(), signature, message)
    assert not cu.verify(signer.public_key(), signature, b"different bytes")


def test_public_key_encoding_roundtrip_and_invalid_point():
    key = cu.generate_private_key()
    raw = cu.public_key_to_bytes(key.public_key())
    assert len(raw) == 65
    assert cu.public_key_to_bytes(cu.public_key_from_bytes(raw)) == raw

    # A point that is not on P-256 must be refused (invalid-curve defence).
    bogus = b"\x04" + b"\x01" * 64
    with pytest.raises(ValueError):
        cu.public_key_from_bytes(bogus)


# ------------------------------------------------------------- AEAD framing


def _pair():
    key = cu.random_bytes(32)
    session_id = cu.random_bytes(16)
    prefix = cu.random_bytes(4)
    return (
        cu.AeadSender(key, session_id, prefix),
        cu.AeadReceiver(key, session_id, prefix),
    )


def test_aead_roundtrip_in_order():
    sender, receiver = _pair()
    for expected_seq in range(5):
        seq, nonce, ct = sender.encrypt(f"message {expected_seq}".encode())
        assert seq == expected_seq
        assert receiver.decrypt(seq, nonce, ct) == f"message {expected_seq}".encode()


def test_nonce_is_prefix_plus_counter_and_never_repeats():
    sender, _ = _pair()
    nonces = set()
    for _ in range(100):
        _, nonce, _ = sender.encrypt(b"x")
        assert len(nonce) == 12
        nonces.add(nonce)
    assert len(nonces) == 100


def test_tampered_ciphertext_is_rejected():
    sender, receiver = _pair()
    seq, nonce, ct = sender.encrypt(b"temperature 7.4")
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]

    with pytest.raises(InvalidTag):
        receiver.decrypt(seq, nonce, tampered)


def test_sequence_number_is_bound_into_the_aad():
    """A ciphertext cannot be moved to a different sequence number.

    Present the seq-0 ciphertext as if it were seq 5, with the nonce that seq 5
    would legitimately have. The nonce check passes, so this is genuinely the
    AAD doing the work: the tag covers the sequence number.
    """
    sender, receiver = _pair()
    _, nonce, ct = sender.encrypt(b"payload")
    prefix = nonce[:4]

    with pytest.raises(InvalidTag):
        receiver.decrypt(5, prefix + counter_bytes(5), ct)


def test_nonce_that_does_not_match_the_counter_is_rejected():
    """The nonce is fully determined by session and counter, so a mismatch is
    protocol abuse and is caught before any decryption is attempted."""
    sender, receiver = _pair()
    seq, nonce, ct = sender.encrypt(b"payload")

    with pytest.raises(cu.ReplayRejected, match="nonce does not match"):
        receiver.decrypt(seq, b"\x00" * 12, ct)


def test_replayed_message_is_rejected():
    sender, receiver = _pair()
    seq, nonce, ct = sender.encrypt(b"reading")
    assert receiver.decrypt(seq, nonce, ct) == b"reading"

    with pytest.raises(cu.ReplayRejected):
        receiver.decrypt(seq, nonce, ct)


def test_out_of_order_message_is_rejected():
    sender, receiver = _pair()
    first = sender.encrypt(b"one")
    second = sender.encrypt(b"two")

    assert receiver.decrypt(*second) == b"two"
    with pytest.raises(cu.ReplayRejected):
        receiver.decrypt(*first)


def test_wrong_key_cannot_decrypt():
    sender, _ = _pair()
    seq, nonce, ct = sender.encrypt(b"secret reading")
    wrong = cu.AeadReceiver(cu.random_bytes(32), cu.random_bytes(16), nonce[:4])

    with pytest.raises(InvalidTag):
        wrong.decrypt(seq, nonce, ct)


def test_session_key_is_not_in_repr():
    """Guards the 'never log key material' rule."""
    from services.common.handshake import DerivedSession

    session = DerivedSession(cu.random_bytes(16), cu.random_bytes(4), cu.random_bytes(32))
    assert "redacted" in repr(session)
    assert session.key.hex() not in repr(session)
