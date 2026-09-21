import pytest
from hypothesis import given
from hypothesis import strategies as st

from pqcwire.frames import (
    MAX_SEQ,
    DataFrame,
    FrameError,
    HandshakeRequest,
    b64e,
    canonical,
    data_aad,
    dumps,
    loads,
    nonce_for_seq,
)
from pqcwire.protocol import LEGACY_RSA, PROTOCOL_VERSION


def test_data_frame_round_trips_through_json():
    frame = DataFrame(
        suite=LEGACY_RSA, session_id="a1b2c3d4e5f60718", seq=7, ciphertext=b"\x00\xffdata"
    )
    restored = DataFrame.from_dict(loads(dumps(frame)))
    assert restored == frame


def test_handshake_round_trips_through_json():
    request = HandshakeRequest(
        suite=LEGACY_RSA, session_id="a1b2c3d4e5f60718", kem_payload={"rsa_ct": b64e(b"ct")}
    )
    assert HandshakeRequest.from_dict(loads(dumps(request))) == request


def test_nonce_is_unique_per_sequence_number():
    nonces = {nonce_for_seq(seq) for seq in range(1000)}
    assert len(nonces) == 1000
    assert all(len(n) == 12 for n in nonces)


@pytest.mark.parametrize("seq", [-1, MAX_SEQ + 1])
def test_nonce_rejects_sequence_numbers_outside_the_safe_range(seq):
    with pytest.raises(FrameError):
        nonce_for_seq(seq)


def test_aad_binds_every_field():
    base = data_aad(PROTOCOL_VERSION, LEGACY_RSA, "session", 1)
    assert base != data_aad(PROTOCOL_VERSION + 1, LEGACY_RSA, "session", 1)
    assert base != data_aad(PROTOCOL_VERSION, "OTHER-SUITE", "session", 1)
    assert base != data_aad(PROTOCOL_VERSION, LEGACY_RSA, "session2", 1)
    assert base != data_aad(PROTOCOL_VERSION, LEGACY_RSA, "session", 2)


@given(
    st.tuples(st.text(max_size=12), st.text(max_size=12), st.integers(0, 4096)),
    st.tuples(st.text(max_size=12), st.text(max_size=12), st.integers(0, 4096)),
)
def test_aad_encoding_is_injective(left, right):
    """Distinct field tuples must never collide onto the same AAD.

    A delimiter-joined encoding would fail this: ("a|b", "c") and ("a", "b|c")
    would produce identical bytes, letting an attacker reinterpret field
    boundaries.
    """
    a = data_aad(PROTOCOL_VERSION, left[0], left[1], left[2])
    b = data_aad(PROTOCOL_VERSION, right[0], right[1], right[2])
    assert (a == b) == (left == right)


@given(st.lists(st.binary(max_size=32), max_size=6))
def test_canonical_encoding_is_reversible(fields):
    encoded = canonical(*fields)
    decoded, offset = [], 0
    while offset < len(encoded):
        length = int.from_bytes(encoded[offset : offset + 4], "big")
        offset += 4
        decoded.append(encoded[offset : offset + length])
        offset += length
    assert decoded == fields


@pytest.mark.parametrize(
    "session_id",
    [
        "",
        "0" * 15,
        "0" * 17,
        "é" * 16,
        "ABCDEF0123456789",
        "0123456789abcdeg",
    ],
    ids=["empty", "short", "oversized", "non-ascii", "uppercase", "non-hex"],
)
def test_decoding_rejects_noncanonical_session_identifiers(session_id):
    handshake = HandshakeRequest(
        suite=LEGACY_RSA,
        session_id=session_id,
        kem_payload={"rsa_ct": b64e(b"ct")},
    ).to_dict()
    frame = DataFrame(
        suite=LEGACY_RSA,
        session_id=session_id,
        seq=0,
        ciphertext=b"ct",
    ).to_dict()

    with pytest.raises(FrameError, match="16 lowercase hexadecimal"):
        HandshakeRequest.from_dict(handshake)
    with pytest.raises(FrameError, match="16 lowercase hexadecimal"):
        DataFrame.from_dict(frame)


@pytest.mark.parametrize("session_id", ["0" * 16, "0123456789abcdef", "f" * 16])
def test_decoding_accepts_canonical_session_identifier_boundaries(session_id):
    request = HandshakeRequest(
        suite=LEGACY_RSA,
        session_id=session_id,
        kem_payload={"rsa_ct": b64e(b"ct")},
    )
    assert HandshakeRequest.from_dict(request.to_dict()).session_id == session_id


def test_decoding_rejects_unsupported_protocol_versions_before_use():
    handshake = HandshakeRequest(
        suite=LEGACY_RSA, session_id="0123456789abcdef", kem_payload={"rsa_ct": b64e(b"ct")}
    ).to_dict()
    frame = DataFrame(
        suite=LEGACY_RSA, session_id="0123456789abcdef", seq=0, ciphertext=b"ct"
    ).to_dict()

    with pytest.raises(FrameError, match="unsupported protocol version"):
        HandshakeRequest.from_dict({**handshake, "v": PROTOCOL_VERSION + 1})
    with pytest.raises(FrameError, match="unsupported protocol version"):
        DataFrame.from_dict({**frame, "v": PROTOCOL_VERSION + 1})


def test_decoding_rejects_malformed_frames():
    valid = DataFrame(
        suite=LEGACY_RSA, session_id="0123456789abcdef", seq=0, ciphertext=b"x"
    ).to_dict()

    with pytest.raises(FrameError):
        DataFrame.from_dict({k: v for k, v in valid.items() if k != "ct"})
    with pytest.raises(FrameError):
        DataFrame.from_dict({**valid, "ct": "not base64!!"})
    with pytest.raises(FrameError):
        DataFrame.from_dict({**valid, "seq": "0"})
    with pytest.raises(FrameError):
        DataFrame.from_dict({**valid, "seq": MAX_SEQ + 1})
    with pytest.raises(FrameError):
        loads("not json")
    with pytest.raises(FrameError):
        loads("[1,2,3]")
