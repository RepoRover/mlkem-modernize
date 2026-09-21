"""Validate our ML-KEM backend against an independent implementation.

Round-trip tests cannot establish correctness: they pass whenever both sides
are wrong in the same way. These tests compare `cryptography` (Rust bindings
over OpenSSL/AWS-LC) against `kyber-py` (a pure-Python FIPS 203
implementation). Two independently written implementations agreeing on
deterministic outputs is real evidence; one implementation agreeing with
itself is not.

`kyber-py` is a test-only dependency and must never reach a runtime image.
"""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem
from kyber_py.ml_kem import ML_KEM_768 as KYBER

# FIPS 203, Table 2 (ML-KEM-768).
ENCAPSULATION_KEY_BYTES = 1184
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32
SEED_BYTES = 64

SEEDS = [
    bytes(SEED_BYTES),
    bytes(range(SEED_BYTES)),
    b"\xff" * SEED_BYTES,
    bytes.fromhex("a1" * SEED_BYTES),
]


@pytest.mark.parametrize("seed", SEEDS, ids=["zeros", "counter", "ones", "repeated"])
def test_both_implementations_derive_the_same_key_from_a_seed(seed):
    """Deterministic keygen is the strongest available cross-check.

    FIPS 203 fixes the expansion from seed to key pair completely, so any
    disagreement here is a genuine standards-conformance bug in one of them.
    """
    kyber_public, _ = KYBER.key_derive(seed)
    theirs = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()

    assert kyber_public == theirs
    assert len(theirs) == ENCAPSULATION_KEY_BYTES


def test_parameter_sizes_match_the_standard():
    private_key = mlkem.MLKEM768PrivateKey.generate()
    shared_secret, ciphertext = private_key.public_key().encapsulate()

    assert len(private_key.public_key().public_bytes_raw()) == ENCAPSULATION_KEY_BYTES
    assert len(ciphertext) == CIPHERTEXT_BYTES
    assert len(shared_secret) == SHARED_SECRET_BYTES
    assert len(private_key.private_bytes_raw()) == SEED_BYTES


def test_our_backend_encapsulates_into_the_reference_implementation():
    seed = os.urandom(SEED_BYTES)
    _, kyber_private = KYBER.key_derive(seed)
    private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)

    shared_secret, ciphertext = private_key.public_key().encapsulate()
    assert KYBER.decaps(kyber_private, ciphertext) == shared_secret


def test_the_reference_implementation_encapsulates_into_our_backend():
    seed = os.urandom(SEED_BYTES)
    kyber_public, _ = KYBER.key_derive(seed)
    private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)

    shared_secret, ciphertext = KYBER.encaps(kyber_public)
    assert private_key.decapsulate(ciphertext) == shared_secret


def test_encapsulate_returns_the_secret_before_the_ciphertext():
    """Regression guard for an argument-order trap.

    `encapsulate()` returns (shared_secret, ciphertext), the reverse of what
    most examples and most generated code assume. Swapping them does not fail
    at the call site -- it fails much later at decapsulation, with a misleading
    "invalid ciphertext" error.
    """
    private_key = mlkem.MLKEM768PrivateKey.generate()
    first, second = private_key.public_key().encapsulate()

    assert len(first) == SHARED_SECRET_BYTES
    assert len(second) == CIPHERTEXT_BYTES
    assert private_key.decapsulate(second) == first


def test_encapsulation_key_coefficients_enforce_the_fips_203_modulus_boundary():
    """FIPS 203 encoding accepts q-1 and rejects coefficients at or above q."""
    raw = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()

    def with_first_coefficient(value):
        changed = bytearray(raw)
        changed[0] = value & 0xFF
        changed[1] = (changed[1] & 0xF0) | ((value >> 8) & 0x0F)
        return bytes(changed)

    mlkem.MLKEM768PublicKey.from_public_bytes(with_first_coefficient(3328))
    for invalid in (3329, 3500, 4095):
        with pytest.raises(ValueError):
            mlkem.MLKEM768PublicKey.from_public_bytes(with_first_coefficient(invalid))


def test_corrupted_ciphertexts_are_implicitly_rejected_identically():
    """FIPS 203 mandates implicit rejection, and both agree on the result.

    This is the single most important behavioural fact about ML-KEM for
    protocol design: decapsulating a corrupted ciphertext does NOT raise. It
    returns a deterministic pseudo-random secret derived from the private key.
    A protocol that treats "decapsulation succeeded" as "the peer is genuine"
    is therefore broken by construction; only the AEAD tag over a
    transcript-bound key establishes that, which is what our suite relies on.
    """
    seed = os.urandom(SEED_BYTES)
    _, kyber_private = KYBER.key_derive(seed)
    private_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)

    shared_secret, ciphertext = private_key.public_key().encapsulate()
    corrupted = bytearray(ciphertext)
    corrupted[0] ^= 0xFF
    corrupted = bytes(corrupted)

    ours = private_key.decapsulate(corrupted)
    theirs = KYBER.decaps(kyber_private, corrupted)

    assert ours != shared_secret
    assert len(ours) == SHARED_SECRET_BYTES
    assert ours == theirs


def test_a_wrong_length_ciphertext_is_rejected_outright():
    """A length check is legitimate and distinct from implicit rejection."""
    private_key = mlkem.MLKEM768PrivateKey.generate()
    _, ciphertext = private_key.public_key().encapsulate()

    with pytest.raises(ValueError):
        private_key.decapsulate(ciphertext[:-1])
