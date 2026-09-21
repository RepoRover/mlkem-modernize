"""The two handshakes of the legacy baseline.

The hops are deliberately NOT the same, and the difference is the whole point:

  hop 1  device -> gateway   STATIC-STATIC ECDH P-256
      Both peers use their long-term ECDH key. Identity is implicit: only the
      real device holds a private key that produces the expected shared secret,
      so a forged client fails at the first AEAD open rather than at handshake
      time. This is what a lot of real, non-upgradeable firmware actually does.
      It has NO forward secrecy -- every session on this hop derives from the
      same Z -- and the ServerHello is unauthenticated. Intentional legacy cruft.

  hop 2  gateway -> cloud    EPHEMERAL-EPHEMERAL ECDH P-256 + mutual ECDSA
      Both peers contribute a fresh ephemeral key and sign the transcript with
      a long-term ECDSA key, so both are explicitly authenticated and the hop
      has full forward secrecy. The KDF binds the complete transcript.
      This is the clean classical baseline that ML-KEM-768 gets added to, so
      the before/after measurement isolates the cost of the KEM and nothing else.

KDF transcript binding differs by hop ON PURPOSE:
  hop 1 binds only the two handshake nonces (info is a fixed label). The public
        keys are NOT in the transcript. This is a real and common legacy
        shortcut, and it is one of the weaknesses the PQC rebuild fixes.
  hop 2 binds protocol, hop label, both ephemeral public keys and both nonces.

See docs/ARCHITECTURE.md for the wire format and docs/DECISIONS.md for why.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import cryptoutil as cu
from .suites import SUITE_CLASSICAL, SUITE_HYBRID, canonical_suites
from .wire import (
    DIR_CLIENT_TO_SERVER,
    DIR_SERVER_TO_CLIENT,
    HOP_DEVICE_GATEWAY,
    HOP_GATEWAY_CLOUD,
    PROTOCOL,
    PROTOCOL_V2,
    lp,
    s,
)


class HandshakeError(Exception):
    """Handshake could not be completed. Never carries key material in its text."""


@dataclass(frozen=True)
class DerivedSession:
    """Output of a hop 1 handshake: ONE key, used in ONE direction.

    Hop 1 is strictly one-way encrypted: the device encrypts readings to the
    gateway and the gateway answers in plaintext. There is therefore no second
    direction that could reuse this (key, nonce_prefix) pair.

    That is enforced, not merely hoped for: the gateway never constructs an
    AeadSender for hop 1, and `tests/test_pqc.py::test_hop1_is_strictly_one_way`
    asserts the responses are plaintext. If encrypted responses are ever added
    to hop 1, this type must become a DirectionalSession first -- reusing this
    key with the same nonce prefix in the other direction would repeat
    (key, nonce) pairs and break AES-GCM catastrophically.
    """

    session_id: bytes
    nonce_prefix: bytes
    key: bytes

    def __repr__(self) -> str:  # pragma: no cover - defensive
        # Make it impossible to leak the session key into a log line by accident.
        return f"DerivedSession(session_id={self.session_id.hex()}, key=<redacted>)"


@dataclass(frozen=True)
class DirectionalSession:
    """Output of a hop 2 v2 handshake: a SEPARATE key per direction.

    Both directions share a session id and nonce prefix, so if they also shared
    a key then message N from the gateway and message N from the cloud would use
    the same (key, nonce) pair -- the one thing AES-GCM must never do. Deriving
    two keys from the same HKDF input with different direction labels removes
    the possibility entirely, rather than relying on the channel staying
    one-way by convention.

    Only `key_c2s` carries data today; responses are still plaintext (W5).
    `key_s2c` is derived anyway so that adding encrypted responses later cannot
    accidentally reuse the sending key.
    """

    session_id: bytes
    nonce_prefix: bytes
    key_c2s: bytes  # gateway -> cloud
    key_s2c: bytes  # cloud -> gateway
    suite: str

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (
            f"DirectionalSession(session_id={self.session_id.hex()}, "
            f"suite={self.suite}, keys=<redacted>)"
        )


# --------------------------------------------------------------------------
# hop 1: device -> gateway  (static-static ECDH, no forward secrecy)
# --------------------------------------------------------------------------


def hop1_derive(
    own_static_private: cu.ec.EllipticCurvePrivateKey,
    peer_static_public: cu.ec.EllipticCurvePublicKey,
    client_nonce: bytes,
    server_nonce: bytes,
    session_id: bytes,
    nonce_prefix: bytes,
) -> DerivedSession:
    """Both sides run this and MUST arrive at the same key.

    Z is identical for every session between this device and this gateway --
    only the HKDF salt varies. If both nonces ever repeated, the session key
    would repeat too, and since the AEAD counter restarts at 0 that would be a
    catastrophic (key, nonce) reuse. 16 random bytes per side makes that
    negligible in practice, but the design is structurally fragile.
    """
    z = cu.ecdh(own_static_private, peer_static_public)

    # Weak by design: the label does not cover the peers' public keys.
    info = lp(s(PROTOCOL), s(HOP_DEVICE_GATEWAY))
    key = cu.hkdf_sha256(ikm=z, salt=client_nonce + server_nonce, info=info)

    return DerivedSession(session_id=session_id, nonce_prefix=nonce_prefix, key=key)


# --------------------------------------------------------------------------
# hop 2: gateway -> cloud  (ephemeral ECDHE + mutual ECDSA)
# --------------------------------------------------------------------------


def hop2_client_transcript(client_id: str, client_nonce: bytes, client_eph_pub: bytes) -> bytes:
    """Bytes the gateway signs in its ClientHello."""
    return lp(
        s(PROTOCOL),
        s(HOP_GATEWAY_CLOUD),
        s("client-hello"),
        s(client_id),
        client_nonce,
        client_eph_pub,
    )


def hop2_server_transcript(
    client_id: str,
    client_nonce: bytes,
    client_eph_pub: bytes,
    session_id: bytes,
    server_nonce: bytes,
    server_eph_pub: bytes,
    nonce_prefix: bytes,
    expires_at: str,
    max_records: int,
) -> bytes:
    """Bytes the cloud signs in its ServerHello.

    This covers the client's contribution as well, so the signature authenticates
    the server AND binds it to this specific exchange -- a captured ServerHello
    cannot be replayed into a different session.
    """
    return lp(
        s(PROTOCOL),
        s(HOP_GATEWAY_CLOUD),
        s("server-hello"),
        s(client_id),
        client_nonce,
        client_eph_pub,
        session_id,
        server_nonce,
        server_eph_pub,
        nonce_prefix,
        s(expires_at),
        s(str(max_records)),
    )


def hop2_derive(
    own_ephemeral_private: cu.ec.EllipticCurvePrivateKey,
    peer_ephemeral_public: cu.ec.EllipticCurvePublicKey,
    client_nonce: bytes,
    server_nonce: bytes,
    client_eph_pub: bytes,
    server_eph_pub: bytes,
    session_id: bytes,
    nonce_prefix: bytes,
) -> DerivedSession:
    """Both sides run this and MUST arrive at the same key.

    Full transcript binding: both ephemeral public keys and both nonces are in
    the HKDF info, so the derived key commits to every value that was exchanged.

    THIS is the function the PQC migration changes. The hybrid version becomes
        ikm  = Z_x25519 || ss_mlkem768
        info = ... || mlkem_ciphertext || mlkem_public_key
    and nothing else in the system has to move.
    """
    z = cu.ecdh(own_ephemeral_private, peer_ephemeral_public)

    info = lp(
        s(PROTOCOL),
        s(HOP_GATEWAY_CLOUD),
        client_eph_pub,
        server_eph_pub,
        client_nonce,
        server_nonce,
    )
    key = cu.hkdf_sha256(ikm=z, salt=client_nonce + server_nonce, info=info)

    return DerivedSession(session_id=session_id, nonce_prefix=nonce_prefix, key=key)


# --------------------------------------------------------------------------
# hop 2 v2: suite negotiation + hybrid X25519 + ML-KEM-768
# --------------------------------------------------------------------------
#
# Message flow (one round trip, no extra trip for negotiation):
#
#   gateway -> cloud   ClientHello   offered_suites + a key share per suite,
#                                    signed with the gateway's long-term ECDSA key
#   cloud   -> gateway ServerHello   selected_suite + the matching key share
#                                    (for hybrid: the ML-KEM ciphertext),
#                                    signed over the FULL transcript
#
# The gateway generates the ML-KEM keypair and the cloud encapsulates to it,
# matching TLS 1.3's direction for key_share.


@dataclass(frozen=True)
class KeyShare:
    """A peer's public key material for one suite. Absent parts are b"".

    Carried verbatim into the transcript, so an absent part contributes a
    zero-length field rather than being skipped -- otherwise a hybrid share and
    a classical share could produce the same transcript bytes.
    """

    x25519_pub: bytes = b""
    mlkem768_ek: bytes = b""
    p256_pub: bytes = b""


def _share_fields(share: KeyShare) -> tuple[bytes, bytes, bytes]:
    return (share.x25519_pub, share.mlkem768_ek, share.p256_pub)


def hop2_v2_client_transcript(
    client_id: str,
    client_nonce: bytes,
    offered_suites: tuple[str, ...] | list[str],
    shares: dict[str, KeyShare],
) -> bytes:
    """Bytes the gateway signs in its v2 ClientHello.

    Covers the whole offer -- every suite name AND every key share. An attacker
    who strips `hybrid-x25519-mlkem768` from the list, or swaps a key share,
    changes these bytes and the cloud's signature check fails. This is the first
    of the three downgrade defences (signature, KDF binding, policy).
    """
    parts: list[bytes] = [
        s(PROTOCOL_V2),
        s(HOP_GATEWAY_CLOUD),
        s("client-hello"),
        s(client_id),
        client_nonce,
        s(canonical_suites(list(offered_suites))),
    ]
    # Iterate the offered order, not dict order, so the transcript is stable.
    for suite in offered_suites:
        share = shares.get(suite, KeyShare())
        parts.append(s(suite))
        parts.extend(_share_fields(share))
    return lp(*parts)


def hop2_v2_server_transcript(
    client_id: str,
    client_nonce: bytes,
    offered_suites: tuple[str, ...] | list[str],
    client_shares: dict[str, KeyShare],
    selected_suite: str,
    session_id: bytes,
    server_nonce: bytes,
    server_share: KeyShare,
    mlkem768_ct: bytes,
    nonce_prefix: bytes,
    expires_at: str,
    max_records: int,
) -> bytes:
    """Bytes the cloud signs in its v2 ServerHello.

    Deliberately re-includes the client's entire offer. That is what makes a
    downgrade detectable: the gateway verifies this signature against the offer
    it actually sent, so a man-in-the-middle who removed the hybrid suite on the
    way out cannot produce a ServerHello the gateway will accept.

    It also binds session_id, nonce_prefix and the expiry, so a captured
    ServerHello cannot be replayed into a different session.
    """
    parts: list[bytes] = [
        s(PROTOCOL_V2),
        s(HOP_GATEWAY_CLOUD),
        s("server-hello"),
        s(client_id),
        client_nonce,
        s(canonical_suites(list(offered_suites))),
    ]
    for suite in offered_suites:
        share = client_shares.get(suite, KeyShare())
        parts.append(s(suite))
        parts.extend(_share_fields(share))
    parts.extend(
        [
            s(selected_suite),
            session_id,
            server_nonce,
            *_share_fields(server_share),
            mlkem768_ct,
            nonce_prefix,
            s(expires_at),
            s(str(max_records)),
        ]
    )
    return lp(*parts)


def _hop2_v2_info_base(
    selected_suite: str,
    client_id: str,
    offered_suites: tuple[str, ...] | list[str],
    client_nonce: bytes,
    server_nonce: bytes,
    client_share: KeyShare,
    server_share: KeyShare,
    mlkem768_ct: bytes,
) -> bytes:
    """Shared HKDF info for both directions.

    Binds everything that was negotiated: the selected suite, the FULL offer
    list, both nonces, both key shares and the ML-KEM ciphertext. CLAUDE.md
    requires both public keys and the ciphertext to be in the transcript; the
    offer list is the extra binding that makes a downgrade change the key.
    """
    return lp(
        s(PROTOCOL_V2),
        s(HOP_GATEWAY_CLOUD),
        s(selected_suite),
        s(client_id),
        s(canonical_suites(list(offered_suites))),
        client_nonce,
        server_nonce,
        *_share_fields(client_share),
        *_share_fields(server_share),
        mlkem768_ct,
    )


def hop2_v2_derive(
    selected_suite: str,
    ss_mlkem768: bytes,
    ss_classical: bytes,
    client_id: str,
    offered_suites: tuple[str, ...] | list[str],
    client_nonce: bytes,
    server_nonce: bytes,
    client_share: KeyShare,
    server_share: KeyShare,
    mlkem768_ct: bytes,
    session_id: bytes,
    nonce_prefix: bytes,
) -> DirectionalSession:
    """Derive the per-direction session keys. Both sides run this identically.

    The combiner is concatenation into HKDF, with the ML-KEM secret FIRST:

        IKM = ss_mlkem768 ‖ ss_x25519          (hybrid)
        IKM = ss_p256                          (classical fallback)

    ML-KEM goes first because NIST SP 800-56C Rev2 permits HKDF over two shared
    secrets provided the FIPS-approved one leads. TLS's X25519MLKEM768 orders it
    the same way, so we match a construction that has had real scrutiny rather
    than inventing our own.

    The security claim: the hybrid key is safe if EITHER ML-KEM or X25519 holds.
    A classical attacker must break ML-KEM; a quantum attacker must break
    X25519 *and* ML-KEM, and only ML-KEM is believed to resist them.

    Per-direction keys come from the same IKM with different direction labels
    appended to the info, so the two directions can share a nonce prefix without
    ever repeating a (key, nonce) pair.
    """
    if selected_suite == SUITE_HYBRID:
        if len(ss_mlkem768) != cu.MLKEM768_SS_LEN:
            raise HandshakeError("ML-KEM shared secret has the wrong length")
        if len(ss_classical) != cu.X25519_SHARED_LEN:
            raise HandshakeError("X25519 shared secret has the wrong length")
        ikm = ss_mlkem768 + ss_classical
    elif selected_suite == SUITE_CLASSICAL:
        if ss_mlkem768:
            raise HandshakeError("classical suite must not carry an ML-KEM secret")
        if len(ss_classical) != cu.SHARED_SECRET_LEN:
            raise HandshakeError("P-256 shared secret has the wrong length")
        ikm = ss_classical
    else:
        raise HandshakeError(f"unknown suite {selected_suite!r}")

    info_base = _hop2_v2_info_base(
        selected_suite=selected_suite,
        client_id=client_id,
        offered_suites=offered_suites,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        client_share=client_share,
        server_share=server_share,
        mlkem768_ct=mlkem768_ct,
    )
    salt = client_nonce + server_nonce

    return DirectionalSession(
        session_id=session_id,
        nonce_prefix=nonce_prefix,
        key_c2s=cu.hkdf_sha256(
            ikm=ikm, salt=salt, info=info_base + lp(s(DIR_CLIENT_TO_SERVER))
        ),
        key_s2c=cu.hkdf_sha256(
            ikm=ikm, salt=salt, info=info_base + lp(s(DIR_SERVER_TO_CLIENT))
        ),
        suite=selected_suite,
    )
