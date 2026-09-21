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
from .wire import HOP_DEVICE_GATEWAY, HOP_GATEWAY_CLOUD, PROTOCOL, lp, s


class HandshakeError(Exception):
    """Handshake could not be completed. Never carries key material in its text."""


@dataclass(frozen=True)
class DerivedSession:
    """Output of a completed handshake, for either hop."""

    session_id: bytes
    nonce_prefix: bytes
    key: bytes

    def __repr__(self) -> str:  # pragma: no cover - defensive
        # Make it impossible to leak the session key into a log line by accident.
        return f"DerivedSession(session_id={self.session_id.hex()}, key=<redacted>)"


# --------------------------------------------------------------------------
# hop 1: device -> gateway  (static-static ECDH, no forward secrecy)
# --------------------------------------------------------------------------


def hop1_derive(
    own_static_private: "cu.ec.EllipticCurvePrivateKey",
    peer_static_public: "cu.ec.EllipticCurvePublicKey",
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
    own_ephemeral_private: "cu.ec.EllipticCurvePrivateKey",
    peer_ephemeral_public: "cu.ec.EllipticCurvePublicKey",
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
