"""Hybrid post-quantum key establishment on hop 2.

Covers the six behaviours the design has to get right:

  1. hybrid handshake succeeds and actually carries data
  2. a tampered ML-KEM ciphertext surfaces as an AEAD TAG FAILURE, not an
     exception (FIPS 203 implicit rejection)
  3. version / suite negotiation
  4. a forced downgrade is refused when policy forbids it
  5. key rotation -- fresh ML-KEM keys every handshake
  6. per-direction key separation
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from services.cloud.main import create_app as create_cloud_app
from services.common import cryptoutil as cu
from services.common.handshake import (
    HandshakeError,
    KeyShare,
    hop2_v2_client_transcript,
    hop2_v2_derive,
    hop2_v2_server_transcript,
)
from services.common.suites import (
    SUITE_CLASSICAL,
    SUITE_HYBRID,
    DowngradeRefused,
    NoCommonSuite,
    Policy,
    canonical_suites,
    client_offer,
    is_post_quantum,
    negotiate,
)
from services.common.wire import PROTOCOL, PROTOCOL_V2, b64d, b64e
from services.gateway.cloud_client import CloudClient, DowngradeRejected
from services.gateway.main import create_app as create_gateway_app

log = logging.getLogger("test")
GATEWAY_ID = "gw-01"


# ------------------------------------------------------------------ helpers


def build_cloud(keys_dir: Path, policy: Policy = Policy.REQUIRE, **kwargs) -> TestClient:
    app = create_cloud_app(
        keys_dir=str(keys_dir), db_path=":memory:", policy=policy, **kwargs
    )
    return TestClient(app, base_url="http://cloud")


def build_client(
    keys_dir: Path, cloud_http: TestClient, policy: Policy = Policy.PREFER
) -> CloudClient:
    return CloudClient(
        base_url="http://cloud",
        gateway_id=GATEWAY_ID,
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=log,
        http_client=cloud_http,
        policy=policy,
    )


def envelope(date: str = "2024-01-01") -> dict:
    return {
        "gateway_id": GATEWAY_ID,
        "device_id": "device-berlin-01",
        "reading": {
            "date": date, "temp_max_c": 7.4, "temp_min_c": 3.4,
            "precip_mm": 1.8, "wind_max_kmh": 19.7,
        },
        "received_at": "2026-09-21T10:00:02Z",
        "device_hop": {"verified": True, "suite": "ECDH-P256-static-static+AES-256-GCM"},
    }


class RawHybridClient:
    """Hand-driven v2 client, so individual fields can be corrupted.

    Keeps the ML-KEM private key around so tests can decapsulate a tampered
    ciphertext themselves.
    """

    def __init__(self, cloud_http: TestClient, keys_dir: Path,
                 offered=(SUITE_HYBRID, SUITE_CLASSICAL)):
        self.http = cloud_http
        self.keys_dir = keys_dir
        self.offered = list(offered)

        self.x_priv = cu.generate_x25519_private_key()
        self.x_pub = cu.x25519_public_bytes(self.x_priv.public_key())
        self.kem_priv = cu.generate_mlkem768_private_key()
        self.ek = cu.mlkem768_encapsulation_key_bytes(self.kem_priv)
        self.p256_priv = cu.generate_private_key()
        self.p256_pub = cu.public_key_to_bytes(self.p256_priv.public_key())

        self.shares: dict[str, KeyShare] = {}
        wire_shares: dict[str, dict] = {}
        for suite in self.offered:
            if suite == SUITE_HYBRID:
                self.shares[suite] = KeyShare(x25519_pub=self.x_pub, mlkem768_ek=self.ek)
                wire_shares[suite] = {
                    "x25519_pub": b64e(self.x_pub), "mlkem768_ek": b64e(self.ek)
                }
            else:
                self.shares[suite] = KeyShare(p256_pub=self.p256_pub)
                wire_shares[suite] = {"eph_pub": b64e(self.p256_pub)}

        self.nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        self.signing_key = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
        self.hello = {
            "protocol": PROTOCOL_V2,
            "hop": "gateway-cloud",
            "client_id": GATEWAY_ID,
            "client_nonce": b64e(self.nonce),
            "offered_suites": self.offered,
            "key_shares": wire_shares,
            "sig": b64e(cu.sign(self.signing_key, hop2_v2_client_transcript(
                GATEWAY_ID, self.nonce, self.offered, self.shares))),
        }

    def send_hello(self):
        return self.http.post("/handshake", json=self.hello)

    def complete(self, response_body: dict, mlkem_ct_override: bytes | None = None):
        """Derive session keys from a ServerHello, optionally with a bad ct."""
        selected = response_body["selected_suite"]
        server_nonce = b64d(response_body["server_nonce"])
        session_id = b64d(response_body["session_id"])
        prefix = b64d(response_body["nonce_prefix"])

        if selected == SUITE_HYBRID:
            server_share = KeyShare(x25519_pub=b64d(response_body["x25519_pub"]))
            real_ct = b64d(response_body["mlkem768_ct"])
            ct_for_decap = mlkem_ct_override if mlkem_ct_override is not None else real_ct
            ss_mlkem = cu.mlkem768_decapsulate(self.kem_priv, ct_for_decap)
            ss_classical = cu.x25519_exchange(
                self.x_priv, cu.x25519_public_from_bytes(server_share.x25519_pub)
            )
            # The transcript always carries the ciphertext the cloud actually
            # sent; only the decapsulated secret differs.
            ct_in_transcript = real_ct
        else:
            server_share = KeyShare(p256_pub=b64d(response_body["eph_pub"]))
            ss_mlkem = b""
            ss_classical = cu.ecdh(
                self.p256_priv, cu.public_key_from_bytes(server_share.p256_pub)
            )
            ct_in_transcript = b""

        return hop2_v2_derive(
            selected_suite=selected,
            ss_mlkem768=ss_mlkem,
            ss_classical=ss_classical,
            client_id=GATEWAY_ID,
            offered_suites=self.offered,
            client_nonce=self.nonce,
            server_nonce=server_nonce,
            client_share=self.shares[selected],
            server_share=server_share,
            mlkem768_ct=ct_in_transcript,
            session_id=session_id,
            nonce_prefix=prefix,
        )


# =========================================================================
# 1. hybrid handshake success
# =========================================================================


def test_hybrid_handshake_succeeds_and_carries_data(keys_dir: Path):
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)

    result = client.send(envelope())

    assert result["status"] == "accepted"
    assert client.suite == SUITE_HYBRID
    assert client.handshakes_hybrid == 1
    assert client.handshakes_classical == 0

    stats = cloud_http.get("/stats").json()
    assert stats["pqc"]["handshakes_hybrid"] == 1
    assert stats["pqc"]["handshakes_classical"] == 0
    assert stats["pqc"]["pqc_fraction"] == 1.0
    assert cloud_http.get("/readings").json()["count"] == 1

    client.close()
    cloud_http.close()


def test_hybrid_key_is_agreed_by_both_sides():
    """Both peers must derive the same keys from a hybrid exchange."""
    client_x = cu.generate_x25519_private_key()
    server_x = cu.generate_x25519_private_key()
    kem = cu.generate_mlkem768_private_key()
    ek = cu.mlkem768_encapsulation_key_bytes(kem)

    ss_enc, ct = cu.mlkem768_encapsulate(cu.mlkem768_encapsulation_key_from_bytes(ek))
    ss_dec = cu.mlkem768_decapsulate(kem, ct)
    assert ss_enc == ss_dec

    client_x_pub = cu.x25519_public_bytes(client_x.public_key())
    server_x_pub = cu.x25519_public_bytes(server_x.public_key())
    shared_client = cu.x25519_exchange(client_x, cu.x25519_public_from_bytes(server_x_pub))
    shared_server = cu.x25519_exchange(server_x, cu.x25519_public_from_bytes(client_x_pub))
    assert shared_client == shared_server

    common: dict[str, Any] = dict(
        selected_suite=SUITE_HYBRID, client_id=GATEWAY_ID,
        offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(x25519_pub=client_x_pub, mlkem768_ek=ek),
        server_share=KeyShare(x25519_pub=server_x_pub),
        mlkem768_ct=ct,
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    a = hop2_v2_derive(ss_mlkem768=ss_enc, ss_classical=shared_server, **common)
    b = hop2_v2_derive(ss_mlkem768=ss_dec, ss_classical=shared_client, **common)

    assert a.key_c2s == b.key_c2s
    assert a.key_s2c == b.key_s2c
    assert a.suite == SUITE_HYBRID


def test_hybrid_ikm_puts_mlkem_first():
    """SP 800-56C Rev2 requires the FIPS-approved secret to lead.

    Swapping the two halves must produce a different key, which is what proves
    the order is actually part of the construction rather than incidental.
    """
    ss_mlkem = cu.random_bytes(32)
    ss_x = cu.random_bytes(32)
    common: dict[str, Any] = dict(
        selected_suite=SUITE_HYBRID, client_id=GATEWAY_ID,
        offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
        server_share=KeyShare(x25519_pub=b"s" * 32),
        mlkem768_ct=b"t" * 1088,
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    normal = hop2_v2_derive(ss_mlkem768=ss_mlkem, ss_classical=ss_x, **common)
    swapped = hop2_v2_derive(ss_mlkem768=ss_x, ss_classical=ss_mlkem, **common)
    assert normal.key_c2s != swapped.key_c2s


def test_hybrid_is_safe_if_either_component_holds():
    """Changing EITHER half changes the key -- an attacker must break both."""
    base: dict[str, Any] = dict(
        selected_suite=SUITE_HYBRID, client_id=GATEWAY_ID,
        offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
        server_share=KeyShare(x25519_pub=b"s" * 32),
        mlkem768_ct=b"t" * 1088,
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    ss_mlkem, ss_x = cu.random_bytes(32), cu.random_bytes(32)
    reference = hop2_v2_derive(ss_mlkem768=ss_mlkem, ss_classical=ss_x, **base)

    only_mlkem_known = hop2_v2_derive(
        ss_mlkem768=ss_mlkem, ss_classical=cu.random_bytes(32), **base)
    only_x_known = hop2_v2_derive(
        ss_mlkem768=cu.random_bytes(32), ss_classical=ss_x, **base)

    assert reference.key_c2s != only_mlkem_known.key_c2s
    assert reference.key_c2s != only_x_known.key_c2s


# =========================================================================
# 2. tampered ML-KEM ciphertext -> AEAD tag failure, NOT an exception
# =========================================================================


def test_mlkem_decapsulation_implicitly_rejects_rather_than_raising():
    """FIPS 203 s7.3: a tampered ciphertext yields a pseudorandom secret.

    Decapsulation MUST NOT raise -- distinguishing valid from invalid
    ciphertexts is exactly what would break IND-CCA security. Code or tests
    that expect an exception here are wrong.
    """
    kem = cu.generate_mlkem768_private_key()
    ss, ct = cu.mlkem768_encapsulate(kem.public_key())

    for position in (0, 543, len(ct) - 1):
        bad = bytearray(ct)
        bad[position] ^= 0x01
        recovered = cu.mlkem768_decapsulate(kem, bytes(bad))  # must not raise
        assert len(recovered) == cu.MLKEM768_SS_LEN
        assert recovered != ss


def test_tampered_mlkem_ciphertext_in_transit_fails_the_signature_first(keys_dir: Path):
    """In the real protocol the ServerHello signature catches it before decapsulation.

    The cloud signs the ML-KEM ciphertext as part of the transcript, so an
    attacker flipping a bit in flight invalidates the signature. The gateway
    therefore aborts at verification and never derives a key at all.

    This is the OUTER defence. The test below covers the inner one, for the
    case where an attacker can produce a valid signature.
    """
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)

    real_post = cloud_http.post

    def tampering_post(url, **kwargs):
        response = real_post(url, **kwargs)
        if url.endswith("/handshake") and response.status_code == 200:
            body = response.json()
            ct = b64d(body["mlkem768_ct"])
            body["mlkem768_ct"] = b64e(bytes([ct[0] ^ 0x01]) + ct[1:])
            response._content = json.dumps(body).encode()
        return response

    cloud_http.post = tampering_post  # type: ignore[method-assign]
    with pytest.raises(HandshakeError, match="signature did not verify"):
        client.handshake()

    cloud_http.post = real_post  # type: ignore[method-assign]
    client.close()
    cloud_http.close()


def test_tampered_mlkem_ciphertext_causes_aead_tag_failure(keys_dir: Path):
    """The INNER defence: a key mismatch surfaces at the AEAD, not as an exception.

    This is the headline test for the ML-KEM integration. It deliberately
    bypasses the ServerHello signature (which would catch the tampering first,
    see the test above) to isolate what ML-KEM itself does: decapsulating a
    corrupted ciphertext succeeds and returns a *different* pseudorandom
    secret. The mismatch only becomes visible when the cloud cannot
    authenticate the first record.

    Defence in depth matters here because the signature is ECDSA, which a
    future quantum attacker can forge. If that outer layer falls, this inner
    one still prevents a tampered ciphertext from producing a usable session.
    """
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])

    response = raw.send_hello()
    assert response.status_code == 200
    body = response.json()
    assert body["selected_suite"] == SUITE_HYBRID

    real_ct = b64d(body["mlkem768_ct"])
    tampered_ct = bytes([real_ct[0] ^ 0x01]) + real_ct[1:]

    # Decapsulating the tampered ciphertext does NOT raise ...
    session = raw.complete(body, mlkem_ct_override=tampered_ct)
    good_session = raw.complete(body)

    # ... it silently yields a different key.
    assert session.key_c2s != good_session.key_c2s

    # And the failure appears as a rejected message with reason 'bad_tag'.
    sender = cu.AeadSender(session.key_c2s, session.session_id, session.nonce_prefix)
    seq, nonce, ct = sender.encrypt(json.dumps(envelope()).encode())
    result = cloud_http.post("/ingest", json={
        "session_id": b64e(session.session_id), "seq": seq,
        "nonce": b64e(nonce), "ct": b64e(ct),
    })

    assert result.status_code == 400
    assert result.json()["reason"] == "bad_tag"
    assert cloud_http.get("/readings").json()["count"] == 0
    cloud_http.close()


def test_wrong_length_mlkem_ciphertext_does_raise():
    """Length is structural, so it is checked rather than implicitly rejected."""
    kem = cu.generate_mlkem768_private_key()
    _, ct = cu.mlkem768_encapsulate(kem.public_key())

    for bad in (ct[:-1], ct + b"\x00", b"", b"\x00" * 32):
        with pytest.raises(ValueError, match="1088 bytes"):
            cu.mlkem768_decapsulate(kem, bad)


# =========================================================================
# invalid encapsulation key (FIPS 203 input validation)
# =========================================================================


def test_all_zero_encapsulation_key_is_accepted():
    """A zero key is a VALID encoding: every coefficient is 0, which is < q.

    Recorded explicitly because an earlier probe wrongly treated this as the
    test for input validation. See docs/DECISIONS.md.
    """
    key = cu.mlkem768_encapsulation_key_from_bytes(b"\x00" * cu.MLKEM768_EK_LEN)
    shared, ct = cu.mlkem768_encapsulate(key)
    assert len(shared) == cu.MLKEM768_SS_LEN and len(ct) == cu.MLKEM768_CT_LEN


def test_encapsulation_key_with_coefficient_at_or_above_q_is_rejected():
    """The real FIPS 203 s7.2 modulus check: coefficients must be < q = 3329.

    12-bit coefficients are packed little-endian in pairs:
        c0 = b0 | ((b1 & 0x0F) << 8)
    so writing 3329 into c0 is a one-coefficient violation.
    """
    real = cu.mlkem768_encapsulation_key_bytes(cu.generate_mlkem768_private_key())

    def with_first_coeff(value: int) -> bytes:
        blob = bytearray(real)
        blob[0] = value & 0xFF
        blob[1] = (blob[1] & 0xF0) | ((value >> 8) & 0x0F)
        return bytes(blob)

    # q - 1 is the largest legal coefficient.
    cu.mlkem768_encapsulation_key_from_bytes(with_first_coeff(3328))

    # q itself, and anything above it, must be refused.
    for bad_value in (3329, 3500, 4095):
        with pytest.raises(cu.InvalidEncapsulationKey):
            cu.mlkem768_encapsulation_key_from_bytes(with_first_coeff(bad_value))

    # A whole polynomial section of 0xFF is coefficients of 4095 throughout.
    with pytest.raises(cu.InvalidEncapsulationKey):
        cu.mlkem768_encapsulation_key_from_bytes(b"\xff" * cu.MLKEM768_EK_LEN)


def test_wrong_length_encapsulation_key_is_rejected():
    real = cu.mlkem768_encapsulation_key_bytes(cu.generate_mlkem768_private_key())
    for bad in (real[:-1], real + b"\x00", b"", b"\x00" * 32):
        with pytest.raises(cu.InvalidEncapsulationKey, match="1184 bytes"):
            cu.mlkem768_encapsulation_key_from_bytes(bad)


def test_cloud_rejects_an_invalid_encapsulation_key(keys_dir: Path):
    """End to end: a bad ek is a clean 400, not a crash."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)

    bad_ek = b"\xff" * cu.MLKEM768_EK_LEN
    x_pub = cu.x25519_public_bytes(cu.generate_x25519_private_key().public_key())
    nonce = cu.random_bytes(16)
    offered = [SUITE_HYBRID]
    shares = {SUITE_HYBRID: KeyShare(x25519_pub=x_pub, mlkem768_ek=bad_ek)}
    signing = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")

    response = cloud_http.post("/handshake", json={
        "protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(nonce), "offered_suites": offered,
        "key_shares": {SUITE_HYBRID: {
            "x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(bad_ek)}},
        "sig": b64e(cu.sign(signing, hop2_v2_client_transcript(
            GATEWAY_ID, nonce, offered, shares))),
    })

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_encapsulation_key"
    # Service survives.
    assert cloud_http.get("/health").json()["status"] == "ok"
    cloud_http.close()


# =========================================================================
# 3. version and suite negotiation
# =========================================================================


def test_negotiate_picks_hybrid_when_available():
    for policy in (Policy.REQUIRE, Policy.PREFER):
        assert negotiate([SUITE_HYBRID, SUITE_CLASSICAL], policy) == SUITE_HYBRID
        assert negotiate([SUITE_CLASSICAL, SUITE_HYBRID], policy) == SUITE_HYBRID


def test_negotiate_falls_back_only_under_prefer():
    assert negotiate([SUITE_CLASSICAL], Policy.PREFER) == SUITE_CLASSICAL
    with pytest.raises(DowngradeRefused):
        negotiate([SUITE_CLASSICAL], Policy.REQUIRE)


def test_negotiate_ignores_unknown_suites_for_forward_compatibility():
    """A future peer offering a newer suite must still interoperate."""
    assert negotiate(["hybrid-x25519-mlkem1024", SUITE_HYBRID], Policy.REQUIRE) == SUITE_HYBRID
    with pytest.raises(NoCommonSuite):
        negotiate(["something-nobody-implements"], Policy.PREFER)


def test_negotiate_rejects_a_non_list():
    with pytest.raises(NoCommonSuite):
        negotiate("hybrid-x25519-mlkem768", Policy.PREFER)  # type: ignore[arg-type]


def test_client_offer_depends_on_policy():
    assert client_offer(Policy.REQUIRE) == (SUITE_HYBRID,)
    assert client_offer(Policy.CLASSICAL_ONLY) == (SUITE_CLASSICAL,)
    assert set(client_offer(Policy.PREFER)) == {SUITE_HYBRID, SUITE_CLASSICAL}


def test_policy_parsing_rejects_nonsense():
    assert Policy.parse("require") is Policy.REQUIRE
    assert Policy.parse("  PREFER ") is Policy.PREFER
    assert Policy.parse("classical-only") is Policy.CLASSICAL_ONLY
    with pytest.raises(ValueError, match="invalid PQC policy"):
        Policy.parse("maybe")


def test_cloud_advertises_both_protocol_versions(keys_dir: Path):
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    health = cloud_http.get("/health").json()
    assert PROTOCOL in health["protocols"]
    assert PROTOCOL_V2 in health["protocols"]
    assert health["policy"] == "prefer"
    cloud_http.close()


def test_unknown_protocol_version_is_rejected(keys_dir: Path):
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    response = cloud_http.post("/handshake", json={
        "protocol": "wx-future/99", "hop": "gateway-cloud", "client_id": GATEWAY_ID})
    assert response.status_code == 400
    cloud_http.close()


def test_legacy_v1_gateway_still_works_under_prefer(keys_dir: Path):
    """An un-upgraded gateway must not break the moment the cloud is deployed."""
    from services.common.handshake import hop2_client_transcript

    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    signing = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    nonce = cu.random_bytes(16)
    eph_pub = cu.public_key_to_bytes(cu.generate_private_key().public_key())

    response = cloud_http.post("/handshake", json={
        "protocol": PROTOCOL, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(nonce), "eph_pub": b64e(eph_pub),
        "sig": b64e(cu.sign(signing, hop2_client_transcript(GATEWAY_ID, nonce, eph_pub))),
    })

    assert response.status_code == 200
    assert response.json()["protocol"] == PROTOCOL
    stats = cloud_http.get("/stats").json()
    assert stats["messages"]["handshakes_legacy_v1"] == 1
    assert stats["pqc"]["handshakes_classical"] == 1
    cloud_http.close()


def test_legacy_v1_gateway_is_refused_under_require(keys_dir: Path):
    """The migration's forcing function: v1 peers stop working at phase 2."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)

    response = cloud_http.post("/handshake", json={
        "protocol": PROTOCOL, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(cu.random_bytes(16)),
        "eph_pub": b64e(cu.public_key_to_bytes(cu.generate_private_key().public_key())),
        "sig": b64e(b"whatever"),
    })

    assert response.status_code == 403
    assert response.json()["detail"] == "downgrade_refused"
    assert cloud_http.get("/stats").json()["pqc"]["handshakes_downgrade_refused"] == 1
    cloud_http.close()


# =========================================================================
# 4. forced downgrade is rejected
# =========================================================================


def test_stripping_the_hybrid_suite_breaks_the_signature(keys_dir: Path):
    """An active attacker editing offered_suites in flight is detected.

    The gateway signs its whole offer, so removing the hybrid entry means the
    signature no longer matches the bytes the cloud verifies.
    """
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID, SUITE_CLASSICAL])

    tampered = dict(raw.hello)
    tampered["offered_suites"] = [SUITE_CLASSICAL]          # hybrid stripped
    classical_share = raw.hello["key_shares"][SUITE_CLASSICAL]  # type: ignore[index]
    tampered["key_shares"] = {SUITE_CLASSICAL: classical_share}

    response = cloud_http.post("/handshake", json=tampered)

    assert response.status_code == 403
    assert "signature" in response.json()["detail"].lower()
    # Nothing was negotiated at all.
    assert cloud_http.get("/stats").json()["pqc"]["handshakes_classical"] == 0
    cloud_http.close()


def test_reordering_offered_suites_breaks_the_signature(keys_dir: Path):
    """Order is preference, so it is signed too."""
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID, SUITE_CLASSICAL])

    tampered = dict(raw.hello)
    tampered["offered_suites"] = [SUITE_CLASSICAL, SUITE_HYBRID]

    assert cloud_http.post("/handshake", json=tampered).status_code == 403
    cloud_http.close()


def test_require_policy_refuses_a_classical_only_offer(keys_dir: Path):
    """The policy control, independent of any signature check."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_CLASSICAL])

    response = raw.send_hello()   # correctly signed, genuinely classical-only

    assert response.status_code == 403
    assert response.json()["detail"] == "downgrade_refused"

    stats = cloud_http.get("/stats").json()
    assert stats["pqc"]["handshakes_downgrade_refused"] == 1
    assert stats["pqc"]["handshakes_classical"] == 0
    cloud_http.close()


def test_prefer_policy_allows_classical_but_never_silently(keys_dir: Path, caplog):
    """Fallback is permitted under 'prefer' -- and is logged and counted."""
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_CLASSICAL])

    with caplog.at_level(logging.WARNING):
        response = raw.send_hello()

    assert response.status_code == 200
    assert response.json()["selected_suite"] == SUITE_CLASSICAL

    stats = cloud_http.get("/stats").json()
    assert stats["pqc"]["handshakes_classical"] == 1
    assert stats["pqc"]["pqc_fraction"] == 0.0

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "CLASSICAL" in logged
    cloud_http.close()


def test_gateway_refuses_a_classical_selection_under_require(keys_dir: Path):
    """Client-side enforcement: a signed classical ServerHello is still refused.

    The cloud is on 'prefer' and would happily go classical; the gateway is on
    'require' and will not. Downgrade protection has to work from both ends,
    because either peer may be the one that has been rolled back.
    """
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    client = build_client(keys_dir, cloud_http, Policy.REQUIRE)

    # Force the cloud to have only classical available by making the gateway's
    # offer classical-only at the wire level, while its policy says require.
    from services.common import suites as suites_module

    original = suites_module.client_offer
    try:
        import services.gateway.cloud_client as cc

        cc.client_offer = lambda policy: (SUITE_CLASSICAL,)
        with pytest.raises(DowngradeRejected, match="require"):
            client.handshake()
    finally:
        cc.client_offer = original

    client.close()
    cloud_http.close()


def test_classical_only_policy_is_an_explicit_opt_out(keys_dir: Path, caplog):
    """Turning PQC off must be loud at startup, not a quiet config value."""
    with caplog.at_level(logging.WARNING):
        cloud_http = build_cloud(keys_dir, Policy.CLASSICAL_ONLY)

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "classical-only" in logged
    assert "harvest-now-decrypt-later" in logged

    # And it genuinely refuses hybrid.
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])
    assert raw.send_hello().status_code == 403
    cloud_http.close()


def test_gateway_reports_a_refused_downgrade_actionably(keys_dir: Path):
    """The error must say what happened, not just 'HTTP 403'.

    A gateway rolled back to classical against a require-policy cloud is an
    operational situation someone has to diagnose from a log line.
    """
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    client = build_client(keys_dir, cloud_http, Policy.CLASSICAL_ONLY)

    with pytest.raises(HandshakeError) as exc:
        client.handshake()

    message = str(exc.value)
    assert "classical-only offer" in message
    assert "policy=require on the cloud" in message
    assert SUITE_CLASSICAL in message      # names what we actually offered

    client.close()
    cloud_http.close()


def test_classical_fallback_completes_end_to_end(keys_dir: Path):
    """The classical suite must still work -- it is the Phase 1 fallback."""
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    client = build_client(keys_dir, cloud_http, Policy.CLASSICAL_ONLY)

    result = client.send(envelope())

    assert result["status"] == "accepted"
    assert client.suite == SUITE_CLASSICAL
    assert client.handshakes_classical == 1
    assert client.handshakes_hybrid == 0
    assert cloud_http.get("/readings").json()["count"] == 1
    assert cloud_http.get("/stats").json()["pqc"]["pqc_fraction"] == 0.0

    client.close()
    cloud_http.close()


@pytest.mark.parametrize(
    "corruption",
    [
        {"protocol": "wx-something-else/3"},
        {"session_id": "!!!not base64!!!"},
        {"server_nonce": None},
        {"max_records": "many"},
        {"mlkem768_ct": "!!!"},
    ],
)
def test_malformed_server_hello_is_rejected_by_the_gateway(keys_dir: Path, corruption):
    """A broken or hostile cloud must not produce a half-built session."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)

    real_post = cloud_http.post

    def corrupting_post(url, **kwargs):
        response = real_post(url, **kwargs)
        if url.endswith("/handshake") and response.status_code == 200:
            body = response.json()
            body.update(corruption)
            response._content = json.dumps(body).encode()
        return response

    cloud_http.post = corrupting_post  # type: ignore[method-assign]
    with pytest.raises(HandshakeError):
        client.handshake()
    # No usable session was left behind.
    assert client.suite is None

    cloud_http.post = real_post  # type: ignore[method-assign]
    client.close()
    cloud_http.close()


def test_server_hello_omitting_the_mlkem_ciphertext_is_rejected(keys_dir: Path):
    """Claiming the hybrid suite without supplying a ciphertext must fail."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)

    real_post = cloud_http.post

    def stripping_post(url, **kwargs):
        response = real_post(url, **kwargs)
        if url.endswith("/handshake") and response.status_code == 200:
            body = response.json()
            body.pop("mlkem768_ct", None)
            response._content = json.dumps(body).encode()
        return response

    cloud_http.post = stripping_post  # type: ignore[method-assign]
    with pytest.raises(HandshakeError, match="malformed ServerHello"):
        client.handshake()

    cloud_http.post = real_post  # type: ignore[method-assign]
    client.close()
    cloud_http.close()


def test_cloud_cannot_select_a_suite_that_was_not_offered(keys_dir: Path):
    """Guards the client's own check against a malicious or buggy cloud."""
    cloud_http = build_cloud(keys_dir, Policy.PREFER)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)

    real_post = cloud_http.post

    def lying_post(url, **kwargs):
        response = real_post(url, **kwargs)
        if url.endswith("/handshake") and response.status_code == 200:
            body = response.json()
            body["selected_suite"] = "suite-we-never-offered"
            response._content = json.dumps(body).encode()
        return response

    cloud_http.post = lying_post  # type: ignore[method-assign]
    with pytest.raises(HandshakeError, match="unknown suite"):
        client.handshake()

    cloud_http.post = real_post  # type: ignore[method-assign]
    client.close()
    cloud_http.close()


# =========================================================================
# replayed ServerHello
# =========================================================================


def test_replayed_server_hello_is_rejected(keys_dir: Path):
    """A captured ServerHello cannot be replayed into a fresh handshake.

    The cloud's signature binds the client's nonce and key shares, so a
    ServerHello from an earlier exchange verifies against that exchange's
    transcript and no other.
    """
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)

    first = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])
    captured = first.send_hello().json()

    # A brand new handshake, with fresh nonce and fresh keys.
    second = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])
    response = second.send_hello()
    assert response.status_code == 200

    # Replaying the captured ServerHello at the second client must not verify.
    server_share = KeyShare(x25519_pub=b64d(captured["x25519_pub"]))
    transcript = hop2_v2_server_transcript(
        client_id=GATEWAY_ID,
        client_nonce=second.nonce,                # the NEW client nonce
        offered_suites=second.offered,
        client_shares=second.shares,
        selected_suite=captured["selected_suite"],
        session_id=b64d(captured["session_id"]),
        server_nonce=b64d(captured["server_nonce"]),
        server_share=server_share,
        mlkem768_ct=b64d(captured["mlkem768_ct"]),
        nonce_prefix=b64d(captured["nonce_prefix"]),
        expires_at=captured["expires_at"],
        max_records=int(captured["max_records"]),
    )
    assert not cu.verify(
        cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        b64d(captured["sig"]), transcript,
    )
    cloud_http.close()


def test_replayed_client_hello_is_rejected_by_nonce_table(keys_dir: Path):
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])

    assert raw.send_hello().status_code == 200
    assert raw.send_hello().status_code == 409     # byte-identical replay
    cloud_http.close()


# =========================================================================
# 5. key rotation
# =========================================================================


def test_every_handshake_uses_a_fresh_mlkem_keypair(keys_dir: Path):
    """Reusing an ML-KEM keypair across sessions would forfeit forward secrecy."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)

    encapsulation_keys = set()
    ciphertexts = set()
    for _ in range(5):
        raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])
        body = raw.send_hello().json()
        encapsulation_keys.add(raw.ek)
        ciphertexts.add(b64d(body["mlkem768_ct"]))

    assert len(encapsulation_keys) == 5, "gateway reused an ML-KEM encapsulation key"
    assert len(ciphertexts) == 5, "cloud reused an ML-KEM ciphertext"
    cloud_http.close()


def test_session_keys_rotate_on_the_record_budget(keys_dir: Path):
    """Hitting max_records forces a fresh hybrid handshake, not a key reuse."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE, max_records=2)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)

    for day in range(1, 8):
        result = client.send(envelope(f"2024-01-{day:02d}"))
        assert result["status"] == "accepted"

    # 7 records with a 2-record budget: at least 4 separate sessions.
    assert client.handshakes_hybrid >= 4
    stats = cloud_http.get("/stats").json()
    assert stats["pqc"]["handshakes_hybrid"] >= 4
    assert stats["pqc"]["pqc_fraction"] == 1.0
    assert stats["storage"]["total"] == 7

    client.close()
    cloud_http.close()


def test_rotated_sessions_use_different_keys(keys_dir: Path):
    """Two handshakes in a row must not produce the same session key."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)

    derived = []
    for _ in range(3):
        raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])
        derived.append(raw.complete(raw.send_hello().json()))

    keys = {d.key_c2s for d in derived}
    assert len(keys) == 3
    assert len({d.session_id for d in derived}) == 3
    assert len({d.nonce_prefix for d in derived}) == 3
    cloud_http.close()


def test_ephemeral_keys_are_discarded_after_the_handshake(keys_dir: Path):
    """The client must not retain ML-KEM/X25519 private keys past the handshake.

    They are locals inside handshake(); this asserts they were never stashed on
    the instance, which is what forward secrecy depends on.
    """
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    client = build_client(keys_dir, cloud_http, Policy.PREFER)
    client.handshake()

    leaked = [
        name for name, value in vars(client).items()
        if "mlkem" in name.lower() or "x25519" in name.lower() or "eph" in name.lower()
    ]
    assert leaked == [], f"ephemeral key material retained on the client: {leaked}"

    client.close()
    cloud_http.close()


# =========================================================================
# 6. per-direction key separation
# =========================================================================


def test_directions_derive_different_keys():
    """Same secret, same nonce prefix -- the keys MUST differ.

    Both directions share a session id and nonce prefix, so identical keys
    would mean message N in each direction reused the same (key, nonce) pair.
    For AES-GCM that is catastrophic: it leaks the XOR of the plaintexts and
    the authentication key.
    """
    session = hop2_v2_derive(
        selected_suite=SUITE_HYBRID,
        ss_mlkem768=cu.random_bytes(32),
        ss_classical=cu.random_bytes(32),
        client_id=GATEWAY_ID,
        offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16),
        server_nonce=cu.random_bytes(16),
        client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
        server_share=KeyShare(x25519_pub=b"s" * 32),
        mlkem768_ct=b"t" * 1088,
        session_id=cu.random_bytes(16),
        nonce_prefix=cu.random_bytes(4),
    )

    assert session.key_c2s != session.key_s2c
    assert len(session.key_c2s) == 32 and len(session.key_s2c) == 32


def test_direction_separation_holds_for_the_classical_suite():
    session = hop2_v2_derive(
        selected_suite=SUITE_CLASSICAL,
        ss_mlkem768=b"",
        ss_classical=cu.random_bytes(32),
        client_id=GATEWAY_ID,
        offered_suites=[SUITE_CLASSICAL],
        client_nonce=cu.random_bytes(16),
        server_nonce=cu.random_bytes(16),
        client_share=KeyShare(p256_pub=b"c" * 65),
        server_share=KeyShare(p256_pub=b"s" * 65),
        mlkem768_ct=b"",
        session_id=cu.random_bytes(16),
        nonce_prefix=cu.random_bytes(4),
    )
    assert session.key_c2s != session.key_s2c


def test_a_message_sent_on_the_wrong_direction_key_fails(keys_dir: Path):
    """Encrypting with key_s2c and sending client->server must be rejected."""
    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    raw = RawHybridClient(cloud_http, keys_dir, offered=[SUITE_HYBRID])
    session = raw.complete(raw.send_hello().json())

    wrong_way = cu.AeadSender(session.key_s2c, session.session_id, session.nonce_prefix)
    seq, nonce, ct = wrong_way.encrypt(json.dumps(envelope()).encode())

    response = cloud_http.post("/ingest", json={
        "session_id": b64e(session.session_id), "seq": seq,
        "nonce": b64e(nonce), "ct": b64e(ct),
    })
    assert response.status_code == 400
    assert response.json()["reason"] == "bad_tag"
    cloud_http.close()


def test_direction_keys_are_independent_of_the_nonce_prefix():
    """Separation comes from the KDF label, not from distinct prefixes."""
    common: dict[str, Any] = dict(
        selected_suite=SUITE_HYBRID,
        ss_mlkem768=cu.random_bytes(32), ss_classical=cu.random_bytes(32),
        client_id=GATEWAY_ID, offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
        server_share=KeyShare(x25519_pub=b"s" * 32),
        mlkem768_ct=b"t" * 1088, session_id=cu.random_bytes(16),
    )
    a = hop2_v2_derive(nonce_prefix=b"\x00\x00\x00\x00", **common)
    b = hop2_v2_derive(nonce_prefix=b"\xff\xff\xff\xff", **common)

    # Prefix is not in the KDF, so the keys match; separation is the label's job.
    assert a.key_c2s == b.key_c2s
    assert a.key_c2s != a.key_s2c


def test_hop1_is_strictly_one_way(keys_dir: Path):
    """Hop 1 keeps a single key because only one direction is ever encrypted.

    Enforced rather than assumed: the gateway's responses must be plaintext
    JSON. If encrypted responses are ever added to hop 1, DerivedSession must
    become directional first.
    """
    from services.common.handshake import hop1_derive

    cloud_http = build_cloud(keys_dir, Policy.REQUIRE)
    cloud_client = build_client(keys_dir, cloud_http, Policy.PREFER)
    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir), cloud_url="http://cloud", cloud_client=cloud_client)
    gateway_http = TestClient(gateway_app, base_url="http://gateway")

    nonce = cu.random_bytes(16)
    hello = gateway_http.post("/handshake", json={
        "protocol": PROTOCOL, "hop": "device-gateway",
        "client_id": "device-berlin-01", "client_nonce": b64e(nonce),
    }).json()

    # The ServerHello is plaintext -- readable without any key.
    assert "session_id" in hello and "nonce_prefix" in hello

    session_id = b64d(hello["session_id"])
    derived = hop1_derive(
        cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        nonce, b64d(hello["server_nonce"]), session_id, b64d(hello["nonce_prefix"]),
    )
    sender = cu.AeadSender(derived.key, session_id, derived.nonce_prefix)
    seq, aead_nonce, ct = sender.encrypt(json.dumps({
        "device_id": "device-berlin-01", "date": "2024-01-01",
        "temp_max_c": 7.4, "temp_min_c": 3.4, "precip_mm": 1.8, "wind_max_kmh": 19.7,
    }).encode())

    response = gateway_http.post("/ingest", json={
        "session_id": b64e(session_id), "seq": seq,
        "nonce": b64e(aead_nonce), "ct": b64e(ct),
    })

    # Response is plaintext JSON: nothing is encrypted gateway -> device.
    body = response.json()
    assert body["status"] == "accepted"
    assert "ct" not in body

    gateway_http.close()
    cloud_client.close()
    cloud_http.close()


# =========================================================================
# transcript binding
# =========================================================================


def test_kdf_binds_the_offered_suite_list():
    """Downgrade binding in the KDF, independent of the signature.

    Even if an attacker could forge signatures, deriving with a different
    offer list yields a different key, so the session would fail at the AEAD.
    """
    common: dict[str, Any] = dict(
        selected_suite=SUITE_HYBRID,
        ss_mlkem768=cu.random_bytes(32), ss_classical=cu.random_bytes(32),
        client_id=GATEWAY_ID,
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
        server_share=KeyShare(x25519_pub=b"s" * 32),
        mlkem768_ct=b"t" * 1088,
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    both = hop2_v2_derive(offered_suites=[SUITE_HYBRID, SUITE_CLASSICAL], **common)
    stripped = hop2_v2_derive(offered_suites=[SUITE_HYBRID], **common)
    reordered = hop2_v2_derive(offered_suites=[SUITE_CLASSICAL, SUITE_HYBRID], **common)

    assert both.key_c2s != stripped.key_c2s
    assert both.key_c2s != reordered.key_c2s


def test_kdf_binds_the_mlkem_ciphertext_and_public_keys():
    """CLAUDE.md requires both public keys and the ciphertext in the transcript."""
    base: dict[str, Any] = dict(
        selected_suite=SUITE_HYBRID,
        ss_mlkem768=cu.random_bytes(32), ss_classical=cu.random_bytes(32),
        client_id=GATEWAY_ID, offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    reference = hop2_v2_derive(
        client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
        server_share=KeyShare(x25519_pub=b"s" * 32),
        mlkem768_ct=b"t" * 1088, **base)

    variants = [
        hop2_v2_derive(
            client_share=KeyShare(x25519_pub=b"X" * 32, mlkem768_ek=b"e" * 1184),
            server_share=KeyShare(x25519_pub=b"s" * 32),
            mlkem768_ct=b"t" * 1088, **base),
        hop2_v2_derive(
            client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"E" * 1184),
            server_share=KeyShare(x25519_pub=b"s" * 32),
            mlkem768_ct=b"t" * 1088, **base),
        hop2_v2_derive(
            client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
            server_share=KeyShare(x25519_pub=b"S" * 32),
            mlkem768_ct=b"t" * 1088, **base),
        hop2_v2_derive(
            client_share=KeyShare(x25519_pub=b"c" * 32, mlkem768_ek=b"e" * 1184),
            server_share=KeyShare(x25519_pub=b"s" * 32),
            mlkem768_ct=b"T" * 1088, **base),
    ]
    for variant in variants:
        assert variant.key_c2s != reference.key_c2s


def test_derive_rejects_mismatched_secret_lengths():
    common: dict[str, Any] = dict(
        client_id=GATEWAY_ID, offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(), server_share=KeyShare(), mlkem768_ct=b"",
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    with pytest.raises(HandshakeError, match="ML-KEM shared secret"):
        hop2_v2_derive(selected_suite=SUITE_HYBRID, ss_mlkem768=b"short",
                       ss_classical=cu.random_bytes(32), **common)
    with pytest.raises(HandshakeError, match="X25519 shared secret"):
        hop2_v2_derive(selected_suite=SUITE_HYBRID, ss_mlkem768=cu.random_bytes(32),
                       ss_classical=b"short", **common)
    with pytest.raises(HandshakeError, match="must not carry an ML-KEM secret"):
        hop2_v2_derive(selected_suite=SUITE_CLASSICAL, ss_mlkem768=cu.random_bytes(32),
                       ss_classical=cu.random_bytes(32), **common)
    with pytest.raises(HandshakeError, match="unknown suite"):
        hop2_v2_derive(selected_suite="nonsense", ss_mlkem768=b"",
                       ss_classical=cu.random_bytes(32), **common)


def test_canonical_suites_preserves_order():
    assert canonical_suites([SUITE_HYBRID, SUITE_CLASSICAL]) == \
        f"{SUITE_HYBRID},{SUITE_CLASSICAL}"
    assert canonical_suites([SUITE_CLASSICAL, SUITE_HYBRID]) != \
        canonical_suites([SUITE_HYBRID, SUITE_CLASSICAL])


def test_is_post_quantum_classification():
    assert is_post_quantum(SUITE_HYBRID) is True
    assert is_post_quantum(SUITE_CLASSICAL) is False


# =========================================================================
# X25519 wrapper behaviour
# =========================================================================


def test_x25519_agreement_is_symmetric():
    a, b = cu.generate_x25519_private_key(), cu.generate_x25519_private_key()
    a_pub = cu.x25519_public_bytes(a.public_key())
    b_pub = cu.x25519_public_bytes(b.public_key())

    assert cu.x25519_exchange(a, cu.x25519_public_from_bytes(b_pub)) == \
        cu.x25519_exchange(b, cu.x25519_public_from_bytes(a_pub))


def test_x25519_rejects_a_wrong_length_public_key():
    for bad in (b"", b"\x00" * 31, b"\x00" * 33):
        with pytest.raises(ValueError, match="32 bytes"):
            cu.x25519_public_from_bytes(bad)


def test_x25519_low_order_point_is_rejected():
    """RFC 7748 s6.1: an all-zero shared secret must abort the handshake."""
    private_key = cu.generate_x25519_private_key()
    all_zero = cu.x25519_public_from_bytes(b"\x00" * 32)
    with pytest.raises(ValueError):
        cu.x25519_exchange(private_key, all_zero)


def test_mlkem_sizes_match_fips_203():
    assert cu.MLKEM768_EK_LEN == 1184
    assert cu.MLKEM768_CT_LEN == 1088
    assert cu.MLKEM768_SS_LEN == 32

    kem = cu.generate_mlkem768_private_key()
    ek = cu.mlkem768_encapsulation_key_bytes(kem)
    shared, ct = cu.mlkem768_encapsulate(kem.public_key())
    assert (len(ek), len(ct), len(shared)) == (1184, 1088, 32)


def test_encapsulate_returns_secret_first_not_ciphertext():
    """Guards the easiest mistake in the whole integration."""
    kem = cu.generate_mlkem768_private_key()
    shared, ct = cu.mlkem768_encapsulate(kem.public_key())
    assert len(shared) == 32, "shared secret must come first"
    assert len(ct) == 1088, "ciphertext must come second"


def test_session_repr_does_not_leak_direction_keys():
    session = hop2_v2_derive(
        selected_suite=SUITE_CLASSICAL, ss_mlkem768=b"",
        ss_classical=cu.random_bytes(32), client_id=GATEWAY_ID,
        offered_suites=[SUITE_CLASSICAL],
        client_nonce=cu.random_bytes(16), server_nonce=cu.random_bytes(16),
        client_share=KeyShare(), server_share=KeyShare(), mlkem768_ct=b"",
        session_id=cu.random_bytes(16), nonce_prefix=cu.random_bytes(4),
    )
    text = repr(session)
    assert "redacted" in text
    assert session.key_c2s.hex() not in text
    assert session.key_s2c.hex() not in text
