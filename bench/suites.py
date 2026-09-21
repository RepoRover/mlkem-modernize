"""Suite-specific benchmark definitions.

Only the legacy suite exists at the v0 baseline. The modernized suite is added
by the migration, and the same harness measures it so the two are comparable.
"""

from __future__ import annotations

import pqcsuite as cs
from bench.harness import DEFAULT_ITERATIONS, SuiteBenchmark, Timing
from pqcwire.frames import b64d
from pqcwire.protocol import HYBRID_PQC, LEGACY_RSA, suite_spec
from pqcwire.telemetry import WeatherReading

SAMPLE_READING = WeatherReading("2024-01-01", 7.4, 3.4, 1.8, 19.7)
SAMPLE_PAYLOAD = SAMPLE_READING.to_json().encode()


def benchmark_legacy(iterations: int = DEFAULT_ITERATIONS) -> SuiteBenchmark:
    server = cs.LegacyServer(cs.generate_private_key())
    client = cs.LegacyClient(server.public_key)

    request, client_session = client.open_session()
    server_session = server.accept(request)
    sealed = client_session.seal(SAMPLE_PAYLOAD)

    # A fresh pair per opened frame keeps sequence state from drifting while
    # the operation is measured repeatedly.
    def open_one() -> None:
        _, sending = client.open_session()
        receiving = server.accept(_)
        receiving.open(sending.seal(SAMPLE_PAYLOAD))

    benchmark = SuiteBenchmark(
        suite=LEGACY_RSA,
        quantum_resistant=suite_spec(LEGACY_RSA).quantum_resistant,
        timings=[
            Timing.measure(
                "keygen (RSA-2048)",
                cs.generate_private_key,
                max(iterations // 20, 5),
            ),
            Timing.measure("handshake: client", client.open_session, iterations),
            Timing.measure("handshake: server", lambda: server.accept(request), iterations),
            Timing.measure(
                "seal one reading",
                lambda: client_session.seal(SAMPLE_PAYLOAD),
                iterations,
            ),
            Timing.measure("handshake + seal + open", open_one, max(iterations // 4, 10)),
        ],
        sizes_bytes={
            "plaintext_reading": len(SAMPLE_PAYLOAD),
            "handshake_kem_payload": len(request.kem_payload["rsa_ct"]),
            "data_frame_ciphertext": len(sealed.ciphertext),
            "aead_overhead": len(sealed.ciphertext) - len(SAMPLE_PAYLOAD),
        },
        notes={
            "forward_secrecy": False,
            "key_derivation": "none: the transported secret is used directly as the AES key",
            "transcript_binding": False,
        },
    )
    _ = server_session  # established above to prove the pair interoperates
    return benchmark


def benchmark_hybrid(iterations: int = DEFAULT_ITERATIONS) -> SuiteBenchmark:
    """Measure the post-quantum suite the same way the legacy one is measured."""
    identity = cs.generate_identity_key()
    gateway_identity = cs.generate_identity_key()
    pool_size = max(iterations // 4, 10)
    server = cs.HybridServer(
        identity,
        gateway_identity.public_key(),
        # Initial offer + server pool + Timing.measure's untimed warmup and samples.
        max_pending_offers=iterations + pool_size + 3,
    )
    client = cs.HybridClient(identity.public_key(), gateway_identity)

    # One offer, reused for client-side measurements. The server consumes an
    # offer on accept, so those need a pre-built pool instead.
    offer = server.make_offer()
    request, client_session = client.open_session(offer)

    pool = []
    for _ in range(pool_size + 1):
        pooled_offer = server.make_offer()
        pooled_request, _ = client.open_session(pooled_offer)
        pool.append(pooled_request)
    pending = iter(pool)

    def accept_one() -> None:
        server.accept(next(pending))

    sealed = client_session.seal(SAMPLE_PAYLOAD)
    mlkem = cs.mlkem_module()

    return SuiteBenchmark(
        suite=HYBRID_PQC,
        quantum_resistant=suite_spec(HYBRID_PQC).quantum_resistant,
        timings=[
            Timing.measure(
                "keygen (ML-KEM-768)",
                mlkem.MLKEM768PrivateKey.generate,
                max(iterations // 20, 5),
            ),
            Timing.measure("offer: keygen + ML-DSA sign", server.make_offer, iterations),
            Timing.measure(
                "handshake: client",
                lambda: client.open_session(offer),
                iterations,
            ),
            Timing.measure("handshake: server", accept_one, pool_size),
            Timing.measure(
                "seal one reading",
                lambda: client_session.seal(SAMPLE_PAYLOAD),
                iterations,
            ),
        ],
        sizes_bytes={
            "plaintext_reading": len(SAMPLE_PAYLOAD),
            "mlkem_public_key": len(offer.mlkem_pub),
            "mlkem_ciphertext": len(b64d(request.kem_payload["mlkem_ct"])),
            "x25519_public_key": len(offer.x25519_pub),
            "cloud_mldsa_signature": len(offer.signature),
            "gateway_mldsa_signature": len(b64d(request.kem_payload["gateway_signature"])),
            "data_frame_ciphertext": len(sealed.ciphertext),
            "aead_overhead": len(sealed.ciphertext) - len(SAMPLE_PAYLOAD),
        },
        notes={
            "forward_secrecy": True,
            "key_derivation": "HKDF-SHA256 over ss_pq || ss_ec, salted with the transcript hash",
            "transcript_binding": True,
            "authentication": "pinned ML-DSA-65 signatures from cloud and gateway",
        },
    )
