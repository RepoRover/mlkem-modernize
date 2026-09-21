"""Suite-specific benchmark definitions.

Only the legacy suite exists at the v0 baseline. The modernized suite is added
by the migration, and the same harness measures it so the two are comparable.
"""

from __future__ import annotations

import cryptosuite as cs
from bench.harness import DEFAULT_ITERATIONS, SuiteBenchmark, Timing
from wire.protocol import LEGACY_RSA, suite_spec
from wire.telemetry import WeatherReading

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
