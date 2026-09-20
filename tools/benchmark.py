"""Informational crypto timings, never a performance acceptance gate."""

import argparse
import json
import math
import platform
import resource
import statistics
import time
from datetime import date
from pathlib import Path

import cryptography
from cloud.crypto import decrypt_cloud_envelope
from cloud.models import CloudEnvelope
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gateway.crypto import encrypt_cloud_envelope
from gateway.models import Observation


def main() -> None:
    """Print warm-up-adjusted median/p95 timings and runtime context as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    if args.iterations < 20:
        parser.error("at least 20 iterations are required")
    observation = Observation(
        observation_id="benchmark:2024-01-01",
        device_id="benchmark",
        observed_on=date(2024, 1, 1),
        latitude=52,
        longitude=13,
        elevation_m=38,
        utc_offset_seconds=0,
        timezone="UTC",
        timezone_abbreviation="UTC",
        temperature_max_c=7,
        temperature_min_c=3,
        precipitation_mm=1,
        wind_speed_max_kmh=20,
    )
    private = MLKEM768PrivateKey.generate()
    public = private.public_key()
    _, kem_ciphertext = public.encapsulate()
    envelope = CloudEnvelope.model_validate_json(
        encrypt_cloud_envelope(observation, "gw", "key", public).model_dump_json()
    )
    aes = AESGCM(AESGCM.generate_key(bit_length=256))
    payload = observation.model_dump_json().encode()
    nonce_counter = 0

    def aes_encrypt():
        nonlocal nonce_counter
        nonce_counter += 1
        return aes.encrypt(nonce_counter.to_bytes(12, "big"), payload, b"benchmark")

    ciphertext = aes_encrypt()
    operations = {
        "aes256gcm_encrypt": aes_encrypt,
        "aes256gcm_decrypt": lambda: aes.decrypt(
            (1).to_bytes(12, "big"), ciphertext, b"benchmark"
        ),
        "mlkem768_encapsulate": public.encapsulate,
        "mlkem768_decapsulate": lambda: private.decapsulate(kem_ciphertext),
        "gateway_envelope": lambda: encrypt_cloud_envelope(
            observation, "gw", "key", public
        ),
        "cloud_envelope": lambda: decrypt_cloud_envelope(envelope, private),
    }
    results = {}
    for name, operation in operations.items():
        for _ in range(20):
            operation()
        durations: list[float] = []
        for _ in range(args.iterations):
            start = time.perf_counter_ns()
            operation()
            durations.append((time.perf_counter_ns() - start) / 1000)
        results[name] = {
            "median_us": statistics.median(durations),
            "p95_us": sorted(durations)[math.ceil(len(durations) * 0.95) - 1],
            "operations": args.iterations,
            "warmup_operations": 20,
        }
    cpu = platform.processor()
    if Path("/proc/cpuinfo").exists():
        cpu = next(
            (
                line.partition(":")[2].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            cpu,
        )
    print(
        json.dumps(
            {
                "event": "benchmark_results",
                "python": platform.python_version(),
                "cryptography": cryptography.__version__,
                "openssl": backend.openssl_version_text(),
                "platform": platform.platform(),
                "cpu": cpu,
                "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                * (1 if platform.system() == "Darwin" else 1024),
                "timings": results,
                "limitations": "Container timings do not reproduce ESP8266 timing or prove ML-KEM infeasibility. Image sizes are recorded by tools/benchmark.sh.",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
