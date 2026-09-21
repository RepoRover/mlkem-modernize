"""Prometheus metrics shared by the modern services.

Deliberately not part of pqcnode: that package is stdlib-only so the legacy
device can use it, and prometheus_client is a third-party dependency the device
does not have.

The series that matters operationally is
``pqc_quantum_vulnerable_frames_total``, but it must be read **per service**.
Summing it across the deployment is misleading: the gateway necessarily accepts
quantum-vulnerable frames from a device that cannot speak anything else, so the
total can never reach zero and a dashboard that aggregates it will show a
healthy migration as a failure.

Scoped to the cloud, the counter answers the question that matters -- did
quantum-vulnerable traffic get all the way in? -- and should stay at zero once
every gateway has cut over. Scoped to the gateway, it quantifies the residual
last-mile exposure that brokering does not remove.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from pqcwire.protocol import suite_spec

REGISTRY = CollectorRegistry()

HANDSHAKES = Counter(
    "pqc_handshakes_total",
    "Key establishment attempts, labelled by suite and outcome.",
    ["service", "suite", "result"],
    registry=REGISTRY,
)

HANDSHAKE_DURATION = Histogram(
    "pqc_handshake_duration_seconds",
    "Time to complete key establishment.",
    ["service", "suite"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    registry=REGISTRY,
)

FRAMES = Counter(
    "pqc_frames_total",
    "Data frames processed, labelled by suite and outcome.",
    ["service", "suite", "result"],
    registry=REGISTRY,
)

QUANTUM_VULNERABLE_FRAMES = Counter(
    "pqc_quantum_vulnerable_frames_total",
    "Frames accepted under a suite a quantum adversary is expected to break. "
    "Read per service: zero at the cloud means the migration is complete, while "
    "a non-zero count at the gateway is the expected last-mile exposure.",
    ["service", "suite"],
    registry=REGISTRY,
)

ACTIVE_SESSIONS = Gauge(
    "pqc_active_sessions",
    "Sessions currently held in memory.",
    ["service"],
    registry=REGISTRY,
)

SUITE_IN_USE = Gauge(
    "pqc_suite_in_use",
    "1 for the suite this node is configured to use on each link.",
    ["service", "direction", "suite", "quantum_resistant"],
    registry=REGISTRY,
)

CRYPTO_OPERATION = Histogram(
    "pqc_crypto_operation_duration_seconds",
    "Duration of individual cryptographic operations.",
    ["service", "operation"],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
    registry=REGISTRY,
)


def record_suite(service: str, direction: str, suite: str) -> None:
    """Publish which suite a link is configured to use."""
    spec = suite_spec(suite)
    SUITE_IN_USE.labels(
        service=service,
        direction=direction,
        suite=suite,
        quantum_resistant=str(spec.quantum_resistant).lower(),
    ).set(1)


def record_handshake(service: str, suite: str, result: str) -> None:
    HANDSHAKES.labels(service=service, suite=suite, result=result).inc()


def record_frame(service: str, suite: str, result: str) -> None:
    FRAMES.labels(service=service, suite=suite, result=result).inc()
    if result != "accepted":
        return
    try:
        resistant = suite_spec(suite).quantum_resistant
    except Exception:
        return
    if not resistant:
        QUANTUM_VULNERABLE_FRAMES.labels(service=service, suite=suite).inc()


@contextmanager
def timed(histogram: Histogram, **labels: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        histogram.labels(**labels).observe(time.perf_counter() - start)


def render() -> tuple[bytes, str]:
    """Render the registry in the Prometheus text exposition format.

    Body and content type must come from the same exposition module. Pairing
    the OpenMetrics content type with this generator makes Prometheus reject
    every scrape with "data does not end with # EOF", because OpenMetrics
    requires a terminator the text format does not emit.
    """
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
