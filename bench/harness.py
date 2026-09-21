"""Measurement harness for comparing cipher suites.

Written so the same code measures the baseline and the modernized suite. The
before/after comparison is only meaningful if both sides are measured the same
way, on the same machine, with the same payloads.
"""

from __future__ import annotations

import json
import platform
import statistics
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import cryptography

DEFAULT_ITERATIONS = 200


@dataclass
class Timing:
    """Latency distribution for one operation, in milliseconds."""

    operation: str
    samples: int
    median_ms: float
    p95_ms: float
    mean_ms: float
    min_ms: float
    max_ms: float

    @classmethod
    def measure(cls, operation: str, fn: Callable[[], Any], iterations: int) -> Timing:
        # One untimed call so that lazy imports and first-use backend
        # initialisation are not attributed to the operation itself.
        fn()
        durations = []
        for _ in range(iterations):
            start = time.perf_counter()
            fn()
            durations.append((time.perf_counter() - start) * 1000.0)
        durations.sort()
        return cls(
            operation=operation,
            samples=iterations,
            median_ms=round(statistics.median(durations), 4),
            p95_ms=round(durations[min(int(len(durations) * 0.95), len(durations) - 1)], 4),
            mean_ms=round(statistics.fmean(durations), 4),
            min_ms=round(durations[0], 4),
            max_ms=round(durations[-1], 4),
        )


@dataclass
class SuiteBenchmark:
    suite: str
    quantum_resistant: bool
    timings: list[Timing] = field(default_factory=list)
    sizes_bytes: dict[str, int] = field(default_factory=dict)
    notes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "quantum_resistant": self.quantum_resistant,
            "timings": [asdict(timing) for timing in self.timings],
            "sizes_bytes": self.sizes_bytes,
            "notes": self.notes,
        }


def environment() -> dict[str, Any]:
    return {
        "python_version": platform.python_version(),
        "cryptography_version": cryptography.__version__,
        "machine": platform.machine(),
        "system": platform.system(),
        "processor": platform.processor() or "unknown",
    }


def write_report(path: Path, label: str, benchmarks: list[SuiteBenchmark]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "label": label,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": environment(),
        "suites": [benchmark.to_dict() for benchmark in benchmarks],
    }
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return path


def render_table(benchmarks: list[SuiteBenchmark]) -> str:
    rows = [
        "{:<34} {:>11} {:>11} {:>11}".format("operation", "median ms", "p95 ms", "max ms"),
        "-" * 70,
    ]
    for benchmark in benchmarks:
        rows.append(
            "{} ({})".format(
                benchmark.suite,
                "quantum-resistant" if benchmark.quantum_resistant else "quantum-vulnerable",
            )
        )
        for timing in benchmark.timings:
            rows.append(
                f"  {timing.operation:<32} {timing.median_ms:>11.4f}"
                f" {timing.p95_ms:>11.4f} {timing.max_ms:>11.4f}"
            )
        if benchmark.sizes_bytes:
            sizes = "  ".join(
                f"{name}={value}B" for name, value in sorted(benchmark.sizes_bytes.items())
            )
            rows.append(f"  wire sizes: {sizes}")
        rows.append("")
    return "\n".join(rows)
