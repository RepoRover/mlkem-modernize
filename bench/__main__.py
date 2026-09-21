"""Run the suite benchmarks and write a JSON report.

Usage: uv run python -m bench [label] [iterations]
"""

from __future__ import annotations

import sys
from pathlib import Path

from bench.harness import DEFAULT_ITERATIONS, render_table, write_report
from bench.suites import benchmark_legacy

REPORT_DIR = Path(__file__).resolve().parent / "results"


def main(argv: list[str]) -> int:
    label = argv[1] if len(argv) > 1 else "baseline"
    iterations = int(argv[2]) if len(argv) > 2 else DEFAULT_ITERATIONS

    benchmarks = [benchmark_legacy(iterations)]
    try:
        from bench.suites import benchmark_hybrid  # type: ignore[attr-defined]
    except ImportError:
        pass
    else:
        benchmarks.append(benchmark_hybrid(iterations))

    print(render_table(benchmarks))
    path = write_report(REPORT_DIR / f"{label}.json", label, benchmarks)
    print(f"report written to {path.relative_to(Path.cwd())}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
