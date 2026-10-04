"""Authority evidence validation benchmark (v2.6).

Offline, deterministic corpus evaluation: runs the real ``safeai
scan`` CLI path against ``tests/benchmarks/authority/`` and compares
structurally with hand-verified expected truth. The benchmark
measures; it never gates.
"""

from safeai.benchmark.runner import (
    BenchmarkError,
    discover_cases,
    evaluate_case,
    run_corpus,
)

__all__ = [
    "BenchmarkError",
    "discover_cases",
    "evaluate_case",
    "run_corpus",
]
