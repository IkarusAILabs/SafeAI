"""Shared SafeAI CLI version-option helpers."""
from __future__ import annotations

import sys

SAFEAI_VERSION = "2.5.0"
VERSION_FLAGS = ("--version", "-V")


def version_requested(argv: list[str] | None = None) -> bool:
    """Return whether argv requests version output as a standalone option."""
    values = sys.argv[1:] if argv is None else list(argv)
    return len(values) == 1 and values[0] in VERSION_FLAGS


def print_version(version: str = SAFEAI_VERSION) -> None:
    """Print a stable machine-readable version line."""
    print(version)
