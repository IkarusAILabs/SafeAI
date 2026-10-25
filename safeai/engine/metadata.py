"""Machine-readable scanner metadata for SafeAI reports.

Emits a ``scanner_metadata`` section in the report with engine version,
schema version, ruleset version, policy-profile version, and adapter
versions. This allows downstream consumers to verify compatibility
and detect drift.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any


def _file_sha256(path: str) -> str:
    """Return the hex SHA-256 of a file, or empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _ruleset_version(rules_dir: str | None) -> dict[str, Any]:
    """Derive a ruleset version from the rules directory hash."""
    if not rules_dir:
        rules_dir = os.path.join(
            os.path.dirname(__file__), os.pardir, "rules"
        )
    rules_path = os.path.join(rules_dir, "base_rules.yaml")
    sha = _file_sha256(rules_path)
    # Count rules for a human-readable summary
    count = 0
    try:
        import yaml
        with open(rules_path, encoding="utf-8") as f:
            rules = yaml.safe_load(f)
        count = len(rules) if isinstance(rules, list) else 0
    except Exception:
        pass
    return {
        "file": "base_rules.yaml",
        "sha256": sha,
        "rule_count": count,
    }


def _adapter_versions(parsers: list) -> dict[str, str]:
    """Return a mapping of adapter name to version string."""
    versions = {}
    for parser in parsers:
        name = getattr(parser, "name", type(parser).__name__)
        version = getattr(parser, "version", "1.0.0")
        versions[name] = version
    return versions


def build_scanner_metadata(
    *,
    rules_dir: str | None = None,
    parsers: list | None = None,
    policy_path: str | None = None,
    scan_root: str | None = None,
) -> dict[str, Any]:
    """Build the scanner metadata section for the report.

    Returns a dict suitable for inclusion as ``report["scanner_metadata"]``.
    """
    from safeai.version import SAFEAI_VERSION

    metadata: dict[str, Any] = {
        "engine_version": SAFEAI_VERSION,
        "schema_version": "1.3",
        "ruleset": _ruleset_version(rules_dir),
        "adapters": _adapter_versions(parsers or []),
    }

    if policy_path:
        metadata["policy_profile"] = {
            "path": policy_path,
            "sha256": _file_sha256(policy_path),
        }

    if scan_root:
        metadata["scan_root"] = scan_root

    return metadata
