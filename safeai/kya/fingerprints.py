"""Deterministic finding fingerprints.

Fingerprint algorithm (documented contract):

    fingerprint = SHA-256(
        normalized_rule_id      + "\\n" +
        normalized_rel_path     + "\\n" +
        normalized_line         + "\\n" +
        normalized_evidence
    ).hexdigest()

Where:
  * ``normalized_rule_id``  — upper-cased, whitespace-trimmed rule ID.
  * ``normalized_rel_path`` — ``fingerprint_path(path)``: forward
                              slashes with every leading ``.`` and ``/``
                              removed. This is the pre-2.12 form, frozen so
                              that fingerprints (baselines, suppressions,
                              registry history) stay stable; it differs
                              from the displayed path (``normalize_path``)
                              for dot-files and dot-directories.
  * ``normalized_line``     — decimal line number (``0`` when unknown).
  * ``normalized_evidence`` — whitespace-collapsed, secret-redacted
                              evidence string (see ``util.normalize_evidence``).

Properties:
  * Independent of timestamps, absolute paths, scan IDs, and dict ordering.
  * Survives whitespace-only formatting changes in evidence.
  * A material change to rule, location, or matched evidence yields a new
    fingerprint — which is exactly what baseline diffing needs.
"""

import fnmatch

from safeai.kya.util import normalize_evidence, sha256_text


def normalize_path(path):
    """Normalize a reported path: relative, POSIX-style, name kept intact.

    Removes leading ``./`` segments and leading slashes only. Before 2.12
    this used ``lstrip("./")``, which also dropped the leading dot of
    names, so ``.claude/settings.json`` was reported as
    ``claude/settings.json``; ``fingerprint_path`` keeps that form for
    identity hashes.
    """
    if not path:
        return ""
    text = str(path).replace("\\", "/").strip()
    while text.startswith(("./", "/")):
        text = text[2:] if text.startswith("./") else text[1:]
    return "" if text == "." else text


def fingerprint_path(path):
    """The frozen pre-2.12 path form hashed into fingerprints and agent IDs."""
    if not path:
        return ""
    return str(path).replace("\\", "/").lstrip("./").strip()


def path_glob_matches(path, pattern):
    """Match a suppression/policy path glob against a finding path.

    Globs written before 2.12 were matched against the reported path with
    leading dots dropped (``claude/**``); they keep matching, as do globs
    for the real path (``.claude/**``).
    """
    text = str(path or "").replace("\\", "/")
    return (fnmatch.fnmatch(text, pattern)
            or fnmatch.fnmatch(fingerprint_path(text), pattern))


def normalize_rule_id(rule_id):
    """Normalize a rule ID for fingerprinting."""
    return str(rule_id or "UNKNOWN").strip().upper()


def compute_fingerprint(rule_id, path, line, evidence=""):
    """Compute the deterministic SHA-256 fingerprint for a finding."""
    material = "\n".join([
        normalize_rule_id(rule_id),
        fingerprint_path(path),
        str(int(line or 0)),
        normalize_evidence(evidence),
    ])
    return sha256_text(material)


def fingerprint_finding(finding):
    """Compute and attach ``fingerprint``/``finding_id`` to a finding dict.

    Returns the fingerprint. Idempotent: an existing fingerprint is kept
    so re-processing never churns identities.
    """
    existing = finding.get("fingerprint")
    if existing:
        return existing
    fp = compute_fingerprint(
        finding.get("rule_id"),
        finding.get("file"),
        finding.get("line"),
        finding.get("evidence") or finding.get("message") or "",
    )
    finding["fingerprint"] = fp
    finding.setdefault("finding_id", fp)
    return fp
