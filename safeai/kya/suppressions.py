"""Auditable suppression workflow (``.safeai/suppressions.yml``).

A *suppression* records a technical false positive or accepted local
exception. It is distinct from a *policy exception* (an authorised risk
acceptance for a defined period, expressed in ``.safeai/policy.yml``).

Rules:
  * Every suppression requires ``reason``, ``owner``, and ``created``.
  * Matching uses ``fingerprint`` (preferred) or ``rule_id``, optionally
    narrowed by a ``path`` glob.
  * Suppressions are never silent: suppressed findings keep status
    ``suppressed`` and stay visible in JSON/HTML/SARIF/registry output.
  * Expired suppressions are surfaced as warnings (never dropped).
  * An optional ``approval`` block (v2.12; ``safeai.kya.approval``)
    records who approved the decision; it never changes whether the
    suppression applies.
"""

import fnmatch
import os
from datetime import UTC, date, datetime

import yaml

from safeai.kya.approval import ApprovalError, approval_state, parse_approval

DEFAULT_SUPPRESSIONS_PATH = os.path.join(".safeai", "suppressions.yml")

#: Findings that carry structural payloads (inventories, asset lists) consumed
#: by reports and downstream correlation. They are informational carriers, not
#: security verdicts, so they are never suppressed — a broad ``rule_id`` or
#: ``path`` suppression must not be able to blank the inventory section.
_CARRYING_RULE_IDS = frozenset({"ENV_DEP_INVENTORY", "MCP_ASSETS_DISCOVERED"})

_REQUIRED_FIELDS = ("reason", "owner", "created")


class SuppressionError(Exception):
    """Raised for invalid suppression files."""


def default_suppressions_path(root):
    return os.path.join(root, DEFAULT_SUPPRESSIONS_PATH)


def _parse_date(value, field, index):
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise SuppressionError(
            f"Suppression #{index}: field '{field}' must be an ISO date (YYYY-MM-DD), got {value!r}."
        ) from exc


def load_suppressions(path):
    """Load and validate a suppressions file.

    Returns ``(entries, warnings)``. Missing file yields empty results.
    Invalid entries raise ``SuppressionError`` — silent suppression is
    never permitted.
    """
    if not path or not os.path.exists(path):
        return [], []

    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SuppressionError(f"Unable to read suppressions file {path}: {exc}") from exc

    raw_entries = document.get("suppressions") or []
    if not isinstance(raw_entries, list):
        raise SuppressionError(f"Suppressions file {path}: 'suppressions' must be a list.")

    entries = []
    warnings = []
    today = datetime.now(UTC).date()

    for index, raw in enumerate(raw_entries, 1):
        if not isinstance(raw, dict):
            raise SuppressionError(f"Suppression #{index}: entry must be a mapping.")

        if not raw.get("fingerprint") and not raw.get("rule_id"):
            raise SuppressionError(
                f"Suppression #{index}: either 'fingerprint' or 'rule_id' is required."
            )
        for field in _REQUIRED_FIELDS:
            if not raw.get(field):
                raise SuppressionError(f"Suppression #{index}: missing required field '{field}'.")

        entry = {
            "fingerprint": raw.get("fingerprint"),
            "rule_id": raw.get("rule_id"),
            "reason": str(raw["reason"]),
            "owner": str(raw["owner"]),
            "created": _parse_date(raw["created"], "created", index),
            "expires": _parse_date(raw["expires"], "expires", index) if raw.get("expires") else None,
            "path": raw.get("path"),
        }
        try:
            entry["approval"] = parse_approval(raw.get("approval"),
                                               expires=entry["expires"], today=today)
        except ApprovalError as exc:
            raise SuppressionError(f"Suppression #{index}: {exc}.") from exc
        entry["approval_state"] = approval_state(entry["approval"], entry["owner"])
        if entry["expires"] and entry["expires"] < today:
            warnings.append(
                f"Suppression #{index} ({entry.get('fingerprint') or entry.get('rule_id')}) "
                f"expired on {entry['expires'].isoformat()} and no longer applies."
            )
            entry["expired"] = True
        else:
            entry["expired"] = False
        entries.append(entry)

    return entries, warnings


def _matches(entry, finding):
    if entry.get("fingerprint"):
        if finding.get("fingerprint") != entry["fingerprint"]:
            return False
    elif entry.get("rule_id") and str(finding.get("rule_id", "")).upper() != str(entry["rule_id"]).upper():
        return False
    path_scope = entry.get("path")
    if path_scope:
        finding_path = str(finding.get("file") or "").replace("\\", "/")
        if not fnmatch.fnmatch(finding_path, path_scope):
            return False
    return True


def apply_suppressions(findings, entries):
    """Mark matching findings as ``suppressed``.

    Expired entries never suppress. Returns a summary dict with counts
    and the list of applied suppression descriptors for audit output.
    """
    applied = []
    suppressed_count = 0
    for finding in findings:
        if finding.get("rule_id") in _CARRYING_RULE_IDS:
            continue
        for entry in entries:
            if entry.get("expired"):
                continue
            if _matches(entry, finding):
                finding["status"] = "suppressed"
                finding["suppression"] = {
                    "reason": entry["reason"],
                    "owner": entry["owner"],
                    "created": entry["created"].isoformat(),
                    "expires": entry["expires"].isoformat() if entry["expires"] else None,
                    "approval": entry.get("approval"),
                    "approval_state": entry.get("approval_state", "unrecorded"),
                }
                suppressed_count += 1
                applied.append({
                    "fingerprint": finding.get("fingerprint"),
                    "rule_id": finding.get("rule_id"),
                    "owner": entry["owner"],
                    "reason": entry["reason"],
                    "approval_state": entry.get("approval_state", "unrecorded"),
                })
                break
    return {"suppressed": suppressed_count, "applied": applied}


def detect_stale_suppressions(entries, findings):
    """Detect suppressions whose fingerprint no longer matches any current finding.

    A fingerprint-bound suppression is considered *stale* when the
    underlying code has materially shifted — the fingerprint changed
    because the line, context, or code around it was modified.  This
    means the suppression no longer targets the exact code it was
    written for.

    Returns a list of stale suppression dicts for CI failure reporting.
    Rule-id-based suppressions are not checked (they match by rule, not
    by exact code location).
    """
    current_fps = {f.get("fingerprint") for f in findings if f.get("fingerprint")}
    stale = []
    for entry in entries:
        fp = entry.get("fingerprint")
        if not fp:
            continue
        if entry.get("expired"):
            continue
        if fp not in current_fps:
            stale.append({
                "fingerprint": fp,
                "rule_id": entry.get("rule_id"),
                "owner": entry.get("owner"),
                "reason": entry.get("reason"),
                "created": entry.get("created").isoformat() if entry.get("created") else None,
            })
    return stale


def suppression_template(finding):
    """Return a YAML suppression template snippet for a finding."""
    today = datetime.now(UTC).date().isoformat()
    lines = [
        f"- fingerprint: \"{finding.get('fingerprint') or ''}\"",
        f"  rule_id: {finding.get('rule_id') or ''}",
        "  reason: \"\"  # required: why is this a false positive / accepted?",
        "  owner: \"\"   # required: accountable person or team",
        f"  created: \"{today}\"  # YYYY-MM-DD",
        "  # expires: \"YYYY-MM-DD\"  # optional",
        "  # path: \"src/**\"          # optional glob scope",
        "  # approval:                   # optional: who approved, when, escalation",
        "  #   approved_by: \"\"",
        f"  #   approved_at: \"{today}\"",
        "  #   escalation_owner: \"\"",
    ]
    return "\n".join(lines)
