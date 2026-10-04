"""File-backed policy exception records (``.safeai/exceptions.yml``).

An exception names a risk owner who accepts a specific target for a
bounded scope and time, with compensating controls and re-review
triggers. Exceptions warn by default; ``--strict-exceptions`` turns
expired, stale, scope-mismatched, or invalid exceptions into a scan
failure.

Target model (explicit since v2.4): ``target_type`` is one of
``finding`` (rule_id), ``policy`` (policy match id), ``escalation``
(escalation id), or ``authority_change`` (changed tool key). The legacy
``finding_or_policy`` key is still accepted and auto-classified, but new
files should prefer the explicit form.

States (never silently converted into one another): ``active`` (target
live, unexpired, scope satisfied), ``expired`` (past ``expires_at``),
``stale`` (no live target), ``scope-mismatch`` (target live but
repository scope differs), ``invalid`` (defensive only — the loader
rejects malformed entries before evaluation).

Metadata-only fields (recorded, never enforced): ``commit_range``,
``compensating_controls``, ``review_trigger``. They document intent;
SafeAI does not watch the repository for trigger events.
"""

import os
from datetime import UTC, datetime

import yaml

DEFAULT_EXCEPTIONS_PATH = os.path.join(".safeai", "exceptions.yml")

#: Explicit exception target namespaces.
TARGET_TYPES = ("finding", "policy", "escalation", "authority_change")

#: Evaluation states. Distinct states are never merged: each prints its
#: own warning and gates independently under --strict-exceptions.
EXCEPTION_STATES = ("active", "expired", "stale", "scope-mismatch", "invalid")


class ExceptionError(Exception):
    """Raised for invalid exception files."""


def default_exceptions_path(root):
    return os.path.join(root, DEFAULT_EXCEPTIONS_PATH)


def _resolve_target(raw, exception_id):
    """Resolve (target_type, target_id) from explicit or legacy keys.

    Explicit ``target_type`` + ``target_id`` is preferred. The legacy
    ``finding_or_policy`` key maps to target_type ``"unspecified"`` and
    keeps the historical union matching (rule, policy, or escalation id).
    """
    target_type = raw.get("target_type")
    target_id = raw.get("target_id")
    legacy = raw.get("finding_or_policy")
    if target_type is not None or target_id is not None:
        if not target_type or not target_id:
            raise ExceptionError(
                f"Exception {exception_id!r}: 'target_type' and 'target_id' "
                f"must be given together."
            )
        if target_type not in TARGET_TYPES:
            raise ExceptionError(
                f"Exception {exception_id!r}: 'target_type' must be one of "
                f"{', '.join(TARGET_TYPES)}, got {target_type!r}."
            )
        return str(target_type), str(target_id)
    if not legacy:
        raise ExceptionError(
            f"Exception {exception_id!r}: missing required target "
            f"('target_type' + 'target_id', or legacy 'finding_or_policy')."
        )
    return "unspecified", str(legacy)


def _parse_date(value, field, exception_id):
    from datetime import date

    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ExceptionError(
            f"Exception {exception_id!r}: field '{field}' must be an ISO date "
            f"(YYYY-MM-DD), got {value!r}."
        ) from exc


def load_exceptions(path):
    """Load and validate an exceptions file.

    Returns ``(entries, warnings)``. A missing file yields empty results.
    Invalid entries raise ``ExceptionError`` — silent exceptions are never
    permitted.
    """
    if not path or not os.path.exists(path):
        return [], []

    try:
        with open(path, encoding="utf-8") as fh:
            document = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ExceptionError(f"Unable to read exceptions file {path}: {exc}") from exc

    raw_entries = document.get("exceptions") or []
    if not isinstance(raw_entries, list):
        raise ExceptionError(f"Exceptions file {path}: 'exceptions' must be a list.")

    entries = []
    today = datetime.now(UTC).date()
    for index, raw in enumerate(raw_entries, 1):
        if not isinstance(raw, dict):
            raise ExceptionError(f"Exception #{index}: entry must be a mapping.")
        exception_id = raw.get("exception_id") or f"exception-#{index}"
        for field in ("risk_owner", "rationale"):
            if not raw.get(field):
                raise ExceptionError(
                    f"Exception {exception_id!r}: missing required field '{field}'."
                )
        target_type, target_id = _resolve_target(raw, exception_id)
        scope = raw.get("scope") or {}
        if not isinstance(scope, dict):
            raise ExceptionError(f"Exception {exception_id!r}: 'scope' must be a mapping.")
        controls = raw.get("compensating_controls") or []
        if not isinstance(controls, list):
            raise ExceptionError(
                f"Exception {exception_id!r}: 'compensating_controls' must be a list."
            )
        triggers = raw.get("review_trigger") or []
        if not isinstance(triggers, list):
            raise ExceptionError(f"Exception {exception_id!r}: 'review_trigger' must be a list.")
        expires_at = None
        if raw.get("expires_at"):
            expires_at = _parse_date(raw["expires_at"], "expires_at", exception_id)
        entries.append({
            "exception_id": str(exception_id),
            "target_type": target_type,
            "target_id": target_id,
            "scope": {
                "repository": scope.get("repository"),
                "commit_range": scope.get("commit_range"),
            },
            "risk_owner": str(raw["risk_owner"]),
            "rationale": str(raw["rationale"]),
            "compensating_controls": [str(c) for c in controls],
            "expires_at": expires_at.isoformat() if expires_at else None,
            "expired": bool(expires_at and expires_at < today),
            "review_trigger": [str(t) for t in triggers],
        })

    return entries, []


def _live_targets(findings, escalations, policy_ids=(), changed_tool_keys=()):
    """Collect matchable ids per namespace: findings (rule ids), policy
    match ids, escalation ids, and changed tool keys."""
    targets = {
        "finding": set(),
        "policy": set(policy_ids or ()),
        "escalation": set(),
        "authority_change": set(changed_tool_keys or ()),
        "unspecified": set(),
    }
    for finding in findings or []:
        if finding.get("rule_id"):
            targets["finding"].add(str(finding["rule_id"]))
    for escalation in escalations or []:
        if escalation.get("id"):
            targets["escalation"].add(str(escalation["id"]))
    targets["unspecified"] = (
        targets["finding"] | targets["policy"] | targets["escalation"]
    )
    return targets


def evaluate_exceptions(entries, findings, escalations, policy_ids=(),
                         changed_tool_keys=(), project_identities=()):
    """Evaluate exception records against live scan evidence.

    Returns evaluation records: ``exception_id``, ``target_type``,
    ``target_id``, ``state`` (``active`` | ``expired`` | ``stale`` |
    ``scope-mismatch`` | ``invalid``), ``risk_owner``, ``expires_at``,
    and ``warnings``. States are never merged: a scope mismatch is not
    reported as stale, and an expired exception never reads as active.

    ``commit_range``, ``compensating_controls``, and ``review_trigger``
    are metadata-only: they are carried on the record but enforce
    nothing. ``project_identities`` is the set of identifiers the
    scanned project is known by (project id, directory name, remote
    fingerprint); repository scope is enforced only against these, and
    an absent identity is recorded — never treated as a match.

    ``scope_verified`` reports whether a declared repository scope could
    be checked: ``None`` when none was declared, ``True`` when it was
    checked against a known identity, ``False`` when one was declared and
    no identity was available. ``False`` means the entry stayed active
    without its scope being confirmed, which ``--strict-exceptions``
    refuses (#196).
    """
    live = _live_targets(findings, escalations, policy_ids, changed_tool_keys)
    evaluations = []
    for entry in entries:
        warnings = []
        target_type = entry.get("target_type", "unspecified")
        target_id = entry.get("target_id") or entry.get("finding_or_policy", "")
        label = f"{target_type}:{target_id}"
        if target_type not in ("unspecified",) + TARGET_TYPES:
            evaluations.append({
                "exception_id": entry.get("exception_id"),
                "target_type": target_type,
                "target_id": target_id,
                "state": "invalid",
                "risk_owner": entry.get("risk_owner"),
                "expires_at": entry.get("expires_at"),
                "compensating_controls": entry.get("compensating_controls") or [],
                "review_trigger": entry.get("review_trigger") or [],
                "scope_verified": None,
                "warnings": [
                    (
                        f"Exception {entry.get('exception_id')} has unknown target_type "
                        f"{target_type!r}; it can never activate."
                    )
                ],
            })
            continue
        matched = target_id in live.get(target_type, set())
        if entry.get("expired"):
            state = "expired"
            warnings.append(
                f"Exception {entry['exception_id']} ({label}) expired on "
                f"{entry.get('expires_at')} and no longer applies."
            )
        elif not matched:
            state = "stale"
            warnings.append(
                f"Exception {entry['exception_id']} ({label}) matches no current "
                f"target — the authority has shifted."
            )
        else:
            state = "active"
        # ``scope_verified`` is tri-state and deliberately separate from
        # ``state``: None when the entry declares no repository scope, True
        # when a declared scope was checked against a known identity, False
        # when one was declared and could not be checked at all.
        #
        # The False case is a fail-open. With no identity the evaluator cannot
        # tell an exception scoped to *this* project from one scoped to
        # somebody else's, so both stay active and suppress. The state is left
        # alone here to keep that long-standing behaviour, but the fact is now
        # recorded so --strict-exceptions can refuse it rather than the risk
        # staying invisible to the gate. See issue #196.
        scope_verified = None
        scope_repo = (entry.get("scope") or {}).get("repository")
        if scope_repo:
            identities = set(project_identities or ())
            if identities and scope_repo not in identities:
                scope_verified = True
                state = "scope-mismatch"
                warnings.append(
                    f"Exception {entry['exception_id']} scope repository "
                    f"{scope_repo!r} does not match the scanned project; "
                    f"it is not active here."
                )
            elif identities:
                scope_verified = True
            else:
                scope_verified = False
                warnings.append(
                    f"Exception {entry['exception_id']} scope repository "
                    f"{scope_repo!r} is unverified (no project identity); "
                    f"recorded, not enforced - it would suppress here even if "
                    f"it names another repository."
                )
        evaluations.append({
            "exception_id": entry["exception_id"],
            "target_type": target_type,
            "target_id": target_id,
            "state": state,
            "risk_owner": entry.get("risk_owner"),
            "expires_at": entry.get("expires_at"),
            "compensating_controls": entry.get("compensating_controls") or [],
            "review_trigger": entry.get("review_trigger") or [],
            "scope_verified": scope_verified,
            "warnings": warnings,
        })
    return evaluations
