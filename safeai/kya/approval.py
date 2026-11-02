"""Approval metadata on exceptions and suppressions (v2.12, plan 2.12-3).

An exception (``.safeai/exceptions.yml``) or a suppression
(``.safeai/suppressions.yml``) is a decision somebody took. The optional
``approval`` block records who approved it, when, and who it escalates
to when it lapses::

    approval:
      approved_by: security-lead@example.org    # required in the block
      approved_at: 2026-10-30                   # required, ISO date
      escalation_owner: ciso@example.org        # optional

The expiry stays where it already is (``expires_at`` on an exception,
``expires`` on a suppression). The block is metadata: it never changes an
exception's state or whether a suppression applies. What it adds is an
``approval_state`` per decision:

* ``approved`` — an approver other than the owner is recorded;
* ``self-approved`` — the approver is the risk owner (or suppression
  owner), so nobody independent signed off;
* ``unrecorded`` — no approval block.

``--require-approval`` turns an active decision whose state is not
``approved`` into a scan failure. A malformed block (missing approver,
non-ISO or future date, approval after expiry) is a load error, like any
other malformed entry: silent exceptions are never permitted.
"""

from datetime import UTC, date, datetime

from safeai.kya.contract import APPROVAL_STATES  # noqa: F401  (single source)


class ApprovalError(ValueError):
    """Raised for a malformed ``approval`` block; callers re-raise as their own error."""


def _iso_date(value, field):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ApprovalError(
            f"approval.{field} must be an ISO date (YYYY-MM-DD), got {value!r}") from exc


def parse_approval(raw, expires=None, today=None):
    """Validate an ``approval`` block. Returns a normalized dict or ``None``.

    ``expires`` is the decision's own expiry date (or ``None``); an
    approval dated after it is rejected, as is one dated in the future.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ApprovalError("'approval' must be a mapping")
    unknown = sorted(set(raw) - {"approved_by", "approved_at", "escalation_owner"})
    if unknown:
        raise ApprovalError(f"'approval' has unknown field(s): {', '.join(unknown)}")
    approver = str(raw.get("approved_by") or "").strip()
    if not approver:
        raise ApprovalError("approval.approved_by is required")
    if not raw.get("approved_at"):
        raise ApprovalError("approval.approved_at is required")
    approved_at = _iso_date(raw["approved_at"], "approved_at")
    today = today or datetime.now(UTC).date()
    if approved_at > today:
        raise ApprovalError(
            f"approval.approved_at {approved_at.isoformat()} is in the future")
    if expires is not None and approved_at > expires:
        raise ApprovalError(
            f"approval.approved_at {approved_at.isoformat()} is after the expiry "
            f"{expires.isoformat()}")
    escalation = str(raw.get("escalation_owner") or "").strip() or None
    return {"approved_by": approver, "approved_at": approved_at.isoformat(),
            "escalation_owner": escalation}


def approval_state(approval, owner):
    """``approved``, ``self-approved`` or ``unrecorded`` (see module docstring)."""
    if not approval:
        return "unrecorded"
    if str(approval.get("approved_by", "")).strip().lower() == str(owner or "").strip().lower():
        return "self-approved"
    return "approved"
