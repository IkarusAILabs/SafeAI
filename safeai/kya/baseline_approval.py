"""Approval of the baseline manifest (v2.15, plan 2.15-3; ROADMAP P6).

The baseline is the approved static ceiling every authority change is
measured against, so who approved it matters as much as who approved an
exception. ``safeai manifest approve M --by X`` writes a record next to
the manifest (``M.approval.json``)::

    {"approval_type": "safeai-baseline-approval/v1",
     "manifest": {"name": "baseline.json", "payload_sha256": "<integrity digest>"},
     "baseline_owner": "platform-team@example.org",
     "approval": {"approved_by": "security-lead@example.org",
                  "approved_at": "2026-11-04", "escalation_owner": null}}

The record is bound to the manifest's integrity digest, so it stops
applying as soon as the baseline changes. A scan with ``--baseline M``
reads it (or ``--baseline-approval PATH``) and reports
``baseline_approval.state``:

* ``approved`` — an approver other than ``baseline_owner`` is recorded;
* ``self-approved`` — the approver is the baseline owner;
* ``unrecorded`` — no approval record;
* ``digest-mismatch`` — the record approves a different manifest;
* ``unverifiable`` — the baseline is not a manifest with a verifying
  integrity digest (a JSON report, or an edited manifest).

``--require-approval`` fails the scan unless the state is ``approved``.
The record is unsigned metadata, like an exception's approval block:
anyone who can edit the repository can edit it, which review of the
change that adds it is meant to catch.
"""

import json
import os

from safeai.kya.approval import ApprovalError, approval_state, parse_approval
from safeai.kya.integrity import OK, verify_document

APPROVAL_TYPE = "safeai-baseline-approval/v1"
BASELINE_APPROVAL_STATES = ("approved", "self-approved", "unrecorded", "digest-mismatch",
                            "unverifiable")


class BaselineApprovalError(ValueError):
    """Raised for a malformed approval record or an unapprovable manifest."""


def sidecar_path(manifest_path):
    return f"{manifest_path}.approval.json"


def build_record(manifest, manifest_name, approved_by, approved_at, escalation_owner=None,
                 owner=None):
    """An approval record for ``manifest``; refuses one whose digest does not verify."""
    status, detail = verify_document(manifest)
    if status != OK:
        raise BaselineApprovalError(f"{status}: {detail}; only a manifest whose integrity "
                                    "digest verifies can be approved")
    try:
        approval = parse_approval({"approved_by": approved_by, "approved_at": approved_at,
                                   "escalation_owner": escalation_owner})
    except ApprovalError as exc:
        raise BaselineApprovalError(str(exc)) from exc
    return {"approval_type": APPROVAL_TYPE,
            "manifest": {"name": manifest_name,
                         "payload_sha256": manifest["integrity"]["payload_sha256"]},
            "baseline_owner": (str(owner).strip() or None) if owner else None,
            "approval": approval}


def write_record(record, path):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")


def _load_record(path):
    with open(path, encoding="utf-8") as handle:
        record = json.load(handle)
    if not isinstance(record, dict) or record.get("approval_type") != APPROVAL_TYPE:
        raise BaselineApprovalError(f"{path}: not a {APPROVAL_TYPE} record")
    try:
        approval = parse_approval(record.get("approval"))
    except ApprovalError as exc:
        raise BaselineApprovalError(f"{path}: {exc}") from exc
    if approval is None:
        raise BaselineApprovalError(f"{path}: 'approval' is required")
    digest = (record.get("manifest") or {}).get("payload_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise BaselineApprovalError(f"{path}: 'manifest.payload_sha256' is required")
    return dict(record, approval=approval)


def evaluate(baseline_path, baseline_doc, approval_path=None):
    """``baseline_approval`` section for the scan's baseline (see module docstring).

    ``approval_path`` defaults to the sidecar; a missing default sidecar is
    ``unrecorded``, a missing explicit path or a malformed record raises.
    """
    explicit = approval_path is not None
    path = approval_path or sidecar_path(baseline_path)
    section = {"state": "unrecorded", "approval": None, "baseline_owner": None,
               "approved_payload_sha256": None, "baseline_payload_sha256": None,
               "record": None}
    status = "not-a-manifest"
    if isinstance(baseline_doc, dict):
        status, _detail = verify_document(baseline_doc)
        section["baseline_payload_sha256"] = (baseline_doc.get("integrity") or {}).get(
            "payload_sha256")
    if not explicit and not os.path.exists(path):
        if status != OK:
            section["state"] = "unverifiable"
        return section
    try:
        record = _load_record(path)
    except (OSError, ValueError) as exc:
        raise BaselineApprovalError(f"baseline approval: {exc}") from exc
    section.update(record=os.path.basename(path), approval=record["approval"],
                   baseline_owner=record.get("baseline_owner"),
                   approved_payload_sha256=record["manifest"]["payload_sha256"])
    if status != OK:
        section["state"] = "unverifiable"
    elif record["manifest"]["payload_sha256"] != section["baseline_payload_sha256"]:
        section["state"] = "digest-mismatch"
    else:
        section["state"] = approval_state(record["approval"], record.get("baseline_owner"))
    return section
