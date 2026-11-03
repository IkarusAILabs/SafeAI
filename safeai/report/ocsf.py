"""File-only OCSF export of findings and authority changes (v2.13, plan 2.13-1; ROADMAP B4).

``safeai scan --ocsf PATH`` (or ``safeai manifest export M --format ocsf``)
writes one OCSF 1.9.0 event per line (JSON Lines), built from the
manifest so paths are repository-relative and the output is a pure
function of the manifest:

* each finding is an **Application Security Posture Finding**
  (``class_uid`` 2007);
* each tool authority change other than ``NO_CHANGE`` is an **IAM
  Analysis Finding** (``class_uid`` 2008): the tool is analysed for what
  it may do, and its current capabilities are the granted privileges.

Nothing is sent anywhere. Fields OCSF has no attribute for (rule ID,
provenance class, gateability, change types, escalations) are kept
under ``unmapped.safeai``. SafeAI emits no risk score, so the OCSF
``risk_*`` attributes stay unset. The events validate against the OCSF
1.9.0 class schemas vendored in ``schemas/ocsf/1.9.0/`` (no profiles);
see ``docs/exports/OCSF.md``.
"""

import hashlib

from safeai.report.exports import epoch_seconds

OCSF_VERSION = "1.9.0"
FINDINGS_CATEGORY_UID = 2
ASPF_CLASS_UID = 2007
IAM_ANALYSIS_CLASS_UID = 2008
ACTIVITY_CREATE = 1

#: SafeAI severity -> OCSF ``severity_id``.
SEVERITY_IDS = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
#: Change class -> OCSF ``severity_id`` when no escalation is higher.
CHANGE_CLASS_SEVERITY_IDS = {"LOW_CHANGE": 2, "MATERIAL_CHANGE": 3,
                             "HIGH_RISK_CHANGE": 4, "UNKNOWN": 0}
CONFIDENCE_IDS = {"low": 1, "medium": 2, "high": 3}
STATUS_SUPPRESSED = 3



def _uid(*parts):
    return hashlib.sha256("\n".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def _metadata(manifest, event_uid):
    safeai = manifest.get("safeai") or {}
    scan = manifest.get("scan") or {}
    return {
        "version": OCSF_VERSION,
        "product": {"name": "SafeAI", "vendor_name": "IkarusAILabs",
                    "version": str(safeai.get("version") or "")},
        "uid": event_uid,
        "correlation_uid": str(scan.get("scan_id") or ""),
        "profiles": [],
    }


def _application(manifest):
    project = manifest.get("project") or {}
    app = {"uid": str(project.get("project_id") or "unknown")}
    if project.get("name"):
        app["name"] = str(project["name"])
    return app


def _envelope(class_uid, class_name, manifest, event_uid, severity_id, time_ms):
    return {
        "activity_id": ACTIVITY_CREATE,
        "activity_name": "Create",
        "category_uid": FINDINGS_CATEGORY_UID,
        "category_name": "Findings",
        "class_uid": class_uid,
        "class_name": class_name,
        "type_uid": class_uid * 100 + ACTIVITY_CREATE,
        "severity_id": severity_id,
        "time": time_ms,
        "metadata": _metadata(manifest, event_uid),
    }


def finding_event(finding, manifest, time_ms):
    location = finding.get("location") or {}
    fingerprint = str(finding.get("fingerprint") or finding.get("finding_id") or "")
    event = _envelope(ASPF_CLASS_UID, "Application Security Posture Finding", manifest,
                      _uid("finding", fingerprint), SEVERITY_IDS.get(finding.get("severity"), 0),
                      time_ms)
    title = str(finding.get("title") or finding.get("message") or finding.get("rule_id") or "")
    event["finding_info"] = {"uid": fingerprint or event["metadata"]["uid"], "title": title,
                             "types": [str(finding.get("rule_id") or "")]}
    if finding.get("message"):
        event["message"] = str(finding["message"])
        event["finding_info"]["desc"] = str(finding["message"])
    event["application"] = _application(manifest)
    if location.get("path"):
        event["resources"] = [{"type": "file", "name": str(location["path"]),
                               "uid": str(location["path"])}]
    if finding.get("remediation"):
        event["remediation"] = {"desc": str(finding["remediation"])}
    confidence = CONFIDENCE_IDS.get(str(finding.get("confidence") or "").lower())
    if confidence:
        event["confidence_id"] = confidence
    if finding.get("status") == "suppressed":
        event["status_id"] = STATUS_SUPPRESSED
    event["unmapped"] = {"safeai": {
        "rule_id": finding.get("rule_id"),
        "status": finding.get("status"),
        "provenance_class": finding.get("provenance_class"),
        "gateability": finding.get("gateability"),
        "line_start": location.get("line_start"),
        "line_end": location.get("line_end"),
    }}
    return event


def change_event(change, manifest, time_ms, surface, escalations):
    tool_key = str(change.get("tool_key") or "")
    change_class = change.get("change_class")
    change_types = sorted(change.get("change_types") or [])
    project_id = (manifest.get("project") or {}).get("project_id")
    tool_escalations = sorted(
        ({k: e.get(k) for k in ("id", "severity", "before", "after", "summary")}
         for e in escalations if e.get("tool_key") == tool_key),
        key=lambda e: (str(e["id"]), str(e["summary"])))
    severity_id = max([CHANGE_CLASS_SEVERITY_IDS.get(change_class, 0)]
                      + [SEVERITY_IDS.get(e["severity"], 0) for e in tool_escalations])
    finding_uid = _uid("authority-change", project_id, tool_key, change_class, *change_types)
    event = _envelope(IAM_ANALYSIS_CLASS_UID, "IAM Analysis Finding", manifest,
                      _uid("authority-change-event", finding_uid,
                           (manifest.get("integrity") or {}).get("payload_sha256")),
                      severity_id, time_ms)
    title = f"Authority change on {tool_key}: {change_class}"
    event["finding_info"] = {"uid": finding_uid, "title": title, "types": change_types}
    if tool_escalations:
        event["finding_info"]["desc"] = "; ".join(str(e["summary"]) for e in tool_escalations)
    event["message"] = title
    event["applications"] = [_application(manifest)]
    entry = surface.get(tool_key) or {}
    tool = entry.get("tool") or {}
    privileges = sorted({f"{c.get('name')}:{c.get('access_mode')}"
                         for c in entry.get("capabilities") or []})
    policy = {"name": tool_key}
    if tool.get("kind"):
        policy["type"] = str(tool["kind"])
    event["permission_analysis_results"] = [{"policy": policy, "granted_privileges": privileges}]
    event["unmapped"] = {"safeai": {
        "tool_key": tool_key,
        "change_class": change_class,
        "change_types": change_types,
        "status": change.get("status"),
        "inferred_only": bool(change.get("inferred_only")),
        "escalations": tool_escalations,
    }}
    return event


def build_events(manifest):
    """All OCSF events for ``manifest``: findings first, then authority changes."""
    time_ms = 1000 * epoch_seconds((manifest.get("scan") or {}).get("completed_at"))
    surface = {t.get("tool_key"): t for t in manifest.get("tool_surface") or []}
    escalations = manifest.get("escalations") or []
    findings = sorted(manifest.get("findings") or [],
                      key=lambda f: str(f.get("fingerprint") or f.get("finding_id") or ""))
    changes = sorted((c for c in manifest.get("authority_changes") or []
                      if c.get("change_class") != "NO_CHANGE"),
                     key=lambda c: str(c.get("tool_key")))
    return ([finding_event(f, manifest, time_ms) for f in findings]
            + [change_event(c, manifest, time_ms, surface, escalations) for c in changes])

