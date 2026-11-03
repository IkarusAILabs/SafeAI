"""File-only SSF Security Event Token payloads (v2.13, plan 2.13-2; ROADMAP B4).

``safeai scan --ssf-set PATH`` (or ``safeai manifest export M --format
ssf-set``) writes one SET claims set (RFC 8417) per line for every tool
authority change classed ``MATERIAL_CHANGE`` or ``HIGH_RISK_CHANGE``.
The payloads follow the OpenID Shared Signals Framework 1.0: a top-level
``sub_id`` (RFC 9493 ``opaque`` format), one event per SET, no ``sub``
and no ``exp``.

**No transmission, no signing.** Community Edition writes the claims
sets to a file. Signing them as JWTs (header ``typ: secevent+jwt``) and
delivering them to a receiver is the user's pipeline (RFC 8417 requires
integrity protection for any SET that leaves the file).

**Event type.** No CAEP 1.0 event type describes a repository change
that widens an agent tool's static authority: ``risk-level-change``
would need a risk level SafeAI does not emit, and
``token-claims-change`` / ``credential-change`` describe runtime
credentials. The event type is therefore SafeAI's own, experimental,
documented at its URI (``docs/exports/ssf-agent-authority-change-v0.1-experimental.md``).

Every claim is derived from the manifest, so the same manifest gives
the same payloads: ``iat`` is the scan completion time, ``jti`` a digest
of the manifest digest and the tool, ``txn`` the scan ID.
"""

import hashlib

from safeai.report.exports import epoch_seconds

EVENT_TYPE = ("https://github.com/IkarusAILabs/SafeAI/blob/main/docs/exports/"
              "ssf-agent-authority-change-v0.1-experimental.md")
EVENT_VERSION = "0.1-experimental"
EXPORTED_CHANGE_CLASSES = ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")



def default_issuer(manifest):
    project_id = (manifest.get("project") or {}).get("project_id") or "unknown"
    return f"urn:safeai:project:{project_id}"


def _event(change, manifest, when, surface, escalations):
    tool_key = str(change.get("tool_key") or "")
    tool = (surface.get(tool_key) or {}).get("tool") or {}
    tool_escalations = sorted(
        ({k: e.get(k) for k in ("id", "severity", "before", "after", "summary")}
         for e in escalations if e.get("tool_key") == tool_key),
        key=lambda e: (str(e["id"]), str(e["summary"])))
    repository = (manifest.get("project") or {}).get("repository") or {}
    reason = f"Tool {tool_key}: {change.get('change_class')}"
    if tool_escalations:
        reason += " (" + "; ".join(str(e["summary"]) for e in tool_escalations) + ")"
    return {
        "event_version": EVENT_VERSION,
        "event_timestamp": when,
        "change_class": change.get("change_class"),
        "change_types": sorted(change.get("change_types") or []),
        "status": change.get("status"),
        "inferred_only": bool(change.get("inferred_only")),
        "tool": {"key": tool_key, "kind": tool.get("kind"), "name": tool.get("name"),
                 "framework": tool.get("framework")},
        "escalations": tool_escalations,
        "evidence": {
            "manifest_payload_sha256": (manifest.get("integrity") or {}).get("payload_sha256"),
            "commit_sha": repository.get("commit_sha"),
        },
        "reason_admin": {"en": reason},
    }


def build_payloads(manifest, issuer=None, audience=None):
    """SET claims sets for the manifest's MATERIAL / HIGH_RISK authority changes."""
    scan = manifest.get("scan") or {}
    when = epoch_seconds(scan.get("completed_at"))
    digest = (manifest.get("integrity") or {}).get("payload_sha256") or ""
    project_id = (manifest.get("project") or {}).get("project_id") or "unknown"
    surface = {t.get("tool_key"): t for t in manifest.get("tool_surface") or []}
    escalations = manifest.get("escalations") or []
    payloads = []
    for change in sorted((c for c in manifest.get("authority_changes") or []
                          if c.get("change_class") in EXPORTED_CHANGE_CLASSES),
                         key=lambda c: str(c.get("tool_key"))):
        tool_key = str(change.get("tool_key") or "")
        claims = {
            "iss": issuer or default_issuer(manifest),
            "iat": when,
            "jti": hashlib.sha256(f"{digest}\n{tool_key}".encode()).hexdigest(),
            "txn": str(scan.get("scan_id") or ""),
            "sub_id": {"format": "opaque", "id": f"{project_id}:{tool_key}"},
            "events": {EVENT_TYPE: _event(change, manifest, when, surface, escalations)},
        }
        if audience:
            claims["aud"] = audience[0] if len(audience) == 1 else list(audience)
        payloads.append(claims)
    return payloads

