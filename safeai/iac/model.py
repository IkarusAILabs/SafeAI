"""Authority graph model for IaC evidence (v2.5 redesign).

Entities (all plain dicts — JSON-serializable, deterministic):

- **Identity**: ``{kind, name, namespace, source_ref}`` where ``kind`` is
  ``aws_iam_role`` or ``kubernetes_service_account`` (plus
  ``kubernetes_user`` / ``kubernetes_group`` where statically evidenced).
- **Grant**: ``{identity, actions, resources, scope, source, source_file,
  line, provenance, fidelity}`` where ``actions``/``resources`` are
  ``{values, resolution}`` with resolution in
  ``resolved | partially-resolved | unresolved``.
- **GrantBinding**: ``{identity, binding_kind, binding_name, role,
  grant_index?, source_file, line}`` — the evidenced relationship chain
  (Role → policy → statement; ServiceAccount → Binding → Role → rule).
- **AgentIdentityLink**: ``{agent, identity, link_type, confidence,
  evidence}`` — explicit repository evidence only (see
  ``safeai.iac.linking``); never string coincidence.
- **Verdict**: ``{agent_ref, identity_ref, domain, verdict,
  declared_evidence_refs, grant_evidence_refs, link_evidence_refs,
  resolution, reason}``.

Resolution vocabulary (per-field, ADR-0006 refined):

- ``resolved`` — literal value, fully visible statically.
- ``partially-resolved`` — value visible but contains unresolvable parts
  (interpolation, wildcards are *observed* and therefore resolved —
  breadth is not uncertainty; only *unknown content* degrades).
- ``unresolved`` — value comes from a module, external file, dynamic
  block, ``for_each``/``count`` expansion, or generated configuration.

Wildcards (``*``) are resolved-observed breadth, flagged in
``fidelity`` (``wildcard-action`` / ``wildcard-resource`` /
``admin-wildcard``), never confused with unresolved content.
"""

#: Per-field resolution states.
RESOLVED = "resolved"
PARTIALLY_RESOLVED = "partially-resolved"
UNRESOLVED = "unresolved"
RESOLUTIONS = (RESOLVED, PARTIALLY_RESOLVED, UNRESOLVED)

#: Identity kinds with IaC collectors in v2.5.
IDENTITY_KINDS = (
    "aws_iam_role",
    "kubernetes_service_account",
    "kubernetes_user",
    "kubernetes_group",
)

#: Agent→Identity link types (explicit evidence only).
LINK_TYPES = (
    "workload-service-account",
    "explicit-config-reference",
)

#: Correlation verdict vocabulary (public, stable).
VERDICTS = ("MATCH", "EXCESS_AUTHORITY", "AUTHORITY_MISMATCH",
            "UNVERIFIED_LINK", "UNKNOWN")

#: Repo-level agent ref used when the link evidence is workload/config
#: scoped rather than tool scoped.
REPO_AGENT_REF = "<repo>"


def identity(kind, name, namespace="", source_ref=""):
    """Build an Identity record (never raises on odd input)."""
    return {
        "kind": str(kind or "unknown"),
        "name": str(name or "<unnamed>"),
        "namespace": str(namespace or ""),
        "source_ref": str(source_ref or ""),
    }


def identity_key(identity):
    """Stable key: kind + namespace + name (namespaces isolate)."""
    ident = identity or {}
    return (str(ident.get("kind") or ""), str(ident.get("namespace") or ""),
            str(ident.get("name") or ""))


def field(values, resolution, notes=None):
    """Build a resolved-state field ``{values, resolution, notes}``."""
    return {
        "values": list(values or []),
        "resolution": resolution if resolution in RESOLUTIONS else UNRESOLVED,
        "notes": list(notes or []),
    }


def grant(identity_ref, actions, resources, scope="", source="",
          source_file="", line=1, provenance="repo-iac-observed",
          fidelity=None, family=""):
    """Build a Grant record bound to an identity reference."""
    return {
        "identity": identity_ref,
        "actions": actions if isinstance(actions, dict) else field(actions, RESOLVED),
        "resources": (resources if isinstance(resources, dict)
                      else field(resources, RESOLVED)),
        "scope": str(scope or ""),
        "source": str(source or ""),
        "source_file": str(source_file or ""),
        "line": int(line or 0),
        "provenance": str(provenance or "repo-iac-observed"),
        "fidelity": list(fidelity or []),
        "family": str(family or ""),
    }


def grant_binding(identity_ref, binding_kind="", binding_name="", role="",
                  source_file="", line=1, notes=None):
    """Build a GrantBinding chain link (identity → binding → role)."""
    return {
        "identity": identity_ref,
        "binding_kind": str(binding_kind or ""),
        "binding_name": str(binding_name or ""),
        "role": str(role or ""),
        "source_file": str(source_file or ""),
        "line": int(line or 0),
        "notes": list(notes or []),
    }


def agent_link(agent, identity_ref, link_type, confidence, evidence):
    """Build an AgentIdentityLink (explicit evidence required)."""
    return {
        "agent": str(agent or REPO_AGENT_REF),
        "identity": identity_ref,
        "link_type": str(link_type or ""),
        "confidence": str(confidence or ""),
        "evidence": list(evidence or []),
    }


def verdict(agent_ref, identity_ref, domain, name, declared_refs=None,
            grant_refs=None, link_refs=None, resolution=RESOLVED, reason=""):
    """Build a correlation verdict with full evidence refs."""
    return {
        "agent_ref": str(agent_ref or REPO_AGENT_REF),
        "identity_ref": identity_ref,
        "domain": str(domain or ""),
        "verdict": str(name or "UNKNOWN"),
        "declared_evidence_refs": list(declared_refs or []),
        "grant_evidence_refs": list(grant_refs or []),
        "link_evidence_refs": list(link_refs or []),
        "resolution": resolution if resolution in RESOLUTIONS else UNRESOLVED,
        "reason": str(reason or ""),
    }
