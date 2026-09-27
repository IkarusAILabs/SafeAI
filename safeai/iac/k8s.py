"""Kubernetes RBAC authority extraction (v2.5 redesign).

Reads repository YAML documents and constructs the explicit RBAC
authority chain::

    ServiceAccount
      -> RoleBinding / ClusterRoleBinding
        -> Role / ClusterRole
          -> rule (verbs + resources)

Namespace rules are respected: RoleBindings resolve Roles in their own
namespace; subjects match ServiceAccounts by (name, namespace); a
subject without a namespace matches only a uniquely-named
ServiceAccount, otherwise the chain is left unbuilt (ambiguous — never
guessed). Duplicate role names across namespaces stay isolated by
(namespaced) keys.

Workload manifests (Deployment, StatefulSet, DaemonSet, Job, CronJob,
Pod, ReplicaSet) contribute ``workload_refs`` — ``serviceAccountName``
references used by the identity-link resolver. Only in-repo YAML is
read (never the cluster API); ``line`` is a best-effort text search
for the object name, since PyYAML discards positions.
"""

import yaml

from safeai.iac.model import (
    RESOLVED,
    field,
    grant,
    grant_binding,
    identity,
)

#: RBAC object kinds with authority meaning.
_ROLE_KINDS = {"Role", "ClusterRole"}
_BINDING_KINDS = {"RoleBinding", "ClusterRoleBinding"}

#: Workload kinds carrying a service-account reference.
_WORKLOAD_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
    "Pod", "ReplicaSet", "ReplicationController",
}

_MAX_DOCS_PER_FILE = 200


def _best_effort_line(text, name):
    """Line number of the first ``name: <name>`` occurrence, else 1."""
    try:
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("name:"):
                value = stripped[len("name:"):].strip().strip("\"'")
                if value == name:
                    return i
    except Exception:
        pass
    return 1


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _wildcard_notes(values):
    notes = []
    if any(v == "*" for v in values):
        notes.append("admin-wildcard")
    elif any("*" in v for v in values):
        notes.append("wildcard-pattern")
    return notes


def _workload_service_account(doc):
    """Extract (service_account, namespace_hint) from a workload doc."""
    spec = doc.get("spec") or {}
    if not isinstance(spec, dict):
        return None, ""
    if doc.get("kind") == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
        if not isinstance(spec, dict):
            return None, ""
    pod_spec = spec.get("template", spec).get("spec", spec) \
        if isinstance(spec.get("template"), dict) else spec
    if not isinstance(pod_spec, dict):
        pod_spec = spec
    for key in ("serviceAccountName", "serviceAccount"):
        value = pod_spec.get(key)
        if value:
            return str(value), ""
    return None, ""


def parse_k8s_file(rel_path, text):
    """Extract ``(identities, grants, grant_bindings, workload_refs, meta)``.

    ``rel_path`` is the root-relative forward-slash path. Never raises:
    unparseable or non-RBAC content yields empty collections (with
    ``meta["unparsed"]`` on YAML failure).
    """
    identities, grants, bindings = [], [], []
    workloads = []
    meta = {"unparsed": False}
    try:
        docs = [d for d in list(yaml.safe_load_all(text))[:_MAX_DOCS_PER_FILE]
                if isinstance(d, dict)]
    except Exception:
        meta["unparsed"] = True
        return identities, grants, bindings, workloads, meta

    service_accounts = {}
    roles = {}
    binding_docs = []
    for doc in docs:
        kind = doc.get("kind")
        meta_doc = doc.get("metadata") or {}
        if not isinstance(meta_doc, dict):
            meta_doc = {}
        name = str(meta_doc.get("name") or "<unnamed>")
        namespace = str(meta_doc.get("namespace") or "")
        line = _best_effort_line(text, name)
        ref = f"{rel_path}:{line}"
        if kind == "ServiceAccount":
            key = ("ServiceAccount", namespace, name)
            service_accounts[key] = identity(
                "kubernetes_service_account", name,
                namespace=namespace, source_ref=ref)
        elif kind in _ROLE_KINDS:
            scope = namespace if kind == "Role" else "*"
            roles[(kind, namespace if kind == "Role" else "", name)] = {
                "rules": [r for r in doc.get("rules") or []
                          if isinstance(r, dict)],
                "scope": scope,
                "ref": ref,
            }
        elif kind in _BINDING_KINDS:
            binding_docs.append((doc, name, namespace, line, ref))
        elif kind in _WORKLOAD_KINDS:
            sa_name, _ = _workload_service_account(doc)
            if sa_name:
                workloads.append({
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "service_account": sa_name,
                    "source_file": rel_path,
                    "line": line,
                })

    identities.extend(sorted(
        service_accounts.values(), key=lambda i: (i["namespace"], i["name"])))

    for doc, binding_name, binding_ns, line, _ref in binding_docs:
        kind = doc.get("kind")
        ref = doc.get("roleRef") or {}
        role_kind = str(ref.get("kind") or "Role")
        role_name = str(ref.get("name") or "")
        subjects = [s for s in doc.get("subjects") or []
                    if isinstance(s, dict)]
        role_key = (role_kind, binding_ns if role_kind == "Role" else "",
                    role_name)
        role = roles.get(role_key)
        for subject in subjects:
            subject_kind = str(subject.get("kind") or "")
            subject_name = str(subject.get("name") or "")
            subject_ns = str(subject.get("namespace") or "")
            if subject_kind != "ServiceAccount" or not subject_name:
                continue
            candidates = [
                key for key in service_accounts
                if key[2] == subject_name
                and (subject_ns == key[1] or
                     (not subject_ns and _unique_sa_name(
                         service_accounts, subject_name)))
            ]
            identity_ref = {"kind": "kubernetes_service_account",
                            "name": subject_name,
                            "namespace": subject_ns or binding_ns}
            notes = []
            if len(candidates) != 1:
                notes.append("ambiguous-subject-namespace"
                             if candidates else "subject-not-in-repo")
            bindings.append(grant_binding(
                identity_ref, binding_kind=kind,
                binding_name=binding_name,
                role=f"{role_kind}/{role_name}",
                source_file=rel_path, line=line, notes=notes))
            if len(candidates) != 1 or role is None:
                continue
            for rule in role["rules"]:
                verbs = _as_list(rule.get("verbs"))
                resources = _as_list(rule.get("resources"))
                actions = field(verbs or ["*"], RESOLVED,
                                _wildcard_notes(verbs))
                res_field = field(resources or ["*"], RESOLVED,
                                  _wildcard_notes(resources))
                if not verbs or not resources:
                    actions["notes"].append("empty-rule-clause")
                    res_field["notes"].append("empty-rule-clause")
                grants.append(grant(
                    identity_ref, actions, res_field, scope=role["scope"],
                    source="kubernetes", source_file=rel_path, line=line,
                    fidelity=(actions["notes"] + res_field["notes"]
                              + [f"via-{kind}:{binding_name}"]),
                    family="kubernetes"))
    return identities, grants, bindings, workloads, meta


def _unique_sa_name(service_accounts, name):
    """True when exactly one collected ServiceAccount carries ``name``."""
    return sum(1 for key in service_accounts if key[2] == name) == 1
