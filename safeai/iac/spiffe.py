"""Static SPIFFE workload-identity evidence (v2.10, ROADMAP S1/S3).

Answers one question from repository YAML: *which SPIFFE ID would each
workload be issued, and who is declared allowed to call it?* Nothing
is contacted: no SPIRE server, no cluster API, no trust bundle.

Sources read:

* ``ClusterSPIFFEID`` (``spire.spiffe.io``): ``spiffeIDTemplate``,
  ``podSelector``, ``namespaceSelector``, ``federatesWith``;
* ``ClusterFederatedTrustDomain``: federated trust domains and their
  bundle endpoints;
* the SPIRE controller manager's ``ControllerManagerConfig`` (as its own
  document or inside a ConfigMap): ``trustDomain``, ``clusterName``,
  ``clusterDomain``, ``ignoreNamespaces``;
* ``Namespace`` labels, for namespace selectors;
* workload manifests (pod template labels, service account, and the
  *names* of credentials the pod is handed);
* Istio ``AuthorizationPolicy``: ``source.principals`` as declared
  callers of the selected workloads.

The chain is workload → ServiceAccount → SPIFFE ID. A template is
rendered per matched workload; a field that cannot be known statically
(a generated pod name, a trust domain set outside the repository)
leaves the ID ``partially-resolved`` with the placeholder kept. A
selector that cannot be evaluated (namespace labels not in the
repository, an unknown operator, a workload with no namespace) creates
no assignment: the workload's identity stays ``unknown``, recorded with
the reason. Credential values are never read into a record.
"""

import re

import yaml

from safeai.iac.k8s import _best_effort_line
from safeai.iac.model import (
    PARTIALLY_RESOLVED,
    REPO_AGENT_REF,
    RESOLVED,
    UNRESOLVED,
    agent_link,
    identity,
)

#: Workload kinds whose pod template is read.
_WORKLOAD_KINDS = frozenset({
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
    "Pod", "ReplicaSet", "ReplicationController",
})

#: SPIRE controller manager's default ``ignoreNamespaces``.
DEFAULT_IGNORED_NAMESPACES = ("kube-system", "kube-public", "spire-system")

#: Istio's default root namespace: a selector-less policy there is mesh-wide.
ISTIO_ROOT_NAMESPACE = "istio-system"

#: Label every namespace carries (Kubernetes >= 1.21).
_NAMESPACE_NAME_LABEL = "kubernetes.io/metadata.name"

_MAX_DOCS_PER_FILE = 200

_PLACEHOLDER_RE = re.compile(r"\{\{\s*(.*?)\s*\}\}")
_INDEX_RE = re.compile(r'^index\s+\.PodMeta\.(Labels|Annotations)\s+"([^"]+)"$')

#: Environment variable names that hold a credential when set literally.
_CREDENTIAL_NAME_RE = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY(?:_ID)?|"
    r"PRIVATE_KEY|CREDENTIALS?|AUTH)(?:$|_)")

#: Static-credential rule (Lane B, review-only).
RULE_STATIC_CREDENTIAL = "IAC_STATIC_CREDENTIAL_WITH_WORKLOAD_IDENTITY"


def empty_collection():
    """Documents gathered across files, before resolution."""
    return {"registrations": [], "federations": [], "configs": [],
            "namespaces": {}, "workloads": [], "policies": []}


def _meta(doc):
    meta = doc.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _dict(value):
    return value if isinstance(value, dict) else {}


def _str_list(value):
    if isinstance(value, list):
        return [str(v) for v in value if v is not None and str(v)]
    if value is None or value == "":
        return []
    return [str(value)]


def _labels(value):
    return {str(k): str(v) for k, v in _dict(value).items()}


def _pod_template(doc):
    """Return ``(pod_metadata, pod_spec)`` for a workload document."""
    kind = doc.get("kind")
    spec = _dict(doc.get("spec"))
    if kind == "Pod":
        return _meta(doc), spec
    if kind == "CronJob":
        spec = _dict(_dict(spec.get("jobTemplate")).get("spec"))
    template = _dict(spec.get("template"))
    return _dict(template.get("metadata")), _dict(template.get("spec"))


def _credentials(pod_spec):
    """Credential *names* a pod is handed; values are never kept."""
    found = []
    containers = ([c for c in pod_spec.get("containers") or [] if isinstance(c, dict)]
                  + [c for c in pod_spec.get("initContainers") or []
                     if isinstance(c, dict)])
    for container in containers:
        cname = str(container.get("name") or "")
        for env in container.get("env") or []:
            if not isinstance(env, dict) or not env.get("name"):
                continue
            name = str(env["name"])
            secret_ref = _dict(_dict(env.get("valueFrom")).get("secretKeyRef"))
            if secret_ref:
                found.append({"name": name, "source": "secret",
                              "secret": str(secret_ref.get("name") or ""),
                              "container": cname})
            elif env.get("value") not in (None, "") and _CREDENTIAL_NAME_RE.search(
                    name.upper()):
                found.append({"name": name, "source": "literal", "secret": "",
                              "container": cname})
        for env_from in container.get("envFrom") or []:
            secret_ref = _dict(_dict(env_from).get("secretRef"))
            if secret_ref.get("name"):
                found.append({"name": str(secret_ref["name"]), "source": "secret-env",
                              "secret": str(secret_ref["name"]), "container": cname})
    for volume in pod_spec.get("volumes") or []:
        secret = _dict(_dict(volume).get("secret"))
        if secret.get("secretName"):
            found.append({"name": str(secret["secretName"]), "source": "secret-volume",
                          "secret": str(secret["secretName"]), "container": ""})
    found.sort(key=lambda c: (c["source"], c["name"], c["container"]))
    return found


def _config_from(doc):
    """A ControllerManagerConfig document, or one embedded in a ConfigMap."""
    if doc.get("kind") == "ControllerManagerConfig":
        return doc
    if doc.get("kind") != "ConfigMap":
        return None
    for value in _dict(doc.get("data")).values():
        if "ControllerManagerConfig" not in str(value):
            continue
        try:
            inner = yaml.safe_load(str(value))
        except Exception:
            continue
        if isinstance(inner, dict) and inner.get("kind") == "ControllerManagerConfig":
            return inner
    return None


def collect_file(collection, rel_path, text):
    """Add one YAML file's workload-identity documents to ``collection``.

    Never raises; unparseable YAML adds nothing (the RBAC pass already
    records the file as unparsed).
    """
    try:
        docs = [d for d in list(yaml.safe_load_all(text))[:_MAX_DOCS_PER_FILE]
                if isinstance(d, dict)]
    except Exception:
        return collection
    for doc in docs:
        kind = doc.get("kind")
        api = str(doc.get("apiVersion") or "")
        meta = _meta(doc)
        name = str(meta.get("name") or "<unnamed>")
        namespace = str(meta.get("namespace") or "")
        line = _best_effort_line(text, name)
        spec = _dict(doc.get("spec"))
        if kind == "ClusterSPIFFEID" and api.startswith("spire.spiffe.io"):
            collection["registrations"].append({
                "name": name,
                "template": str(spec.get("spiffeIDTemplate") or ""),
                "pod_selector": spec.get("podSelector"),
                "namespace_selector": spec.get("namespaceSelector"),
                "federates_with": sorted(_str_list(spec.get("federatesWith"))),
                "fallback": bool(spec.get("fallback")),
                "source_file": rel_path, "line": line,
            })
        elif kind == "ClusterFederatedTrustDomain" and api.startswith("spire.spiffe.io"):
            profile = _dict(spec.get("bundleEndpointProfile"))
            collection["federations"].append({
                "name": name,
                "trust_domain": str(spec.get("trustDomain") or ""),
                "bundle_endpoint_url": str(spec.get("bundleEndpointURL") or ""),
                "bundle_endpoint_profile": str(profile.get("type") or ""),
                "source_file": rel_path, "line": line,
            })
        elif kind == "Namespace":
            collection["namespaces"][name] = {
                "labels": _labels(meta.get("labels")),
                "source_file": rel_path, "line": line,
            }
        elif kind in _WORKLOAD_KINDS:
            pod_meta, pod_spec = _pod_template(doc)
            account = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
            collection["workloads"].append({
                "kind": kind, "name": name, "namespace": namespace,
                "service_account": str(account or "default"),
                "service_account_defaulted": not account,
                "labels": _labels(pod_meta.get("labels")),
                "annotations": _labels(pod_meta.get("annotations")),
                "credentials": _credentials(pod_spec),
                "source_file": rel_path, "line": line,
            })
        elif kind == "AuthorizationPolicy" and api.startswith("security.istio.io"):
            collection["policies"].append({
                "name": name, "namespace": namespace,
                "action": str(spec.get("action") or "ALLOW"),
                "selector": spec.get("selector"),
                "rules": [r for r in spec.get("rules") or [] if isinstance(r, dict)],
                "has_rules_key": "rules" in spec,
                "source_file": rel_path, "line": line,
            })
        else:
            config = _config_from(doc)
            if config is not None:
                collection["configs"].append({
                    "trust_domain": str(config.get("trustDomain") or ""),
                    "cluster_name": str(config.get("clusterName") or ""),
                    "cluster_domain": str(config.get("clusterDomain") or ""),
                    "ignore_namespaces": _str_list(config.get("ignoreNamespaces")),
                    "has_ignore_namespaces": "ignoreNamespaces" in config,
                    "source_file": rel_path, "line": line,
                })
    return collection


# --- selectors ---------------------------------------------------------------

def _selector_matches(selector, labels, complete=True):
    """Evaluate a Kubernetes label selector.

    Returns ``True``, ``False`` or ``None`` (cannot be decided). With
    ``complete=False`` only the namespace-name label is known, so any
    requirement on another key is undecidable.
    """
    if selector is None:
        return True
    if not isinstance(selector, dict):
        return None
    match_labels = selector.get("matchLabels") or {}
    expressions = selector.get("matchExpressions") or []
    if not isinstance(match_labels, dict) or not isinstance(expressions, list):
        return None

    def known(key):
        return complete or key == _NAMESPACE_NAME_LABEL

    undecided = False
    for key, value in match_labels.items():
        key = str(key)
        if not known(key):
            undecided = True
            continue
        if labels.get(key) != str(value):
            return False
    for expr in expressions:
        if not isinstance(expr, dict):
            return None
        key = str(expr.get("key") or "")
        operator = str(expr.get("operator") or "")
        values = {str(v) for v in expr.get("values") or []}
        if operator not in ("In", "NotIn", "Exists", "DoesNotExist"):
            return None
        if not known(key):
            undecided = True
            continue
        present = key in labels
        if operator == "In" and not (present and labels[key] in values):
            return False
        if operator == "NotIn" and present and labels[key] in values:
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
    return None if undecided else True


def _selects_everything(selector):
    if selector is None:
        return True
    if not isinstance(selector, dict):
        return False
    return not selector.get("matchLabels") and not selector.get("matchExpressions")


def _namespace_labels(namespace, namespaces):
    """``(labels, complete)`` for a namespace from repository evidence."""
    doc = namespaces.get(namespace)
    labels = dict(doc["labels"]) if doc else {}
    labels[_NAMESPACE_NAME_LABEL] = namespace
    return labels, doc is not None


# --- templates ---------------------------------------------------------------

def _render(template, workload, config):
    """Render a ``spiffeIDTemplate`` for one workload.

    Returns ``(spiffe_id, resolution, unresolved_fields)``.
    """
    if not template:
        return "", UNRESOLVED, ["spiffeIDTemplate"]
    unresolved = []

    def value_for(expr):
        if expr == ".TrustDomain":
            return config.get("trust_domain") or None
        if expr == ".ClusterName":
            return config.get("cluster_name") or None
        if expr == ".ClusterDomain":
            return config.get("cluster_domain") or None
        if expr == ".PodMeta.Namespace":
            return workload["namespace"] or None
        if expr == ".PodMeta.Name":
            # Controllers generate pod names; only a bare Pod names itself.
            return workload["name"] if workload["kind"] == "Pod" else None
        if expr == ".PodSpec.ServiceAccountName":
            return workload["service_account"]
        match = _INDEX_RE.match(expr)
        if match:
            source = workload["labels"] if match.group(1) == "Labels" \
                else workload["annotations"]
            return source.get(match.group(2))
        return None

    def substitute(match):
        expr = match.group(1)
        value = value_for(expr)
        if value is None:
            unresolved.append(expr)
            return match.group(0)
        return value

    rendered = _PLACEHOLDER_RE.sub(substitute, template)
    if not rendered.startswith("spiffe://"):
        return rendered, UNRESOLVED, sorted(set(unresolved)) or ["scheme"]
    if unresolved:
        return rendered, PARTIALLY_RESOLVED, sorted(set(unresolved))
    return rendered, RESOLVED, []


# --- Istio principals --------------------------------------------------------

def _principal_matches(pattern, value):
    """Istio string match: exact, ``*``, ``prefix*`` or ``*suffix``."""
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    if pattern.startswith("*"):
        return value.endswith(pattern[1:])
    return value == pattern


_PRINCIPAL_NS_SA_RE = re.compile(r"^[^/]+/ns/([^/]+)/sa/([^/]+)$")


def _workload_ref(workload):
    return f"{workload['kind']}/{workload['namespace'] or '?'}/{workload['name']}"


def _ref(record):
    return {"file": record["source_file"], "line": int(record["line"] or 1)}


def _policy_record(policy, workloads, assignments_by_workload):
    namespace = policy["namespace"]
    selector = policy["selector"]
    mesh_wide = namespace == ISTIO_ROOT_NAMESPACE and _selects_everything(selector)
    notes = []
    if mesh_wide:
        notes.append("mesh-wide (assumes the default root namespace istio-system)")
    targets = []
    for workload in workloads:
        if not mesh_wide and (not namespace or workload["namespace"] != namespace):
            continue
        if _selector_matches(selector, workload["labels"]) is not True:
            continue
        ref = _workload_ref(workload)
        targets.append({
            "workload": ref,
            "spiffe_ids": sorted({a["spiffe_id"] for a in
                                  assignments_by_workload.get(ref, [])}),
        })
    if not namespace:
        notes.append("policy namespace not in repository; targets not evaluated")

    principals = []
    breadth = []
    if policy["action"] == "ALLOW" and policy["has_rules_key"] and not policy["rules"]:
        notes.append("empty rules: ALLOW matches nothing")
    if policy["action"] == "ALLOW" and not policy["has_rules_key"]:
        notes.append("no rules: ALLOW matches nothing")
    for rule in policy["rules"]:
        sources = [_dict(_dict(f).get("source")) for f in rule.get("from") or []]
        if not sources and policy["action"] == "ALLOW":
            breadth.append("any-caller")
        for source in sources:
            for negated, key in ((False, "principals"), (True, "notPrincipals")):
                for principal in _str_list(source.get(key)):
                    if principal == "*" and not negated:
                        breadth.append("any-authenticated-caller")
                    principals.append(_principal_record(
                        principal, negated, workloads, assignments_by_workload))
            if source.get("requestPrincipals"):
                notes.append("requestPrincipals are end-user JWTs, not workload "
                             "identities; not mapped")
    principals.sort(key=lambda p: (p["principal"], p["negated"]))
    return {
        "name": policy["name"], "namespace": namespace, "action": policy["action"],
        "mesh_wide": mesh_wide, "targets": targets, "principals": principals,
        "breadth": sorted(set(breadth)), "notes": sorted(set(notes)),
        "source_file": policy["source_file"], "line": policy["line"],
    }


def _principal_record(principal, negated, workloads, assignments_by_workload):
    spiffe_pattern = "spiffe://" + principal if principal != "*" else "*"
    callers = []
    for workload in workloads:
        ref = _workload_ref(workload)
        for assignment in assignments_by_workload.get(ref, []):
            if assignment["resolution"] == RESOLVED and _principal_matches(
                    spiffe_pattern, assignment["spiffe_id"]):
                callers.append({"workload": ref, "spiffe_id": assignment["spiffe_id"],
                                "basis": "spiffe-assignment"})
    match = _PRINCIPAL_NS_SA_RE.match(principal)
    if match:
        namespace, account = match.groups()
        matched = {c["workload"] for c in callers}
        for workload in workloads:
            ref = _workload_ref(workload)
            if (ref not in matched and workload["namespace"] == namespace
                    and workload["service_account"] == account):
                callers.append({"workload": ref, "spiffe_id": "",
                                "basis": "istio-ns-sa-convention"})
    callers.sort(key=lambda c: (c["workload"], c["basis"]))
    return {"principal": principal, "negated": negated,
            "spiffe_pattern": spiffe_pattern, "callers": callers}


# --- resolution --------------------------------------------------------------

def _effective_config(configs):
    """One controller-manager config, or an empty one with a note."""
    if not configs:
        return ({"trust_domain": "", "cluster_name": "", "cluster_domain": "",
                 "ignore_namespaces": list(DEFAULT_IGNORED_NAMESPACES),
                 "source": None},
                [("no ControllerManagerConfig in repository: trust domain unknown, "
                  "default ignoreNamespaces assumed")])
    ordered = sorted(configs, key=lambda c: (c["source_file"], c["line"]))
    first = ordered[0]
    notes = []
    if len({(c["trust_domain"], c["cluster_name"]) for c in ordered}) > 1:
        # Two configs disagree: which one the cluster runs is not static.
        notes.append("conflicting ControllerManagerConfig documents: trust domain "
                     "treated as unknown")
        first = dict(first, trust_domain="", cluster_name="", cluster_domain="")
    ignore = (first["ignore_namespaces"] if first["has_ignore_namespaces"]
              else list(DEFAULT_IGNORED_NAMESPACES))
    return ({"trust_domain": first["trust_domain"], "cluster_name": first["cluster_name"],
             "cluster_domain": first["cluster_domain"], "ignore_namespaces": ignore,
             "source": _ref(first)}, notes)


def resolve_workload_identity(collection):
    """Resolve workload → ServiceAccount → SPIFFE ID from collected documents.

    Returns the ``workload_identity`` block (deterministic, JSON-ready).
    """
    collection = collection or empty_collection()
    registrations = sorted(collection["registrations"],
                           key=lambda r: (r["name"], r["source_file"], r["line"]))
    federations = sorted(collection["federations"],
                         key=lambda f: (f["trust_domain"], f["name"]))
    workloads = sorted(collection["workloads"],
                       key=lambda w: (w["namespace"], w["kind"], w["name"],
                                      w["source_file"]))
    namespaces = collection["namespaces"]
    config, notes = _effective_config(collection["configs"])
    federated_domains = {f["trust_domain"] for f in federations}

    assignments, unresolved = [], []
    for workload in workloads:
        ref = _workload_ref(workload)
        if workload["namespace"] in config["ignore_namespaces"]:
            continue
        for reg in registrations:
            pod_match = _selector_matches(reg["pod_selector"], workload["labels"])
            if pod_match is False:
                continue
            reason = None
            if pod_match is None:
                reason = "podSelector cannot be evaluated"
            elif _selects_everything(reg["namespace_selector"]):
                ns_match = True
            elif not workload["namespace"]:
                reason = "workload namespace not set in the manifest"
            else:
                labels, complete = _namespace_labels(workload["namespace"], namespaces)
                ns_match = _selector_matches(reg["namespace_selector"], labels, complete)
                if ns_match is None:
                    reason = ("namespaceSelector needs labels of a Namespace "
                              "not declared in the repository")
                elif ns_match is False:
                    continue
            evidence = [_ref(workload), _ref(reg)]
            if reason:
                unresolved.append({"workload": ref, "registration": reg["name"],
                                   "reason": reason, "evidence": evidence})
                continue
            spiffe_id, resolution, missing = _render(reg["template"], workload, config)
            breadth = []
            if _selects_everything(reg["pod_selector"]):
                breadth.append("all-pods")
            if _selects_everything(reg["namespace_selector"]):
                breadth.append("all-namespaces")
            assignment_notes = []
            if workload["service_account_defaulted"]:
                assignment_notes.append("no serviceAccountName: the namespace's "
                                        "'default' ServiceAccount")
            undeclared = [d for d in reg["federates_with"] if d not in federated_domains]
            if undeclared:
                assignment_notes.append("federatesWith names trust domains with no "
                                        "ClusterFederatedTrustDomain in repository: "
                                        + ", ".join(undeclared))
            assignments.append({
                "workload": ref, "workload_kind": workload["kind"],
                "namespace": workload["namespace"],
                "service_account": workload["service_account"],
                "registration": reg["name"], "spiffe_id": spiffe_id,
                "resolution": resolution, "unresolved_fields": missing,
                "federates_with": reg["federates_with"],
                "selector_breadth": breadth, "fallback": reg["fallback"],
                "notes": assignment_notes, "evidence": evidence,
            })

    by_workload = {}
    for assignment in assignments:
        by_workload.setdefault(assignment["workload"], []).append(assignment)

    identities, links, seen = [], [], set()
    for assignment in assignments:
        if assignment["resolution"] == UNRESOLVED:
            continue
        reg = next(r for r in registrations if r["name"] == assignment["registration"])
        ident = identity("spiffe_id", assignment["spiffe_id"],
                         source_ref=f"{reg['source_file']}:{reg['line']}")
        if assignment["spiffe_id"] not in seen:
            seen.add(assignment["spiffe_id"])
            identities.append(ident)
        link = agent_link(
            REPO_AGENT_REF,
            {"kind": "spiffe_id", "name": assignment["spiffe_id"], "namespace": ""},
            "workload-spiffe-id",
            "high" if assignment["resolution"] == RESOLVED else "medium",
            assignment["evidence"])
        link["workload"] = assignment["workload"]
        link["service_account"] = assignment["service_account"]
        link["resolution"] = assignment["resolution"]
        links.append(link)

    # Per-workload identity state. "unknown" has two causes, counted
    # apart: a selector that could not be decided, and no in-repository
    # registration matching (SPIRE may still register it elsewhere).
    undecided = {u["workload"] for u in unresolved}
    states, workload_states = [], []
    for workload in workloads:
        ref = _workload_ref(workload)
        if workload["namespace"] in config["ignore_namespaces"]:
            continue
        resolutions = {a["resolution"] for a in by_workload.get(ref, [])}
        if RESOLVED in resolutions:
            state = RESOLVED
        elif PARTIALLY_RESOLVED in resolutions:
            state = PARTIALLY_RESOLVED
        elif ref in undecided:
            state = "undecidable"
        else:
            state = "unmatched"
        states.append(state)
        workload_states.append({
            "workload": ref, "service_account": workload["service_account"],
            "identity_state": state if state in (RESOLVED, PARTIALLY_RESOLVED)
            else "unknown",
            "unknown_reason": {"undecidable": "undecidable-selector",
                               "unmatched": "no-matching-registration"}.get(state, ""),
        })
    counts = {
        "registrations": len(registrations),
        "federations": len(federations),
        "workloads": len(states),
        "resolved": states.count(RESOLVED),
        "partially_resolved": states.count(PARTIALLY_RESOLVED),
        "unknown": states.count("undecidable") + states.count("unmatched"),
        "unknown_undecidable_selector": states.count("undecidable"),
        "unknown_no_matching_registration": states.count("unmatched"),
    }
    counts["unknown_rate"] = (round(counts["unknown"] / counts["workloads"], 4)
                              if counts["workloads"] else None)

    static_credentials = []
    for workload in workloads:
        ref = _workload_ref(workload)
        held = [a for a in by_workload.get(ref, []) if a["resolution"] != UNRESOLVED]
        if not held or not workload["credentials"]:
            continue
        static_credentials.append({
            "workload": ref,
            "spiffe_ids": sorted({a["spiffe_id"] for a in held}),
            "credentials": [{k: c[k] for k in ("name", "source", "container")}
                            for c in workload["credentials"]],
            "source_file": workload["source_file"], "line": workload["line"],
        })

    policies = sorted(
        (_policy_record(p, workloads, by_workload) for p in collection["policies"]),
        key=lambda p: (p["namespace"], p["name"], p["source_file"]))

    return {
        "lane": "B",
        "trust_domain": {
            "value": config["trust_domain"],
            "resolution": RESOLVED if config["trust_domain"] else UNRESOLVED,
            "source": config["source"],
        },
        "ignore_namespaces": sorted(config["ignore_namespaces"]),
        "registrations": [
            {k: r[k] for k in ("name", "template", "federates_with", "fallback",
                               "source_file", "line")}
            | {"selects_all_pods": _selects_everything(r["pod_selector"]),
               "selects_all_namespaces": _selects_everything(r["namespace_selector"])}
            for r in registrations],
        "federations": federations,
        "identities": identities,
        "workloads": workload_states,
        "assignments": assignments,
        "links": links,
        "unresolved": unresolved,
        "authorization_policies": policies,
        "static_credentials": static_credentials,
        "counts": counts,
        "notes": notes,
    }


def empty_workload_identity():
    """The ``workload_identity`` block for a scan with no YAML evidence."""
    return resolve_workload_identity(empty_collection())


def static_credential_findings(block):
    """Review-only findings: a static credential beside a workload identity."""
    findings = []
    for item in (block or {}).get("static_credentials") or []:
        names = ", ".join(f"{c['name']} ({c['source']})" for c in item["credentials"])
        findings.append({
            "rule_id": RULE_STATIC_CREDENTIAL,
            "severity": "low",
            "message": "Workload holds a static credential although it is issued "
                       "a SPIFFE workload identity",
            "file": item["source_file"],
            "line": int(item["line"] or 1),
            "risk_category": "Integration",
            "affected_framework": "generic",
            "affected_capability": "workload_identity",
            "provenance_class": "repo-iac-observed",
            "gateability": "review-only",
            "evidence": (f"workload={item['workload']} "
                         f"spiffe_id={', '.join(item['spiffe_ids'])} "
                         f"credentials={names}"),
            "reason": ("The pod is handed a credential by name while SPIRE issues it an "
                       "SVID. If the credential authenticates to a service that "
                       "accepts the SVID, it is a second, longer-lived path to the "
                       "same authority."),
            "remediation": (
                "Authenticate with the workload's SVID where the target accepts it "
                "(mTLS or JWT-SVID), and remove the static credential; otherwise "
                "record why it is still needed."
            ),
            "confidence": 0.5,
            "score_contribution": 2,
        })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings
