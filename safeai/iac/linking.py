"""Agent→Identity link resolver (v2.5 redesign).

Links are created **only** from explicit repository evidence:

1. **Workload manifests** — a Kubernetes workload (Deployment,
   StatefulSet, DaemonSet, Job, CronJob, Pod, …) whose
   ``serviceAccountName`` names a collected ServiceAccount in the same
   namespace (``link_type="workload-service-account"``).
2. **Structured config references** — YAML/JSON files with exact identity
   keys (``role_arn``, ``role``, ``service_account``, …) whose value
   equals a collected identity name or role ARN
   (``link_type="explicit-config-reference"``).

A tool-key or inventory-name string coincidence alone NEVER creates a
link. Every link carries ``{file, line}`` evidence. Without a link,
verdicts stay UNVERIFIED_LINK (never MATCH).
"""

import json
import os

import yaml

from safeai.iac.model import REPO_AGENT_REF, agent_link, identity_key

#: Workload kinds whose service-account references are workload
#: evidence (handled by the workload pass, excluded from the generic
#: config pass to avoid double links).
_WORKLOAD_KINDS = frozenset({
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
    "Pod", "ReplicaSet", "ReplicationController",
})

#: Exact (lowercased) config keys treated as identity references.
_IDENTITY_KEYS = frozenset({
    "role_arn",
    "role-arn",
    "role",
    "iam_role",
    "iam-role",
    "service_account",
    "serviceaccountname",
    "service-account-name",
    "service_account_name",
    "eks_role",
})

_CONFIG_EXTS = (".yaml", ".yml", ".json")
_MAX_CONFIG_BYTES = 512 * 1024
_MAX_CONFIG_FILES = 300


def _best_effort_line(text, value):
    """Line number of the first line containing ``value``, else 1."""
    try:
        for i, line in enumerate(text.splitlines(), 1):
            if str(value) in line:
                return i
    except Exception:
        pass
    return 1


def _arn_role_name(value):
    """Extract a role name from an ARN (``...:role/NAME``), else None."""
    text = str(value or "").strip()
    if ":role/" not in text:
        return None
    name = text.split(":role/")[-1].split("/")[0].strip()
    return name or None


def _walk_nested(node, keys):
    """Yield ``(key, value)`` for every dict entry in nested YAML/JSON."""
    if isinstance(node, dict):
        for key, value in node.items():
            keys.append((key, value))
            _walk_nested(value, keys)
    elif isinstance(node, list):
        for item in node:
            _walk_nested(item, keys)
    return keys


def _iter_config_files(root, excluded):
    """Yield ``(rel_path, text)`` for bounded config candidates."""
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for filename in sorted(filenames):
            if not filename.lower().endswith(_CONFIG_EXTS):
                continue
            full = os.path.join(dirpath, filename)
            try:
                rel = os.path.relpath(full, root).replace("\\", "/")
            except ValueError:
                continue
            if rel.startswith(".."):
                continue
            skip = False
            for marker in excluded or []:
                clean = str(marker).replace("\\", "/").strip("/")
                if rel == clean or rel.startswith(clean + "/"):
                    skip = True
                    break
            if skip:
                continue
            try:
                if os.path.getsize(full) > _MAX_CONFIG_BYTES:
                    continue
                with open(full, "r", encoding="utf-8") as handle:
                    text = handle.read()
            except Exception:
                continue
            seen += 1
            if seen > _MAX_CONFIG_FILES:
                return
            yield rel, text


def _parse_config(rel_path, text):
    """Parse YAML (multi-doc) or JSON; return a list of documents.

    Workload manifests are excluded: their ``serviceAccountName``
    references are workload evidence handled by the workload pass, not
    generic config references (avoids double links).
    """
    try:
        if rel_path.lower().endswith(".json"):
            data = json.loads(text)
            return [data]
        return [d for d in yaml.safe_load_all(text)
                if isinstance(d, (dict, list))
                and not (isinstance(d, dict)
                         and d.get("kind") in _WORKLOAD_KINDS)]
    except Exception:
        return []


def resolve_links(root, identities, workload_refs, excluded_paths=None):
    """Resolve Agent→Identity links from explicit repository evidence.

    Returns ``(links, meta)``. ``links`` use agent ``<repo>`` — the
    evidence ties the repository's workload/config to the identity, not
    an individual tool. Never raises; deterministic ordering.
    """
    links = []
    meta = {"workload_files": [], "config_files": [], "links": 0}
    by_key = {}
    for ident in identities or []:
        if isinstance(ident, dict):
            by_key.setdefault(identity_key(ident), ident)

    seen_links = set()
    for workload in workload_refs or []:
        if not isinstance(workload, dict):
            continue
        sa_name = str(workload.get("service_account") or "")
        workload_ns = str(workload.get("namespace") or "")
        if not sa_name:
            continue
        key = ("kubernetes_service_account", workload_ns, sa_name)
        ident = by_key.get(key)
        if ident is None:
            continue
        evidence = [{"file": workload.get("source_file"),
                     "line": int(workload.get("line") or 1)}]
        signature = (key, "workload-service-account")
        if signature in seen_links:
            continue
        seen_links.add(signature)
        links.append(agent_link(
            REPO_AGENT_REF, ident, "workload-service-account", "high",
            evidence))
        source_file = workload.get("source_file")
        if source_file and source_file not in meta["workload_files"]:
            meta["workload_files"].append(source_file)

    for rel_path, text in _iter_config_files(root, excluded_paths):
        documents = _parse_config(rel_path, text)
        if not documents:
            continue
        meta["config_files"].append(rel_path)
        for _key, value in _walk_nested(documents, []):
            if str(_key or "").lower() not in _IDENTITY_KEYS:
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            raw = value.strip()
            role_name = _arn_role_name(raw)
            matched = None
            confidence = "medium"
            if role_name is not None:
                candidate = ("aws_iam_role", "", role_name)
                matched = by_key.get(candidate)
                confidence = "high"
            else:
                candidates = [ident for key, ident in by_key.items()
                              if ident.get("name") == raw]
                if len(candidates) == 1:
                    matched = candidates[0]
                # Multiple identities share this bare name (e.g. same
                # ServiceAccount name in several namespaces): ambiguous,
                # never guessed. An ARN or workload manifest disambiguates.
            if matched is None:
                continue
            evidence = [{"file": rel_path,
                         "line": _best_effort_line(text, raw)}]
            signature = (identity_key(matched), "explicit-config-reference",
                         rel_path)
            if signature in seen_links:
                continue
            seen_links.add(signature)
            links.append(agent_link(
                REPO_AGENT_REF, matched, "explicit-config-reference",
                confidence, evidence))

    meta["config_files"] = sorted(set(meta["config_files"]))
    meta["workload_files"] = sorted(set(meta["workload_files"]))
    meta["links"] = len(links)
    links.sort(key=lambda l: (str(l.get("identity", {}).get("kind")),
                              str(l.get("identity", {}).get("namespace")),
                              str(l.get("identity", {}).get("name"))))
    return links, meta
