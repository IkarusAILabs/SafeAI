"""IaC authority evidence collectors (v2.5 redesign).

Walks the scan root for Terraform (``*.tf``) and Kubernetes YAML files,
extracts Identities, Grants, GrantBindings, and workload references,
then resolves Agent→Identity links from explicit evidence (see
``safeai.iac.linking``). Self-contained: never touches the analyzer
file cache, never executes anything, never leaves the repo.

Fidelity ceiling (ADR-0006, refined ADR-0009): heuristic extraction
only, per-field resolution states. Unparseable files are recorded in
``meta["files"]["unparsed"]`` and skipped — never guessed.
"""

import os

from safeai.iac.k8s import parse_k8s_file
from safeai.iac.linking import resolve_links
from safeai.iac.model import identity_key
from safeai.iac.terraform import parse_terraform_file

#: Per-file read cap for IaC sources (pathological files are skipped).
_MAX_IAC_BYTES = 1024 * 1024

#: YAML extensions sniffed for RBAC kinds.
_YAML_EXTS = (".yaml", ".yml")


def _is_within_root(root, path):
    root_real = os.path.normcase(os.path.realpath(root))
    path_real = os.path.normcase(os.path.realpath(path))
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False


def _excluded(rel_path, excluded_paths):
    normalized = rel_path.replace("\\", "/")
    for excluded in excluded_paths or []:
        marker = str(excluded).replace("\\", "/").strip("/")
        if normalized == marker or normalized.startswith(marker + "/"):
            return True
    return False


def collect_iac_files(root, excluded_paths=None):
    """Return ``(tf_files, yaml_files)`` as root-relative paths.

    Mirrors ``collect_dependency_files``: a side collection pass that
    leaves the analyzer file cache untouched.
    """
    tf_files, yaml_files = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Never descend into version-control internals; everything else is
        # fair game (IaC lives in arbitrary directories, dot-dirs included).
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            if not _is_within_root(root, full):
                continue
            try:
                rel = os.path.relpath(full, root).replace("\\", "/")
            except ValueError:
                continue
            if _excluded(rel, excluded_paths):
                continue
            lower = filename.lower()
            if lower.endswith(".tf"):
                tf_files.append(rel)
            elif lower.endswith(_YAML_EXTS):
                yaml_files.append(rel)
    return tf_files, yaml_files


def _read_capped(root, rel_path):
    """Read a file with size cap; return ``None`` when unreadable/huge."""
    full = os.path.join(root, rel_path)
    try:
        if os.path.getsize(full) > _MAX_IAC_BYTES:
            return None
        with open(full, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return None


def scan_iac(root, excluded_paths=None):
    """Scan IaC sources under ``root`` into an authority graph.

    Returns ``(graph, meta)`` where ``graph`` holds ``identities``,
    ``grants``, ``grant_bindings``, ``workload_refs``, and
    ``agent_links``, and ``meta`` holds ``files`` (terraform,
    kubernetes_rbac, unparsed lists), ``has_modules``, and link
    metadata. Never raises; deterministic ordering.
    """
    identities, grants, bindings, workloads = [], [], [], []
    meta = {"files": {"terraform": [], "kubernetes_rbac": [],
                      "unparsed": []},
            "has_modules": False}
    try:
        tf_files, yaml_files = collect_iac_files(root, excluded_paths)
    except Exception:
        return empty_graph(), meta
    meta["files"]["terraform"] = tf_files
    seen_identities = set()
    for rel in tf_files:
        text = _read_capped(root, rel)
        if text is None:
            meta["files"]["unparsed"].append(rel)
            continue
        try:
            file_idents, file_grants, file_bindings, file_meta = (
                parse_terraform_file(rel, text))
        except Exception:
            meta["files"]["unparsed"].append(rel)
            continue
        if file_meta.get("unparsed") and not (
                file_idents or file_grants or file_bindings):
            meta["files"]["unparsed"].append(rel)
        if file_meta.get("module_refs"):
            meta["has_modules"] = True
        for ident in file_idents:
            key = identity_key(ident)
            if key not in seen_identities:
                seen_identities.add(key)
                identities.append(ident)
        grants.extend(file_grants)
        bindings.extend(file_bindings)
    for rel in yaml_files:
        text = _read_capped(root, rel)
        if text is None:
            continue
        try:
            (file_idents, file_grants, file_bindings, file_workloads,
             file_meta) = parse_k8s_file(rel, text)
        except Exception:
            meta["files"]["unparsed"].append(rel)
            continue
        if file_meta.get("unparsed"):
            meta["files"]["unparsed"].append(rel)
            continue
        if file_idents or file_grants or file_bindings or file_workloads:
            meta["files"]["kubernetes_rbac"].append(rel)
        for ident in file_idents:
            key = identity_key(ident)
            if key not in seen_identities:
                seen_identities.add(key)
                identities.append(ident)
        grants.extend(file_grants)
        bindings.extend(file_bindings)
        workloads.extend(file_workloads)
    try:
        links, link_meta = resolve_links(root, identities, workloads,
                                         excluded_paths)
    except Exception:
        links, link_meta = [], {"workload_files": [], "config_files": [],
                                "links": 0}
    meta["files"]["unparsed"] = sorted(set(meta["files"]["unparsed"]))
    meta["link_meta"] = link_meta
    graph = {"identities": identities, "grants": grants,
             "grant_bindings": bindings, "workload_refs": workloads,
             "agent_links": links}
    return graph, meta


def empty_graph():
    """Return an empty authority graph (no IaC evidence)."""
    return {"identities": [], "grants": [], "grant_bindings": [],
            "workload_refs": [], "agent_links": []}
