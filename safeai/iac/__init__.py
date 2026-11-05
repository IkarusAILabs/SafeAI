"""IaC authority evidence collectors (v2.5 redesign).

Walks the scan root for Terraform (``*.tf``) and Kubernetes YAML files,
and (v2.16) CloudFormation templates, Serverless Framework files and Helm
chart templates; extracts Identities, Grants, GrantBindings, and workload
references,
then resolves Agent→Identity links from explicit evidence (see
``safeai.iac.linking``). Self-contained: never touches the analyzer
file cache, never executes anything, never leaves the repo.

Fidelity ceiling (ADR-0006, refined ADR-0009): heuristic extraction
only, per-field resolution states. Unparseable files are recorded in
``meta["files"]["unparsed"]`` and skipped — never guessed.
"""

import os

from safeai.iac.cloudformation import parse_cloudformation
from safeai.iac.helm import parse_helm_template
from safeai.iac.k8s import parse_k8s_file
from safeai.iac.linking import resolve_links
from safeai.iac.model import identity_key
from safeai.iac.serverless import FILENAMES as SERVERLESS_FILENAMES
from safeai.iac.serverless import parse_serverless
from safeai.iac.spiffe import (
    collect_file,
    empty_collection,
    empty_workload_identity,
    resolve_workload_identity,
)
from safeai.iac.terraform import parse_terraform_file

#: Per-file read cap for IaC sources (pathological files are skipped).
_MAX_IAC_BYTES = 1024 * 1024

#: YAML extensions sniffed for RBAC kinds.
_YAML_EXTS = (".yaml", ".yml")
#: JSON extensions sniffed for CloudFormation templates (v2.16).
_JSON_EXTS = (".json", ".template")


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


def collect_more_iac_files(root, excluded_paths=None):
    """``(json_files, chart_dirs)``: JSON candidates and Helm chart roots (v2.16)."""
    json_files, chart_dirs = [], []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "node_modules"))
        try:
            rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        except ValueError:
            continue
        rel_dir = "" if rel_dir == "." else rel_dir
        if _excluded(rel_dir, excluded_paths) and rel_dir:
            dirnames[:] = []
            continue
        if "Chart.yaml" in filenames:
            chart_dirs.append(rel_dir)
        for filename in sorted(filenames):
            if filename.lower().endswith(_JSON_EXTS):
                rel = f"{rel_dir}/{filename}" if rel_dir else filename
                if not _excluded(rel, excluded_paths) and _is_within_root(
                        root, os.path.join(dirpath, filename)):
                    json_files.append(rel)
    return json_files, chart_dirs


def _in_chart_templates(rel, chart_dirs):
    return any(rel.startswith(f"{chart}/templates/" if chart else "templates/")
               for chart in chart_dirs)


def _looks_like_cloudformation(text):
    return "AWS::" in text and ("Resources" in text or "AWSTemplateFormatVersion" in text)


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
    ``agent_links``, plus the SPIFFE ``workload_identity`` block (v2.10,
    kept apart from ``agent_links``: a SPIFFE ID holds no RBAC or IAM
    grant, so it must not count as a link in grant correlation), and
    ``meta`` holds ``files`` (terraform,
    kubernetes_rbac, unparsed lists), ``has_modules``, and link
    metadata. Never raises; deterministic ordering.
    """
    identities, grants, bindings, workloads = [], [], [], []
    meta = {"files": {"terraform": [], "kubernetes_rbac": [], "cloudformation": [],
                      "serverless": [], "helm": [], "unparsed": []},
            "has_modules": False}
    try:
        tf_files, yaml_files = collect_iac_files(root, excluded_paths)
        json_files, chart_dirs = collect_more_iac_files(root, excluded_paths)
    except Exception:
        return empty_graph(), meta
    meta["files"]["terraform"] = tf_files
    seen_identities = set()
    spiffe_docs = empty_collection()
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
    def add(file_idents, file_grants, file_bindings):
        for ident in file_idents:
            key = identity_key(ident)
            if key not in seen_identities:
                seen_identities.add(key)
                identities.append(ident)
        grants.extend(file_grants)
        bindings.extend(file_bindings)

    # v2.16: CloudFormation (YAML or JSON) and Serverless Framework files.
    for rel in yaml_files + json_files:
        text = _read_capped(root, rel)
        name = rel.rsplit("/", 1)[-1].lower()
        if text is None:
            continue
        try:
            if name in SERVERLESS_FILENAMES:
                file_idents, file_grants, file_bindings, file_meta = parse_serverless(rel, text)
                if file_meta.get("unparsed"):
                    meta["files"]["unparsed"].append(rel)
                elif file_idents or file_grants or file_bindings:
                    meta["files"]["serverless"].append(rel)
                add(file_idents, file_grants, file_bindings)
            elif _looks_like_cloudformation(text):
                file_idents, file_grants, file_bindings, file_meta = (
                    parse_cloudformation(rel, text))
                if file_meta.get("template"):
                    meta["files"]["cloudformation"].append(rel)
                add(file_idents, file_grants, file_bindings)
        except Exception:
            meta["files"]["unparsed"].append(rel)
    handled = set(meta["files"]["cloudformation"]) | set(meta["files"]["serverless"])
    for rel in yaml_files:
        if rel in handled or rel.rsplit("/", 1)[-1].lower() in SERVERLESS_FILENAMES:
            continue
        text = _read_capped(root, rel)
        if text is None:
            continue
        helm = _in_chart_templates(rel, chart_dirs)
        if not helm:
            collect_file(spiffe_docs, rel, text)
        try:
            (file_idents, file_grants, file_bindings, file_workloads,
             file_meta) = (parse_helm_template if helm else parse_k8s_file)(rel, text)
        except Exception:
            meta["files"]["unparsed"].append(rel)
            continue
        if file_meta.get("unparsed"):
            meta["files"]["unparsed"].append(rel)
            continue
        if helm and (file_idents or file_grants or file_bindings or file_workloads):
            meta["files"]["helm"].append(rel)
            add(file_idents, file_grants, file_bindings)
            workloads.extend(file_workloads)
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
    try:
        workload_identity = resolve_workload_identity(spiffe_docs)
    except Exception:
        workload_identity = empty_workload_identity()
    meta["files"]["unparsed"] = sorted(set(meta["files"]["unparsed"]))
    meta["link_meta"] = link_meta
    graph = {"identities": identities, "grants": grants,
             "grant_bindings": bindings, "workload_refs": workloads,
             "agent_links": links, "workload_identity": workload_identity}
    return graph, meta


def empty_graph():
    """Return an empty authority graph (no IaC evidence)."""
    return {"identities": [], "grants": [], "grant_bindings": [],
            "workload_refs": [], "agent_links": [],
            "workload_identity": empty_workload_identity()}
