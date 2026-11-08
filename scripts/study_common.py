"""Shared helpers for the credibility-track studies (docs/research/CREDIBILITY_TRACK.md).

Study tooling, not scanner code: it clones public repositories with
``git`` and runs ``safeai scan`` on exported trees. Nothing here is
imported by the ``safeai`` package, so the scan path stays offline.
Target code is never installed or executed: trees are exported with
``git archive`` (no checkout, no hooks) and extracted with the tarfile
``data`` filter.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import subprocess  # every call uses a fixed argv list, never shell=True
import sys
import tarfile
from typing import Any

GIT_TIMEOUT = 600
SCAN_TIMEOUT = 1800
MIN_SAMPLE = 10

# A commit that changes only these files cannot change what SafeAI reads.
BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".mp4", ".mov",
    ".mp3", ".wav", ".zip", ".gz", ".tgz",
)


class StudyError(Exception):
    """A study could not run (bad input, git or scan failure)."""


# --- git ---------------------------------------------------------------------------

def git(args: list[str], cwd: str | None = None, timeout: int = GIT_TIMEOUT) -> str:
    """Run ``git`` with a fixed argv; return stdout or raise StudyError."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StudyError(f"git {args[0]} failed: {exc}") from exc
    if result.returncode != 0:
        raise StudyError(f"git {args[0]} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def clone(url: str, dest: str) -> str:
    """Clone without a checkout (no working tree, so no hooks or filters run)."""
    git(["clone", "--quiet", "--no-checkout", url, dest])
    return dest


def first_parent_commits(repo: str, start: str | None, end: str) -> list[str]:
    """Commits from ``start`` (inclusive) to ``end`` along first parents, oldest first."""
    end_sha = git(["rev-parse", "--verify", f"{end}^{{commit}}"], cwd=repo).strip()
    if start:
        start_sha = git(["rev-parse", "--verify", f"{start}^{{commit}}"], cwd=repo).strip()
        later = git(["rev-list", "--first-parent", "--reverse", f"{start_sha}..{end_sha}"],
                    cwd=repo).split()
        return [start_sha, *later]
    return git(["rev-list", "--first-parent", "--reverse", end_sha], cwd=repo).split()


def commit_info(repo: str, sha: str) -> dict[str, str]:
    out = git(["show", "-s", "--format=%H%x00%P%x00%cI%x00%s", sha], cwd=repo)
    full, parents, date, subject = out.rstrip("\n").split("\x00", 3)
    return {"sha": full, "parents": parents.split(), "date": date, "subject": subject}


def changed_files(repo: str, parent: str, sha: str) -> list[str]:
    out = git(["diff", "--name-only", "--no-renames", parent, sha], cwd=repo)
    return sorted(line for line in out.splitlines() if line)


def only_binary(files: list[str]) -> bool:
    return bool(files) and all(f.lower().endswith(BINARY_SUFFIXES) for f in files)


_WINDOWS_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')


def portable_name(name: str, windows: bool = os.name == "nt") -> str:
    """A member name every filesystem can hold.

    On Windows, a path component cannot end in a space or a dot or contain
    ``<>:"|?*``; real repositories have such names (``config /agents.yaml``).
    They are rewritten (trailing spaces and dots dropped, bad characters
    replaced by ``_``) so the commit is scanned instead of failing.
    Elsewhere names are kept as they are.
    """
    if not windows:
        return name
    parts = [_WINDOWS_BAD.sub("_", part).rstrip(" .") or "_" for part in name.split("/")]
    return "/".join(parts)


def _extract_filter(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    renamed = portable_name(member.name)
    if renamed != member.name:
        member = member.replace(name=renamed, deep=False)
    return tarfile.data_filter(member, path)


def export_tree(repo: str, sha: str, dest: str) -> str:
    """Write the tree of ``sha`` into ``dest`` without a checkout.

    ``core.protectNTFS`` is turned off for the archive only: it guards
    checkouts on Windows, and nothing is checked out here. Extraction goes
    through the tarfile ``data`` filter (no absolute paths, no traversal,
    no links outside ``dest``) after :func:`portable_name`.
    """
    try:
        data = subprocess.run(
            ["git", "-c", "core.protectNTFS=false", "archive", "--format=tar", sha], cwd=repo,
            capture_output=True, timeout=GIT_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StudyError(f"git archive failed: {exc}") from exc
    if data.returncode != 0:
        raise StudyError("git archive failed: "
                         + data.stderr.decode("utf-8", "replace").strip()[:300])
    if not hasattr(tarfile, "data_filter"):
        raise StudyError("this Python has no tarfile data filter; use 3.11.4 or later")
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data.stdout)) as archive:
        archive.extractall(dest, filter=_extract_filter)
    return dest


# --- scanning ----------------------------------------------------------------------

def scan_tree(tree: str, out_json: str, baseline: str | None = None,
              timeout: int = SCAN_TIMEOUT) -> dict[str, Any]:
    """Run ``safeai scan`` in a child process; return the JSON report."""
    argv = [sys.executable, "-m", "safeai", "scan", tree, "--no-registry",
            "--json", out_json, "--sarif", out_json[:-5] + ".sarif"]
    if baseline:
        argv += ["--baseline", baseline]
    try:
        subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StudyError(f"scan failed: {exc}") from exc
    sarif = out_json[:-5] + ".sarif"
    if os.path.isfile(sarif):
        os.remove(sarif)
    if not os.path.isfile(out_json):
        raise StudyError("scan wrote no JSON report")
    with open(out_json, encoding="utf-8") as fh:
        return json.load(fh)


def _paths(items: list[dict[str, Any]]) -> list[str]:
    paths = set()
    for item in items:
        for ev in item.get("evidence") or []:
            if isinstance(ev, dict) and ev.get("path"):
                paths.add(str(ev["path"]).replace("\\", "/"))
    return sorted(paths)


def unit_id(*parts: Any) -> str:
    text = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def change_units(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every change SafeAI reports against the baseline, as labellable units.

    A unit is a tool change (anything but an unchanged tool without
    escalations), the unattributed bucket when it changed, a delegation
    change or a workload-identity change.
    """
    diff = report.get("capability_diff") or {}
    if not diff.get("baseline_available"):
        return []
    units = []
    for tool in diff.get("tools") or []:
        escalations = tool.get("escalations") or []
        if tool.get("status") == "unchanged" and not escalations:
            continue
        added = tool.get("capabilities_added") or []
        removed = tool.get("capabilities_removed") or []
        units.append({
            "kind": "tool",
            "subject": tool.get("tool_key"),
            "type": tool.get("status"),
            "change_class": tool.get("change_class"),
            "escalations": sorted(e.get("id") for e in escalations if e.get("id")),
            "capabilities_added": sorted(c.get("name") for c in added if c.get("name")),
            "capabilities_removed": sorted(c.get("name") for c in removed if c.get("name")),
            "access_mode_changes": [
                [m.get("capability"), m.get("before"), m.get("after")]
                for m in tool.get("access_mode_changes") or []],
            "paths": _paths(added + escalations),
        })
    unattributed = diff.get("unattributed") or {}
    if unattributed.get("change_class") not in (None, "NO_CHANGE"):
        added = unattributed.get("capabilities_added") or []
        units.append({
            "kind": "unattributed", "subject": "unattributed",
            "type": unattributed.get("status"),
            "change_class": unattributed.get("change_class"),
            "escalations": sorted(e.get("id") for e in unattributed.get("escalations") or []
                                  if e.get("id")),
            "capabilities_added": sorted(c.get("name") for c in added if c.get("name")),
            "capabilities_removed": [], "access_mode_changes": [],
            "paths": _paths(added),
        })
    for key, kind in (("delegation_changes", "delegation"),
                      ("workload_identity_changes", "identity")):
        for change in (diff.get(key) or {}).get("changes") or []:
            subject = change.get("subject")
            if kind == "identity" and change.get("workload"):
                subject = f"{change['workload']}: {subject}"
            units.append({
                "kind": kind, "subject": subject, "type": change.get("type"),
                "change_class": None, "detail": change.get("detail"),
                "escalations": [], "capabilities_added": [],
                "capabilities_removed": [], "access_mode_changes": [],
                "paths": sorted({str(e.get("path") or e.get("file") or "").replace("\\", "/")
                                 for e in change.get("evidence") or []
                                 if isinstance(e, dict)} - {""}),
            })
    for unit in units:
        unit["unit_id"] = unit_id(unit["kind"], unit["subject"], unit["type"])
    return sorted(units, key=lambda u: (u["kind"], str(u["subject"]), str(u["type"])))


# --- statistics and files ------------------------------------------------------------

def wilson(successes: int, n: int, z: float = 1.96) -> dict[str, Any]:
    """Point estimate with a 95% Wilson interval; *insufficient* below MIN_SAMPLE."""
    if n < MIN_SAMPLE:
        return {"n": n, "k": successes, "status": "insufficient"}
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return {"n": n, "k": successes, "status": "measured", "rate": round(p, 4),
            "low": round(max(0.0, centre - half), 4), "high": round(min(1.0, centre + half), 4)}


def write_jsonl(path: str, rows: list[dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def read_jsonl(path: str) -> list[dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_yaml(path: str) -> Any:
    import yaml

    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)
