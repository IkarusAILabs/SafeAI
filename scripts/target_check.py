"""C-2 target eligibility: check proposed targets against the written criteria.

For every target in ``research/credibility/targets.yml`` that is not
``excluded``, this records the facts the selection criteria
(``docs/research/CREDIBILITY_TRACK.md``, C-2) depend on, so the owner can
confirm or exclude a target from evidence rather than memory:

- licence, archived / fork flags and owner, from the GitHub API;
- the number of first-parent commits on the default branch;
- at the head commit only: the frameworks SafeAI detects and how many
  tools and MCP assets it finds. Findings are **not** recorded: the
  eligibility check must not show how SafeAI scores a target before the
  target is chosen.

It also suggests a range: ``to`` = the head commit at the check,
``from`` = the first-parent commit ``--window`` commits earlier (or the
root). The suggestion is a starting point; the owner pins the range.

Writes ``--out`` (JSON). Never edits ``targets.yml``. Target code is never
installed or executed: the head tree is exported with ``git archive``.

Usage:
    python scripts/target_check.py --targets research/credibility/targets.yml \\
        --out research/credibility/target_check.json

Exit codes: 0 written · 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # every call uses a fixed argv list, never shell=True
import sys
import tempfile
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from history_study import load_targets, pin_project_id
from study_common import StudyError, export_tree, git, scan_tree

MIN_COMMITS = 50
DEFAULT_WINDOW = 300
SAFEAI_OWNERS = {"ikarusailabs", "ikaruscareer"}
REPO_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def gh_repo(owner: str, name: str) -> dict[str, Any]:
    try:
        result = subprocess.run(["gh", "api", "-X", "GET", f"repos/{owner}/{name}"],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StudyError(f"gh api repos/{owner}/{name}: {exc}") from exc
    if result.returncode != 0:
        raise StudyError(f"gh api repos/{owner}/{name}: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout)


def repo_facts(meta: dict[str, Any]) -> dict[str, Any]:
    licence = (meta.get("license") or {}).get("spdx_id")
    return {"licence": licence if licence and licence != "NOASSERTION" else None,
            "archived": bool(meta.get("archived")), "fork": bool(meta.get("fork")),
            "owner": (meta.get("owner") or {}).get("login"),
            "default_branch": meta.get("default_branch")}


def surface(report: dict[str, Any]) -> dict[str, Any]:
    """What SafeAI parses at the head commit: frameworks and counts, no findings."""
    tools = report.get("tool_surface") or []
    frameworks = set(report.get("detected_frameworks") or [])
    frameworks |= {str((t.get("tool") or {}).get("framework")) for t in tools
                   if (t.get("tool") or {}).get("framework")}
    return {"frameworks": sorted(frameworks), "tools": len(tools),
            "mcp_assets": len(report.get("mcp_assets") or []),
            "files_scanned": report.get("files_scanned")}


def assess(facts: dict[str, Any]) -> list[str]:
    """Criteria the target fails (empty when it meets them all)."""
    fails = []
    if not facts.get("licence"):
        fails.append("no recognised open-source licence")
    if facts.get("archived"):
        fails.append("archived")
    if facts.get("fork"):
        fails.append("a fork")
    if str(facts.get("owner") or "").lower() in SAFEAI_OWNERS:
        fails.append("written by SafeAI's authors")
    if (facts.get("first_parent_commits") or 0) < MIN_COMMITS:
        fails.append(f"fewer than {MIN_COMMITS} first-parent commits")
    head = facts.get("head_surface") or {}
    if not (head.get("frameworks") or head.get("tools") or head.get("mcp_assets")):
        fails.append("SafeAI finds no agent framework, tool or MCP asset at the head commit")
    return fails


def check_target(target: dict[str, Any], workdir: str, window: int,
                 meta: dict[str, Any] | None = None, repo: str | None = None) -> dict[str, Any]:
    match = REPO_URL.match(str(target["url"]))
    if not match:
        raise StudyError(f"{target['id']}: only github.com URLs can be checked")
    facts = repo_facts(meta if meta is not None else gh_repo(*match.groups()))
    if repo is None:
        repo = os.path.join(workdir, "repo")
        git(["clone", "--quiet", "--no-checkout", "--filter=blob:none", target["url"], repo])
    shas = git(["rev-list", "--first-parent", "HEAD"], cwd=repo).split()
    facts["first_parent_commits"] = len(shas)
    facts["head"] = shas[0]
    facts["head_date"] = git(["show", "-s", "--format=%cI", shas[0]], cwd=repo).strip()
    tree = os.path.join(workdir, "tree")
    export_tree(repo, shas[0], tree)
    pin_project_id(tree, target["id"])
    report = scan_tree(tree, os.path.join(workdir, "head.json"))
    shutil.rmtree(tree, ignore_errors=True)
    facts["head_surface"] = surface(report)
    start = shas[min(window, len(shas)) - 1]
    facts["suggested_range"] = {"from": start, "to": shas[0],
                                "first_parent_commits": min(window, len(shas))}
    facts["fails"] = assess(facts)
    facts["eligible"] = not facts["fails"]
    return facts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="target_check", description=__doc__.split("\n\n")[0])
    parser.add_argument("--targets", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    args = parser.parse_args(argv)
    try:
        targets = [t for t in load_targets(args.targets) if t["status"] != "excluded"
                   and (not args.target or t["id"] in args.target)]
    except StudyError as exc:
        print(f"target_check: {exc}", file=sys.stderr)
        return 2
    results = []
    for target in targets:
        work = tempfile.mkdtemp(prefix="safeai-target-")
        try:
            facts = check_target(target, work, args.window)
        except StudyError as exc:
            facts = {"eligible": False, "fails": [f"check failed: {exc}"]}
        finally:
            shutil.rmtree(work, ignore_errors=True)
        results.append({"id": target["id"], "url": target["url"], "status": target["status"],
                        **facts})
        print(f"{target['id']}: {'eligible' if facts['eligible'] else 'not eligible'}"
              + (f" ({'; '.join(facts['fails'])})" if facts["fails"] else ""))
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"date": datetime.now(UTC).strftime("%Y-%m-%d"), "window": args.window,
                   "criteria": {"min_first_parent_commits": MIN_COMMITS,
                                "recorded_at_head": "frameworks, tool and MCP asset counts; "
                                                    "no findings"},
                   "targets": results}, fh, indent=1)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
