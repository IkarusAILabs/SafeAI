"""C-2 real-world change study: replay repository history through ``--baseline``.

For each confirmed target in ``research/credibility/targets.yml`` this
clones the repository (no checkout), walks the first-parent commits from
``from`` to ``to``, exports each commit's tree with ``git archive``, and
scans it with the previous scanned commit's report as the baseline. It
writes, under ``--out``:

``commits.jsonl``  one row per commit: status (``baseline``, ``scanned``,
                   ``skipped`` or ``error``), changed files, highest change
                   class and the number of reported changes;
``changes.jsonl``  one row per reported change unit (tool change, the
                   unattributed bucket, delegation or identity change);
``run.json``       SafeAI version, targets, ranges and counts.

Labels are added later with ``scripts/label_kit.py``. Protocol:
``docs/research/CREDIBILITY_TRACK.md`` (C-2). Target code is never
installed or executed, and nothing is published.

Usage:
    python scripts/history_study.py --targets research/credibility/targets.yml --out study/
    python scripts/history_study.py --targets T.yml --target mcp-servers --max-commits 200 --out study/
    python scripts/history_study.py --repo-path ./checkout --from A --to B --id local --out study/

Exit codes: 0 every target ran · 1 some targets failed · 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from study_common import (
    StudyError,
    change_units,
    changed_files,
    clone,
    commit_info,
    export_tree,
    first_parent_commits,
    load_yaml,
    only_binary,
    scan_tree,
    write_jsonl,
)

TARGET_STATUSES = ("proposed", "confirmed", "excluded")


def load_targets(path: str) -> list[dict[str, Any]]:
    """Validate the targets file; return every target (any status)."""
    data = load_yaml(path) or {}
    targets = data.get("targets")
    if not isinstance(targets, list):
        raise StudyError(f"{path}: 'targets' must be a list")
    seen = set()
    for t in targets:
        if not isinstance(t, dict) or not t.get("id") or not t.get("url"):
            raise StudyError(f"{path}: every target needs 'id' and 'url'")
        if t["id"] in seen:
            raise StudyError(f"{path}: duplicate target id {t['id']!r}")
        seen.add(t["id"])
        if t.get("status") not in TARGET_STATUSES:
            raise StudyError(f"{path}: target {t['id']!r} status must be one of "
                             f"{', '.join(TARGET_STATUSES)}")
        if not str(t["url"]).startswith("https://"):
            raise StudyError(f"{path}: target {t['id']!r} url must be https")
        if t["status"] == "confirmed" and not (t.get("from") and t.get("to")):
            raise StudyError(f"{path}: confirmed target {t['id']!r} needs pinned 'from' and 'to'")
    return targets


def pin_project_id(tree: str, project_id: str) -> None:
    """Give every commit's tree the same project id, so agent ids stay stable.

    Without one, each scan invents a local project id and agent ids
    differ between baseline and current. A repository's own
    ``.safeai/config.yml`` is left as it is.
    """
    config = os.path.join(tree, ".safeai", "config.yml")
    if os.path.exists(config):
        return
    os.makedirs(os.path.dirname(config), exist_ok=True)
    with open(config, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"project_id: {json.dumps('study-' + project_id)}\n")


def study_target(target: dict[str, Any], repo: str, workdir: str,
                 max_commits: int | None) -> tuple[list, list]:
    """Scan every commit of one target; return (commit rows, change rows)."""
    shas = first_parent_commits(repo, target.get("from"), target.get("to") or "HEAD")
    if max_commits and len(shas) > max_commits:
        shas = shas[:max_commits]
    commit_rows: list[dict[str, Any]] = []
    change_rows: list[dict[str, Any]] = []
    baseline_json = None
    baseline_sha = None
    for index, sha in enumerate(shas):
        info = commit_info(repo, sha)
        row = {"target": target["id"], "url": target["url"], "index": index,
               "sha": info["sha"], "date": info["date"], "subject": info["subject"][:200],
               "baseline_sha": baseline_sha, "files": [], "units": 0,
               "highest_change_class": None}
        try:
            if baseline_json is not None:
                row["files"] = changed_files(repo, baseline_sha, info["sha"])
                if not row["files"] or only_binary(row["files"]):
                    row["status"] = "skipped"
                    commit_rows.append(row)
                    continue
            tree = os.path.join(workdir, "tree")
            shutil.rmtree(tree, ignore_errors=True)
            export_tree(repo, info["sha"], tree)
            pin_project_id(tree, target["id"])
            out_json = os.path.join(workdir, f"scan-{index:05d}.json")
            report = scan_tree(tree, out_json, baseline=baseline_json)
            shutil.rmtree(tree, ignore_errors=True)
        except StudyError as exc:
            row["status"] = "error"
            row["error"] = str(exc)
            commit_rows.append(row)
            continue
        if baseline_json is None:
            row["status"] = "baseline"
        else:
            units = change_units(report)
            row["status"] = "scanned"
            row["units"] = len(units)
            row["highest_change_class"] = (report.get("capability_diff") or {}).get(
                "highest_change_class")
            change_rows += [dict(u, target=target["id"], sha=info["sha"], index=index)
                            for u in units]
            os.remove(baseline_json)
        baseline_json, baseline_sha = out_json, info["sha"]
        commit_rows.append(row)
    return commit_rows, change_rows


def _safeai_version() -> str:
    try:
        from safeai.version import SAFEAI_VERSION
    except ImportError:
        return "unknown"
    return SAFEAI_VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="history_study",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("--targets", help="targets file (research/credibility/targets.yml)")
    parser.add_argument("--target", action="append", default=[],
                        help="only this target id (repeatable)")
    parser.add_argument("--include-proposed", action="store_true",
                        help="also run proposed targets (dry runs only; never for results)")
    parser.add_argument("--repo-path", help="use this local clone instead of a targets file")
    parser.add_argument("--id", default="local", help="target id with --repo-path")
    parser.add_argument("--from", dest="start", help="first commit with --repo-path")
    parser.add_argument("--to", dest="end", default="HEAD", help="last commit with --repo-path")
    parser.add_argument("--max-commits", type=int, default=None)
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--out", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if bool(args.targets) == bool(args.repo_path):
        print("history_study: give exactly one of --targets or --repo-path", file=sys.stderr)
        return 2
    try:
        if args.repo_path:
            runs = [({"id": args.id, "url": "local", "status": "local", "from": args.start,
                      "to": args.end}, os.path.abspath(args.repo_path))]
        else:
            wanted = {"confirmed", "proposed"} if args.include_proposed else {"confirmed"}
            targets = [t for t in load_targets(args.targets) if t["status"] in wanted
                       and (not args.target or t["id"] in args.target)]
            runs = [(t, None) for t in targets]
    except StudyError as exc:
        print(f"history_study: {exc}", file=sys.stderr)
        return 2
    if not runs:
        print("history_study: no target to run (only confirmed targets run without "
              "--include-proposed)", file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)
    work = args.workdir or tempfile.mkdtemp(prefix="safeai-history-")
    commits: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    summary = []
    failed = 0
    for target, repo in runs:
        tdir = os.path.join(work, target["id"])
        os.makedirs(tdir, exist_ok=True)
        try:
            if repo is None:
                repo = clone(target["url"], os.path.join(tdir, "repo"))
            rows, units = study_target(target, repo, tdir, args.max_commits)
        except StudyError as exc:
            failed += 1
            summary.append({"id": target["id"], "status": "failed", "error": str(exc)})
            continue
        commits += rows
        changes += units
        summary.append({"id": target["id"], "status": "ran", "url": target["url"],
                        "from": target.get("from"), "to": target.get("to"),
                        "commits": len(rows),
                        "by_status": {s: sum(r["status"] == s for r in rows)
                                      for s in ("baseline", "scanned", "skipped", "error")},
                        "changes": len(units)})
        print(f"{target['id']}: {len(rows)} commits, {len(units)} reported changes")
    write_jsonl(os.path.join(args.out, "commits.jsonl"), commits)
    write_jsonl(os.path.join(args.out, "changes.jsonl"), changes)
    with open(os.path.join(args.out, "run.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"safeai_version": _safeai_version(),
                   "started": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "max_commits": args.max_commits, "targets": summary}, fh, indent=1)
    if not args.workdir:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
