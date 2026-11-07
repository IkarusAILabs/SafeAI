"""C-3 incident replay: would SafeAI have flagged a disclosed flaw before the fix?

Reads ``research/credibility/incidents.yml``. For each ``verified``
incident it clones the repository (no checkout), exports the vulnerable
revision with ``git archive`` and scans it. An incident is **detected**
when a rule in ``expected.rules`` fires on a file under
``expected.paths``, or, when ``introduced_ref`` is given, when scanning
that commit against its parent reports a change touching
``expected.paths``. Incidents marked ``static_visibility: runtime-only``
are reported apart as expected ``unknown``: a static scanner flagging
one would be a coincidence, not a hit.

Writes ``replay.json`` (per-incident outcome and the recall over verified,
statically visible incidents, with a 95% Wilson interval) and
``replay.md`` under ``--out``. Protocol:
``docs/research/CREDIBILITY_TRACK.md`` (C-3).

Usage:
    python scripts/incident_replay.py --registry research/credibility/incidents.yml --out replay/
    python scripts/incident_replay.py --registry R.yml --repo-path INCIDENT_ID=./checkout --out replay/
    python scripts/incident_replay.py --registry R.yml --check

Exit codes: 0 ran (or registry valid) · 1 some incidents failed to run ·
2 usage error or invalid registry.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from study_common import (
    StudyError,
    change_units,
    clone,
    commit_info,
    export_tree,
    git,
    load_yaml,
    scan_tree,
    wilson,
)

STATUSES = ("candidate", "verified", "rejected")
VISIBILITY = ("visible", "runtime-only", "undetermined")
REQUIRED = ("id", "advisory", "repository", "vulnerable_ref", "static_visibility", "status",
            "expected")


def validate(data: Any) -> list[dict[str, Any]]:
    """Return the incidents; raise StudyError on the first malformed entry."""
    if not isinstance(data, dict) or not isinstance(data.get("incidents"), list):
        raise StudyError("registry needs an 'incidents' list")
    search = data.get("search")
    if not isinstance(search, dict) or not search.get("query") or not search.get("date"):
        raise StudyError("registry needs 'search.query' and 'search.date' (the selection record)")
    seen = set()
    for entry in data["incidents"]:
        if not isinstance(entry, dict):
            raise StudyError("every incident must be a mapping")
        missing = [k for k in REQUIRED if not entry.get(k)]
        if missing:
            raise StudyError(f"incident {entry.get('id', '?')!r} lacks {', '.join(missing)}")
        if entry["id"] in seen:
            raise StudyError(f"duplicate incident id {entry['id']!r}")
        seen.add(entry["id"])
        if entry["status"] not in STATUSES:
            raise StudyError(f"incident {entry['id']!r}: status must be one of {STATUSES}")
        if entry["static_visibility"] not in VISIBILITY:
            raise StudyError(f"incident {entry['id']!r}: static_visibility must be one of "
                             f"{VISIBILITY}")
        if entry["status"] == "verified" and entry["static_visibility"] == "undetermined":
            raise StudyError(f"incident {entry['id']!r}: a verified incident needs "
                             "static_visibility visible or runtime-only")
        for key in ("advisory", "repository"):
            if not str(entry[key]).startswith("https://"):
                raise StudyError(f"incident {entry['id']!r}: {key} must be an https URL")
        expected = entry["expected"]
        if not isinstance(expected, dict) or not (expected.get("rules") or expected.get("paths")):
            raise StudyError(f"incident {entry['id']!r}: expected needs 'rules' or 'paths'")
        for key in ("rules", "paths"):
            if not isinstance(expected.get(key, []), list):
                raise StudyError(f"incident {entry['id']!r}: expected.{key} must be a list")
    return data["incidents"]


def _under(path: str, prefixes: list[str]) -> bool:
    path = path.replace("\\", "/").removeprefix("./")
    return not prefixes or any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/")
                               for p in (q.replace("\\", "/").removeprefix("./")
                                         for q in prefixes))


def rule_hits(report: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    rules = set(expected.get("rules") or [])
    paths = expected.get("paths") or []
    if not rules:
        return []
    return sorted(({"rule": f.get("rule_id"), "file": f.get("file"), "line": f.get("line")}
                   for f in report.get("findings") or []
                   if f.get("rule_id") in rules and _under(str(f.get("file") or ""), paths)),
                  key=lambda h: (str(h["rule"]), str(h["file"]), h["line"] or 0))


def observed_on_paths(report: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    paths = expected.get("paths") or []
    if not paths:
        return []
    return sorted({str(f.get("rule_id")) for f in report.get("findings") or []
                   if f.get("rule_id") and _under(str(f.get("file") or ""), paths)})


def change_hits(report: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    paths = expected.get("paths") or []
    return [{"kind": u["kind"], "subject": u["subject"], "type": u["type"],
             "change_class": u["change_class"]}
            for u in change_units(report)
            if paths and any(_under(p, paths) for p in u.get("paths") or [])]


def replay(entry: dict[str, Any], repo: str, work: str) -> dict[str, Any]:
    tree = os.path.join(work, "tree")
    shutil.rmtree(tree, ignore_errors=True)
    export_tree(repo, entry["vulnerable_ref"], tree)
    report = scan_tree(tree, os.path.join(work, "vulnerable.json"))
    shutil.rmtree(tree, ignore_errors=True)
    outcome = {"rule_hits": rule_hits(report, entry["expected"]), "change_hits": [],
               # What fired on the flaw's files: lets the verifier fill expected.rules
               # from evidence instead of guessing. Never scored.
               "observed_on_paths": observed_on_paths(report, entry["expected"])}
    if entry.get("introduced_ref"):
        info = commit_info(repo, entry["introduced_ref"])
        if not info["parents"]:
            raise StudyError("introduced_ref has no parent to compare with")
        export_tree(repo, info["parents"][0], tree)
        base = os.path.join(work, "before.json")
        scan_tree(tree, base)
        shutil.rmtree(tree, ignore_errors=True)
        export_tree(repo, info["sha"], tree)
        introduced = scan_tree(tree, os.path.join(work, "introduced.json"), baseline=base)
        shutil.rmtree(tree, ignore_errors=True)
        outcome["change_hits"] = change_hits(introduced, entry["expected"])
    flagged = bool(outcome["rule_hits"] or outcome["change_hits"])
    if entry["status"] != "verified" or entry["static_visibility"] == "undetermined":
        # Dry runs over candidates: what they would give, never scored.
        outcome["outcome"] = "unscored-flagged" if flagged else "unscored"
    elif entry["static_visibility"] == "runtime-only":
        outcome["outcome"] = "expected-unknown-flagged" if flagged else "expected-unknown"
    else:
        outcome["outcome"] = "detected" if flagged else "missed"
    return outcome


def summarise(results: list[dict[str, Any]]) -> dict[str, Any]:
    visible = [r for r in results if r.get("outcome") in ("detected", "missed")]
    return {
        "recall": wilson(sum(r["outcome"] == "detected" for r in visible), len(visible)),
        "unscored": sum(r.get("outcome", "").startswith("unscored") for r in results),
        "runtime_only": sum(r.get("outcome", "").startswith("expected-unknown") for r in results),
        "runtime_only_flagged": sum(r.get("outcome") == "expected-unknown-flagged"
                                    for r in results),
        "errors": sum(r.get("outcome") == "error" for r in results),
    }


def render(results: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    recall = summary["recall"]
    head = (f"{recall['rate']:.3f} [{recall['low']:.3f}, {recall['high']:.3f}]"
            if recall["status"] == "measured" else "insufficient")
    lines = ["# Incident replay", "",
             (f"Recall over verified, statically visible incidents: {head} "
              f"(n={recall['n']})."),
             (f"Runtime-only incidents (expected unknown): {summary['runtime_only']}, "
              f"of which flagged anyway: {summary['runtime_only_flagged']}."),
             (f"Unscored (candidates or undetermined visibility, dry run): "
              f"{summary['unscored']}."), "",
             "| Incident | Visibility | Outcome | Evidence | Rules on the flaw's files |",
             "|---|---|---|---|---|"]
    for r in results:
        evidence = ", ".join(f"`{h['rule']}` {h['file']}" for h in r.get("rule_hits", [])) or \
            ", ".join(f"{h['kind']} `{h['subject']}`" for h in r.get("change_hits", [])) or \
            r.get("error", "—")
        observed = ", ".join(f"`{x}`" for x in r.get("observed_on_paths", [])) or "—"
        lines.append(f"| [{r['id']}]({r['advisory']}) | {r['static_visibility']} | "
                     f"{r['outcome']} | {evidence} | {observed} |")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="incident_replay",
                                     description=__doc__.split("\n\n")[0])
    parser.add_argument("--registry", required=True)
    parser.add_argument("--out", default=None)
    parser.add_argument("--check", action="store_true", help="validate the registry and stop")
    parser.add_argument("--include-candidates", action="store_true",
                        help="also replay candidate entries (dry runs only; never for results)")
    parser.add_argument("--repo-path", action="append", default=[], metavar="ID=PATH",
                        help="use a local clone for this incident")
    parser.add_argument("--workdir", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        incidents = validate(load_yaml(args.registry))
    except (StudyError, OSError) as exc:
        print(f"incident_replay: {exc}", file=sys.stderr)
        return 2
    counts = {s: sum(i["status"] == s for i in incidents) for s in STATUSES}
    if args.check:
        print(f"registry valid: {len(incidents)} incidents "
              + ", ".join(f"{v} {k}" for k, v in counts.items()))
        return 0
    if not args.out:
        print("incident_replay: --out is required unless --check", file=sys.stderr)
        return 2
    local = dict(item.split("=", 1) for item in args.repo_path if "=" in item)
    wanted = {"verified", "candidate"} if args.include_candidates else {"verified"}
    selected = [i for i in incidents if i["status"] in wanted]
    work = args.workdir or tempfile.mkdtemp(prefix="safeai-replay-")
    clones: dict[str, str] = {}
    results = []
    for entry in selected:
        idir = os.path.join(work, entry["id"])
        os.makedirs(idir, exist_ok=True)
        row = {k: entry[k] for k in ("id", "advisory", "repository", "vulnerable_ref",
                                      "static_visibility", "status")}
        try:
            repo = local.get(entry["id"])
            if repo is None:
                repo = clones.get(entry["repository"])
            if repo is None:
                repo = clone(entry["repository"], os.path.join(idir, "repo"))
                clones[entry["repository"]] = repo
            git(["rev-parse", "--verify", f"{entry['vulnerable_ref']}^{{commit}}"], cwd=repo)
            row.update(replay(entry, os.path.abspath(repo), idir))
        except StudyError as exc:
            row.update(outcome="error", error=str(exc))
        results.append(row)
    summary = summarise(results)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "replay.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"registry": counts, "summary": summary, "incidents": results}, fh,
                  indent=1, sort_keys=True)
    with open(os.path.join(args.out, "replay.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(results, summary))
    print(render(results, summary))
    if not args.workdir:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
