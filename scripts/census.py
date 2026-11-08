"""C-5 authority surface census (docs/research/CREDIBILITY_TRACK.md, C-5).

Describes what agent authority looks like in public MCP server
repositories, as SafeAI reports it, over a pre-registered random sample
of the official MCP registry. Aggregates only: no per-project ranking,
and published output never names a repository.

Subcommands, in the order the protocol runs them:

``frame``
    Snapshot the registry: every *active*, *latest* server entry whose
    ``repository`` is on github.com, reduced to distinct repositories.
    Writes the sorted list (gzip) and its counts.
``sample``
    Order the frame by ``sha256("C5:<seed>:<repo>")`` and screen
    repositories in that order (GitHub API facts only, no scan) until
    ``--n`` are eligible; pins each eligible repository's head commit.
    Every screened repository is recorded with its reason.
``run``
    Fetch each pinned commit (depth 1), export it with ``git archive``,
    scan it, and keep only the census attributes (never findings) in
    ``<out>/units.jsonl``. Resumable.
``aggregate``
    Shares with 95% Wilson intervals; *insufficient* below 10.
``packets`` / ``agreement``
    The human check: a seeded subsample gets a blank sheet (SafeAI's
    answers are never shown); ``agreement`` scores SafeAI's attributes
    against the adjudicated sheet.

Network use is in this study tool only (``curl`` for the registry, ``gh``
and ``git`` for GitHub); target code is never installed or executed and
the ``safeai`` scanner gains no network path.

Exit codes: 0 done · 1 some repositories failed (``run``) · 2 usage error.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import shutil
import subprocess  # every call uses a fixed argv list, never shell=True
import sys
import tempfile
import urllib.parse
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from history_study import pin_project_id
from study_common import (
    StudyError,
    export_tree,
    fetch,
    git,
    read_jsonl,
    scan_tree,
    wilson,
    write_jsonl,
)
from target_check import REPO_URL, SAFEAI_OWNERS, repo_facts

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
REGISTRY_META = "io.modelcontextprotocol.registry/official"
MAX_PAGES = 5000
MAX_REPO_KB = 500_000  # larger repositories are excluded, not truncated

# Census attributes. Each is a yes/no per repository, as SafeAI reports it.
ATTRIBUTES = {
    "surface": "SafeAI finds an agent framework, a tool or an MCP asset",
    "execute": "some capability has access mode execute",
    "write_or_broader": "some capability has access mode write, mutate or execute",
    "approval_missing": "write-or-broader authority and GOV_APPROVAL_MISSING reported",
    "static_credential": "a hardcoded-secret rule fires",
}
# The denominator of each attribute: all scanned repositories, or those
# where another attribute holds.
DENOMINATOR = {
    "surface": None,
    "execute": "surface",
    "write_or_broader": "surface",
    "approval_missing": "write_or_broader",
    "static_credential": "surface",
}
SECRET_RULES = frozenset({"MCP_HARDCODED_SECRET", "SKILL_HARDCODED_SECRET", "DATA_LEAKAGE"})
BROAD_MODES = frozenset({"write", "mutate", "execute"})
CHECK_FIELDS = ["surface", "execute", "write_or_broader", "approval_missing",
                "static_credential"]


# --- frame --------------------------------------------------------------------------

def github_repo(url: str) -> str | None:
    """``https://github.com/owner/name`` (lower case), or None."""
    match = REPO_URL.match(str(url or "").strip())
    if not match:
        return None
    return f"https://github.com/{match.group(1)}/{match.group(2)}".lower()


def build_frame(pages: Iterable[dict[str, Any]]) -> dict[str, Any]:
    entries = active = linked = 0
    repos: set[str] = set()
    for page in pages:
        for item in page.get("servers") or []:
            entries += 1
            meta = (item.get("_meta") or {}).get(REGISTRY_META) or {}
            if meta.get("status") != "active" or meta.get("isLatest") is False:
                continue
            active += 1
            repo = github_repo(((item.get("server") or {}).get("repository") or {}).get("url"))
            if repo:
                linked += 1
                repos.add(repo)
    return {"entries": entries, "active": active, "with_github_repository": linked,
            "repositories": sorted(repos)}


def registry_pages(get: Callable[[str], bytes] = fetch) -> Iterable[dict[str, Any]]:
    cursor = None
    for _ in range(MAX_PAGES):
        query = {"limit": "100", "version": "latest"}
        if cursor:
            query["cursor"] = cursor
        page = json.loads(get(REGISTRY + "?" + urllib.parse.urlencode(query)))
        yield page
        cursor = (page.get("metadata") or {}).get("nextCursor")
        if not cursor:
            return
    raise StudyError(f"registry did not end within {MAX_PAGES} pages")


def write_frame(frame: dict[str, Any], path: str) -> str:
    body = "".join(r + "\n" for r in frame["repositories"]).encode("utf-8")
    # No file name or time in the gzip header, so the same list gives the same bytes.
    with open(path, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb",
                                                mtime=0) as fh:
        fh.write(body)
    return hashlib.sha256(body).hexdigest()


def read_frame(path: str) -> list[str]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


# --- sample -------------------------------------------------------------------------

def seeded_order(repos: Iterable[str], seed: str) -> list[str]:
    return sorted(repos, key=lambda r: hashlib.sha256(f"C5:{seed}:{r}".encode()).hexdigest())


def gh_json(path: str) -> dict[str, Any] | None:
    """``gh api`` GET; None when GitHub answers 404 (deleted or private)."""
    try:
        result = subprocess.run(["gh", "api", "-X", "GET", path], capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StudyError(f"gh api {path}: {exc}") from exc
    if result.returncode != 0:
        if "404" in result.stderr or "Not Found" in result.stderr:
            return None
        raise StudyError(f"gh api {path}: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout)


def screen(meta: dict[str, Any] | None) -> list[str]:
    """Reasons a repository is not eligible (empty when it is)."""
    if meta is None:
        return ["not found"]
    facts = repo_facts(meta)
    fails = []
    if not facts["licence"]:
        fails.append("no recognised open-source licence")
    if facts["archived"]:
        fails.append("archived")
    if facts["fork"]:
        fails.append("a fork")
    if str(facts["owner"] or "").lower() in SAFEAI_OWNERS:
        fails.append("written by SafeAI's authors")
    if not meta.get("size"):
        fails.append("empty")
    elif meta["size"] > MAX_REPO_KB:
        fails.append(f"larger than {MAX_REPO_KB // 1000} MB")
    return fails


def draw_sample(frame: list[str], seed: str, n: int,
                lookup: Callable[[str], dict[str, Any] | None],
                head: Callable[[str, str], str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    eligible = 0
    for rank, repo in enumerate(seeded_order(frame, seed), 1):
        if eligible >= n:
            break
        owner_name = repo.removeprefix("https://github.com/")
        meta = lookup(owner_name)
        fails = screen(meta)
        row: dict[str, Any] = {"rank": rank, "repository": repo, "eligible": not fails}
        if fails:
            row["reasons"] = fails
        else:
            eligible += 1
            row["licence"] = repo_facts(meta)["licence"]
            row["commit"] = head(owner_name, meta["default_branch"])
        rows.append(row)
    if eligible < n:
        rows.append({"note": f"frame exhausted: {eligible} eligible of {n} wanted"})
    return rows


# --- run ----------------------------------------------------------------------------

def attributes(report: dict[str, Any]) -> dict[str, Any]:
    """The census attributes of one scan; findings are not kept."""
    caps = [c for t in report.get("tool_surface") or [] for c in t.get("capabilities") or []]
    modes = {str(c.get("access_mode")) for c in caps}
    rules = {str(f.get("rule_id")) for f in report.get("findings") or []}
    surface = bool(report.get("detected_frameworks") or report.get("tool_surface")
                   or report.get("mcp_assets"))
    broad = bool(modes & BROAD_MODES)
    rate = (((report.get("evidence_metrics") or {}).get("rates") or {})
            .get("unattributed_authority_rate") or {})
    return {
        "surface": surface,
        "execute": "execute" in modes,
        "write_or_broader": broad,
        "approval_missing": broad and "GOV_APPROVAL_MISSING" in rules,
        "static_credential": bool(rules & SECRET_RULES),
        "unattributed": [rate.get("numerator") or 0, rate.get("denominator") or 0],
        "files_scanned": report.get("files_scanned") or 0,
    }


def unit_key(repo: str) -> str:
    return hashlib.sha256(repo.encode()).hexdigest()[:16]


def run_one(row: dict[str, Any], workdir: str) -> dict[str, Any]:
    repo = os.path.join(workdir, "repo")
    os.makedirs(repo)
    git(["init", "--quiet", repo])
    git(["fetch", "--quiet", "--depth", "1", row["repository"], row["commit"]], cwd=repo)
    tree = os.path.join(workdir, "tree")
    export_tree(repo, row["commit"], tree)
    pin_project_id(tree, "census-" + unit_key(row["repository"]))
    return attributes(scan_tree(tree, os.path.join(workdir, "scan.json")))


def run(sample: list[dict[str, Any]], out: str,
        one: Callable[[dict[str, Any], str], dict[str, Any]] = run_one) -> int:
    os.makedirs(out, exist_ok=True)
    units_path = os.path.join(out, "units.jsonl")
    units = read_jsonl(units_path)
    done = {u["repository"] for u in units}
    errors = []
    for row in sample:
        if not row.get("eligible") or row["repository"] in done:
            continue
        workdir = tempfile.mkdtemp(prefix="safeai-census-")
        try:
            unit = {"repository": row["repository"], "commit": row["commit"],
                    **one(row, workdir)}
        except StudyError as exc:
            errors.append({"repository": row["repository"], "error": str(exc)})
            continue
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        units.append(unit)
        write_jsonl(units_path, units)
    write_jsonl(os.path.join(out, "errors.jsonl"), errors)
    print(f"{len(units)} scanned, {len(errors)} failed", file=sys.stderr)
    return 1 if errors else 0


# --- aggregate ----------------------------------------------------------------------

def aggregate(units: list[dict[str, Any]], errors: int = 0) -> dict[str, Any]:
    shares = {}
    for name, description in ATTRIBUTES.items():
        base = DENOMINATOR[name]
        pool = [u for u in units if base is None or u.get(base)]
        shares[name] = {"description": description,
                        "of": "all scanned" if base is None else base,
                        **wilson(sum(1 for u in pool if u.get(name)), len(pool))}
    num = sum(u["unattributed"][0] for u in units if u.get("surface"))
    den = sum(u["unattributed"][1] for u in units if u.get("surface"))
    return {
        "study": "C-5 authority surface census",
        "scanned": len(units), "failed": errors,
        "shares": shares,
        "unattributed_authority": {
            "statements": den, "unattributed": num,
            "rate": round(num / den, 4) if den else None,
            "note": "pooled over statements; statements in one repository are not "
                    "independent, so no interval is given"},
        "reading": "Shares are as SafeAI reports them; the human check gives "
                   "SafeAI's agreement with people on each attribute.",
    }


# --- human check --------------------------------------------------------------------

def check_subsample(units: list[dict[str, Any]], seed: str, count: int) -> list[dict[str, Any]]:
    by_repo = {u["repository"]: u for u in units}
    return [by_repo[r] for r in seeded_order(by_repo, "check:" + seed)[:count]]


def write_packets(units: list[dict[str, Any]], seed: str, count: int, out: str,
                  checkers: list[str]) -> list[str]:
    os.makedirs(out, exist_ok=True)
    chosen = check_subsample(units, seed, count)
    paths = []
    for who in checkers:
        path = os.path.join(out, f"check.{who}.csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["repository", "commit", *CHECK_FIELDS, "notes"])
            for unit in chosen:  # SafeAI's answers are never written to the sheet
                writer.writerow([unit["repository"], unit["commit"],
                                 *([""] * len(CHECK_FIELDS)), ""])
        paths.append(path)
    return paths


def _yes(value: str) -> bool | None:
    value = str(value or "").strip().lower()
    if value in ("y", "yes", "1", "true"):
        return True
    if value in ("n", "no", "0", "false"):
        return False
    return None


def agreement(units: list[dict[str, Any]], sheet: list[dict[str, str]]) -> dict[str, Any]:
    """SafeAI against the adjudicated human sheet, per attribute."""
    by_repo = {u["repository"]: u for u in units}
    result = {}
    for name in CHECK_FIELDS:
        tp = fp = fn = tn = 0
        for row in sheet:
            human = _yes(row.get(name, ""))
            unit = by_repo.get(row.get("repository", ""))
            if human is None or unit is None:
                continue
            said = bool(unit.get(name))
            tp += said and human
            fp += said and not human
            fn += human and not said
            tn += not said and not human
        result[name] = {"precision": wilson(tp, tp + fp), "recall": wilson(tp, tp + fn),
                        "agreement": wilson(tp + tn, tp + fp + fn + tn)}
    return result


# --- CLI ----------------------------------------------------------------------------

def _head(owner_name: str, branch: str) -> str:
    data = gh_json(f"repos/{owner_name}/commits/{urllib.parse.quote(branch, safe='')}")
    if not data or not data.get("sha"):
        raise StudyError(f"no head commit for {owner_name}")
    return data["sha"]


def _write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="census", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("frame")
    p.add_argument("--out", required=True, help="frame list (.txt.gz)")
    p.add_argument("--meta", required=True, help="frame counts (JSON)")
    p = sub.add_parser("sample")
    p.add_argument("--frame", required=True)
    p.add_argument("--seed", required=True)
    p.add_argument("--n", type=int, required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("run")
    p.add_argument("--sample", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("aggregate")
    p.add_argument("study")
    p.add_argument("--json", required=True)
    p = sub.add_parser("packets")
    p.add_argument("study")
    p.add_argument("--seed", required=True)
    p.add_argument("--count", type=int, default=30)
    p.add_argument("--checkers", required=True, help="comma-separated names")
    p.add_argument("--out", required=True)
    p = sub.add_parser("agreement")
    p.add_argument("study")
    p.add_argument("sheet", help="adjudicated check sheet (CSV)")
    p.add_argument("--json", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "frame":
            frame = build_frame(registry_pages())
            digest = write_frame(frame, args.out)
            _write_json(args.meta, {
                "snapshot": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "registry": REGISTRY, "entries": frame["entries"],
                "active_latest": frame["active"],
                "with_github_repository": frame["with_github_repository"],
                "repositories": len(frame["repositories"]),
                "list": os.path.basename(args.out), "list_sha256": digest})
            print(f"{len(frame['repositories'])} repositories", file=sys.stderr)
            return 0
        if args.command == "sample":
            rows = draw_sample(read_frame(args.frame), args.seed, args.n, lambda r: gh_json(
                f"repos/{r}"), _head)
            _write_json(args.out, {"seed": args.seed, "n": args.n,
                                   "drawn": datetime.now(UTC).strftime("%Y-%m-%d"),
                                   "rows": rows})
            return 0
        if args.command == "run":
            with open(args.sample, encoding="utf-8") as fh:
                return run(json.load(fh)["rows"], args.out)
        units = read_jsonl(os.path.join(args.study, "units.jsonl"))
        if not units:
            print(f"census: no units in {args.study}", file=sys.stderr)
            return 2
        if args.command == "aggregate":
            failed = len(read_jsonl(os.path.join(args.study, "errors.jsonl")))
            _write_json(args.json, aggregate(units, failed))
            return 0
        if args.command == "packets":
            names = [n.strip() for n in args.checkers.split(",") if n.strip()]
            for path in write_packets(units, args.seed, args.count, args.out, names):
                print(path)
            return 0
        with open(args.sheet, encoding="utf-8", newline="") as fh:
            _write_json(args.json, agreement(units, list(csv.DictReader(fh))))
        return 0
    except (StudyError, OSError, ValueError) as exc:
        print(f"census: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
