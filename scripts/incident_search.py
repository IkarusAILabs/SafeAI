"""C-3 incident search: build the candidate registry from the GitHub Advisory Database.

Runs the search recorded in ``research/credibility/incidents.yml`` and
screens every advisory it returns with fixed, written rules, so the
registry holds *every* matching advisory rather than a hand-picked set:

1. **Search.** Reviewed, not withdrawn advisories for the ``pip`` and
   ``npm`` ecosystems published on or after ``--since``.
2. **Keyword screen.** Summary or description mentions MCP, the Model
   Context Protocol, AI / LLM / coding agents, agentic, agent skills,
   Claude Code, tool or function calling, or prompt injection; or an
   affected package name contains ``mcp`` or ``agent``.
3. **Flaw-class screen.** At least one CWE that agent authority evidence
   can bear on: command, argument or code injection (CWE-77, 78, 88, 94,
   95), path traversal and link following (CWE-22, 23, 59, 73), SSRF
   (CWE-918), LLM prompt injection (CWE-1427). Other classes (XSS,
   missing authentication, access-control logic, DoS) are screened out:
   they live in server or runtime code, not in what an agent is wired to
   do.
4. **Fix commit.** The advisory cites a fix commit on GitHub. Without one
   there is no revision to replay.

Advisories that pass all four become ``candidate`` entries: the parent of
the fix commit is ``vulnerable_ref``, the fix is ``fixed_ref``, and the
non-test files the fix changes are ``expected.paths``.
``static_visibility`` is ``undetermined`` and ``expected.rules`` is empty
until a human reads the advisory and the fix diff (``verified``). Every
advisory from step 2 is listed in the screening record with the step
that excluded it.

Uses the ``gh`` CLI (authenticated) for GitHub API calls. Study tooling:
the ``safeai`` scanner is not involved and gains no network path.

Usage:
    python scripts/incident_search.py --since 2025-01-01 \\
        --registry research/credibility/incidents.yml \\
        --screening research/credibility/incident_screening.json

Exit codes: 0 written · 2 usage or API error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess  # every call uses a fixed argv list, never shell=True
import sys
from collections import Counter
from datetime import UTC, datetime
from typing import Any

ECOSYSTEMS = ("pip", "npm")
KEYWORDS = re.compile(
    r"\b(mcp|model context protocol|ai agents?|llm agents?|agentic|coding agents?|"
    r"agent skills?|claude code|tool[- ]call(?:ing|s)?|function[- ]call(?:ing)?|"
    r"prompt injection)\b", re.IGNORECASE)
PACKAGE_KEYWORDS = re.compile(r"mcp|agent", re.IGNORECASE)
IN_SCOPE_CWES = ("CWE-22", "CWE-23", "CWE-59", "CWE-73", "CWE-77", "CWE-78", "CWE-88",
                 "CWE-94", "CWE-95", "CWE-918", "CWE-1427")
COMMIT_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})",
                        re.IGNORECASE)
NOT_EVIDENCE = re.compile(
    r"(^|/)(tests?|__tests__|spec|e2e|docs?|\.github)/|(^|/)test_[^/]*$|_test\.py$|\.test\.[jt]sx?$|"
    r"\.spec\.[jt]sx?$|(^|/)(changelog|readme|security)[^/]*$|"
    r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|uv\.lock|poetry\.lock)$",
    re.IGNORECASE)


class SearchError(Exception):
    pass


def gh_api(path: str, params: dict[str, str] | None = None, paginate: bool = False) -> Any:
    argv = ["gh", "api", "-X", "GET", path]
    for key, value in (params or {}).items():
        argv += ["-f", f"{key}={value}"]
    if paginate:
        argv += ["--paginate", "--jq", ".[]"]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                                timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SearchError(f"gh api {path}: {exc}") from exc
    if result.returncode != 0:
        raise SearchError(f"gh api {path}: {result.stderr.strip()[:300]}")
    if paginate:
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return json.loads(result.stdout)


def fetch_advisories(since: str) -> list[dict[str, Any]]:
    """Each advisory once, even when it affects packages in both ecosystems."""
    advisories: dict[str, dict[str, Any]] = {}
    for ecosystem in ECOSYSTEMS:
        for advisory in gh_api("advisories", {"ecosystem": ecosystem, "type": "reviewed",
                                              "published": f">={since}", "per_page": "100"},
                               paginate=True):
            seen = advisories.setdefault(advisory["ghsa_id"], dict(advisory, _ecosystem=[]))
            seen["_ecosystem"].append(ecosystem)
    return [dict(a, _ecosystem="+".join(a["_ecosystem"])) for a in advisories.values()]


def keyword_hit(advisory: dict[str, Any]) -> bool:
    text = f"{advisory.get('summary') or ''} {advisory.get('description') or ''}"
    packages = [v["package"]["name"] for v in advisory.get("vulnerabilities") or []
                if v.get("package")]
    return bool(KEYWORDS.search(text)) or any(PACKAGE_KEYWORDS.search(p) for p in packages)


def fix_commits(advisory: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(owner, repo, sha)`` for each cited fix commit, the advisory's own repo first."""
    home = (advisory.get("source_code_location") or "").lower().rstrip("/")
    found = []
    for ref in advisory.get("references") or []:
        match = COMMIT_URL.match(ref)
        if match:
            owner, repo, sha = match.groups()
            found.append((owner, repo.removesuffix(".git"), sha.lower()))
    found = list(dict.fromkeys(found))
    return sorted(found, key=lambda f: f"https://github.com/{f[0]}/{f[1]}".lower() != home)


def screen(advisory: dict[str, Any]) -> str:
    if advisory.get("withdrawn_at"):
        return "withdrawn"
    if not keyword_hit(advisory):
        return "no-keyword"
    cwes = {c["cwe_id"] for c in advisory.get("cwes") or []}
    if not cwes & set(IN_SCOPE_CWES):
        return "flaw-class-out-of-scope"
    if not fix_commits(advisory):
        return "no-fix-commit"
    return "candidate"


def draft_entry(advisory: dict[str, Any]) -> dict[str, Any]:
    owner, repo, sha = fix_commits(advisory)[0]
    commit = gh_api(f"repos/{owner}/{repo}/commits/{sha}")
    parents = [p["sha"] for p in commit.get("parents") or []]
    if not parents:
        raise SearchError(f"{advisory['ghsa_id']}: fix commit has no parent")
    files = sorted(f["filename"] for f in commit.get("files") or [])
    evidence = [f for f in files if not NOT_EVIDENCE.search(f)] or files
    packages = sorted({f"{v['package']['ecosystem']}:{v['package']['name']}"
                       for v in advisory.get("vulnerabilities") or [] if v.get("package")})
    return {
        "id": advisory["ghsa_id"],
        "advisory": advisory["html_url"],
        "repository": f"https://github.com/{owner}/{repo}.git",
        "vulnerable_ref": parents[0],
        "fixed_ref": commit["sha"],
        "static_visibility": "undetermined",
        "expected": {"rules": [], "paths": evidence[:20]},
        "status": "candidate",
        "published": advisory["published_at"][:10],
        "packages": packages,
        "cwes": sorted(c["cwe_id"] for c in advisory.get("cwes") or []),
        "notes": (advisory.get("summary") or "").strip()[:300],
    }


def render_registry(entries: list[dict[str, Any]], since: str, date: str,
                    counts: dict[str, int]) -> str:
    import yaml

    head = """# C-3 incident replay registry (docs/research/CREDIBILITY_TRACK.md).
#
# Generated by scripts/incident_search.py from the search below; the
# screening record (incident_screening.json) lists every advisory the
# keyword screen matched and the step that excluded it. Re-running the
# search on a later date adds advisories; it never removes one a human
# has verified or rejected.
#
# An entry is `candidate` until a human has read the advisory and the
# fix diff, set static_visibility (visible | runtime-only), filled
# expected.rules and corrected expected.paths. Only `verified` entries
# are scored; `rejected` entries stay listed with a reason in notes.
#
# Fields: id, advisory, repository, vulnerable_ref (parent of the fix),
# fixed_ref, introduced_ref (optional), static_visibility, expected.rules,
# expected.paths, status (candidate | verified | rejected), published,
# packages, cwes, notes.
#
# `python scripts/incident_replay.py --registry research/credibility/incidents.yml --check`
# validates this file.

"""
    body = {
        "version": 1,
        "search": {
            "query": (f"GitHub Advisory Database, reviewed, ecosystems "
                      f"{' and '.join(ECOSYSTEMS)}, published on or after {since}; keyword, "
                      f"flaw-class and fix-commit screens in scripts/incident_search.py"),
            "date": date,
            "counts": counts,
        },
        "incidents": entries,
    }
    return head + yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=100)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="incident_search", description=__doc__.split("\n\n")[0])
    parser.add_argument("--since", default="2025-01-01")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--screening", required=True)
    parser.add_argument("--existing", default=None,
                        help="keep verified / rejected entries from this registry")
    args = parser.parse_args(argv)
    date = datetime.now(UTC).strftime("%Y-%m-%d")
    try:
        advisories = fetch_advisories(args.since)
        decisions = {a["ghsa_id"]: screen(a) for a in advisories}
        kept: dict[str, dict[str, Any]] = {}
        if args.existing:
            import yaml

            with open(args.existing, encoding="utf-8") as fh:
                old = yaml.safe_load(fh) or {}
            kept = {e["id"]: e for e in old.get("incidents") or []
                    if e.get("status") in ("verified", "rejected")}
        entries, failures = [], {}
        for advisory in sorted(advisories, key=lambda a: a["ghsa_id"]):
            ghsa = advisory["ghsa_id"]
            if ghsa in kept:
                entries.append(kept[ghsa])
            elif decisions[ghsa] == "candidate":
                try:
                    entries.append(draft_entry(advisory))
                except SearchError as exc:
                    decisions[ghsa] = "fix-commit-unreadable"
                    failures[ghsa] = str(exc)
    except SearchError as exc:
        print(f"incident_search: {exc}", file=sys.stderr)
        return 2
    counts = Counter(decisions.values())
    summary = {"advisories_searched": len(advisories),
               "keyword_matches": len(advisories) - counts["no-keyword"] - counts["withdrawn"],
               **{k: counts[k] for k in ("flaw-class-out-of-scope", "no-fix-commit",
                                         "fix-commit-unreadable", "candidate")}}
    screening = [{"id": a["ghsa_id"], "ecosystem": a["_ecosystem"],
                  "published": a["published_at"][:10],
                  "cwes": sorted(c["cwe_id"] for c in a.get("cwes") or []),
                  "decision": decisions[a["ghsa_id"]],
                  **({"error": failures[a["ghsa_id"]]} if a["ghsa_id"] in failures else {}),
                  "summary": (a.get("summary") or "")[:200]}
                 for a in sorted(advisories, key=lambda a: a["ghsa_id"])
                 if decisions[a["ghsa_id"]] not in ("no-keyword", "withdrawn")]
    with open(args.screening, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"date": date, "since": args.since, "summary": summary,
                   "rules": {"keywords": KEYWORDS.pattern, "package_keywords":
                             PACKAGE_KEYWORDS.pattern, "in_scope_cwes": list(IN_SCOPE_CWES)},
                   "advisories": screening}, fh, indent=1)
        fh.write("\n")
    with open(args.registry, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_registry(entries, args.since, date, summary))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
