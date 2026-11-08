"""C-3 incident verification kit: lay out candidates for people to verify, apply their answers.

The registry (``research/credibility/incidents.yml``) holds candidates the
search drafted. A candidate is scored only after people have read the
advisory and the fix diff and filled in what a static scanner could see.
This tool never fills an answer. It:

``order``    prints the pre-registered verification order: candidates
             sorted by ``sha256("<seed>:<id>")``. Verifying a prefix of
             this order is a random sample, not a hand-picked one, and
             adding candidates later does not reshuffle the existing ones.
``packets``  writes one Markdown packet per candidate (advisory text,
             CWEs, fix commit with its diff, the full rule catalogue) and a
             blank sheet per verifier. Packets never show what SafeAI
             reports on the code: the expected rules are chosen blind.
``apply``    reads two verifiers' sheets (and an optional adjudication
             sheet) and writes agreed answers into the registry, with
             ``verified_by`` and ``verified_on``. Rows the verifiers
             disagree on, and that no adjudication settles, stay candidates
             and are listed.

Protocol: ``docs/research/CREDIBILITY_TRACK.md`` (C-3). Uses the ``gh``
CLI for the advisory text and fix diff (``--offline`` skips it); the
``safeai`` scanner is not run and gains no network path.

Usage:
    python scripts/incident_verify.py order --registry research/credibility/incidents.yml
    python scripts/incident_verify.py packets --registry R.yml --count 20 --out verify/ \\
        --verifiers ana,ben
    python scripts/incident_verify.py apply --registry R.yml verify/sheet.ana.csv \\
        verify/sheet.ben.csv [--adjudication verify/adjudicated.csv]

Exit codes: 0 done · 1 some rows not applied (disagreement or bad answer) ·
2 usage error.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess  # every call uses a fixed argv list, never shell=True
import sys
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from study_common import StudyError, load_yaml

SEED = 20261107
SHEET_FIELDS = ["id", "decision", "static_visibility", "rules", "paths", "introduced_ref",
                "reason"]
DECISIONS = ("verified", "rejected", "unsure")
VISIBILITY = ("visible", "runtime-only")
MAX_PATCH_LINES = 120
REPO_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
NAME = re.compile(r"^[A-Za-z0-9_-]+$")
SHA = re.compile(r"^[0-9a-f]{7,40}$")


# --- order -------------------------------------------------------------------------

def rank_key(incident_id: str, seed: int = SEED) -> str:
    return hashlib.sha256(f"{seed}:{incident_id}".encode()).hexdigest()


def verification_order(incidents: list[dict[str, Any]], seed: int = SEED) -> list[dict[str, Any]]:
    """Candidates in the pre-registered order; verified and rejected entries drop out."""
    return sorted((i for i in incidents if i.get("status") == "candidate"),
                  key=lambda i: rank_key(i["id"], seed))


def load_registry(path: str) -> dict[str, Any]:
    data = load_yaml(path) or {}
    if not isinstance(data.get("incidents"), list):
        raise StudyError(f"{path}: needs an 'incidents' list")
    return data


# --- packets -----------------------------------------------------------------------

def gh_json(path: str) -> Any:
    try:
        result = subprocess.run(["gh", "api", "-X", "GET", path], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StudyError(f"gh api {path}: {exc}") from exc
    if result.returncode != 0:
        raise StudyError(f"gh api {path}: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout)


def fetch_context(entry: dict[str, Any]) -> dict[str, Any]:
    """Advisory text and the fix commit, from the GitHub API."""
    context: dict[str, Any] = {}
    advisory = gh_json(f"advisories/{entry['id']}")
    context["advisory"] = {k: advisory.get(k) for k in ("summary", "description", "severity",
                                                         "references")}
    match = REPO_URL.match(str(entry.get("repository") or ""))
    if match and entry.get("fixed_ref"):
        commit = gh_json(f"repos/{match.group(1)}/{match.group(2)}/commits/{entry['fixed_ref']}")
        context["fix"] = {
            "message": (commit.get("commit") or {}).get("message", ""),
            "files": [{"filename": f.get("filename"), "status": f.get("status"),
                       "patch": f.get("patch") or ""} for f in commit.get("files") or []],
        }
    return context


def rule_catalogue() -> list[dict[str, str]]:
    """Every built-in rule id and description (the choices for ``rules``)."""
    from safeai.rules.loader import load_rules

    rules = load_rules()[0]
    return sorted(({"id": r["id"], "description": r.get("description", "")} for r in rules),
                  key=lambda r: r["id"])


def _repo_web(entry: dict[str, Any]) -> str:
    return str(entry.get("repository") or "").removesuffix(".git")


def _patch(text: str) -> list[str]:
    lines = text.splitlines()
    shown = lines[:MAX_PATCH_LINES]
    if len(lines) > MAX_PATCH_LINES:
        shown.append(f"... {len(lines) - MAX_PATCH_LINES} more lines in the commit")
    return shown


def packet(entry: dict[str, Any], rank: int, context: dict[str, Any] | None) -> str:
    web = _repo_web(entry)
    lines = [f"# {entry['id']} (verification rank {rank})", "",
             f"- Advisory: {entry['advisory']}",
             f"- Repository: {web}",
             (f"- Vulnerable revision (parent of the fix): "
             f"[`{entry['vulnerable_ref'][:12]}`]({web}/tree/{entry['vulnerable_ref']})")]
    if entry.get("fixed_ref"):
        lines.append(f"- Fix: [`{entry['fixed_ref'][:12]}`]({web}/commit/{entry['fixed_ref']})")
    lines += [f"- Published: {entry.get('published', '?')}",
              f"- Packages: {', '.join(entry.get('packages') or []) or '?'}",
              f"- CWEs: {', '.join(entry.get('cwes') or []) or '?'}",
              (f"- Drafted paths (non-test files the fix changes): "
              f"{', '.join(f'`{p}`' for p in entry['expected'].get('paths') or []) or '—'}"),
              "", "## Advisory", ""]
    advisory = (context or {}).get("advisory")
    if advisory:
        lines += [f"**{advisory.get('summary') or ''}** (severity {advisory.get('severity')})",
                  "", (advisory.get("description") or "").strip(), ""]
    else:
        lines += [entry.get("notes") or "", "", "_Advisory text not fetched; open the link._", ""]
    fix = (context or {}).get("fix")
    if fix:
        lines += ["## Fix commit", "", "```text", fix["message"].strip(), "```", ""]
        for f in fix["files"]:
            lines += [f"### `{f['filename']}` ({f['status']})", ""]
            if f["patch"]:
                lines += ["```diff", *_patch(f["patch"]), "```", ""]
    lines += [
        "## Questions (answer in your sheet, row `" + entry["id"] + "`)", "",
        ("1. `decision`: `verified` if the advisory describes a real flaw that is present at "
        "the vulnerable revision and the fields below are right; `rejected` if it is not an "
        "agent, MCP or tool flaw, or the cited commit does not fix it (say why in `reason`); "
        "`unsure` otherwise."),
        ("2. `static_visibility`: `visible` if the flaw is in the repository's files (a tool "
        "that runs model input as a command, an unchecked path, an over-broad tool); "
        "`runtime-only` if it needs run-time state (a race, a server-side check, a "
        "dependency's behaviour)."),
        ("3. `rules`: the SafeAI rules (catalogue below, `;`-separated) that **should** flag "
        "the flaw if SafeAI worked as documented. Decide from the flaw, not from a scan: this "
        "packet does not show what SafeAI reports, on purpose. Leave empty if none fits."),
        "4. `paths`: the files where the flaw lives (`;`-separated); correct the drafted list.",
        "5. `introduced_ref`: the commit that introduced the flaw, if you found it (optional).",
        "", "## Rule catalogue", "", "| Rule | Description |", "|---|---|"]
    lines += [f"| `{r['id']}` | {r['description']} |" for r in rule_catalogue()]
    return "\n".join(lines) + "\n"


def cmd_order(args: argparse.Namespace) -> int:
    order = verification_order(load_registry(args.registry)["incidents"], args.seed)
    for rank, entry in enumerate(order, 1):
        print(f"{rank:4d}  {entry['id']}  {', '.join(entry.get('cwes') or [])}  "
              f"{(entry.get('notes') or '')[:80]}")
    return 0


def _names(value: str) -> list[str]:
    names = [n.strip() for n in (value or "").split(",") if n.strip()]
    bad = [n for n in names if not NAME.match(n)]
    if bad:
        raise StudyError(f"bad verifier name {bad[0]!r}")
    if len(set(names)) < 2:
        raise StudyError("give two different verifiers (--verifiers ana,ben)")
    return names


def cmd_packets(args: argparse.Namespace) -> int:
    verifiers = _names(args.verifiers)
    order = verification_order(load_registry(args.registry)["incidents"], args.seed)
    ranked = list(enumerate(order, 1))
    if args.ids:
        wanted = set(args.ids)
        ranked = [(r, e) for r, e in ranked if e["id"] in wanted]
    else:
        ranked = ranked[:args.count]
    if not ranked:
        raise StudyError("no candidate selected")
    os.makedirs(os.path.join(args.out, "packets"), exist_ok=True)
    index = ["# Incident verification", "",
             (f"{len(ranked)} candidates, in the pre-registered order (seed {args.seed}). "
             "Protocol: docs/research/CREDIBILITY_TRACK.md (C-3)."), "",
             "| Rank | Incident | CWEs | Packet |", "|---|---|---|---|"]
    failed = 0
    for rank, entry in ranked:
        context = None
        if not args.offline:
            try:
                context = fetch_context(entry)
            except StudyError as exc:
                failed += 1
                print(f"{entry['id']}: {exc} (packet written without it)", file=sys.stderr)
        name = f"{rank:03d}-{entry['id']}.md"
        with open(os.path.join(args.out, "packets", name), "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write(packet(entry, rank, context))
        index.append(f"| {rank} | {entry['id']} | {', '.join(entry.get('cwes') or [])} | "
                     f"[packets/{name}](packets/{name}) |")
    with open(os.path.join(args.out, "INDEX.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(index) + "\n")
    for verifier in verifiers:
        with open(os.path.join(args.out, f"sheet.{verifier}.csv"), "w", encoding="utf-8",
                  newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=SHEET_FIELDS)
            writer.writeheader()
            for _, entry in ranked:
                writer.writerow({"id": entry["id"]})
    print(f"{len(ranked)} packets in {args.out}" + (f" ({failed} without API context)"
                                                    if failed else ""))
    return 0


# --- apply -------------------------------------------------------------------------

def _split(value: str) -> list[str]:
    return sorted({v.strip() for v in (value or "").split(";") if v.strip()})


def read_answers(path: str) -> dict[str, dict[str, Any]]:
    """One verifier's sheet; rows without a decision are skipped."""
    with open(path, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    answers = {}
    for row in rows:
        row = {k: (v or "").strip() for k, v in row.items() if k}
        if not row.get("id") or not row.get("decision"):
            continue
        answers[row["id"]] = {
            "decision": row["decision"].lower(),
            "static_visibility": row.get("static_visibility", "").lower(),
            "rules": _split(row.get("rules", "")),
            "paths": _split(row.get("paths", "")),
            "introduced_ref": row.get("introduced_ref", "").lower(),
            "reason": row.get("reason", ""),
        }
    return answers


def check_answer(answer: dict[str, Any]) -> str | None:
    """Why this answer cannot be applied, or None."""
    if answer["decision"] not in DECISIONS:
        return f"decision must be one of {', '.join(DECISIONS)}"
    if answer["decision"] == "rejected" and not answer["reason"]:
        return "a rejection needs a reason"
    if answer["decision"] == "verified":
        if answer["static_visibility"] not in VISIBILITY:
            return f"static_visibility must be one of {', '.join(VISIBILITY)}"
        if not (answer["rules"] or answer["paths"]):
            return "a verified incident needs rules or paths"
    if answer["introduced_ref"] and not SHA.match(answer["introduced_ref"]):
        return "introduced_ref must be a commit SHA"
    return None


COMPARED = ("decision", "static_visibility", "rules", "paths", "introduced_ref")


def _same(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if a["decision"] != b["decision"]:
        return False
    if a["decision"] != "verified":
        return True
    return all(a[k] == b[k] for k in COMPARED)


def _verifier(path: str) -> str:
    base = os.path.basename(path)
    parts = base.split(".")
    return parts[1] if len(parts) == 3 and parts[0] == "sheet" else os.path.splitext(base)[0]


def merge(sheets: list[tuple[str, dict[str, dict[str, Any]]]],
          adjudication: tuple[str, dict[str, dict[str, Any]]] | None
          ) -> tuple[dict[str, tuple[dict[str, Any], list[str]]], list[dict[str, Any]]]:
    """(id -> (answer, verifiers)) for settled rows, and the problems."""
    (name_a, a), (name_b, b) = sheets
    settled: dict[str, tuple[dict[str, Any], list[str]]] = {}
    problems: list[dict[str, Any]] = []
    for incident in sorted(set(a) | set(b)):
        answer, by = None, [name_a, name_b]
        if incident in a and incident in b and _same(a[incident], b[incident]):
            answer = a[incident]
        elif adjudication and incident in adjudication[1]:
            answer, by = adjudication[1][incident], [name_a, name_b, adjudication[0]]
        elif incident not in a or incident not in b:
            problems.append({"id": incident, "problem": "answered by one verifier only"})
            continue
        else:
            diff = [k for k in COMPARED if a[incident][k] != b[incident][k]]
            problems.append({"id": incident, "problem": "verifiers disagree on " + ", ".join(diff)})
            continue
        reason = check_answer(answer)
        if reason:
            problems.append({"id": incident, "problem": reason})
        elif answer["decision"] == "unsure":
            problems.append({"id": incident, "problem": "unsure; stays a candidate"})
        else:
            settled[incident] = (answer, by)
    return settled, problems


def apply_answers(data: dict[str, Any], settled: dict[str, tuple[dict[str, Any], list[str]]],
                  today: str) -> int:
    applied = 0
    for entry in data["incidents"]:
        if entry["id"] not in settled or entry.get("status") != "candidate":
            continue
        answer, by = settled[entry["id"]]
        entry["status"] = answer["decision"]
        entry["verified_by"] = by
        entry["verified_on"] = today
        if answer["decision"] == "verified":
            entry["static_visibility"] = answer["static_visibility"]
            entry["expected"] = {"rules": answer["rules"],
                                 "paths": answer["paths"] or entry["expected"].get("paths", [])}
            if answer["introduced_ref"]:
                entry["introduced_ref"] = answer["introduced_ref"]
        else:
            entry["notes"] = f"{entry.get('notes', '')} Rejected: {answer['reason']}".strip()
        applied += 1
    return applied


def write_registry(path: str, data: dict[str, Any]) -> None:
    """Rewrite the body, keeping the file's leading comment block."""
    import yaml

    with open(path, encoding="utf-8") as fh:
        head = []
        for line in fh:
            if line.startswith("#") or not line.strip():
                head.append(line)
            else:
                break
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(head))
        fh.write(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100))


def cmd_apply(args: argparse.Namespace) -> int:
    if len(args.sheets) != 2:
        raise StudyError("give exactly two verifier sheets")
    sheets = [(_verifier(p), read_answers(p)) for p in args.sheets]
    if sheets[0][0] == sheets[1][0]:
        raise StudyError("the two sheets must come from different verifiers")
    adjudication = ((_verifier(args.adjudication), read_answers(args.adjudication))
                    if args.adjudication else None)
    data = load_registry(args.registry)
    known = {e["id"] for e in data["incidents"]}
    settled, problems = merge(sheets, adjudication)
    for incident in [i for i in settled if i not in known]:
        problems.append({"id": incident, "problem": "not in the registry"})
        del settled[incident]
    applied = apply_answers(data, settled, args.today or datetime.now(UTC).strftime("%Y-%m-%d"))
    write_registry(args.registry, data)
    print(json.dumps({"applied": applied, "problems": problems}, indent=1))
    return 1 if problems else 0


# --- CLI ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="incident_verify", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    order = sub.add_parser("order", help="print the pre-registered verification order")
    order.add_argument("--registry", required=True)
    order.add_argument("--seed", type=int, default=SEED)
    pk = sub.add_parser("packets", help="verification packets and blank sheets")
    pk.add_argument("--registry", required=True)
    pk.add_argument("--out", required=True)
    pk.add_argument("--verifiers", required=True)
    pk.add_argument("--count", type=int, default=20, help="first N candidates in the order")
    pk.add_argument("--ids", nargs="*", default=None, help="these candidates instead")
    pk.add_argument("--seed", type=int, default=SEED)
    pk.add_argument("--offline", action="store_true", help="do not fetch advisory and fix diff")
    ap = sub.add_parser("apply", help="write agreed answers into the registry")
    ap.add_argument("--registry", required=True)
    ap.add_argument("sheets", nargs="+")
    ap.add_argument("--adjudication", default=None)
    ap.add_argument("--today", default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # advisory text on a cp1252 console
    try:
        return {"order": cmd_order, "packets": cmd_packets, "apply": cmd_apply}[args.command](args)
    except (StudyError, OSError) as exc:
        print(f"incident_verify: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
