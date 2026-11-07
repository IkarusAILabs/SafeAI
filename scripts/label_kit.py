"""Human labelling kit for the credibility track (docs/research/CREDIBILITY_TRACK.md).

Subcommands:

``review-packets``  C-1: one Markdown packet per pending benchmark case and a
                    blank review sheet per reviewer.
``packets``         C-2: labelling packets for every change a history study
                    reported, plus a seeded sample of silent commits; SafeAI's
                    change class is withheld from the packets (blind labels).
``agreement``       Percent agreement and Cohen's kappa between two sheets.
``score``           Precision, materiality and miss rate from adjudicated labels.

Labels are written by people. This tool only lays out what to label and
counts the answers; it never fills a label.

Usage:
    python scripts/label_kit.py review-packets --out review/ --reviewers ana,ben
    python scripts/label_kit.py packets study/ --out labels/ --labellers ana,ben
    python scripts/label_kit.py agreement labels/sheet.ana.csv labels/sheet.ben.csv --field real
    python scripts/label_kit.py score study/ labels/adjudicated.csv --json score.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import sys
from collections import Counter
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from study_common import MIN_SAMPLE, read_jsonl, wilson, write_jsonl

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PENDING = os.path.join(REPO, "tests", "benchmarks", "authority-pending")
MAX_INPUT_LINES = 400

REVIEW_FIELDS = ["case", "verdict", "corrections"]
REVIEW_VERDICTS = ("correct", "partly", "wrong")
LABEL_FIELDS = ["item", "kind", "target", "sha", "real", "material", "missed", "notes"]
ANSWERS = ("yes", "no", "unsure")
SERIOUS = ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")

# What each truth key asserts, for reviewers who do not read the harness.
TRUTH_KEYS = {
    "tools": "Tools the scanner must find, with their capabilities and access modes.",
    "agents": "Agents the scanner must find (framework and name).",
    "changes": "Tool changes against the baseline, with change class and escalations.",
    "must_fire": "Rules that must fire on this input.",
    "must_not_fire": "Rules that must not fire on this input.",
    "identities": "IaC identities (roles, ServiceAccounts) that must be found.",
    "grants": "Permission grants each identity must hold.",
    "links": "Agent / tool to identity links and their verdicts.",
    "verdicts": "IaC correlation verdicts.",
    "uncertainty": "Values that must stay unknown or unresolved.",
    "workload_identity": "SPIFFE assignments, unknowns, callers, federations, static credentials (exact sets).",
    "identity_changes": "Workload-identity changes: exact set of (type, workload, subject).",
    "delegation_edges": "Delegation edges and the tools each delegate holds beyond its delegator.",
    "delegation_unresolved": "How many delegation targets cannot be resolved statically.",
    "delegation_changes": "Delegation changes: exact set of (type, subject).",
    "sod_conflicts": "Separation-of-Duties conflicts: exact set of (holder, pair).",
    "agent_identity_links": "Identifiers attributed to an agent through its workload.",
    "agent_identity_states": "Expected workload_identity.state per agent source file.",
    "evidence_refs": "Files and lines the evidence must cite.",
}
SKIP_KEYS = {"case", "notes", "annotation", "canonical", "truth_schema_version"}


# --- C-1: review packets for the pending corpus ----------------------------------------

def pending_cases(corpus: str) -> list[dict[str, Any]]:
    cases = []
    for category in sorted(os.listdir(corpus)):
        catdir = os.path.join(corpus, category)
        if not os.path.isdir(catdir):
            continue
        for name in sorted(os.listdir(catdir)):
            expected = os.path.join(catdir, name, "expected", "expected.json")
            if os.path.isfile(expected):
                cases.append({"id": f"{category}/{name}", "dir": os.path.join(catdir, name)})
    return cases


def _input_files(case_dir: str) -> list[str]:
    root = os.path.join(case_dir, "input")
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".safeai")
        files.extend(os.path.relpath(os.path.join(dirpath, f), root).replace("\\", "/")
                     for f in sorted(filenames))
    return files


def _fence(path: str) -> str:
    ext = os.path.splitext(path)[1].lstrip(".").lower()
    return {"py": "python", "yml": "yaml", "md": "markdown", "tf": "hcl"}.get(ext, ext)


def review_packet(case: dict[str, Any]) -> str:
    with open(os.path.join(case["dir"], "expected", "expected.json"), encoding="utf-8") as fh:
        truth = json.load(fh)
    meta_path = os.path.join(case["dir"], "metadata", "meta.json")
    meta = {}
    if os.path.isfile(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    lines = [f"# Review: `{case['id']}`", ""]
    if meta.get("description"):
        lines += [f"**What the case is about.** {meta['description']}", ""]
    if meta.get("version"):
        lines += [f"Added in {meta['version']}.", ""]
    lines += [
        "**Your task.** Read the input below and decide whether every expected",
        "value is what a careful human would conclude from these files alone.",
        "Record `correct`, `partly` or `wrong` in your sheet, and write each",
        "correction (key, what is wrong, what it should be). Fix the truth,",
        "never the input. Do not run SafeAI, and do not compare notes with the",
        "other reviewer until both sheets are done.", "",
        "## Input files", "",
    ]
    root = os.path.join(case["dir"], "input")
    for rel in _input_files(case["dir"]):
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            body = fh.read().splitlines()
        cut = len(body) > MAX_INPUT_LINES
        lines += [f"### `{rel}`", "", f"```{_fence(rel)}", *body[:MAX_INPUT_LINES], "```"]
        if cut:
            lines.append(f"*({len(body) - MAX_INPUT_LINES} more lines in the case directory.)*")
        lines.append("")
    lines += ["## Expected truth (candidate, AI-assisted)", ""]
    if truth.get("notes"):
        lines += [f"Author's note: {truth['notes']}", ""]
    for key in sorted(k for k in truth if k not in SKIP_KEYS):
        lines += [f"### `{key}`", "", TRUTH_KEYS.get(key, "(see the pending corpus README)"), "",
                  "```json", json.dumps(truth[key], indent=1, sort_keys=True), "```", ""]
    return "\n".join(lines)


def write_sheet(path: str, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def cmd_review_packets(args: argparse.Namespace) -> int:
    cases = pending_cases(args.corpus)
    if not cases:
        print(f"no cases under {args.corpus}", file=sys.stderr)
        return 2
    os.makedirs(os.path.join(args.out, "packets"), exist_ok=True)
    index = ["# Pending corpus review", "",
             f"{len(cases)} cases. Protocol: docs/research/CREDIBILITY_TRACK.md (C-1).", "",
             "| Case | Packet |", "|---|---|"]
    for case in cases:
        name = case["id"].replace("/", "__") + ".md"
        with open(os.path.join(args.out, "packets", name), "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write(review_packet(case))
        index.append(f"| `{case['id']}` | [packets/{name}](packets/{name}) |")
    with open(os.path.join(args.out, "INDEX.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(index) + "\n")
    for reviewer in _names(args.reviewers):
        write_sheet(os.path.join(args.out, f"review-sheet.{reviewer}.csv"), REVIEW_FIELDS,
                    [{"case": c["id"]} for c in cases])
    print(f"{len(cases)} packets in {args.out}")
    return 0


# --- C-2: labelling packets for a history study ------------------------------------------

def _claim(unit: dict[str, Any]) -> list[str]:
    """What SafeAI reports, without its change class or severity."""
    out = [f"- **{unit['kind']}** `{unit['subject']}`: {unit['type']}"]
    if unit.get("capabilities_added"):
        out.append("  - capabilities added: " + ", ".join(f"`{c}`" for c in unit["capabilities_added"]))
    if unit.get("capabilities_removed"):
        out.append("  - capabilities removed: "
                   + ", ".join(f"`{c}`" for c in unit["capabilities_removed"]))
    for cap, before, after in unit.get("access_mode_changes") or []:
        out.append(f"  - access mode of `{cap}`: {before} → {after}")
    if unit.get("escalations"):
        out.append("  - escalation rules: " + ", ".join(f"`{e}`" for e in unit["escalations"]))
    if unit.get("detail"):
        out.append(f"  - detail: {unit['detail']}")
    if unit.get("paths"):
        out.append("  - evidence: " + ", ".join(f"`{p}`" for p in unit["paths"]))
    return out


def _commit_link(commit: dict[str, Any]) -> str:
    url = (commit.get("url") or "").rstrip("/")
    url = url.removesuffix(".git")
    if url.startswith("https://github.com/"):
        return f"[{commit['sha'][:12]}]({url}/commit/{commit['sha']})"
    return f"`{commit['sha']}`"


def labelling_items(study: str, silent_fraction: float, seed: int) -> tuple[list, list]:
    commits = {(c["target"], c["sha"]): c for c in read_jsonl(os.path.join(study, "commits.jsonl"))}
    changes = read_jsonl(os.path.join(study, "changes.jsonl"))
    items = [dict(u, item=f"change:{u['target']}:{u['sha'][:12]}:{u['unit_id']}", item_kind="change")
             for u in changes]
    silent = sorted((c for c in commits.values() if c.get("status") == "scanned"
                     and not c.get("units") and c.get("files")),
                    key=lambda c: (c["target"], c["index"]))
    want = math.ceil(len(silent) * silent_fraction) if silent_fraction > 0 else 0
    picked = sorted(random.Random(seed).sample(silent, min(want, len(silent))),
                    key=lambda c: (c["target"], c["index"]))
    items += [{"item": f"silent:{c['target']}:{c['sha'][:12]}", "item_kind": "silent",
               "target": c["target"], "sha": c["sha"]} for c in picked]
    return items, [commits, silent]


def cmd_packets(args: argparse.Namespace) -> int:
    items, (commits, silent) = labelling_items(args.study, args.sample_silent, args.seed)
    if not items:
        print("nothing to label: no reported changes and no silent sample", file=sys.stderr)
        return 2
    os.makedirs(os.path.join(args.out, "packets"), exist_ok=True)
    by_commit: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        by_commit.setdefault((item["target"], item["sha"]), []).append(item)
    index = ["# Change study labelling", "",
             (f"{sum(i['item_kind'] == 'change' for i in items)} reported changes and "
              f"{sum(i['item_kind'] == 'silent' for i in items)} of {len(silent)} silent "
              f"commits (seed {args.seed}). Protocol: docs/research/CREDIBILITY_TRACK.md "
              "(C-2)."), "",
             "| Commit | Items | Packet |", "|---|---|---|"]
    for (target, sha), group in sorted(by_commit.items(), key=lambda kv: (
            kv[0][0], commits[kv[0]]["index"])):
        commit = commits[(target, sha)]
        name = f"{target}__{commit['index']:05d}_{sha[:12]}.md"
        lines = [f"# {target} — {_commit_link(commit)}", "",
                 f"*{commit.get('date', '')}* — {commit.get('subject', '')}", "",
                 "Changed files:", "", *[f"- `{f}`" for f in commit.get("files", [])[:100]], ""]
        if len(commit.get("files", [])) > 100:
            lines += [f"*({len(commit['files']) - 100} more.)*", ""]
        for item in group:
            lines += [f"## Item `{item['item']}`", ""]
            if item["item_kind"] == "change":
                lines += ["SafeAI reports this change in the agent's potential authority:", "",
                          *_claim(item), "",
                          "Answer **real** (did authority change as stated?) and **material**",
                          "(should a reviewer look before this merges?): yes / no / unsure.", ""]
            else:
                lines += ["SafeAI reports **no** authority change for this commit.", "",
                          "Answer **missed**: did the commit change what an agent can",
                          "potentially do (yes / no / unsure)? If yes, say what in notes.", ""]
        with open(os.path.join(args.out, "packets", name), "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write("\n".join(lines))
        index.append(f"| {target} {sha[:12]} | {len(group)} | [packets/{name}](packets/{name}) |")
    with open(os.path.join(args.out, "INDEX.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(index) + "\n")
    rows = [{"item": i["item"], "kind": i["item_kind"], "target": i["target"], "sha": i["sha"]}
            for i in items]
    for labeller in _names(args.labellers):
        write_sheet(os.path.join(args.out, f"sheet.{labeller}.csv"), LABEL_FIELDS, rows)
    # The key holds what labellers must not see; it stays with the study lead.
    write_jsonl(os.path.join(args.out, "key.jsonl"),
                [{"item": i["item"], "change_class": i.get("change_class"),
                  "kind": i.get("kind"), "type": i.get("type")} for i in items])
    print(f"{len(items)} items in {len(by_commit)} packets in {args.out}")
    return 0


# --- agreement ---------------------------------------------------------------------

def read_sheet(path: str) -> list[dict[str, str]]:
    with open(path, encoding="utf-8", newline="") as fh:
        return [{k: (v or "").strip() for k, v in row.items()} for row in csv.DictReader(fh)]


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Cohen's kappa for two raters; None when it is undefined."""
    n = len(pairs)
    if not n:
        return None
    observed = sum(a == b for a, b in pairs) / n
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    expected = sum(left[c] * right[c] for c in set(left) | set(right)) / (n * n)
    if expected == 1:
        return None
    return round((observed - expected) / (1 - expected), 4)


def agreement(sheet_a: list[dict[str, str]], sheet_b: list[dict[str, str]], field: str,
              key: str) -> dict[str, Any]:
    a = {r[key]: r.get(field, "") for r in sheet_a if r.get(key)}
    b = {r[key]: r.get(field, "") for r in sheet_b if r.get(key)}
    both = sorted(k for k in a if k in b and a[k] and b[k])
    pairs = [(a[k].lower(), b[k].lower()) for k in both]
    agree = sum(x == y for x, y in pairs)
    return {
        "field": field, "items_in_both": len(both),
        "unlabelled": sorted(k for k in set(a) | set(b) if not a.get(k) or not b.get(k)),
        "percent_agreement": round(agree / len(pairs), 4) if pairs else None,
        "cohen_kappa": cohen_kappa(pairs),
        "status": "measured" if len(pairs) >= MIN_SAMPLE else "insufficient",
        "disagreements": [{key: k, "a": x, "b": y} for k, (x, y) in zip(both, pairs, strict=True)
                          if x != y],
    }


def cmd_agreement(args: argparse.Namespace) -> int:
    sheet_a, sheet_b = read_sheet(args.sheet_a), read_sheet(args.sheet_b)
    key = args.key or ("case" if sheet_a and "case" in sheet_a[0] else "item")
    result = agreement(sheet_a, sheet_b, args.field, key)
    print(json.dumps(result, indent=1))
    return 0


# --- score -------------------------------------------------------------------------

def _answer(row: dict[str, str], field: str) -> str:
    value = row.get(field, "").lower()
    return value if value in ANSWERS else ""


def score(study: str, labels: list[dict[str, str]]) -> dict[str, Any]:
    changes = {f"change:{u['target']}:{u['sha'][:12]}:{u['unit_id']}": u
               for u in read_jsonl(os.path.join(study, "changes.jsonl"))}
    commits = read_jsonl(os.path.join(study, "commits.jsonl"))
    silent_total = sum(1 for c in commits if c.get("status") == "scanned"
                       and not c.get("units") and c.get("files"))
    by_item = {r["item"]: r for r in labels if r.get("item")}

    real = Counter()
    per_type: dict[str, Counter] = {}
    matrix = Counter()
    unlabelled = []
    for item, unit in sorted(changes.items()):
        row = by_item.get(item)
        answer = _answer(row, "real") if row else ""
        if not answer:
            unlabelled.append(item)
            continue
        real[answer] += 1
        kind = f"{unit['kind']}:{unit['type']}"
        per_type.setdefault(kind, Counter())[answer] += 1
        material = _answer(row, "material")
        if unit["kind"] in ("tool", "unattributed") and material in ("yes", "no"):
            matrix[(unit.get("change_class") in SERIOUS, material == "yes")] += 1

    def precision(counter: Counter) -> dict[str, Any]:
        result = wilson(counter["yes"], counter["yes"] + counter["no"])
        result["unsure"] = counter["unsure"]
        return result

    silent_rows = [r for r in labels if r.get("item", "").startswith("silent:")]
    missed = Counter(_answer(r, "missed") for r in silent_rows)
    miss = wilson(missed["yes"], missed["yes"] + missed["no"])
    if miss["status"] == "measured":
        miss["estimated_missed_commits"] = {k: round(miss[k] * silent_total)
                                            for k in ("rate", "low", "high")}
    tp, fp = matrix[(True, True)], matrix[(True, False)]
    fn = matrix[(False, True)]
    return {
        "changes_reported": len(changes),
        "unlabelled": unlabelled,
        "detection_precision": precision(real),
        "detection_precision_by_type": {k: precision(v) for k, v in sorted(per_type.items())},
        "materiality": {
            "table": {"serious_and_material": tp, "serious_not_material": fp,
                      "not_serious_but_material": fn,
                      "not_serious_not_material": matrix[(False, False)]},
            "precision": wilson(tp, tp + fp),
            "recall": wilson(tp, tp + fn),
        },
        "silent_commits": silent_total,
        "silent_sampled": len(silent_rows),
        "miss_rate": miss,
        "unsure_silent": missed["unsure"],
    }


def _fmt(result: dict[str, Any]) -> str:
    if result["status"] != "measured":
        return f"insufficient (n={result['n']})"
    return f"{result['rate']:.3f} [{result['low']:.3f}, {result['high']:.3f}] (n={result['n']})"


def render_score(result: dict[str, Any]) -> str:
    lines = ["# Change study score", "",
             (f"Reported changes: {result['changes_reported']}; "
              f"unlabelled: {len(result['unlabelled'])}."), "",
             f"- Detection precision: {_fmt(result['detection_precision'])}",
             f"- Materiality precision: {_fmt(result['materiality']['precision'])}",
             f"- Materiality recall: {_fmt(result['materiality']['recall'])}",
             (f"- Miss rate in sampled silent commits: {_fmt(result['miss_rate'])} "
              f"({result['silent_sampled']} sampled of {result['silent_commits']})"), "",
             "| Change type | Precision |", "|---|---|"]
    lines += [f"| `{k}` | {_fmt(v)} |" for k, v in result["detection_precision_by_type"].items()]
    return "\n".join(lines) + "\n"


def cmd_score(args: argparse.Namespace) -> int:
    result = score(args.study, read_sheet(args.labels))
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, indent=1, sort_keys=True)
    print(render_score(result))
    return 0


# --- CLI ---------------------------------------------------------------------------

def _names(value: str) -> list[str]:
    names = [n.strip() for n in (value or "").split(",") if n.strip()]
    for name in names:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise SystemExit(f"label_kit: bad name {name!r}")
    return names or ["reviewer-a", "reviewer-b"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="label_kit", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    rp = sub.add_parser("review-packets", help="C-1 review packets for the pending corpus")
    rp.add_argument("--corpus", default=PENDING)
    rp.add_argument("--out", required=True)
    rp.add_argument("--reviewers", default="")
    pk = sub.add_parser("packets", help="C-2 labelling packets for a history study")
    pk.add_argument("study")
    pk.add_argument("--out", required=True)
    pk.add_argument("--labellers", default="")
    pk.add_argument("--sample-silent", type=float, default=0.1)
    pk.add_argument("--seed", type=int, default=20261107)
    ag = sub.add_parser("agreement", help="agreement between two sheets")
    ag.add_argument("sheet_a")
    ag.add_argument("sheet_b")
    ag.add_argument("--field", required=True)
    ag.add_argument("--key", default=None)
    sc = sub.add_parser("score", help="score adjudicated labels")
    sc.add_argument("study")
    sc.add_argument("labels")
    sc.add_argument("--json", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "packets" and not 0 <= args.sample_silent <= 1:
        print("--sample-silent must be between 0 and 1", file=sys.stderr)
        return 2
    return {"review-packets": cmd_review_packets, "packets": cmd_packets,
            "agreement": cmd_agreement, "score": cmd_score}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
