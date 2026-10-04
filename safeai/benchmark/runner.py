"""Authority benchmark runner: deterministic corpus execution + comparison.

Runs the real ``safeai scan`` CLI path (full postprocess: normalize,
baseline, policy, outputs) against every case in
``tests/benchmarks/authority/`` and compares observed output with the
hand-verified ``expected/expected.json`` truth.

Design rules:
- Outputs are ALWAYS written outside the scanned input (a scan that
  ingests its own report is invalid input, not a finding).
- Baseline pairs scan ``input/baseline`` then ``input/current`` with
  ``--baseline``.
- Determinism: every case scans twice; file-order robustness shuffles
  input layout in temp copies (see ``scan_case``).
- The runner measures; it never gates. Exit codes: 0 all hard
  assertions hold, 1 truth mismatch, 2 harness/usage error.
"""

import json
import os
import shutil
import sys
import tempfile

CORPUS_DIRNAME = os.path.join("tests", "benchmarks", "authority")

EXPECTED_FILENAME = os.path.join("expected", "expected.json")


def repo_root():
    """Repository root derived from this package location."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))


def default_corpus():
    """Default corpus path inside a source checkout."""
    return os.path.join(repo_root(), "tests", "benchmarks", "authority")


def discover_cases(corpus_root):
    """List ``(case_id, category, case_dir)`` sorted deterministically."""
    cases = []
    if not os.path.isdir(corpus_root):
        return cases
    for category in sorted(os.listdir(corpus_root)):
        catdir = os.path.join(corpus_root, category)
        if not os.path.isdir(catdir):
            continue
        for case in sorted(os.listdir(catdir)):
            casedir = os.path.join(catdir, case)
            expected = os.path.join(casedir, "expected", "expected.json")
            inputdir = os.path.join(casedir, "input")
            if (
                os.path.isdir(casedir)
                and os.path.isfile(expected)
                and os.path.isdir(inputdir)
            ):
                cases.append(
                    {
                        "id": f"{category}/{case}",
                        "category": category,
                        "dir": casedir,
                    }
                )
    return cases


def load_expected(case_dir):
    """Load and minimally validate an expected-truth document."""
    path = os.path.join(case_dir, EXPECTED_FILENAME)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BenchmarkError(f"unreadable expected truth {path}: {exc}")
    if not isinstance(doc, dict):
        raise BenchmarkError(f"expected truth must be an object: {path}")
    return doc


class BenchmarkError(Exception):
    """Harness/usage failure (exit 2), never a measurement."""


def _cli_scan(scan_dir, out_path, baseline_path=None):
    """Run the real scan CLI; return the parsed JSON report."""
    from safeai.cmd.cli import main

    argv = ["scan", scan_dir, "--json", out_path, "--no-registry"]
    if baseline_path:
        argv += ["--baseline", baseline_path]
    main(argv)
    with open(out_path, encoding="utf-8") as fh:
        return json.load(fh)


def _copy_shuffled(src, reverse=False):
    """Copy an input tree to temp, optionally reversing creation order."""
    tmp = tempfile.mkdtemp(prefix="safeai-bench-")
    entries = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            entries.append(os.path.relpath(os.path.join(dirpath, name), src))
    if reverse:
        entries = list(reversed(entries))
    for rel in entries:
        dest = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(os.path.join(src, rel), dest)
    return tmp


def scan_case(case_dir, workdir):
    """Scan a case; baseline pairs scan baseline then current.

    Returns ``(current_report, baseline_report_or_None)``. All outputs
    land under ``workdir`` (never inside the scanned input).
    """
    inputdir = os.path.join(case_dir, "input")
    basedir = os.path.join(inputdir, "baseline")
    curdir = os.path.join(inputdir, "current")
    os.makedirs(workdir, exist_ok=True)
    if os.path.isdir(basedir) and os.path.isdir(curdir):
        base_json = os.path.join(workdir, "baseline.json")
        cur_json = os.path.join(workdir, "current.json")
        _cli_scan(basedir, base_json)
        current = _cli_scan(curdir, cur_json, baseline_path=base_json)
        with open(base_json, encoding="utf-8") as fh:
            baseline = json.load(fh)
        return current, baseline
    cur_json = os.path.join(workdir, "current.json")
    return _cli_scan(inputdir, cur_json), None


def canonical_projection(report):
    """Deterministic projection used for determinism checks.

    Drops volatile envelope data; keeps everything the benchmark
    measures. Key order normalized, paths made relative-safe strings.
    """

    def tools(r):
        out = []
        for t in r.get("tool_surface") or []:
            caps = sorted(
                (
                    str(c.get("name")),
                    str(c.get("access_mode")),
                    bool(c.get("inferred") or c.get("access_mode_inferred")),
                )
                for c in t.get("capabilities") or []
                if isinstance(c, dict)
            )
            out.append([str(t.get("tool_key")), caps])
        return sorted(out)

    def findings(r):
        return sorted(
            [
                str(f.get("rule_id")),
                str(f.get("file")),
                int(f.get("line") or 0),
                str(f.get("status")),
                str(f.get("provenance_class")),
                str(f.get("gateability")),
            ]
            for f in r.get("findings") or []
            if isinstance(f, dict)
        )

    def iac(r):
        corr = r.get("iac_correlations") or {}
        return {
            "identities": sorted(
                [str(i.get("kind")), str(i.get("name")), str(i.get("namespace") or "")]
                for i in corr.get("identities") or []
                if isinstance(i, dict)
            ),
            "grants": sorted(
                [
                    str((g.get("identity") or {}).get("name")),
                    ",".join(sorted((g.get("actions") or {}).get("values") or [])),
                    ",".join(sorted((g.get("resources") or {}).get("values") or [])),
                    str((g.get("actions") or {}).get("resolution")),
                ]
                for g in corr.get("grants") or []
                if isinstance(g, dict)
            ),
            "verdicts": sorted(
                [str(v.get("domain")), str(v.get("verdict"))]
                for v in corr.get("verdicts") or []
                if isinstance(v, dict)
            ),
        }

    def diff(r):
        return sorted(
            [str(t.get("tool_key")), str(t.get("status")), str(t.get("change_class"))]
            for t in (r.get("capability_diff") or {}).get("tools") or []
            if isinstance(t, dict)
        )

    return {
        "tools": tools(report),
        "findings": findings(report),
        "iac": iac(report),
        "diff": diff(report),
    }


def check_determinism(case_dir, workdir):
    """Scan twice + order-shuffled; return list of violation strings."""
    inputdir = os.path.join(case_dir, "input")
    basedir = os.path.join(inputdir, "baseline")
    target = os.path.join(inputdir, "current") if os.path.isdir(basedir) else inputdir
    first_dir = os.path.join(workdir, "det-a")
    second_dir = os.path.join(workdir, "det-b")
    os.makedirs(first_dir, exist_ok=True)
    os.makedirs(second_dir, exist_ok=True)
    first = _cli_scan(target, os.path.join(first_dir, "r.json"))
    second = _cli_scan(target, os.path.join(second_dir, "r.json"))
    violations = []
    if canonical_projection(first) != canonical_projection(second):
        violations.append("repeated scans of identical input diverged")
    shuffled = _copy_shuffled(target, reverse=True)
    try:
        third = _cli_scan(shuffled, os.path.join(second_dir, "r3.json"))
        proj_first = canonical_projection(first)
        proj_third = canonical_projection(third)
        # File layout order must not change tool/capability/iac truth;
        # finding line numbers may legitimately differ, so compare
        # everything except finding rows.
        for key in ("tools", "iac", "diff"):
            if proj_first[key] != proj_third[key]:
                violations.append(f"input file ordering changed {key} conclusions")
                break
    finally:
        shutil.rmtree(shuffled, ignore_errors=True)
    return violations


def evaluate_case(case, workdir):
    """Run one case; return the structured case result dict."""
    from safeai.benchmark import compare

    expected = load_expected(case["dir"])
    current, baseline = scan_case(case["dir"], workdir)
    result = compare.compare_case(expected, current, baseline)
    result["id"] = case["id"]
    result["category"] = case["category"]
    result["provenance"] = (
        (expected.get("annotation") or {}).get("derivation")
        or "unspecified")
    return result


def run_corpus(corpus_root, workdir, case_filter=None, determinism=True):
    """Run every case; return the aggregate evaluation dict."""
    from safeai.benchmark import metrics as metrics_mod

    os.makedirs(workdir, exist_ok=True)
    case_results = []
    for case in discover_cases(corpus_root):
        if case_filter and case_filter not in (case["id"], case["category"]):
            continue
        casedir = os.path.join(workdir, "cases", case["id"].replace("/", "__"))
        os.makedirs(casedir, exist_ok=True)
        try:
            result = evaluate_case(case, casedir)
        except BenchmarkError as exc:
            result = {
                "id": case["id"],
                "category": case["category"],
                "harness_error": str(exc),
                "failures": [str(exc)],
                "passed": False,
            }
        if determinism:
            try:
                violations = check_determinism(
                    case["dir"], os.path.join(casedir, "det")
                )
                result["determinism"] = {"checked": True, "violations": violations}
                if violations:
                    result.setdefault("failures", []).extend(
                        f"determinism: {v}" for v in violations
                    )
                    result["passed"] = False
            except Exception as exc:  # harness must never crash the run
                result["determinism"] = {
                    "checked": True,
                    "violations": [],
                    "harness_error": str(exc),
                }
                result.setdefault("failures", []).append(
                    f"determinism harness error: {exc}"
                )
                result["passed"] = False
        else:
            result["determinism"] = {"checked": False, "violations": []}
        case_results.append(result)
    return metrics_mod.aggregate(case_results)


def _cli(argv=None):
    """Entry point used by tests (real CLI wiring lives in cli.py)."""
    import argparse

    parser = argparse.ArgumentParser(prog="safeai benchmark authority")
    parser.add_argument("--corpus", default=default_corpus())
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--case", default=None)
    parser.add_argument("--no-determinism", action="store_true")
    parser.add_argument("--json", dest="json_path", default=None)
    parser.add_argument("--markdown", dest="markdown_path", default=None)
    args = parser.parse_args(argv)
    from safeai.benchmark import report as report_mod

    workdir = args.workdir or tempfile.mkdtemp(prefix="safeai-bench-")
    agg = run_corpus(
        args.corpus, workdir, case_filter=args.case, determinism=not args.no_determinism
    )
    if args.json_path:
        report_mod.write_json(agg, args.json_path)
    if args.markdown_path:
        report_mod.write_markdown(agg, args.markdown_path)
    failed = [r["id"] for r in agg.get("cases", []) if not r.get("passed")]
    if failed:
        print(
            f"authority benchmark: {len(failed)} case(s) mismatched: "
            f"{', '.join(failed)}"
        )
        return 1
    print(
        f"authority benchmark: all {len(agg.get('cases', []))} cases hold; "
        f"metrics in {'outputs' if args.json_path or args.markdown_path else 'memory only'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
