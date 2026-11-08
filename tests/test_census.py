"""C-5 authority surface census tooling (scripts/census.py).

Offline: registry pages and GitHub answers are fakes; the end-to-end test
fetches from a local git repository.
"""

import csv
import gzip
import importlib.util
import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIDENED = os.path.join(ROOT, "tests", "benchmarks", "authority", "baseline_changes",
                       "mcp_tool_widened", "input")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "scripts",
                                                                     name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


common = _load("study_common")
census = _load("census")


def _entry(repo, status="active", latest=True):
    server = {"name": "x"}
    if repo is not None:
        server["repository"] = {"url": repo, "source": "github"}
    return {"server": server,
            "_meta": {census.REGISTRY_META: {"status": status, "isLatest": latest}}}


def test_frame_keeps_active_latest_github_repositories_once():
    pages = [{"servers": [
        _entry("https://github.com/Acme/Srv"),
        _entry("https://github.com/acme/srv.git"),       # same repository
        _entry("https://github.com/acme/old", status="deprecated"),
        _entry("https://github.com/acme/prev", latest=False),
        _entry("https://gitlab.com/acme/srv"),
        _entry(None),
    ]}]
    frame = census.build_frame(pages)
    assert frame["repositories"] == ["https://github.com/acme/srv"]
    assert (frame["entries"], frame["active"], frame["with_github_repository"]) == (6, 4, 2)


def test_registry_pages_follow_the_cursor():
    calls = []

    def get(url):
        calls.append(url)
        cursor = None if "cursor=" in url else "c1"
        return json.dumps({"servers": [], "metadata": {"nextCursor": cursor}}).encode()

    assert len(list(census.registry_pages(get))) == 2
    assert "version=latest" in calls[0] and "cursor=c1" in calls[1]


def test_frame_file_round_trips_with_a_stable_digest(tmp_path):
    frame = {"repositories": ["https://github.com/a/b", "https://github.com/c/d"]}
    one = census.write_frame(frame, str(tmp_path / "f1.txt.gz"))
    two = census.write_frame(frame, str(tmp_path / "f2.txt.gz"))
    assert one == two
    assert (tmp_path / "f1.txt.gz").read_bytes() == (tmp_path / "f2.txt.gz").read_bytes()
    assert census.read_frame(str(tmp_path / "f1.txt.gz")) == frame["repositories"]


def _meta(**over):
    meta = {"license": {"spdx_id": "MIT"}, "archived": False, "fork": False,
            "owner": {"login": "someone"}, "default_branch": "main", "size": 120}
    meta.update(over)
    return meta


@pytest.mark.parametrize("meta, reason", [
    (None, "not found"),
    (_meta(license=None), "no recognised open-source licence"),
    (_meta(license={"spdx_id": "NOASSERTION"}), "no recognised open-source licence"),
    (_meta(archived=True), "archived"),
    (_meta(fork=True), "a fork"),
    (_meta(owner={"login": "IkarusAILabs"}), "written by SafeAI's authors"),
    (_meta(size=0), "empty"),
    (_meta(size=census.MAX_REPO_KB + 1), "larger than 500 MB"),
])
def test_screening_reasons(meta, reason):
    assert reason in census.screen(meta)


def test_screening_passes_an_eligible_repository():
    assert census.screen(_meta()) == []


def test_sample_follows_the_seeded_order_until_n_are_eligible():
    frame = [f"https://github.com/o/r{i}" for i in range(40)]
    order = census.seeded_order(frame, "s")
    assert order == census.seeded_order(list(reversed(frame)), "s")
    assert order != census.seeded_order(frame, "t")
    bad = set(order[:3:2])  # the 1st and 3rd in order are archived

    def lookup(owner_name):
        return _meta(archived=("https://github.com/" + owner_name) in bad)

    rows = census.draw_sample(frame, "s", 5, lookup, lambda r, b: "f" * 40)
    assert [r["repository"] for r in rows] == order[:7]
    assert [r["eligible"] for r in rows] == [False, True, False, True, True, True, True]
    assert rows[0]["reasons"] == ["archived"]
    assert all(r["commit"] == "f" * 40 for r in rows if r["eligible"])


def test_sample_says_when_the_frame_runs_out():
    rows = census.draw_sample(["https://github.com/o/a"], "s", 3, lambda r: None,
                              lambda r, b: "x")
    assert rows[-1] == {"note": "frame exhausted: 0 eligible of 3 wanted"}


def _report(modes=(), rules=(), frameworks=(), mcp=0, rate=(0, 0)):
    caps = [{"access_mode": m} for m in modes]
    return {"tool_surface": [{"capabilities": caps}] if caps else [],
            "findings": [{"rule_id": r} for r in rules],
            "detected_frameworks": list(frameworks), "mcp_assets": [{}] * mcp,
            "files_scanned": 3,
            "evidence_metrics": {"rates": {"unattributed_authority_rate": {
                "numerator": rate[0], "denominator": rate[1]}}}}


def test_attributes_are_derived_from_the_report_and_keep_no_findings():
    unit = census.attributes(_report(["read", "execute"], ["GOV_APPROVAL_MISSING",
                                                           "MCP_HARDCODED_SECRET"],
                                     rate=(1, 4)))
    assert unit == {"surface": True, "execute": True, "write_or_broader": True,
                    "approval_missing": True, "static_credential": True,
                    "unattributed": [1, 4], "files_scanned": 3}
    read_only = census.attributes(_report(["read"], ["GOV_APPROVAL_MISSING"]))
    assert read_only["approval_missing"] is False  # only counted with write or broader
    assert census.attributes(_report())["surface"] is False
    assert census.attributes(_report(mcp=1))["surface"] is True


def _unit(i, **attrs):
    base = {"repository": f"https://github.com/o/r{i}", "commit": "c" * 40,
            "surface": True, "execute": False, "write_or_broader": False,
            "approval_missing": False, "static_credential": False,
            "unattributed": [0, 2], "files_scanned": 1}
    base.update(attrs)
    return base


def test_aggregate_uses_the_stated_denominators_and_names_nothing():
    units = ([_unit(i, write_or_broader=True, approval_missing=i < 6) for i in range(12)]
             + [_unit(100 + i, surface=False, unattributed=[5, 5]) for i in range(8)])
    out = census.aggregate(units, errors=1)
    shares = out["shares"]
    assert (shares["surface"]["n"], shares["surface"]["k"]) == (20, 12)
    assert (shares["write_or_broader"]["n"], shares["write_or_broader"]["k"]) == (12, 12)
    assert (shares["approval_missing"]["n"], shares["approval_missing"]["k"]) == (12, 6)
    assert out["unattributed_authority"]["statements"] == 24  # surface repositories only
    assert out["failed"] == 1
    assert "github.com" not in json.dumps(out)


def test_aggregate_is_insufficient_below_ten():
    out = census.aggregate([_unit(i, execute=True) for i in range(9)])
    assert out["shares"]["execute"]["status"] == "insufficient"
    assert "rate" not in out["shares"]["execute"]


def test_run_resumes_and_records_failures(tmp_path):
    sample = [{"repository": "https://github.com/o/a", "eligible": True, "commit": "1" * 40},
              {"repository": "https://github.com/o/b", "eligible": True, "commit": "2" * 40},
              {"repository": "https://github.com/o/c", "eligible": False}]
    seen = []

    def one(row, workdir):
        seen.append(row["repository"])
        if row["repository"].endswith("/b"):
            raise common.StudyError("fetch failed")
        return census.attributes(_report(["write"]))

    assert census.run(sample, str(tmp_path), one) == 1
    assert census.run(sample, str(tmp_path), one) == 1
    assert seen == ["https://github.com/o/a", "https://github.com/o/b",
                    "https://github.com/o/b"]
    units = common.read_jsonl(str(tmp_path / "units.jsonl"))
    assert [u["repository"] for u in units] == ["https://github.com/o/a"]
    assert common.read_jsonl(str(tmp_path / "errors.jsonl"))[0]["error"] == "fetch failed"


def test_packets_are_blind_and_seeded(tmp_path):
    units = [_unit(i, execute=True, static_credential=True) for i in range(40)]
    paths = census.write_packets(units, "s", 10, str(tmp_path), ["ana", "ben"])
    rows = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            rows.append(list(csv.DictReader(fh)))
    assert rows[0] == rows[1] and len(rows[0]) == 10
    assert all(r[f] == "" for r in rows[0] for f in census.CHECK_FIELDS)
    again = census.check_subsample(list(reversed(units)), "s", 10)
    assert [u["repository"] for u in again] == [r["repository"] for r in rows[0]]


def test_agreement_scores_safeai_against_people():
    units = [_unit(i, execute=i < 8) for i in range(12)]
    # People say yes for 0-5 and 8-9: SafeAI has 6 TP, 2 FP (6, 7), 2 FN (8, 9), 2 TN.
    sheet = [{"repository": u["repository"], "execute": "yes" if i < 6 or i in (8, 9)
              else "no"} for i, u in enumerate(units)]
    sheet.append({"repository": "https://github.com/o/unknown", "execute": "yes"})
    out = census.agreement(units, sheet)["execute"]
    assert (out["agreement"]["n"], out["agreement"]["k"]) == (12, 8)
    assert out["precision"]["status"] == "insufficient"  # 8 SafeAI yes < 10
    assert (out["recall"]["n"], out["recall"]["k"]) == (8, 6)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_run_one_scans_a_pinned_commit_without_telemetry(tmp_path, monkeypatch):
    repo = tmp_path / "upstream"
    shutil.copytree(WIDENED, repo)

    def g(*args):
        return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True,
                              check=True).stdout.strip()

    g("init", "-q")
    g("add", "-A")
    g("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "x")
    sha = g("rev-parse", "HEAD")
    captured = {}
    real_run = subprocess.run

    def spy(argv, *a, **kw):
        if "safeai" in argv and "scan" in argv:
            captured["env"] = kw.get("env") or {}
        return real_run(argv, *a, **kw)

    monkeypatch.setattr(common.subprocess, "run", spy)
    work = tmp_path / "work"
    work.mkdir()
    unit = census.run_one({"repository": str(repo), "commit": sha}, str(work))
    assert unit["surface"] is True and unit["write_or_broader"] is True
    assert set(unit) == set(census.ATTRIBUTES) | {"unattributed", "files_scanned"}
    assert captured["env"].get("DO_NOT_TRACK") == "1"


def test_committed_frame_and_sample_agree():
    folder = os.path.join(ROOT, "research", "credibility")
    meta_path = os.path.join(folder, "census_frame.json")
    if not os.path.exists(meta_path):
        pytest.skip("frame not drawn yet")
    with open(meta_path, encoding="utf-8") as fh:
        meta = json.load(fh)
    path = os.path.join(folder, meta["list"])
    with gzip.open(path, "rb") as fh:
        import hashlib
        assert hashlib.sha256(fh.read()).hexdigest() == meta["list_sha256"]
    frame = census.read_frame(path)
    assert len(frame) == meta["repositories"]
    with open(os.path.join(folder, "census_sample.json"), encoding="utf-8") as fh:
        sample = json.load(fh)
    rows = [r for r in sample["rows"] if "repository" in r]
    assert [r["repository"] for r in rows] == census.seeded_order(frame, sample["seed"])[
        :len(rows)]
    assert sum(r["eligible"] for r in rows) == sample["n"]
