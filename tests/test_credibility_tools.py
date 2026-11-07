"""Credibility-track study tooling (scripts/study_common, label_kit, history_study,
incident_replay; docs/research/CREDIBILITY_TRACK.md).

Offline: the end-to-end tests build a local git repository from authority
corpus inputs; nothing is cloned from the network.
"""

import csv
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
    # Registered so the scripts' own ``from study_common import ...`` gets
    # this module (one StudyError class), not a second copy.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


common = _load("study_common")
kit = _load("label_kit")
history = _load("history_study")
replay = _load("incident_replay")

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


# --- helpers and statistics -----------------------------------------------------------

def test_wilson_is_insufficient_below_the_minimum_and_bounded_above_it():
    assert common.wilson(3, 3) == {"n": 3, "k": 3, "status": "insufficient"}
    result = common.wilson(10, 10)
    assert result["rate"] == 1.0 and result["high"] == 1.0
    assert 0.69 < result["low"] < 0.73
    half = common.wilson(50, 100)
    assert half["rate"] == 0.5 and half["low"] == pytest.approx(0.4038, abs=1e-3)


def test_cohen_kappa_matches_a_worked_example():
    pairs = [("yes", "yes")] * 20 + [("yes", "no")] * 5 + [("no", "yes")] * 10 + \
        [("no", "no")] * 15
    assert kit.cohen_kappa(pairs) == 0.4
    assert kit.cohen_kappa([]) is None
    assert kit.cohen_kappa([("yes", "yes")] * 4) is None


def test_change_units_cover_tools_unattributed_delegation_and_identity():
    report = {"capability_diff": {
        "baseline_available": True,
        "tools": [
            {"tool_key": "mcp_server:a", "status": "unchanged", "escalations": []},
            {"tool_key": "mcp_server:b", "status": "escalated", "change_class": "HIGH_RISK_CHANGE",
             "escalations": [{"id": "ESC_X", "evidence": [{"path": ".mcp.json", "line": 1}]}],
             "capabilities_added": [{"name": "mcp_tool:run", "evidence": [{"path": "a\\b.py"}]}],
             "access_mode_changes": [{"capability": "mcp", "before": "read", "after": "execute"}]},
        ],
        "unattributed": {"change_class": "LOW_CHANGE", "status": "new",
                         "capabilities_added": [{"name": "shell"}]},
        "delegation_changes": {"changes": [{"type": "DELEGATE_ADDED", "subject": "x -> y",
                                            "detail": "d",
                                            "evidence": [{"file": "g.py", "line": 3}]}]},
        "workload_identity_changes": {"changes": [{"type": "IDENTITY_ADDED", "workload": "ns/w",
                                                   "subject": "spiffe://t/x"}]},
    }}
    units = common.change_units(report)
    assert [(u["kind"], u["subject"], u["type"]) for u in units] == [
        ("delegation", "x -> y", "DELEGATE_ADDED"),
        ("identity", "ns/w: spiffe://t/x", "IDENTITY_ADDED"),
        ("tool", "mcp_server:b", "escalated"),
        ("unattributed", "unattributed", "new"),
    ]
    tool = units[2]
    assert tool["paths"] == [".mcp.json", "a/b.py"]
    assert tool["access_mode_changes"] == [["mcp", "read", "execute"]]
    assert units[0]["paths"] == ["g.py"]
    assert len({u["unit_id"] for u in units}) == 4
    assert common.change_units({"capability_diff": {"baseline_available": False}}) == []


def test_only_binary_files_are_skipped():
    assert common.only_binary(["logo.PNG", "docs/a.pdf"])
    assert not common.only_binary(["logo.png", "SKILL.md"])
    assert not common.only_binary([])


# --- C-1 review packets ----------------------------------------------------------------

def test_every_pending_truth_key_is_explained_to_reviewers():
    keys = set()
    for case in kit.pending_cases(kit.PENDING):
        with open(os.path.join(case["dir"], "expected", "expected.json"), encoding="utf-8") as fh:
            keys |= set(json.load(fh))
    assert keys - kit.SKIP_KEYS <= set(kit.TRUTH_KEYS)


def test_review_packets_and_sheets(tmp_path):
    out = tmp_path / "review"
    assert kit.main(["review-packets", "--out", str(out), "--reviewers", "ana,ben"]) == 0
    cases = kit.pending_cases(kit.PENDING)
    assert len(list((out / "packets").iterdir())) == len(cases)
    with open(out / "review-sheet.ben.csv", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["case"] for r in rows] == [c["id"] for c in cases]
    assert all(r["verdict"] == "" for r in rows)
    packet = (out / "packets" / "delegation__langgraph_supervisor.md").read_text(encoding="utf-8")
    assert "create_supervisor" in packet and "### `delegation_edges`" in packet
    with pytest.raises(SystemExit):
        kit.main(["review-packets", "--out", str(out), "--reviewers", "../x"])


def test_agreement_pairs_rows_by_key_and_lists_disagreements(tmp_path):
    def sheet(name, verdicts):
        path = tmp_path / name
        kit.write_sheet(str(path), kit.REVIEW_FIELDS,
                        [{"case": f"c{i}", "verdict": v} for i, v in enumerate(verdicts)])
        return str(path)

    a = sheet("a.csv", ["correct"] * 8 + ["wrong", "partly", ""])
    b = sheet("b.csv", ["correct"] * 7 + ["partly", "wrong", "partly", "correct"])
    result = kit.agreement(kit.read_sheet(a), kit.read_sheet(b), "verdict", "case")
    assert result["items_in_both"] == 10
    assert result["unlabelled"] == ["c10"]
    assert result["percent_agreement"] == 0.9
    assert result["disagreements"] == [{"case": "c7", "a": "correct", "b": "partly"}]
    assert result["status"] == "measured"


# --- C-2 history study end to end -----------------------------------------------------------

def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "study@example.org")
    _git(repo, "config", "user.name", "study")
    _git(repo, "config", "core.autocrlf", "false")
    shutil.copytree(os.path.join(WIDENED, "baseline"), repo, dirs_exist_ok=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    (repo / "README.md").write_text("notes\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "docs")
    (repo / "logo.png").write_bytes(b"\x89PNG")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "logo")
    shutil.copytree(os.path.join(WIDENED, "current"), repo, dirs_exist_ok=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "widen")
    return repo


@needs_git
def test_history_study_labels_and_score(tmp_path):
    repo = _repo(tmp_path)
    study = tmp_path / "study"
    assert history.main(["--repo-path", str(repo), "--id", "demo", "--out", str(study)]) == 0
    commits = common.read_jsonl(str(study / "commits.jsonl"))
    assert [(c["status"], c["units"]) for c in commits] == [
        ("baseline", 0), ("scanned", 0), ("skipped", 0), ("scanned", 1)]
    assert commits[3]["files"] == [".mcp.json", "logo.png"]
    assert commits[3]["highest_change_class"] == "HIGH_RISK_CHANGE"
    (change,) = common.read_jsonl(str(study / "changes.jsonl"))
    assert (change["kind"], change["subject"], change["type"]) == (
        "tool", "mcp_server:docs", "escalated")
    assert "ESC_MCP_READ_TO_MUTATE" in change["escalations"]
    run = json.loads((study / "run.json").read_text(encoding="utf-8"))
    assert run["targets"][0]["by_status"] == {"baseline": 1, "scanned": 2, "skipped": 1,
                                              "error": 0}

    labels = tmp_path / "labels"
    assert kit.main(["packets", str(study), "--out", str(labels), "--labellers", "ana",
                     "--sample-silent", "1"]) == 0
    packets = "".join(p.read_text(encoding="utf-8") for p in (labels / "packets").iterdir())
    assert "HIGH_RISK" not in packets and "MATERIAL" not in packets  # blind
    assert "SafeAI reports **no** authority change" in packets
    key = common.read_jsonl(str(labels / "key.jsonl"))
    assert key[0]["change_class"] == "HIGH_RISK_CHANGE"

    rows = kit.read_sheet(str(labels / "sheet.ana.csv"))
    assert [r["kind"] for r in rows] == ["change", "silent"]
    rows[0].update(real="yes", material="yes")
    rows[1].update(missed="no")
    result = kit.score(str(study), rows)
    assert result["unlabelled"] == []
    assert result["detection_precision"] == {"n": 1, "k": 1, "status": "insufficient",
                                             "unsure": 0}
    assert result["materiality"]["table"]["serious_and_material"] == 1
    assert (result["silent_commits"], result["silent_sampled"]) == (1, 1)
    assert "insufficient (n=1)" in kit.render_score(result)


def test_targets_file_rules(tmp_path):
    assert {t["status"] for t in history.load_targets(
        os.path.join(ROOT, "research", "credibility", "targets.yml"))} <= {"proposed", "confirmed"}
    bad = tmp_path / "t.yml"
    bad.write_text("targets:\n  - {id: a, url: 'https://x', status: confirmed}\n",
                   encoding="utf-8")
    with pytest.raises(common.StudyError, match="pinned"):
        history.load_targets(str(bad))
    bad.write_text("targets:\n  - {id: a, url: 'http://x', status: proposed}\n", encoding="utf-8")
    with pytest.raises(common.StudyError, match="https"):
        history.load_targets(str(bad))
    assert history.main(["--targets", str(os.path.join(ROOT, "research", "credibility",
                                                       "targets.yml")),
                         "--out", str(tmp_path / "o")]) == 2  # nothing confirmed yet


# --- C-3 incident replay -------------------------------------------------------------------

def test_committed_registry_is_valid():
    assert replay.main(["--registry", os.path.join(ROOT, "research", "credibility",
                                                   "incidents.yml"), "--check"]) == 0


@pytest.mark.parametrize(("entry", "message"), [
    ({"status": "maybe"}, "status"),
    ({"static_visibility": "sometimes"}, "static_visibility"),
    ({"advisory": "http://x"}, "https"),
    ({"expected": {"notes": "x"}}, "rules"),
    ({"vulnerable_ref": ""}, "lacks"),
])
def test_registry_entries_are_checked(entry, message):
    base = {"id": "I-1", "advisory": "https://a", "repository": "https://r",
            "vulnerable_ref": "abc", "static_visibility": "visible", "status": "verified",
            "expected": {"paths": ["x"]}}
    with pytest.raises(common.StudyError, match=message):
        replay.validate({"search": {"query": "q", "date": "d"}, "incidents": [{**base, **entry}]})
    with pytest.raises(common.StudyError, match="search"):
        replay.validate({"incidents": []})


def test_path_matching_keeps_dotfiles():
    assert replay._under(".mcp.json", [".mcp.json"])
    assert replay._under("./src/a.py", ["src"])
    assert not replay._under("srcx/a.py", ["src"])
    assert replay._under("anything", [])


@needs_git
def test_incident_replay_end_to_end(tmp_path):
    repo = _repo(tmp_path)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()
    registry = tmp_path / "incidents.yml"
    registry.write_text(json.dumps({"search": {"query": "q", "date": "2026-11-07"}, "incidents": [
        {"id": "VIS-1", "advisory": "https://example.org/a", "repository": "https://example.org/r",
         "vulnerable_ref": head, "introduced_ref": head, "static_visibility": "visible",
         "status": "verified", "expected": {"paths": [".mcp.json"]}},
        {"id": "VIS-2", "advisory": "https://example.org/b", "repository": "https://example.org/r",
         "vulnerable_ref": head, "static_visibility": "visible", "status": "verified",
         "expected": {"rules": ["NO_SUCH_RULE"]}},
        {"id": "RT-1", "advisory": "https://example.org/c", "repository": "https://example.org/r",
         "vulnerable_ref": head, "static_visibility": "runtime-only", "status": "verified",
         "expected": {"rules": ["NO_SUCH_RULE"]}},
        {"id": "CAND", "advisory": "https://example.org/d", "repository": "https://example.org/r",
         "vulnerable_ref": head, "static_visibility": "visible", "status": "candidate",
         "expected": {"paths": ["x"]}},
    ]}), encoding="utf-8")
    out = tmp_path / "replay"
    argv = ["--registry", str(registry), "--out", str(out)]
    for incident in ("VIS-1", "VIS-2", "RT-1"):
        argv += ["--repo-path", f"{incident}={repo}"]
    assert replay.main(argv) == 0
    data = json.loads((out / "replay.json").read_text(encoding="utf-8"))
    outcomes = {r["id"]: r["outcome"] for r in data["incidents"]}
    assert outcomes == {"VIS-1": "detected", "VIS-2": "missed", "RT-1": "expected-unknown"}
    assert data["incidents"][0]["change_hits"][0]["subject"] == "mcp_server:docs"
    assert data["summary"]["recall"] == {"n": 2, "k": 1, "status": "insufficient"}
    assert data["registry"] == {"candidate": 1, "verified": 3, "rejected": 0}
    assert "insufficient" in (out / "replay.md").read_text(encoding="utf-8")
