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
    ({"verified_by": ["ana"]}, "two or more"),
    ({"verified_by": ["ana", "ana"]}, "two or more"),
    ({"verified_on": None}, "verified_on"),
])
def test_registry_entries_are_checked(entry, message):
    base = {"id": "I-1", "advisory": "https://a", "repository": "https://r",
            "vulnerable_ref": "abc", "static_visibility": "visible", "status": "verified",
            "expected": {"paths": ["x"]}, "verified_by": ["ana", "ben"],
            "verified_on": "2026-11-08"}
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
    by = {"verified_by": ["ana", "ben"], "verified_on": "2026-11-08"}
    registry.write_text(json.dumps({"search": {"query": "q", "date": "2026-11-07"}, "incidents": [
        {"id": "VIS-1", "advisory": "https://example.org/a", "repository": "https://example.org/r",
         "vulnerable_ref": head, "introduced_ref": head, "static_visibility": "visible",
         "status": "verified", "expected": {"paths": [".mcp.json"]}, **by},
        {"id": "VIS-2", "advisory": "https://example.org/b", "repository": "https://example.org/r",
         "vulnerable_ref": head, "static_visibility": "visible", "status": "verified",
         "expected": {"rules": ["NO_SUCH_RULE"]}, **by},
        {"id": "RT-1", "advisory": "https://example.org/c", "repository": "https://example.org/r",
         "vulnerable_ref": head, "static_visibility": "runtime-only", "status": "verified",
         "expected": {"rules": ["NO_SUCH_RULE"]}, **by},
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


# --- C-3 incident search screens (offline) -----------------------------------------------

search = _load("incident_search")


def _advisory(**kw):
    base = {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": "MCP server command injection",
            "description": "", "cwes": [{"cwe_id": "CWE-78"}],
            "source_code_location": "https://github.com/o/r",
            "references": ["https://github.com/fork/r/commit/abc1234",
                           "https://github.com/o/r/commit/DEF5678", "https://example.org"],
            "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "thing"}}]}
    return {**base, **kw}


def test_search_screens_in_the_documented_order():
    assert search.screen(_advisory()) == "candidate"
    assert search.screen(_advisory(withdrawn_at="2026-01-01")) == "withdrawn"
    assert search.screen(_advisory(summary="XML parser bug")) == "no-keyword"
    assert search.screen(_advisory(summary="bug", vulnerabilities=[
        {"package": {"ecosystem": "npm", "name": "my-mcp-server"}}])) == "candidate"
    assert search.screen(_advisory(summary="user-agent header parsing")) == "no-keyword"
    assert search.screen(_advisory(cwes=[{"cwe_id": "CWE-79"}])) == "flaw-class-out-of-scope"
    assert search.screen(_advisory(references=[])) == "no-fix-commit"


def test_fix_commits_prefer_the_advisory_repository():
    assert search.fix_commits(_advisory()) == [("o", "r", "def5678"), ("fork", "r", "abc1234")]


@pytest.mark.parametrize(("path", "evidence"), [
    ("src/server.py", True), ("Dockerfile", True), ("tests/test_server.py", False),
    ("src/a.test.ts", False), (".github/workflows/ci.yml", False), ("CHANGELOG.md", False),
    ("package-lock.json", False), ("docs/usage.md", False),
])
def test_fix_files_that_are_not_evidence(path, evidence):
    assert (search.NOT_EVIDENCE.search(path) is None) is evidence


def test_committed_registry_matches_its_screening_record():
    reg = common.load_yaml(os.path.join(ROOT, "research", "credibility", "incidents.yml"))
    with open(os.path.join(ROOT, "research", "credibility", "incident_screening.json"),
              encoding="utf-8") as fh:
        screening = json.load(fh)
    candidates = {a["id"] for a in screening["advisories"] if a["decision"] == "candidate"}
    assert {e["id"] for e in reg["incidents"]} == candidates
    assert reg["search"]["counts"] == screening["summary"]
    assert all(e["static_visibility"] == "undetermined"
               for e in reg["incidents"] if e["status"] == "candidate")


def test_candidates_are_never_scored():
    results = [{"outcome": "unscored-flagged"}, {"outcome": "unscored"},
               {"outcome": "detected"}]
    assert replay.summarise(results)["recall"]["n"] == 1
    assert replay.summarise(results)["unscored"] == 2
    with pytest.raises(common.StudyError, match="verified incident needs"):
        replay.validate({"search": {"query": "q", "date": "d"}, "incidents": [
            {"id": "V", "advisory": "https://a", "repository": "https://r", "vulnerable_ref": "x",
             "static_visibility": "undetermined", "status": "verified",
             "expected": {"paths": ["p"]}}]})


# --- C-3 incident verification kit (offline) ---------------------------------------------

verify = _load("incident_verify")

_REGISTRY_HEAD = "# head comment\n#\n\n"


def _registry(tmp_path, n=4):
    incidents = [{"id": f"GHSA-{i}", "advisory": f"https://github.com/advisories/GHSA-{i}",
                  "repository": "https://github.com/o/r.git", "vulnerable_ref": "a" * 40,
                  "fixed_ref": "b" * 40, "static_visibility": "undetermined",
                  "expected": {"rules": [], "paths": ["src/server.py"]},
                  "status": "candidate", "cwes": ["CWE-78"], "notes": f"flaw {i}"}
                 for i in range(n)]
    path = tmp_path / "incidents.yml"
    path.write_text(_REGISTRY_HEAD + json.dumps(
        {"version": 1, "search": {"query": "q", "date": "2026-11-07"}, "incidents": incidents}),
        encoding="utf-8")
    return path


def test_verification_order_is_seeded_and_stable_when_candidates_are_added():
    few = [{"id": f"GHSA-{i}", "status": "candidate"} for i in range(5)]
    more = [*few, *({"id": f"GHSA-x{i}", "status": "candidate"} for i in range(5))]
    order_few = [e["id"] for e in verify.verification_order(few)]
    order_more = [e["id"] for e in verify.verification_order(more)]
    assert [i for i in order_more if i in order_few] == order_few
    assert [e["id"] for e in verify.verification_order(few, seed=1)] != order_few
    done = [{**few[0], "status": "verified"}, *few[1:]]
    assert few[0]["id"] not in [e["id"] for e in verify.verification_order(done)]


def test_packets_are_blind_and_list_the_rule_catalogue(tmp_path):
    registry = _registry(tmp_path)
    out = tmp_path / "verify"
    assert verify.main(["packets", "--registry", str(registry), "--out", str(out),
                        "--verifiers", "ana,ben", "--count", "2", "--offline"]) == 0
    packets = sorted((out / "packets").iterdir())
    assert len(packets) == 2 and packets[0].name.startswith("001-")
    text = packets[0].read_text(encoding="utf-8")
    assert "`CAP_shell`" in text and "does not show what SafeAI reports" in text
    assert "rule_id" not in text and "observed" not in text
    with open(out / "sheet.ana.csv", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["id"] for r in rows] == [p.name[4:-3] for p in packets]
    assert list(rows[0]) == verify.SHEET_FIELDS
    assert verify.main(["packets", "--registry", str(registry), "--out", str(out),
                        "--verifiers", "ana", "--offline"]) == 2


def _sheet(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=verify.SHEET_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


def test_apply_writes_agreed_answers_and_lists_the_rest(tmp_path):
    registry = _registry(tmp_path, n=5)
    agreed = {"id": "GHSA-0", "decision": "verified", "static_visibility": "visible",
              "rules": "CAP_shell; PROMPT_INJECTION", "paths": "src/server.py"}
    rejected = {"id": "GHSA-1", "decision": "rejected", "reason": "not an agent flaw"}
    a = _sheet(tmp_path / "sheet.ana.csv", [
        agreed, rejected,
        {"id": "GHSA-2", "decision": "verified", "static_visibility": "visible",
         "rules": "CAP_shell", "paths": "src/server.py"},
        {"id": "GHSA-3", "decision": "verified", "static_visibility": "runtime-only",
         "paths": "src/server.py"},
        {"id": "GHSA-4", "decision": "unsure"}])
    b = _sheet(tmp_path / "sheet.ben.csv", [
        {**agreed, "rules": "PROMPT_INJECTION;CAP_shell"}, rejected,
        {"id": "GHSA-2", "decision": "verified", "static_visibility": "runtime-only",
         "rules": "CAP_shell", "paths": "src/server.py"},
        {"id": "GHSA-3", "decision": "verified", "static_visibility": "visible",
         "paths": "src/server.py"},
        {"id": "GHSA-4", "decision": "unsure"}])
    adj = _sheet(tmp_path / "sheet.cem.csv", [
        {"id": "GHSA-3", "decision": "verified", "static_visibility": "runtime-only",
         "paths": "src/server.py"}])
    assert verify.main(["apply", "--registry", str(registry), a, b, "--adjudication", adj,
                        "--today", "2026-11-08"]) == 1
    assert registry.read_text(encoding="utf-8").startswith(_REGISTRY_HEAD)
    data = common.load_yaml(str(registry))
    by_id = {e["id"]: e for e in data["incidents"]}
    assert by_id["GHSA-0"]["status"] == "verified"
    assert by_id["GHSA-0"]["expected"]["rules"] == ["CAP_shell", "PROMPT_INJECTION"]
    assert by_id["GHSA-0"]["verified_by"] == ["ana", "ben"]
    assert by_id["GHSA-1"]["status"] == "rejected"
    assert "not an agent flaw" in by_id["GHSA-1"]["notes"]
    assert by_id["GHSA-2"]["status"] == "candidate"
    assert by_id["GHSA-3"]["verified_by"] == ["ana", "ben", "cem"]
    assert by_id["GHSA-3"]["static_visibility"] == "runtime-only"
    assert by_id["GHSA-4"]["status"] == "candidate"
    replay.validate(data)
    assert verify.main(["apply", "--registry", str(registry), a, a]) == 2


@pytest.mark.parametrize(("answer", "problem"), [
    ({"decision": "maybe"}, "decision"),
    ({"decision": "rejected"}, "reason"),
    ({"decision": "verified", "static_visibility": "undetermined", "paths": "x"},
     "static_visibility"),
    ({"decision": "verified", "static_visibility": "visible"}, "rules or paths"),
    ({"decision": "verified", "static_visibility": "visible", "paths": "x",
      "introduced_ref": "HEAD~1"}, "SHA"),
])
def test_bad_answers_are_not_applied(tmp_path, answer, problem):
    path = _sheet(tmp_path / "sheet.x.csv", [{"id": "GHSA-0", **answer}])
    assert problem in verify.check_answer(verify.read_answers(path)["GHSA-0"])


# --- C-2 target eligibility (offline) -----------------------------------------------------

target_check = _load("target_check")

_META = {"license": {"spdx_id": "MIT"}, "archived": False, "fork": False,
         "owner": {"login": "someone"}, "default_branch": "main"}


@needs_git
def test_target_check_records_surface_but_no_findings(tmp_path):
    repo = _repo(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    facts = target_check.check_target(
        {"id": "demo", "url": "https://github.com/someone/demo"}, str(work), window=3,
        meta=_META, repo=str(repo))
    assert facts["first_parent_commits"] == 4
    assert facts["suggested_range"]["first_parent_commits"] == 3
    assert facts["suggested_range"]["to"] == facts["head"]
    assert facts["head_surface"]["tools"] >= 1 and "mcp" in facts["head_surface"]["frameworks"]
    assert "findings" not in json.dumps(facts) and "rule_id" not in json.dumps(facts)
    # Four commits are below the 50-commit criterion.
    assert facts["eligible"] is False
    assert facts["fails"] == ["fewer than 50 first-parent commits"]


@pytest.mark.parametrize(("change", "fail"), [
    ({"licence": None}, "licence"), ({"archived": True}, "archived"), ({"fork": True}, "fork"),
    ({"owner": "IkarusAILabs"}, "SafeAI's authors"),
    ({"head_surface": {"frameworks": [], "tools": 0, "mcp_assets": 0}}, "no agent framework"),
])
def test_target_criteria(change, fail):
    facts = {"licence": "MIT", "archived": False, "fork": False, "owner": "x",
             "first_parent_commits": 60,
             "head_surface": {"frameworks": ["mcp"], "tools": 1, "mcp_assets": 0}}
    assert target_check.assess(facts) == []
    assert any(fail in f for f in target_check.assess({**facts, **change}))
    assert target_check.repo_facts({**_META, "license": {"spdx_id": "NOASSERTION"}})[
        "licence"] is None


# --- portable export (shake-down 2026-11-08) ---------------------------------------------

@pytest.mark.parametrize(("name", "windows", "expected"), [
    ("screenplay_writer/config /agents.yaml", True, "screenplay_writer/config/agents.yaml"),
    ("a/b:c?.py", True, "a/b_c_.py"),
    ("a/../b", True, "a/_/b"),
    ("a/trailing./x", True, "a/trailing/x"),
    ("screenplay_writer/config /agents.yaml", False, "screenplay_writer/config /agents.yaml"),
    ("plain/path.py", True, "plain/path.py"),
])
def test_portable_names(name, windows, expected):
    assert common.portable_name(name, windows=windows) == expected


@needs_git
def test_export_survives_names_windows_cannot_hold(tmp_path):
    repo = tmp_path / "odd"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "study@example.org")
    _git(repo, "config", "user.name", "study")

    def plumbing(*args, stdin):
        # Bytes, not text: text-mode stdin on Windows writes CRLF line ends.
        return subprocess.run(["git", *args], cwd=repo, input=stdin.encode(),
                              capture_output=True, check=True).stdout.decode().strip()

    blob = plumbing("hash-object", "-w", "--stdin", stdin="x: 1\n")
    # Build a tree holding "config /agents.yaml" without touching the filesystem.
    inner = plumbing("mktree", stdin=f"100644 blob {blob}\tagents.yaml\n")
    outer = plumbing("mktree", stdin=f"040000 tree {inner}\tconfig \n")
    commit = plumbing("commit-tree", outer, "-m", "odd", stdin="")
    dest = tmp_path / "tree"
    common.export_tree(str(repo), commit, str(dest))
    files = [os.path.relpath(os.path.join(r, f), dest).replace("\\", "/")
             for r, _, fs in os.walk(dest) for f in fs]
    assert files in (["config/agents.yaml"], ["config /agents.yaml"])
