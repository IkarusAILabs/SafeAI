"""Package-manager authority (v2.9, ROADMAP E1, plan items 2.9-2 to 2.9-5)."""

import json
import os

import pytest

from safeai.analysis import package_managers as pm
from safeai.cmd.cli import main
from safeai.frameworks.claude_code import permissions


@pytest.mark.parametrize(
    ("command", "targets"),
    [
        ("npm install:*", ["npm:install"]),
        ("npm i lodash", ["npm:install"]),
        ("npm ci", ["npm:install"]),
        ("npm publish", ["npm:publish"]),
        ("npm:*", ["npm:install", "npm:publish"]),
        ("npm *", ["npm:install", "npm:publish"]),
        ("pip install -r requirements.txt", ["pip:install"]),
        ("python -m pip install x", ["pip:install"]),
        ("uv pip install x", ["pip:install"]),
        ("pip3 install:*", ["pip:install"]),
        ("uv add requests", ["uv:install"]),
        ("poetry:*", ["poetry:install", "poetry:publish"]),
        ("go get ./...", ["go:install"]),
        ("cargo publish", ["cargo:publish"]),
        ("twine upload dist/*", ["twine:publish"]),
    ],
)
def test_command_targets(command, targets):
    assert pm.command_targets(command) == targets


@pytest.mark.parametrize(
    "command",
    ["npm", "npm run build", "npm test", "pip list", "go test ./...", "git status",
     "uvx ruff check", "echo npm install", "", None],
)
def test_commands_that_change_no_dependency(command):
    assert pm.command_targets(command) == []


def test_access_mode_follows_the_strongest_route():
    assert pm.access_mode_for(["npm:install"]) == "write"
    assert pm.access_mode_for(["npm:install", "npm:publish"]) == "execute"
    assert pm.access_mode_for([]) is None


@pytest.mark.parametrize(
    ("pattern", "targets"),
    [
        ("package.json", ["manifest:package.json"]),
        ("./services/api/go.mod", ["manifest:go.mod"]),
        ("**/Cargo.toml", ["manifest:Cargo.toml"]),
        ("requirements*.txt", ["manifest:requirements*.txt"]),
        ("requirements-dev.txt", ["manifest:requirements-dev.txt"]),
        ("*", []),
        ("**", []),
        ("*.json", []),
        ("src/**", []),
        ("docs/package.json.md", []),
    ],
)
def test_manifest_targets(pattern, targets):
    assert pm.manifest_targets(pattern) == targets


def test_registry_credentials_are_names_from_the_list_only():
    assert pm.registry_credentials(["NPM_TOKEN", "DEBUG", "TWINE_PASSWORD"]) == [
        "NPM_TOKEN", "TWINE_PASSWORD"]


def _caps(entry, decision="allow", credentials=()):
    record = permissions.classify_entry(entry, decision, ".claude/settings.json", 3)
    return permissions.capabilities_for(record, credentials=credentials)


def test_bash_package_manager_grant_adds_a_capability_on_the_same_tool():
    shell, package_manager = _caps("Bash(npm publish)", credentials=["NPM_TOKEN", "HOME"])
    assert shell["name"] == "shell" and shell["access_mode"] == "execute"
    assert package_manager["name"] == "package_manager"
    assert package_manager["access_mode"] == "execute"
    assert package_manager["targets"] == ["npm:publish"]
    assert package_manager["credentials"] == ["NPM_TOKEN"]
    assert package_manager["tool_identity"] == shell["tool_identity"]


@pytest.mark.parametrize("entry", ["Bash", "Bash(*)", "Bash(npm run build)", "Bash(git status)"])
def test_other_bash_grants_add_no_package_manager_capability(entry):
    assert [c["name"] for c in _caps(entry)] == ["shell"]


def test_manifest_write_grant_carries_the_manifest_target():
    (capability,) = _caps("Edit(package.json)")
    assert capability["name"] == "filesystem"
    assert capability["targets"] == ["manifest:package.json"]


def test_broad_write_grant_names_no_manifest():
    (capability,) = _caps("Write(*)")
    assert "targets" not in capability


def test_deny_and_ask_confer_nothing():
    assert _caps("Bash(npm publish)", decision="deny") == []
    assert _caps("Bash(npm publish)", decision="ask") == []


SETTINGS = {
    "env": {"NPM_TOKEN": "npm_SECRETVALUE1234567890", "DEBUG": "1"},
    "permissions": {
        "allow": ["Bash(npm install:*)", "Bash(npm publish)", "Bash(npm run build)",
                  "Edit(package.json)", "Write(*)"],
        "deny": ["Bash(rm *)"],
    },
}


def _project(tmp_path, settings, name="proj"):
    root = tmp_path / name
    (root / ".claude").mkdir(parents=True)
    (root / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    return root


def _scan(root, out, *extra):
    rc = main(["scan", str(root), "--json", str(out), "--no-registry", *extra])
    return rc, json.loads(out.read_text(encoding="utf-8"))


def test_scan_reports_package_manager_authority(tmp_path):
    root = _project(tmp_path, SETTINGS)
    _, report = _scan(root, tmp_path / "r.json")

    surface = {t["tool_key"]: t for t in report["tool_surface"]}
    bash = {c["name"]: c for c in surface["tool:bash"]["capabilities"]}
    assert bash["package_manager"]["access_mode"] == "execute"
    assert bash["package_manager"]["targets"] == ["npm:install", "npm:publish"]
    assert bash["package_manager"]["credentials"] == ["NPM_TOKEN"]
    assert surface["tool:edit"]["capabilities"][0]["targets"] == ["manifest:package.json"]
    assert "targets" not in surface["tool:write"]["capabilities"][0]

    findings = [f for f in report["findings"] if f["rule_id"] == "CAP_package_manager"]
    assert findings and all(f["gateability"] == "review-only" for f in findings)


def test_settings_env_values_never_reach_any_output(tmp_path):
    root = _project(tmp_path, SETTINGS)
    out, sarif, manifest = tmp_path / "r.json", tmp_path / "r.sarif", tmp_path / "m.json"
    main(["scan", str(root), "--json", str(out), "--sarif", str(sarif),
          "--manifest", str(manifest), "--no-registry"])
    for path in (out, sarif, manifest):
        assert "SECRETVALUE" not in path.read_text(encoding="utf-8")


def _strip_package_manager(report):
    """The same report as a pre-v2.9 scan would have produced it."""
    for tool in report["tool_surface"]:
        tool["capabilities"] = [
            {k: v for k, v in c.items() if k not in ("targets", "credentials")}
            for c in tool["capabilities"] if c["name"] != "package_manager"
        ]
    report["normalized_capabilities"] = [
        c for c in report.get("normalized_capabilities") or [] if c.get("name") != "package_manager"
    ]
    return report


@pytest.fixture()
def pre_v29_baseline(tmp_path):
    root = _project(tmp_path, SETTINGS)
    _, report = _scan(root, tmp_path / "base.json")
    path = tmp_path / "base-v28.json"
    path.write_text(json.dumps(_strip_package_manager(report)), encoding="utf-8")
    return root, path


@pytest.mark.parametrize(
    "gate", [["--fail-on-authority-change", "material"], ["--fail-on-escalation", "medium"]]
)
def test_upgrade_against_a_pre_v29_baseline_fails_no_gate(pre_v29_baseline, tmp_path, gate):
    root, baseline = pre_v29_baseline
    rc, report = _scan(root, tmp_path / "d.json", "--baseline", str(baseline), *gate)
    assert rc == 0
    diff = report["capability_diff"]
    bash = next(t for t in diff["tools"] if t["tool_key"] == "tool:bash")
    assert bash["review_only"] is True
    assert bash["escalations"], "the new capability is still reported"
    assert diff["highest_gating_escalation"] is None


@pytest.mark.parametrize(
    "gate", [["--fail-on-authority-change", "material"], ["--fail-on-escalation", "medium"]]
)
def test_a_lane_a_change_next_to_it_still_fails_the_gate(pre_v29_baseline, tmp_path, gate):
    root, baseline = pre_v29_baseline
    settings = json.loads(json.dumps(SETTINGS))
    settings["permissions"]["allow"].append("Bash(curl:*)")
    settings["permissions"]["allow"].append("mcp__github__create_issue")
    (root / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    rc, _ = _scan(root, tmp_path / "d.json", "--baseline", str(baseline), *gate)
    assert rc == 1


def test_dependency_and_credential_dimensions_in_the_diff(pre_v29_baseline, tmp_path):
    root, baseline = pre_v29_baseline
    _, report = _scan(root, tmp_path / "d.json", "--baseline", str(baseline))
    tools = {t["tool_key"]: t for t in report["capability_diff"]["tools"]}
    authority = tools["tool:bash"]["authority"]
    assert authority["dependency"] == {
        "values": ["npm:install", "npm:publish"], "provenance_class": "detected"}
    assert authority["credential"] == {
        "state": "present", "values": ["NPM_TOKEN"], "provenance_class": "detected"}
    assert tools["tool:edit"]["authority"]["dependency"]["values"] == ["manifest:package.json"]
    assert tools["tool:write"]["authority"]["dependency"]["provenance_class"] == "unknown"


PENDING_CORPUS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "benchmarks", "authority-pending"
)


def test_pending_corpus_holds_and_stays_labelled_unreviewed(tmp_path):
    """2.9-1: the E1 cases hold, and say they await human review."""
    from safeai.benchmark import runner

    cases = runner.discover_cases(PENDING_CORPUS)
    assert len(cases) >= 6
    for case in cases:
        annotation = runner.load_expected(case["dir"]).get("annotation") or {}
        assert annotation.get("derivation") == "pending_human_review", case["id"]
        assert annotation.get("basis") != "human_reviewed_source", case["id"]
    result = runner.run_corpus(PENDING_CORPUS, str(tmp_path), determinism=False)
    failed = {r["id"]: r.get("failures") for r in result["cases"] if not r.get("passed")}
    assert failed == {}
