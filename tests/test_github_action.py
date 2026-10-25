"""Tests for the SafeAI GitHub composite action and its driver.

Covers the ``action.yml`` marketplace metadata, the driver script's safe
argv construction, SARIF generation and preservation, exit-code thresholds,
secret redaction, shell-injection resistance, and wheel package data.
"""

import importlib.util
import json
import os
import subprocess
import sys
import zipfile

import pytest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures", "action")
DRIVER = os.path.join(REPO_ROOT, "scripts", "safeai-action.py")
ACTION_YML = os.path.join(REPO_ROOT, "action.yml")

VALID_BRANDING_COLORS = {"white", "yellow", "blue", "green", "orange", "red", "purple", "gray"}
# A representative subset of GitHub's accepted Octicon names used by branding.
VALID_BRANDING_ICONS = {
    "shield", "shield-check", "lock", "bug", "zap", "search", "alert",
    "code-square", "terminal", "package", "robot", "eye", "key", "check",
}


def _load_action():
    with open(ACTION_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_driver():
    spec = importlib.util.spec_from_file_location("safeai_action", DRIVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_driver(env_extra, cwd=None):
    env = dict(os.environ)
    env["SAFEAI_ACTION_SKIP_INSTALL"] = "true"
    env["PYTHONPATH"] = REPO_ROOT
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, DRIVER],
        cwd=cwd or REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture()
def driver():
    return _load_driver()


@pytest.fixture()
def action():
    return _load_action()


def test_action_metadata(action):
    assert action["name"] == "SafeAI Static Analysis"
    assert action["description"]
    assert action["author"] == "IkarusCareer"
    assert action["branding"]["icon"] in VALID_BRANDING_ICONS
    assert action["branding"]["color"] in VALID_BRANDING_COLORS
    assert action["runs"]["using"] == "composite"


def test_action_required_inputs_defaults(action):
    inputs = action["inputs"]
    for name in ("path", "version", "fail-on", "sarif"):
        assert name in inputs
        assert "description" in inputs[name]
        assert "default" in inputs[name]
    assert inputs["path"]["default"] == "."
    assert inputs["version"]["default"] == ""
    assert inputs["fail-on"]["default"] == "critical"
    assert inputs["sarif"]["default"] == "safeai-results.sarif"


def test_action_outputs_mapped_to_step_outputs(action):
    """Composite action outputs must carry a ``value`` mapped to a step
    output; without it consumers read an empty ``sarif-path``."""
    outputs = action["outputs"]
    assert "sarif-path" in outputs
    assert "value" in outputs["sarif-path"]
    assert outputs["sarif-path"]["value"] == "${{ steps.safeai.outputs.sarif-path }}"
    assert "scorecard-path" in outputs
    assert "value" in outputs["scorecard-path"]
    assert outputs["scorecard-path"]["value"] == "${{ steps.safeai.outputs.scorecard-path }}"
    step_ids = {step.get("id") for step in action["runs"]["steps"]}
    assert "safeai" in step_ids


def test_action_inputs_map_to_real_cli_flags():
    """Every exposed input either maps to a tested CLI option or is a
    documented install/scan control; no invented flags."""
    action = _load_action()
    inputs = set(action["inputs"])
    expected = {
        "path",        # scan <directory>
        "version",     # PyPI install version control
        "fail-on",     # --fail-on
        "sarif",       # --sarif
        "rules",       # --rules
        "baseline",    # --baseline
        "fail-on-new", # --fail-on-new
        "fail-on-escalation",  # --fail-on-escalation
        "fail-on-authority-change",  # --fail-on-authority-change
        "unknown-authority",  # --unknown-authority
        "no-registry", # --no-registry
        "extra-args",  # additional argv elements (safe, list-based)
        "scorecard",           # --scorecard
        "scorecard-json",      # --scorecard-json
        "scorecard-summary",   # --scorecard-summary
        "scorecard-fail-under", # --scorecard-fail-under
        "pr-comment-post",     # --pr-comment-post
    }
    assert inputs == expected


def test_action_no_shell_expansion_of_inputs(action):
    """Composite `run:` steps must not interpolate `${{ inputs.* }}` into a
    shell string; inputs pass through env vars only."""
    joined = ""
    for step in action["runs"]["steps"]:
        run = step.get("run", "")
        joined += run + "\n"
        # The only interpolation used is the action's own static script path.
        assert "${{ inputs." not in run
        assert "eval " not in run
    assert "SAFEAI_PY" in joined
    assert "GITHUB_ENV" in joined


def test_driver_build_install_command_exact_version(driver):
    cmd = driver.build_install_command("1.5.0")
    assert cmd[-1] == "SafeAI-Static-Analyzer==1.5.0"
    assert "-m" in cmd and "pip" in cmd


def test_driver_build_install_command_latest(driver):
    cmd = driver.build_install_command("")
    assert cmd[-1] == "SafeAI-Static-Analyzer"


def test_driver_version_validation(driver):
    assert driver.validate_version("1.5.0") is None
    assert driver.validate_version("1.5.0rc1") is None
    assert driver.validate_version("") is None
    for bad in ("1.5.0; curl evil", "$(id)", "1.5.0 --extra-index-url x",
                "..", "1.5.0\n", "1.5.0/../../x", "none", "-1.5.0"):
        assert driver.validate_version(bad) is not None, bad


def test_driver_parse_extra_args(driver):
    assert driver.parse_extra_args('["--verbose"]') == ["--verbose"]
    assert driver.parse_extra_args("[]") == []
    with pytest.raises(TypeError):
        driver.parse_extra_args('["--verbose", 3]')
    with pytest.raises(json.JSONDecodeError):
        driver.parse_extra_args("--verbose")  # not JSON
    with pytest.raises(TypeError):
        driver.parse_extra_args('{"bad": true}')


def test_driver_build_scan_argv_no_shell(driver):
    argv = driver.build_scan_argv(
        "/path/with spi ces", "critical", "/out/re port.sarif",
        rules="/rules dir", baseline="/baseline file.json",
        fail_on_new=True, fail_on_escalation="high", no_registry=True,
        extra_args=["--verbose"],
    )
    assert argv[0] == sys.executable
    assert "scan" in argv and "/path/with spi ces" in argv
    assert "/out/re port.sarif" in argv  # intact single element, no splitting
    assert "--baseline" in argv and "/baseline file.json" in argv
    assert "--fail-on-escalation" in argv and "high" in argv
    assert "--no-registry" in argv
    assert "--verbose" in argv


def test_driver_rejects_invalid_threshold(driver, tmp_path):
    env = {
        "INPUT_PATH": str(tmp_path),
        "INPUT_FAIL_ON": "urgent",
        "INPUT_SARIF": "",
    }
    proc = _run_driver(env)
    assert proc.returncode == 2
    assert "fail-on" in (proc.stderr + proc.stdout).lower()


def test_driver_rejects_missing_path(driver, tmp_path):
    env = {
        "INPUT_PATH": os.path.join(str(tmp_path), "does-not-exist"),
        "INPUT_FAIL_ON": "critical",
        "INPUT_SARIF": str(tmp_path / "r.sarif"),
    }
    proc = _run_driver(env)
    assert proc.returncode == 2
    assert "does not exist" in proc.stderr


def test_driver_rejects_control_char_in_sarif(driver, tmp_path):
    """A newline smuggled through a path input must not reach $GITHUB_OUTPUT;
    it is an operational error (exit 2), not a scan outcome."""
    env = {
        "INPUT_PATH": os.path.join(FIXTURES, "clean"),
        "INPUT_SARIF": "out.sarif\nEVIL=1",
        "INPUT_FAIL_ON": "critical",
    }
    proc = _run_driver(env)
    assert proc.returncode == 2
    assert "control character" in proc.stderr


def test_driver_rejects_control_char_in_path(driver, tmp_path):
    env = {
        "INPUT_PATH": os.path.join(FIXTURES, "cli\nent"),
        "INPUT_SARIF": str(tmp_path / "r.sarif"),
        "INPUT_FAIL_ON": "critical",
    }
    proc = _run_driver(env)
    assert proc.returncode == 2
    assert "control character" in proc.stderr


def test_install_failure_is_operational_error(driver, tmp_path, monkeypatch):
    """A failed pip install must exit 2 (operational error), never 1 (which
    consumers treat as a policy/finding failure)."""

    def fake_call(cmd, *args, **kwargs):
        assert cmd[0] == sys.executable
        assert "pip" in cmd
        assert cmd[-1].startswith("SafeAI-Static-Analyzer==")
        return 1  # pip failed

    monkeypatch.setattr(driver.subprocess, "call", fake_call)
    old_env = dict(os.environ)
    os.environ["INPUT_PATH"] = os.path.join(FIXTURES, "clean")
    os.environ["INPUT_VERSION"] = "1.5.0"
    os.environ["INPUT_FAIL_ON"] = "critical"
    os.environ["INPUT_SARIF"] = ""
    os.environ.pop("SAFEAI_ACTION_SKIP_INSTALL", None)
    try:
        result = driver.main()
    finally:
        os.environ.clear()
        os.environ.update(old_env)
    assert result == 2


def test_sarif_dir_create_failure_is_operational_error(driver, monkeypatch):
    """If the SARIF parent directory cannot be created, exit 2, not 1."""

    def fake_makedirs(path, exist_ok=True):
        raise PermissionError("denied")

    monkeypatch.setattr(driver.os, "makedirs", fake_makedirs)
    old_env = dict(os.environ)
    os.environ["INPUT_PATH"] = os.path.join(FIXTURES, "clean")
    os.environ["INPUT_FAIL_ON"] = "critical"
    os.environ["INPUT_SARIF"] = "/no/such/dir/out.sarif"
    os.environ["SAFEAI_ACTION_SKIP_INSTALL"] = "true"
    try:
        result = driver.main()
    finally:
        os.environ.clear()
        os.environ.update(old_env)
    assert result == 2



def test_clean_fixture_success(driver, tmp_path):
    sarif = str(tmp_path / "clean.sarif")
    proc = _run_driver({
        "INPUT_PATH": os.path.join(FIXTURES, "clean"),
        "INPUT_SARIF": sarif,
        "INPUT_FAIL_ON": "critical",
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    with open(sarif, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["version"] == "2.1.0"


def test_risky_fixture_failure_and_sarif_preserved(driver, tmp_path):
    sarif = str(tmp_path / "risky.sarif")
    env = {
        "INPUT_PATH": os.path.join(FIXTURES, "risky"),
        "INPUT_SARIF": sarif,
        "INPUT_FAIL_ON": "critical",
    }
    proc = _run_driver(env)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    # SARIF must still exist after a policy-failure exit code.
    assert os.path.exists(sarif)
    with open(sarif, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["version"] == "2.1.0"
    rule_ids = {
        r.get("id")
        for run in data["runs"]
        for r in run.get("tool", {}).get("driver", {}).get("rules", [])
    }
    assert "CAP_subprocess_shell" in rule_ids
    # Paths and rule ids are correctly represented.
    assert data["runs"][0]["results"]


def test_risky_fail_on_high_and_medium(driver, tmp_path):
    for level in ("high", "medium"):
        env = {
            "INPUT_PATH": os.path.join(FIXTURES, "risky"),
            "INPUT_FAIL_ON": level,
            "INPUT_SARIF": str(tmp_path / f"r-{level}.sarif"),
        }
        proc = _run_driver(env)
        assert proc.returncode == 1, (level, proc.stdout, proc.stderr)


def test_medium_threshold_only(driver, tmp_path):
    """A medium-severity project passes at critical/high but fails at medium."""
    sarif = str(tmp_path / "m.sarif")
    env_ok = {
        "INPUT_PATH": os.path.join(FIXTURES, "medium"),
        "INPUT_FAIL_ON": "critical",
        "INPUT_SARIF": sarif,
    }
    assert _run_driver(env_ok).returncode == 0
    assert _run_driver({**env_ok, "INPUT_FAIL_ON": "high"}).returncode == 0
    assert _run_driver({**env_ok, "INPUT_FAIL_ON": "medium"}).returncode == 1


def test_sarif_relative_path_resolution_with_spaces(driver, tmp_path):
    spaced = tmp_path / "dir with spaces"
    spaced.mkdir()
    (spaced / "agent.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "graph = StateGraph(dict)\n"
        "graph.add_node('n', lambda s: s)\n",
        encoding="utf-8",
    )
    sarif = os.path.join(str(tmp_path), "out dir", "results.sarif")
    proc = _run_driver({
        "INPUT_PATH": str(spaced),
        "INPUT_SARIF": sarif,
        "INPUT_FAIL_ON": "critical",
    }, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert os.path.exists(sarif)


def test_sarif_parent_dir_created(driver, tmp_path):
    sarif = os.path.join(str(tmp_path), "nested", "deep", "out.sarif")
    proc = _run_driver({
        "INPUT_PATH": os.path.join(FIXTURES, "clean"),
        "INPUT_SARIF": sarif,
        "INPUT_FAIL_ON": "critical",
    })
    assert proc.returncode == 0
    assert os.path.exists(sarif)


def test_driver_scorecard_summary_uses_github_summary_path(driver, tmp_path):
    scorecard_md = str(tmp_path / "scorecard.md")
    scorecard_json = str(tmp_path / "scorecard.json")
    summary_path = str(tmp_path / "step-summary.md")
    proc = _run_driver({
        "INPUT_PATH": os.path.join(FIXTURES, "clean"),
        "INPUT_SARIF": str(tmp_path / "clean.sarif"),
        "INPUT_FAIL_ON": "critical",
        "INPUT_SCORECARD": scorecard_md,
        "INPUT_SCORECARD_JSON": scorecard_json,
        "INPUT_SCORECARD_SUMMARY": "true",
        "GITHUB_STEP_SUMMARY": summary_path,
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert os.path.exists(scorecard_md)
    assert os.path.exists(scorecard_json)
    assert os.path.exists(summary_path)
    # Regression guard: do not treat literal "true" as a filesystem path.
    assert not os.path.exists(os.path.join(REPO_ROOT, "true"))


def test_no_secret_values_in_output(driver, tmp_path):
    sarif = str(tmp_path / "sec.sarif")
    proc = _run_driver({
        "INPUT_PATH": os.path.join(FIXTURES, "risky"),
        "INPUT_SARIF": sarif,
        "INPUT_FAIL_ON": "medium",
    })
    secret = "sk-abcdef0123456789abcdef"
    assert secret not in proc.stdout
    assert secret not in proc.stderr
    with open(sarif, encoding="utf-8") as fh:
        sarif_text = fh.read()
    assert secret not in sarif_text


def test_no_unsafe_shell_in_driver(driver):
    import inspect
    src = inspect.getsource(driver)
    assert "shell=True" not in src
    assert "os.system(" not in src
    assert "eval(" not in src


def test_no_secrets_or_tokens_required_by_action(action):
    joined = json.dumps(action)
    for secret_word in ("GITHUB_TOKEN", "password", "api_key", "token:"):
        assert secret_word not in joined


def test_pyproject_requires_python_3_11():
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        text = fh.read()
    assert 'requires-python = ">=3.11"' in text


def test_wheel_contains_package_data(tmp_path):
    """Built wheel must carry the rules YAML and entry points."""
    build = pytest.importorskip("build")
    pytest.importorskip(
        "setuptools",
        reason="the wheel build needs the 'setuptools.build_meta' backend",
    )
    out = tmp_path / "dist"
    out.mkdir()
    builder = build.ProjectBuilder(REPO_ROOT)
    builder.build("wheel", str(out))
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as zf:
        names = set(zf.namelist())
        assert "safeai/rules/base_rules.yaml" in names
        assert any(n.endswith("entry_points.txt") for n in names)
        dist_infos = [n for n in names if n.endswith("METADATA")]
        meta = zf.read(dist_infos[0]).decode("utf-8")
        assert "Name: SafeAI-Static-Analyzer" in meta
        from safeai.version import SAFEAI_VERSION
        assert f"Version: {SAFEAI_VERSION}" in meta


def test_local_integration_script_present():
    script = os.path.join(REPO_ROOT, "scripts", "run_local_integration.py")
    assert os.path.exists(script)
    assert os.path.exists(os.path.join(REPO_ROOT, "scripts", "check_wheel.py"))


def test_workflow_validates_action():
    wf = os.path.join(REPO_ROOT, ".github", "workflows", "action-test.yml")
    assert os.path.exists(wf)
    with open(wf, encoding="utf-8") as fh:
        text = fh.read()
    assert "uses: ./" in text  # runs the composite action against fixtures
    assert "permissions:" in text
    assert "contents: read" in text
