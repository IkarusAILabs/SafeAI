"""CAP_subprocess_shell must fire on multi-line (black/ruff-wrapped) calls.

Regression: the per-line regex missed ``subprocess.run(\\n cmd, shell=True)``,
so six authority-benchmark cases reported ``must_fire rule silent``.
Single-line detections must keep their exact line and evidence (and so
their fingerprints, which baselines and suppressions key on).
"""

from safeai.analyzers.capability.analyzer import (
    CapabilityAnalyzer,
    _subprocess_shell_calls,
)

RULES = [{"id": "CAP_subprocess_shell", "severity": "critical", "owasp_llm": "LLM06"}]

WRAPPED = (
    "import subprocess\n"
    "\n"
    "def deploy(cmd):\n"
    "    result = subprocess.run(\n"
    "        cmd, shell=True, capture_output=True, text=True, check=False\n"
    "    )\n"
    "    return result.stdout\n"
)


def _shell_findings(source, path="agent.py"):
    findings = CapabilityAnalyzer().run({path: source}, RULES)
    return [f for f in findings if f["rule_id"] == "CAP_subprocess_shell"]


def test_wrapped_call_fires_at_call_line():
    hits = _shell_findings(WRAPPED)
    assert len(hits) == 1
    assert hits[0]["line"] == 4
    assert hits[0]["severity"] == "critical"
    assert "shell=True" in hits[0]["evidence"]
    assert hits[0]["evidence"].startswith("subprocess.run( cmd, shell=True")


def test_single_line_detection_unchanged():
    source = "import subprocess\n\ndef run(x):\n    subprocess.run(x, shell=True)\n"
    hits = _shell_findings(source)
    assert len(hits) == 1
    assert hits[0]["line"] == 4
    # Evidence stays the stripped source line, as before the AST pass.
    assert hits[0]["evidence"] == "subprocess.run(x, shell=True)"


def test_aliases_and_from_imports_resolve():
    source = (
        "import subprocess as sp\n"
        "from subprocess import Popen as P, check_output\n"
        "sp.call(\n    'ls', shell=True)\n"
        "P(\n    'ls',\n    shell=True,\n)\n"
        "check_output(\n    'ls', shell=True)\n"
    )
    assert [line for line, _ in _subprocess_shell_calls(source)] == [3, 5, 9]


def test_non_literal_or_false_shell_not_flagged():
    source = (
        "import subprocess\n"
        "flag = True\n"
        "subprocess.run(\n    'ls', shell=False)\n"
        "subprocess.run(\n    'ls', shell=flag)\n"
        "subprocess.run(\n    'ls', **{'shell': True})\n"
    )
    assert _subprocess_shell_calls(source) == []


def test_unrelated_run_function_not_flagged():
    source = "def run(cmd, shell=False):\n    pass\n\nrun(\n    'ls', shell=True)\n"
    assert _subprocess_shell_calls(source) == []


def test_unparseable_source_falls_back_to_line_regex():
    source = "import subprocess\nsubprocess.run(x, shell=True)\ndef broken(:\n"
    assert _subprocess_shell_calls(source) == []
    hits = _shell_findings(source)
    assert [h["line"] for h in hits] == [2]


def test_ast_pass_only_runs_on_python_files():
    assert _shell_findings(WRAPPED, path="notes.txt") == []
