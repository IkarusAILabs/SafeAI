"""Reported paths keep leading dots; identity hashes keep the pre-2.12 form."""

import json

import pytest

from safeai.cmd.cli import main
from safeai.kya.fingerprints import (
    compute_fingerprint,
    fingerprint_path,
    normalize_path,
    path_glob_matches,
)
from safeai.kya.util import normalize_evidence, sha256_text


@pytest.mark.parametrize(("raw", "expected"), [
    (".claude/settings.json", ".claude/settings.json"),
    ("./.mcp.json", ".mcp.json"),
    (".\\.github\\workflows\\ci.yml", ".github/workflows/ci.yml"),
    ("/src/app.py", "src/app.py"),
    ("././a.py", "a.py"),
    ("src/.env", "src/.env"),
    (".", ""),
    ("", ""),
    (None, ""),
])
def test_normalize_path_keeps_dot_names(raw, expected):
    assert normalize_path(raw) == expected


def test_fingerprints_are_unchanged_by_the_fix():
    # The hash input is the frozen pre-2.12 form, so existing baselines,
    # suppressions and registry history keep matching.
    legacy = sha256_text("\n".join(["CC_X", "claude/settings.json", "3",
                                    normalize_evidence("e")]))
    assert compute_fingerprint("cc_x", ".claude/settings.json", 3, "e") == legacy
    assert compute_fingerprint("cc_x", "claude/settings.json", 3, "e") == legacy
    assert fingerprint_path(".claude/settings.json") == "claude/settings.json"


@pytest.mark.parametrize("pattern", [".claude/**", "claude/**", ".claude/*.json"])
def test_old_and_new_globs_both_match(pattern):
    assert path_glob_matches(".claude/settings.json", pattern)
    assert not path_glob_matches("src/settings.json", pattern)


def _scan(tmp_path, extra_files=None, *flags):
    repo = tmp_path / "repo"
    files = {".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash"]}}),
             **(extra_files or {})}
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    report_path, manifest_path = tmp_path / "r.json", tmp_path / "m.json"
    rc = main(["scan", str(repo), "--json", str(report_path), "--manifest",
               str(manifest_path), "--no-registry", *flags])
    return (rc, json.loads(report_path.read_text(encoding="utf-8")),
            json.loads(manifest_path.read_text(encoding="utf-8")))


def test_scan_reports_dot_directory_paths(tmp_path):
    _, report, manifest = _scan(tmp_path)
    files = {f["file"] for f in report["findings"] if "settings" in str(f["file"])}
    assert files == {".claude/settings.json"}
    paths = {f["location"]["path"] for f in manifest["findings"]
             if "settings" in f["location"]["path"]}
    assert paths == {".claude/settings.json"}
    locations = {loc["path"] for a in manifest["agents"] for loc in a["source_locations"]}
    assert ".claude/settings.json" in locations
    assert "claude/settings.json" not in locations


@pytest.mark.parametrize("pattern", ["claude/**", ".claude/**"])
def test_existing_suppression_globs_still_apply(tmp_path, pattern):
    _, report, _ = _scan(tmp_path)
    rule = next(f["rule_id"] for f in report["findings"]
                if f["file"] == ".claude/settings.json")
    suppressions = (f"suppressions:\n  - rule_id: {rule}\n    path: \"{pattern}\"\n"
                    "    reason: accepted\n    owner: team\n    created: 2026-10-01\n")
    _, report, _ = _scan(tmp_path, {".safeai/suppressions.yml": suppressions})
    statuses = {f["status"] for f in report["findings"]
                if f["rule_id"] == rule and f["file"] == ".claude/settings.json"}
    assert statuses == {"suppressed"}
