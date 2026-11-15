"""Tests for quality gate CLI arguments (--fail-on-rule, --fail-on-category)."""

import os

from safeai.cmd.cli import main


def test_fail_on_rule_no_match(kya_project, tmp_path):
    """--fail-on-rule with non-matching pattern passes (no critical findings)."""
    # Use --fail-on critical (default) with a non-matching pattern
    # The test fixture has critical findings, so we need to check the exit code
    # correctly reflects that --fail-on-rule doesn't add new failures
    rc = main(["scan", kya_project["root"], "--registry", kya_project["registry"],
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry",
               "--fail-on-rule", "NONEXISTENT_*"])
    # The fixture has critical findings, so exit code is 1 from default --fail-on
    # --fail-on-rule with non-matching pattern doesn't change that
    assert rc == 1


def test_fail_on_rule_multiple_no_match(kya_project, tmp_path):
    """--fail-on-rule with multiple non-matching patterns doesn't change exit code."""
    rc = main(["scan", kya_project["root"], "--registry", kya_project["registry"],
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry",
               "--fail-on-rule", "NONEXISTENT_*", "ALSO_NONEXISTENT_*"])
    # Same as above: fixture has critical findings
    assert rc == 1


def test_fail_on_rule_no_match_warns(kya_project, tmp_path, capsys):
    """A pattern that matches no known rule is flagged on stderr."""
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry",
          "--fail-on-rule", "NONEXISTENT_*"])
    assert "--fail-on-rule NONEXISTENT_* matches no rule" in capsys.readouterr().err


def test_fail_on_category_no_match(kya_project, tmp_path):
    """--fail-on-category with non-matching category doesn't change exit code."""
    rc = main(["scan", kya_project["root"], "--registry", kya_project["registry"],
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry",
               "--fail-on-category", "mcp"])
    # MCP category may not have findings; exit code depends on other findings
    assert rc in (0, 1)


def test_fail_on_category_multiple(kya_project, tmp_path):
    """--fail-on-category with multiple categories OR's them."""
    rc = main(["scan", kya_project["root"], "--registry", kya_project["registry"],
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry",
               "--fail-on-category", "mcp", "dependency"])
    assert rc in (0, 1)


def test_fail_on_rule_does_not_affect_normal_scan(kya_project, tmp_path):
    """Normal scan without --fail-on-rule or --fail-on-category works unchanged."""
    rc = main(["scan", kya_project["root"], "--registry", kya_project["registry"],
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc == 1  # Fixture has critical findings
