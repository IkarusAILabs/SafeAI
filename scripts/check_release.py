"""Pre-release checklist verification."""
import os
import subprocess
import sys

import yaml


def detect_tag_version():
    """Return the release version for this run, without a leading ``v``.

    Precedence: explicit argv ``python scripts/check_release.py <version>``,
    then the ``GITHUB_REF_NAME`` environment variable on tag pushes, then
    ``git describe``. Returns None when nothing determines a version.
    """
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip().lstrip("v")
    ref = os.environ.get("GITHUB_REF_NAME", "").strip()
    if ref.startswith("v") and len(ref) > 1:
        return ref[1:]
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        tag = out.stdout.strip()
        if tag.startswith("v") and len(tag) > 1:
            return tag[1:]
    except Exception:
        pass
    return None


def main():
    tag_version = detect_tag_version()
    if not tag_version:
        print("FAIL: cannot determine release version "
              "(pass it explicitly or run on a v* tag)")
        return 1

    if tag_version == "2":
        # Floating major-version tag: no single version to match and no
        # CHANGELOG section; still run the structural checks below.
        print("Floating tag v2 — skipping version-match and CHANGELOG checks")
    else:
        # Check version matches tag
        from safeai.version import SAFEAI_VERSION
        if tag_version != SAFEAI_VERSION:
            print(f"FAIL: Tag version ({tag_version}) != code version ({SAFEAI_VERSION})")
            return 1
        print(f"Version match: {SAFEAI_VERSION}")

        # Check CHANGELOG
        with open("CHANGELOG.md") as f:
            changelog = f.read()
        if f"[{tag_version}]" not in changelog:
            print(f"CHANGELOG.md has no entry for v{tag_version}")
            return 1
        print(f"CHANGELOG entry found for v{tag_version}")

    # Check all rules have required fields
    with open("safeai/rules/base_rules.yaml") as f:
        rules = yaml.safe_load(f)
    required = {"id", "severity", "description"}
    bad = [r for r in rules if not required.issubset(r.keys())]
    if bad:
        for r in bad:
            print(f"Missing fields in rule: {r.get('id', 'UNKNOWN')}")
        return 1
    print(f"All {len(rules)} rules have required fields")

    # Check Action I/O contract
    with open("action.yml") as f:
        action = yaml.safe_load(f)
    expected_inputs = {
        "path", "version", "fail-on", "sarif", "rules", "baseline",
        "fail-on-new", "fail-on-escalation", "no-registry", "extra-args",
        "scorecard", "scorecard-json", "scorecard-summary", "scorecard-fail-under",
    }
    expected_outputs = {"sarif-path", "scorecard-path", "safeai-version"}
    missing_i = expected_inputs - set(action["inputs"].keys())
    missing_o = expected_outputs - set(action["outputs"].keys())
    if missing_i:
        print(f"Missing Action inputs: {missing_i}")
        return 1
    if missing_o:
        print(f"Missing Action outputs: {missing_o}")
        return 1
    print("Action I/O contract stable")

    print("\nAll pre-release checks passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
