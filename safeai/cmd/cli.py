"""Command-line interface for SafeAI.

Usage::

    safeai scan <directory> [--sarif <path>] [--json <path>] [--html <path>]
                            [--manifest <path>] [--baseline <path>]
                            [--policy <path>] [--suppressions <path>]
                            [--registry <path> | --no-registry] [--strict-registry]
                            [--pr-comment <path>] [--pr-comment-stdout]
                            [--fail-on <level>] [--fail-on-new]
                            [--fail-on-escalation <level>]
                            [--fail-on-rule <pattern>] [--fail-on-category <name>]
    safeai init [--profile <name>] [--force]
    safeai registry list|show|history|diff|export|import|components ...
    safeai manifest validate|verify <file>
    safeai rules check [dir]

KYA (Know Your Agent) behavior:
  * Every scan produces normalized findings (stable fingerprints,
    confidence labels, provenance, remediation).
  * Scans persist to a single shared SQLite registry by default —
    ``SAFEAI_REGISTRY`` env var or ``~/.safeai/registry.db`` — so agents
    from every scanned project accumulate in one place and can be listed
    with ``safeai registry list`` from anywhere. ``--registry PATH``
    overrides the location; CI jobs persist only when a registry is
    configured explicitly.
  * ``--pr-comment`` writes a reviewer-facing Markdown summary of
    capability escalations to a file. SafeAI never posts it anywhere;
    publishing is the CI workflow's job.
  * All outputs remain local: no network calls, no uploads — except the
    explicitly enabled ``--pr-comment-post`` integration, which makes one
    GitHub API request and announces itself on stderr.
"""

import argparse
import os
import sys

from safeai.cmd.postprocess import ScanPostProcessor

_POLICY_PROFILES = ("developer", "strict-ci", "mcp", "rag", "production-agent")


def _build_parser():
    parser = argparse.ArgumentParser(prog="safeai")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Statically scan a directory for AI agent capabilities and risks")
    scan.add_argument("directory")
    scan.add_argument("--sarif", default="report.sarif")
    scan.add_argument("--json", dest="json_path")
    scan.add_argument("--html", dest="html_path")
    scan.add_argument("--architecture", action="store_true", default=True, help="Include architecture diagram in HTML report")
    scan.add_argument("--no-architecture", action="store_false", dest="architecture", help="Omit architecture diagram from HTML report")
    scan.add_argument("--architecture-mermaid", action="store_true", default=False, help="Include interactive Mermaid diagram (requires internet)")
    scan.add_argument("--rules")
    scan.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium"])
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--baseline",
                      help="Prior safeai-manifest.json (or legacy JSON report) for new/existing comparison")
    scan.add_argument("--fail-on-new", action="store_true",
                      help="With --baseline: fail only on NEW or REGRESSED findings at/above --fail-on severity")
    scan.add_argument("--manifest", dest="manifest_path",
                      help="Write the canonical KYA manifest (safeai-manifest.json) to this path")
    scan.add_argument("--digest-file", dest="digest_file",
                      help="With --manifest: also write '<canonical-sha256>  <manifest-basename>' "
                           "to PATH (the digest `safeai manifest verify` reports; not a raw file hash)")
    scan.add_argument("--registry",
                      help="Registry database path (default: shared registry — "
                           "SAFEAI_REGISTRY env var or ~/.safeai/registry.db)")
    scan.add_argument("--no-registry", action="store_true",
                      help="Do not create or update the local KYA registry")
    scan.add_argument("--strict-registry", action="store_true",
                      help="Fail the scan if registry persistence fails")
    scan.add_argument("--pr-comment", dest="pr_comment_path",
                      help="Write a reviewer-facing Markdown summary of capability "
                           "escalations to PATH (never posted anywhere)")
    scan.add_argument("--pr-comment-stdout", action="store_true",
                      help="Print the PR comment Markdown to stdout")
    scan.add_argument("--pr-comment-post", action="store_true",
                      help="Post or update the PR comment on GitHub (requires GITHUB_TOKEN "
                           "and CI context with PR number and repository). "
                           "NETWORK: the one explicitly enabled integration that "
                           "makes a GitHub API request; announces itself on stderr.")
    scan.add_argument("--fail-on-escalation", choices=["critical", "high", "medium"],
                      help="Fail the scan when a capability escalation at or above "
                           "this severity is detected (requires --baseline)")
    scan.add_argument("--fail-on-authority-change", choices=["material", "high-risk"],
                      help="With --baseline: fail on tool authority changes at or above "
                           "this class (material includes high-risk). Inferred-only "
                           "changes never fail this gate; UNKNOWN never fails.")
    scan.add_argument("--policy",
                      help="Policy-as-code YAML file (default: <scan-root>/.safeai/policy.yml if present)")
    scan.add_argument("--policy-profile",
                      choices=["developer", "strict-ci", "mcp", "rag", "production-agent"],
                      help="Named policy profile to load (extends --policy, does not replace it)")
    scan.add_argument("--unknown-authority", choices=["pass", "review", "block"],
                      help="How to govern unattributable (UNKNOWN) tool authority when the "
                           "policy file sets no authority.unknown: pass (default, unchanged), "
                           "review (require human review), or block. Explicit policy file "
                           "setting always wins.")
    scan.add_argument("--suppressions",
                      help="Suppressions YAML file (default: <scan-root>/.safeai/suppressions.yml if present)")
    scan.add_argument("--strict-suppressions", action="store_true",
                      help="Fail the scan (exit 1) when expired or moved suppressions are detected")
    scan.add_argument("--exceptions",
                      help="Policy exception records YAML file "
                           "(default: <scan-root>/.safeai/exceptions.yml if present)")
    scan.add_argument("--strict-exceptions", action="store_true",
                      help="Fail the scan (exit 1) when expired or stale exceptions are detected "
                           "(default: warn only)")
    # --- SafeAI Security Scorecard ---
    scan.add_argument("--scorecard", dest="scorecard_path",
                      help="Write the SafeAI Security Scorecard Markdown report to PATH")
    scan.add_argument("--scorecard-json", dest="scorecard_json_path",
                      help="Write the SafeAI Security Scorecard JSON report to PATH")
    scan.add_argument("--scorecard-md", dest="scorecard_md_path",
                      help="Write the SafeAI Security Scorecard Markdown report to PATH")
    scan.add_argument("--scorecard-summary", dest="scorecard_summary_path",
                      help="Append the SafeAI Security Scorecard to the GitHub Actions "
                           "job summary at PATH (or $GITHUB_STEP_SUMMARY when no PATH "
                           "is given); outside GitHub Actions this is a no-op")
    scan.add_argument("--scorecard-fail-under", dest="scorecard_fail_under",
                      type=float, metavar="SCORE",
                      help="Fail the scan when the overall score is below SCORE "
                           "(0-10). This is an additional score-based gate and does "
                           "not change --fail-on/--fail-on-new/--fail-on-escalation.")
    scan.add_argument("--fail-on-rule", dest="fail_on_rule", nargs="+", metavar="PATTERN",
                      help="Fail when any finding matches a rule ID pattern "
                           "(glob-style: GOV_*, MCP_*, ESC_*, etc.). Multiple "
                           "patterns are OR'd. Example: --fail-on-rule GOV_* MCP_*")
    scan.add_argument("--fail-on-category", dest="fail_on_category", nargs="+", metavar="NAME",
                      choices=["security", "governance", "capability", "dataflow",
                               "prompt", "data_leakage", "mcp", "dependency"],
                      help="Fail when any finding belongs to this category. "
                           "Multiple categories are OR'd. "
                           "Example: --fail-on-category security governance")
    scan.add_argument("--mcp-ide-scopes", action="store_true",
                      help="Discover MCP configs in IDE scopes (.cursor/, .windsurf/, "
                           ".vscode/) in addition to the scanned repo")

    init = sub.add_parser("init", help="Scaffold a .safeai/ configuration directory")
    init.add_argument("--force", action="store_true",
                      help="Overwrite existing .safeai/ files without prompting")
    init.add_argument("--profile",
                      choices=_POLICY_PROFILES,
                      default="developer",
                      help="Policy profile to scaffold (default: developer)")

    registry = sub.add_parser("registry", help="Inspect the local KYA registry")
    reg_sub = registry.add_subparsers(dest="registry_command")

    def _common(p):
        p.add_argument("--registry", help="Registry database path")
        p.add_argument("--project-dir", dest="project_dir",
                       help="Inspect the per-project registry at DIR/.safeai/registry.db "
                            "instead of the shared registry")
        p.add_argument("--format", choices=["table", "json", "html"], default="table")

    reg_list = reg_sub.add_parser("list", help="List known agents/workflows")
    _common(reg_list)
    reg_list.add_argument("--project", help="Filter by project ID")

    reg_show = reg_sub.add_parser("show", help="Show the latest KYA record for an agent")
    _common(reg_show)
    reg_show.add_argument("agent_id")
    reg_show.add_argument("--scan", help="Show record from a specific scan ID")

    reg_hist = reg_sub.add_parser("history", help="List scan history for an agent")
    _common(reg_hist)
    reg_hist.add_argument("agent_id")

    reg_comp = reg_sub.add_parser("components", help="List tracked components and their consumers")
    _common(reg_comp)
    reg_comp.add_argument("--type", dest="component_type",
                          choices=["skill", "prompt", "tool", "model_config", "workflow", "mcp"],
                          help="Filter by component type")
    reg_comp.add_argument("--agents", action="store_true",
                          help="Show which agents reference each component")
    reg_comp.add_argument("--lockfile", metavar="PATH",
                          help="Write a pinned component lockfile and exit")
    reg_comp.add_argument("--check-lockfile", metavar="PATH", dest="check_lockfile",
                          help="Exit 1 when components drifted from the lockfile")
    reg_comp.add_argument("--project", help="Scope to a single project ID (lockfile only)")

    reg_diff = reg_sub.add_parser("diff", help="Compare two snapshots of an agent")
    _common(reg_diff)
    reg_diff.add_argument("agent_id")
    reg_diff.add_argument("--from", dest="from_ref", default="previous",
                          help="Scan ID, 'previous', or 'latest' (default: previous)")
    reg_diff.add_argument("--to", dest="to_ref", default="latest",
                          help="Scan ID or 'latest' (default: latest)")

    reg_export = reg_sub.add_parser("export", help="Export a KYA inventory document")
    _common(reg_export)
    reg_export.add_argument("--output", required=True, help="Output file path")
    reg_export.add_argument("--project", help="Export a single project ID")
    reg_export.add_argument("--include-history", action="store_true")
    reg_export.add_argument("--include-suppressed", action="store_true")

    reg_import = reg_sub.add_parser("import", help="Import a portable KYA inventory document")
    _common(reg_import)
    reg_import.add_argument("file", help="Portable inventory JSON file")
    reg_import.add_argument("--dry-run", action="store_true",
                            help="Preview rows that would be imported without writing")
    reg_import.add_argument("--force", action="store_true",
                            help="Overwrite existing agent metadata with imported values")
    reg_import.add_argument("--require-integrity", action="store_true",
                            help="Reject inventories whose integrity digest is "
                                 "missing or invalid (default: accept, for "
                                 "backward compatibility)")

    reg_meta = reg_sub.add_parser("metadata", help="View or set agent metadata (owner, environment)")
    _common(reg_meta)
    reg_meta_sub = reg_meta.add_subparsers(dest="metadata_command")
    meta_set = reg_meta_sub.add_parser("set", help="Set metadata for an agent")
    meta_set.add_argument("agent_id")
    meta_set.add_argument("--owner", help="Business or technical owner")
    meta_set.add_argument("--environment", help="Deployment environment (e.g. production, staging)")
    meta_set.add_argument("--purpose", help="Intended purpose of the agent")
    meta_set.add_argument("--lifecycle", dest="lifecycle_status",
                          choices=["active", "staging", "retired", "deprecated"],
                          help="Lifecycle status")
    meta_get = reg_meta_sub.add_parser("get", help="Show metadata for an agent")
    meta_get.add_argument("agent_id")

    sub.add_parser("welcome", help="Guided first-run experience for new users")

    manifest = sub.add_parser("manifest", help="Validate or verify a KYA manifest (offline)")
    manifest_sub = manifest.add_subparsers(dest="manifest_command")
    man_validate = manifest_sub.add_parser("validate", help="Validate a manifest against Contract v1")
    man_validate.add_argument("file", help="Path to safeai-manifest.json")
    man_verify = manifest_sub.add_parser("verify", help="Verify a manifest integrity digest (offline)")
    man_verify.add_argument("file", help="Path to safeai-manifest.json")

    telemetry = sub.add_parser("telemetry", help="Manage opt-in usage telemetry")
    telemetry.add_argument(
        "telemetry_command",
        choices=["status", "on", "off"],
        help="Telemetry subcommand: status, on, or off",
    )

    rules = sub.add_parser("rules", help="Validate a community rule pack (offline)")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rules_check = rules_sub.add_parser("check", help="Validate rules and run pack fixtures")
    rules_check.add_argument("directory", nargs="?", default=".safeai/rules",
                             help="Rule pack directory (default: .safeai/rules)")

    benchmark = sub.add_parser(
        "benchmark",
        help="Run the offline authority-evidence validation corpus (offline)")
    benchmark.add_argument("--corpus", default=None,
                           help="Corpus root (default: tests/benchmarks/authority)")
    benchmark.add_argument("--case", default=None,
                           help="Run one case or category only (e.g. terraform/linked_match)")
    benchmark.add_argument("--workdir", default=None,
                           help="Scratch directory for scan outputs (default: temp dir)")
    benchmark.add_argument("--no-determinism", action="store_true",
                           help="Skip repeat + order-shuffle determinism checks")
    benchmark.add_argument("--json", dest="json_path", default=None,
                           help="Write the machine-readable evaluation to PATH")
    benchmark.add_argument("--markdown", dest="markdown_path", default=None,
                           help="Write the reviewer-facing brief to PATH")

    return parser


def _run_scan_command(args, parser):
    """Run the post-scan pipeline for ``safeai scan``.

    The pipeline itself lives in :class:`safeai.cmd.postprocess.ScanPostProcessor`
    (normalize, suppress, baseline, policy, identity, manifest, registry,
    outputs, exit code); this keeps the CLI a thin parsing shell.
    """
    return ScanPostProcessor(args, parser).run()


def _configure_stdout():
    """Emit UTF-8 on stdout so output survives redirection/pipes on Windows.

    Without this, ``sys.stdout`` uses the locale encoding (e.g. cp1252)
    and HTML/JSON output containing non-ASCII text is mangled when
    redirected to a file or piped. Safe no-op under test capture, where
    stdout has no ``reconfigure``.
    """
    try:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _run_welcome():
    """Guided first-run experience for new SafeAI users.

    Displays recommended rules, suggests a first scan command, and links
    to documentation.
    """
    print("=" * 60)
    print("  SafeAI — Know Your Agent")
    print("=" * 60)
    print()
    print("Welcome to SafeAI! Here is a quick-start guide.")
    print()

    print("1. RECOMMENDED RULES")
    print("-" * 40)
    print("  SafeAI ships with built-in rules covering OWASP LLM Top 10,")
    print("  agent lifecycle, prompt injection, data leakage, and more.")
    print("  To use custom rules, create a rules directory:")
    print()
    print("    mkdir -p .safeai/rules")
    print("    cp <safeai-repo>/safeai/rules/base_rules.yaml .safeai/rules/")
    print()

    print("2. YOUR FIRST SCAN")
    print("-" * 40)
    print("  Scan the current directory:")
    print()
    print("    safeai scan .")
    print()
    print("  Scan with all outputs:")
    print()
    print("    safeai scan . --sarif report.sarif --json report.json --html report.html")
    print()
    print("  Scan with a named policy profile:")
    print()
    print("    safeai scan . --policy-profile strict-ci")
    print()

    print("3. UNDERSTANDING RESULTS")
    print("-" * 40)
    print("  Findings are classified by severity (critical > high > medium > low)")
    print("  and tagged with OWASP LLM references (LLM01, LLM02, etc.).")
    print()
    print("  Use --fail-on <level> to enforce quality gates in CI:")
    print()
    print("    safeai scan . --fail-on high    # fail on critical + high")
    print("    safeai scan . --fail-on medium  # fail on critical + high + medium")
    print()

    print("4. REGISTRY (KYA)")
    print("-" * 40)
    print("  Every scan persists to a local SQLite registry by default.")
    print("  Inspect your agents over time:")
    print()
    print("    safeai registry list")
    print("    safeai registry show <agent-id>")
    print("    safeai registry history <agent-id>")
    print()

    print("5. DOCUMENTATION")
    print("-" * 40)
    print("  README:            https://github.com/ikaruscareer/SafeAI#readme")
    print("  User Guide:        https://github.com/ikaruscareer/SafeAI/blob/main/USER_GUIDE.md")
    print("  Reporting Guide:   https://github.com/ikaruscareer/SafeAI/blob/main/REPORTING_GUIDE.md")
    print("  Framework Support: https://github.com/ikaruscareer/SafeAI/blob/main/FRAMEWORK_SUPPORT.md")
    print("  Roadmap:           https://github.com/ikaruscareer/SafeAI/blob/main/ROADMAP.md")
    print()
    print("=" * 60)
    print("  Run 'safeai scan .' to get started!")
    print("=" * 60)
    return 0


def _run_init(args):
    """Scaffold a ``.safeai/`` configuration directory.

    Creates:
      * ``.safeai/config.yml`` — project identity and defaults
      * ``.safeai/policy.yml`` — selected policy profile
      * ``.safeai/suppressions.yml`` — empty suppressions file with format hint
      * ``.safeai/rules/`` — custom rules directory with example rule,
        plus a rule-pack authoring scaffold (``pack_example.yaml``,
        ``fixtures/`` safe/risky examples, ``tests/test_pack.py``)

    Idempotent by default: existing files are skipped. ``--force`` overwrites.
    """
    import yaml

    from safeai.kya.identity import load_local_config, save_local_config

    root = os.getcwd()
    safeai_dir = os.path.join(root, ".safeai")
    force = getattr(args, "force", False)
    profile_name = getattr(args, "profile", "developer") or "developer"

    created = []
    skipped = []
    overwritten = []

    os.makedirs(safeai_dir, exist_ok=True)

    # --- .safeai/config.yml ---
    config_path = os.path.join(safeai_dir, "config.yml")
    existing_config = load_local_config(root)
    if os.path.exists(config_path) and not force:
        skipped.append("config.yml")
    else:
        agent_name = os.path.basename(root) or "my-agent"
        config = {
            "project_id": existing_config.get("project_id"),
            "local_project_uuid": existing_config.get("local_project_uuid"),
            "agent_name": agent_name,
            "environment": "development",
            "lifecycle_status": "active",
        }
        save_local_config(root, config)
        if os.path.exists(config_path) and force:
            overwritten.append("config.yml")
        else:
            created.append("config.yml")

    # --- .safeai/policy.yml ---
    policy_path = os.path.join(safeai_dir, "policy.yml")
    if os.path.exists(policy_path) and not force:
        skipped.append("policy.yml")
    else:
        from safeai.kya.policy import load_profile

        profile = load_profile(profile_name)
        if profile is not None:
            with open(policy_path, "w", encoding="utf-8") as fh:
                yaml.safe_dump(profile, fh, sort_keys=True, default_flow_style=False)
            if os.path.exists(policy_path) and force:
                overwritten.append("policy.yml")
            else:
                created.append("policy.yml")

    # --- .safeai/suppressions.yml ---
    suppressions_path = os.path.join(safeai_dir, "suppressions.yml")
    if os.path.exists(suppressions_path) and not force:
        skipped.append("suppressions.yml")
    else:
        suppressions_content = (
            "# SafeAI suppressions — see USER_GUIDE.md for format.\n"
            "# Add entries here to suppress known findings:\n"
            "#\n"
            "# - rule_id: PROMPT_INJECTION\n"
            "#   file: tests/test_data.py\n"
            "#   reason: Test fixture, not deployed code\n"
            "#   owner: your-name\n"
            "suppressions: []\n"
        )
        with open(suppressions_path, "w", encoding="utf-8") as fh:
            fh.write(suppressions_content)
        if os.path.exists(suppressions_path) and force:
            overwritten.append("suppressions.yml")
        else:
            created.append("suppressions.yml")

    # --- .safeai/rules/ directory with example rule ---
    rules_dir = os.path.join(safeai_dir, "rules")
    rules_yaml = os.path.join(rules_dir, "example_rules.yaml")
    if os.path.exists(rules_yaml) and not force:
        skipped.append("rules/example_rules.yaml")
    else:
        os.makedirs(rules_dir, exist_ok=True)
        example_rule = (
            "# Custom SafeAI rules — see DEVELOPER_GUIDE.md for format.\n"
            "# Add your own rules here. They override built-in rules with the same ID.\n"
            "#\n"
            "# Example rule:\n"
            "# - id: CUSTOM_NO_HARDCODED_SECRETS\n"
            "#   description: Detect hardcoded secret values in agent configs\n"
            "#   severity: high\n"
            "#   owasp_llm: LLM06\n"
            "[]\n"
        )
        with open(rules_yaml, "w", encoding="utf-8") as fh:
            fh.write(example_rule)
        if os.path.exists(rules_yaml) and force:
            overwritten.append("rules/example_rules.yaml")
        else:
            created.append("rules/example_rules.yaml")

    # --- Rule-pack authoring scaffold (CE 2.3): example override rule,
    # fixtures proving it takes effect, and a pack test template ---
    pack_yaml = os.path.join(rules_dir, "pack_example.yaml")
    if os.path.exists(pack_yaml) and not force:
        skipped.append("rules/pack_example.yaml")
    else:
        os.makedirs(rules_dir, exist_ok=True)
        pack_rule = (
            "# Example rule pack: override a built-in rule's severity.\n"
            "# Custom rules take effect as overrides of built-in rule IDs\n"
            "# (see docs/guides/COMMUNITY_PACKS.md). Verify with:\n"
            "#   safeai rules check .safeai/rules\n"
            "- id: CAP_subprocess_shell\n"
            "  description: subprocess invoked with shell=True (pack example override)\n"
            "  severity: high\n"
            "  owasp_llm: LLM01\n"
        )
        with open(pack_yaml, "w", encoding="utf-8") as fh:
            fh.write(pack_rule)
        if os.path.exists(pack_yaml) and force:
            overwritten.append("rules/pack_example.yaml")
        else:
            created.append("rules/pack_example.yaml")

    fixtures_dir = os.path.join(rules_dir, "fixtures")
    pack_fixtures = {
        "safe_example.py": (
            '"""Safe fixture: no shell=True, so the pack rule must stay silent."""\n'
            "\n"
            "import subprocess\n"
            "\n"
            "\n"
            "def list_dir(path):\n"
            '    return subprocess.run(["ls", path], capture_output=True)\n'
        ),
        "risky_example.py": (
            '"""Risky fixture: shell=True must fire CAP_subprocess_shell at pack severity."""\n'
            "\n"
            "import subprocess\n"
            "\n"
            "\n"
            "def run_query(user_input):\n"
            "    return subprocess.run(user_input, shell=True)\n"
        ),
    }
    for filename, content in pack_fixtures.items():
        fixture_path = os.path.join(fixtures_dir, filename)
        if os.path.exists(fixture_path) and not force:
            skipped.append(f"rules/fixtures/{filename}")
            continue
        os.makedirs(fixtures_dir, exist_ok=True)
        with open(fixture_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if os.path.exists(fixture_path) and force:
            overwritten.append(f"rules/fixtures/{filename}")
        else:
            created.append(f"rules/fixtures/{filename}")

    pack_test_path = os.path.join(rules_dir, "tests", "test_pack.py")
    if os.path.exists(pack_test_path) and not force:
        skipped.append("rules/tests/test_pack.py")
    else:
        os.makedirs(os.path.join(rules_dir, "tests"), exist_ok=True)
        pack_test = (
            '"""Pack expected-findings test: run with pytest from the repo root."""\n'
            "\n"
            "import os\n"
            "\n"
            "from safeai.rules.pack_test import check_pack\n"
            "\n"
            "PACK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n"
            "\n"
            "\n"
            "def test_pack_fixtures_match_rules():\n"
            "    errors, _warnings = check_pack(PACK_DIR)\n"
            "    assert errors == []\n"
        )
        with open(pack_test_path, "w", encoding="utf-8") as fh:
            fh.write(pack_test)
        if os.path.exists(pack_test_path) and force:
            overwritten.append("rules/tests/test_pack.py")
        else:
            created.append("rules/tests/test_pack.py")

    # --- Summary ---
    print("SafeAI project initialized.")
    print()
    if created:
        print("  Created:")
        for f in created:
            print(f"    .safeai/{f}")
    if overwritten:
        print("  Overwritten:")
        for f in overwritten:
            print(f"    .safeai/{f}")
    if skipped:
        print("  Skipped (already exists, use --force to overwrite):")
        for f in skipped:
            print(f"    .safeai/{f}")
    print()
    print("Next steps:")
    print(f"  1. Review .safeai/config.yml (agent name: {os.path.basename(root) or 'my-agent'})")
    print(f"  2. Review .safeai/policy.yml (profile: {profile_name})")
    print("  3. Add custom rules to .safeai/rules/")
    print("  4. Run: safeai scan .")
    print("  5. Check your rule pack: safeai rules check .safeai/rules")
    return 0


def _run_telemetry(args):
    """Handle `safeai telemetry on/off/status` commands."""
    from safeai.telemetry.config import (
        get_status_text,
        set_telemetry_enabled,
    )

    cmd = getattr(args, "telemetry_command", None)

    if cmd == "status":
        print(get_status_text())
        return 0

    if cmd == "on":
        set_telemetry_enabled(True)
        print("Telemetry enabled.")
        print("Auto-disabled in CI unless SAFEAI_TELEMETRY_IN_CI=1 is also set.")
        print("See PRIVACY.md for the full data contract.")
        return 0

    if cmd == "off":
        set_telemetry_enabled(False)
        print("Telemetry disabled.")
        print("No data will be sent.")
        return 0

    print("Usage: safeai telemetry {status|on|off}")
    return 1


def _run_rules_check(args):
    """Handle ``safeai rules check [dir]``: validate pack + fixtures."""
    import os

    from safeai.rules.pack_test import check_pack

    pack_dir = os.path.abspath(args.directory)
    errors, warnings = check_pack(pack_dir)
    for warning in warnings:
        print(f"warning: {warning}")
    if errors:
        print(f"Rule pack check failed ({len(errors)} error(s)) in {pack_dir}:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"Rule pack OK: {pack_dir}")
    return 0


def _run_benchmark(args):
    """Handle ``safeai benchmark``: run the authority corpus (offline).

    The benchmark measures; it never gates. Exit 0 when every case
    holds, 1 on truth mismatch, 2 on harness/usage error.
    """
    import tempfile

    from safeai.benchmark import report as report_mod
    from safeai.benchmark import runner as runner_mod

    corpus = args.corpus or runner_mod.default_corpus()
    workdir = args.workdir or tempfile.mkdtemp(prefix="safeai-bench-")
    try:
        aggregate = runner_mod.run_corpus(
            corpus, workdir, case_filter=args.case,
            determinism=not args.no_determinism)
    except runner_mod.BenchmarkError as exc:
        print(f"authority benchmark harness error: {exc}")
        return 2
    if args.json_path:
        report_mod.write_json(aggregate, args.json_path)
    if args.markdown_path:
        report_mod.write_markdown(aggregate, args.markdown_path)
    failed = [r["id"] for r in aggregate.get("cases", [])
              if not r.get("passed")]
    if failed:
        print(f"authority benchmark: {len(failed)} case(s) mismatched: "
              f"{', '.join(failed)}")
        return 1
    print(f"authority benchmark: all "
          f"{len(aggregate.get('cases', []))} cases hold")
    return 0


def main(argv=None):
    _configure_stdout()
    parser = _build_parser()
    args = parser.parse_args(argv)

    exit_code = 0

    if args.command == "scan":
        exit_code = _run_scan_command(args, parser)
    elif args.command == "init":
        exit_code = _run_init(args)
    elif args.command == "registry":
        if not getattr(args, "registry_command", None):
            parser.error(
                "registry requires a subcommand: "
                "list|show|history|components|diff|export|import|metadata",
            )
        from safeai.cmd.registry_cli import run_registry_command
        exit_code = run_registry_command(args)
    elif args.command == "welcome":
        exit_code = _run_welcome()
    elif args.command == "manifest":
        if not getattr(args, "manifest_command", None):
            parser.error("manifest requires a subcommand: validate|verify")
        from safeai.cmd.manifest_cli import run_manifest_command
        exit_code = run_manifest_command(args)
    elif args.command == "telemetry":
        exit_code = _run_telemetry(args)
    elif args.command == "rules":
        if getattr(args, "rules_command", None) != "check":
            parser.error("rules requires a subcommand: check")
        exit_code = _run_rules_check(args)
    elif args.command == "benchmark":
        exit_code = _run_benchmark(args)
    else:
        parser.print_help()

    # Fire telemetry after command execution, before exit
    if args.command and args.command != "telemetry":
        from safeai.telemetry.client import send_telemetry
        send_telemetry(args.command)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
