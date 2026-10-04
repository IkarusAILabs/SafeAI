"""Post-scan processing pipeline.

Extracted from ``safeai.cmd.cli._run_scan_command`` so the scan command's
stages are individually testable and the CLI stays a thin argument-parsing
shell. :class:`ScanPostProcessor` runs normalize -> suppress -> baseline ->
policy -> identity -> manifest -> registry -> outputs -> exit code.
"""

import json
import logging
import os
import sys

from safeai.engine.scan import run_scan


def _safeai_version():
    # The PyPI distribution is named ``SafeAI-Static-Analyzer`` while the
    # import package is ``safeai``; try both so the version resolves whether
    # the project was installed from PyPI, from an editable checkout, or is
    # being run straight from the source tree.
    for dist_name in ("SafeAI-Static-Analyzer", "safeai"):
        try:
            from importlib.metadata import version
            return version(dist_name)
        except Exception:
            continue
    import safeai
    return getattr(safeai, "__version__", "unknown")


def _ruleset_version(rules):
    from safeai.kya.util import sha256_text
    canonical = json.dumps(rules or [], sort_keys=True, default=str)
    return f"sha256:{sha256_text(canonical)[:16]}"


#: Exception evaluation states that --strict-exceptions refuses.
GATED_EXCEPTION_STATES = ("expired", "stale", "scope-mismatch", "invalid")


def gated_exception_evaluations(evaluations):
    """Exception evaluations that ``--strict-exceptions`` must refuse.

    State is not sufficient on its own. An entry whose declared repository
    scope could not be checked stays ``active`` and suppresses, so it reaches
    no gate by state alone; an operator asking for strict exceptions is asking
    not to be suppressed by something unverified. ``scope_verified is False``
    is therefore gated alongside the non-active states (#196).
    """
    return [
        evaluation for evaluation in evaluations
        if evaluation["state"] in GATED_EXCEPTION_STATES
        or evaluation.get("scope_verified") is False
    ]


class ScanPostProcessor:
    """Runs the post-scan pipeline for ``safeai scan`` and returns the exit code.

    Stages:
      1. :meth:`_run_scan`           — invoke the engine, capture timings
      2. :meth:`_normalize`          — fingerprints, confidence, provenance
      3. :meth:`_apply_suppressions` — YAML suppressions (never silent)
      4. :meth:`_compare_baseline`   — KYA fingerprint diff
      5. :meth:`_evaluate_policy`    — policy-as-code outcome
      6. :meth:`_resolve_identity`   — project/agent identity + agent records
      7. :meth:`_build_manifest`     — canonical KYA manifest document
      8. :meth:`_persist_registry`   — shared SQLite registry (CI-aware)
      9. :meth:`_write_outputs`      — manifest/SARIF/JSON/HTML/PR-comment
     10. :meth:`_compute_exit_code`  — fail-on thresholds + policy deny
    """

    def __init__(self, args, parser):
        self.args = args
        self.parser = parser
        self.directory = os.path.abspath(args.directory)
        self.started_at = None
        self.completed_at = None
        self.baseline_fps = None
        self.baseline_report = None
        self.report = {}
        self.policy_decision = {}
        self.project_id = None
        self.remote_fp = None
        self.git_meta = {}
        self.agents = []
        self.rules = []
        self.scan_id = None
        self.safeai_meta = {}
        self.project_meta = {}
        self.scan_meta = {}
        self.manifest = {}
        self.scorecard = None
        self.registry_status = {"state": "skipped", "path": None, "reason": None, "stats": None}

    def run(self):
        """Execute all stages in order; returns ``None`` normally or an int
        exit code for an early failure (e.g. --strict-registry)."""
        self._configure_logging()
        if getattr(self.args, "digest_file", None) and not self.args.manifest_path:
            self.parser.error("--digest-file requires --manifest")
        self._load_baseline()
        self._run_scan()
        self._normalize()
        early = self._apply_suppressions()
        if early is not None:
            return early
        self._compare_baseline()
        self._evaluate_policy()
        self._resolve_identity()
        early = self._evaluate_exceptions()
        if early is not None:
            return early
        self._build_manifest()
        early = self._persist_registry()
        if early is not None:
            return early
        from safeai.report.failure_matrix import build_failure_class_matrix
        self.report["failure_class_matrix"] = build_failure_class_matrix(
            self.report.get("findings", [])
        )
        self._write_outputs()
        return self._compute_exit_code()

    def _configure_logging(self):
        logging.basicConfig(
            level=logging.DEBUG if self.args.verbose else logging.WARNING,
            format="[%(levelname)s] %(name)s: %(message)s",
        )

    def _load_baseline(self):
        from safeai.kya import baseline as kya_baseline

        if not self.args.baseline:
            return
        try:
            self.baseline_fps, baseline_doc = kya_baseline.load_baseline(self.args.baseline)
        except (TypeError, ValueError) as exc:
            self.parser.error(str(exc))
        # A legacy JSON report supplies ``normalized_capabilities``; a KYA
        # manifest (v1.1+) supplies ``tool_surface``. Either enables a diff.
        if isinstance(baseline_doc, dict) and (
            "normalized_capabilities" in baseline_doc or "tool_surface" in baseline_doc
        ):
            self.baseline_report = baseline_doc

    def _run_scan(self):
        from safeai.kya.util import utc_now_iso

        self.started_at = utc_now_iso()
        excluded_paths = [
            self.args.manifest_path,
            self.args.json_path,
            self.args.html_path,
            self.args.sarif,
            self.args.pr_comment_path,
            self.args.scorecard_path,
            self.args.scorecard_json_path,
            self.args.scorecard_md_path,
        ]
        self.report = run_scan(
            self.args.directory,
            self.args.rules,
            baseline_report=self.baseline_report,
            excluded_paths=excluded_paths,
            mcp_ide_scopes=getattr(self.args, "mcp_ide_scopes", False),
        )
        self.completed_at = utc_now_iso()

    def _normalize(self):
        from safeai.kya.enrich import normalize_findings

        normalize_findings(self.report["findings"])

    def _apply_suppressions(self):
        from safeai.kya import suppressions as kya_suppressions

        suppressions_path = self.args.suppressions or kya_suppressions.default_suppressions_path(self.directory)
        try:
            suppression_entries, suppression_warnings = kya_suppressions.load_suppressions(suppressions_path)
        except kya_suppressions.SuppressionError as exc:
            self.parser.error(str(exc))
        suppression_summary = kya_suppressions.apply_suppressions(self.report["findings"], suppression_entries)
        for warning in suppression_warnings:
            print(f"warning: {warning}", file=sys.stderr)
        self.report["suppressions"] = {
            "path": suppressions_path if suppression_entries else None,
            **suppression_summary,
        }
        # Stale suppression guard: fingerprint-bound suppressions whose
        # fingerprint no longer matches any current finding indicate that the
        # underlying code has materially shifted.
        stale = kya_suppressions.detect_stale_suppressions(
            suppression_entries, self.report["findings"]
        )
        if stale:
            self.report["suppressions"]["stale"] = stale
            for s in stale:
                print(
                    f"warning: suppression for {s.get('fingerprint', '?')} "
                    f"(rule {s.get('rule_id', '?')}) no longer matches any "
                    f"current finding — the code has shifted",
                    file=sys.stderr,
                )
        if getattr(self.args, "strict_suppressions", False) and (suppression_warnings or stale):
            print("error: --strict-suppressions is set; expired or stale suppressions detected", file=sys.stderr)
            self.report["suppressions"]["strict_failure"] = True
            return 1
        return None

    def _compare_baseline(self):
        from safeai.kya import baseline as kya_baseline

        if self.baseline_fps is not None:
            baseline_summary = kya_baseline.compare_with_baseline(self.report["findings"], self.baseline_fps)
            self.report["baseline"] = baseline_summary

    def _evaluate_policy(self):
        from safeai.kya import policy as kya_policy

        policy_path = self.args.policy or kya_policy.default_policy_path(self.directory)
        try:
            policy_doc = kya_policy.load_policy(policy_path)
        except kya_policy.PolicyError as exc:
            self.parser.error(str(exc))
        profile_name = getattr(self.args, "policy_profile", None)
        if profile_name:
            profile = kya_policy.load_profile(profile_name)
            if profile is None:
                self.parser.error(f"Unknown policy profile: {profile_name!r}")
            policy_doc = kya_policy.merge_profile(profile, policy_doc)
        # CLI fallback for UNKNOWN authority governance: an explicit policy
        # file (or profile) setting always wins; the flag only fills the gap.
        if policy_doc is None:
            policy_doc = {"version": "1", "default_action": "warn", "policies": []}
        unknown_cli = getattr(self.args, "unknown_authority", None)
        if unknown_cli and not (policy_doc.get("authority") or {}).get("unknown"):
            policy_doc = dict(policy_doc)
            policy_doc["authority"] = {
                "unknown": {"pass": "allow", "review": "require_review",
                            "block": "deny"}[unknown_cli],
            }
        self.policy_decision = kya_policy.evaluate_policy(policy_doc, self.report)
        self.report["policy_decision"] = self.policy_decision
        self.report["policy_profile"] = profile_name
        self.policy_profile_name = profile_name

    def _evaluate_exceptions(self):
        from safeai.kya import exceptions as kya_exceptions

        exceptions_path = getattr(self.args, "exceptions", None)
        if not exceptions_path:
            exceptions_path = kya_exceptions.default_exceptions_path(self.directory)
        try:
            entries, load_warnings = kya_exceptions.load_exceptions(exceptions_path)
        except kya_exceptions.ExceptionError as exc:
            self.parser.error(str(exc))
        for warning in load_warnings:
            print(f"warning: {warning}", file=sys.stderr)
        if not entries:
            self.report["exception_evaluations"] = []
            return None
        escalations = []
        diff_tools = ((self.report.get("capability_diff") or {}).get("tools") or [])
        for tool in diff_tools:
            escalations.extend(tool.get("escalations") or [])
        policy_ids = [
            m.get("policy_id")
            for m in (self.policy_decision.get("matches") or [])
            if m.get("policy_id")
        ]
        changed_tool_keys = [
            t.get("tool_key") for t in diff_tools
            if t.get("change_class") in ("MATERIAL_CHANGE", "HIGH_RISK_CHANGE")
        ]
        identities = {
            self.project_id,
            os.path.basename(self.directory) or None,
            self.remote_fp,
        } - {None}
        evaluations = kya_exceptions.evaluate_exceptions(
            entries, self.report.get("findings"), escalations,
            policy_ids=policy_ids, changed_tool_keys=changed_tool_keys,
            project_identities=identities)
        for evaluation in evaluations:
            for warning in evaluation.get("warnings") or []:
                print(f"warning: {warning}", file=sys.stderr)
        self.report["exception_evaluations"] = evaluations
        bad = gated_exception_evaluations(evaluations)
        if getattr(self.args, "strict_exceptions", False) and bad:
            print("error: --strict-exceptions is set; expired, stale or "
                  "unverified-scope exceptions detected",
                  file=sys.stderr)
            return 1
        return None

    def _resolve_identity(self):
        from safeai.kya.enrich import build_agent_records
        from safeai.kya.identity import git_metadata, resolve_project_id

        self.project_id, self.remote_fp = resolve_project_id(self.directory)
        self.git_meta = git_metadata(self.directory)
        self.agents = build_agent_records(self.report, self.project_id)
        self.report["kya_agents"] = self.agents

    def _build_manifest(self):
        from safeai.kya.manifest import build_manifest, config_hash
        from safeai.kya.util import new_scan_id
        from safeai.rules.loader import load_rules

        self.rules, self.rule_pack_metadata = load_rules(
            self.args.rules, scan_root=self.directory
        )
        self.scan_id = new_scan_id()
        safeai_version = _safeai_version()

        # CE 2.3: per-scan plugin/pack versions. Built-ins resolve to the
        # SafeAI version; entry-point plugins carry their dist version.
        from safeai.analyzers import analyzer_records
        from safeai.frameworks import parser_records

        analyzer_versions = {
            rec["name"]: rec["version"] or safeai_version
            for rec in analyzer_records()
        }
        parser_versions = {
            rec["name"]: rec["version"] or safeai_version
            for rec in parser_records()
        }

        effective_config = {
            "rules_dir": os.path.abspath(self.args.rules) if self.args.rules else None,
            "safeai_version": _safeai_version(),
            "fail_on": self.args.fail_on,
        }
        self.safeai_meta = {
            "version": _safeai_version(),
            "ruleset_version": _ruleset_version(self.rules),
            "config_hash": config_hash(effective_config),
            "custom_rules_dir": self.rule_pack_metadata.get("custom_rules_dir"),
            "custom_rules_count": self.rule_pack_metadata.get("custom_rules_count", 0),
            "builtin_rules_count": self.rule_pack_metadata.get("builtin_rules_count", 0),
            "rule_pack_ids": self.rule_pack_metadata.get("rule_pack_ids", []),
            "analyzer_versions": analyzer_versions,
            "parser_versions": parser_versions,
            "policy_profile": getattr(self, "policy_profile_name", None),
        }
        try:
            source_root = os.path.relpath(self.directory, os.getcwd())
        except ValueError:
            source_root = "."
        self.project_meta = {
            "project_id": self.project_id,
            "name": os.path.basename(self.directory) or self.directory,
            "source_root": source_root.replace("\\", "/"),
            "repository": {
                "remote_fingerprint": self.remote_fp,
                "commit_sha": self.git_meta.get("commit_sha"),
                "branch": self.git_meta.get("branch"),
                "tag": self.git_meta.get("tag"),
            },
        }
        self.scan_meta = {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

        self.manifest = build_manifest(
            self.report,
            project=self.project_meta,
            scan_meta=self.scan_meta,
            safeai_meta=self.safeai_meta,
            agents=self.agents,
            policy_decision={
                "outcome": self.policy_decision["outcome"],
                "reasons": self.policy_decision["reasons"],
                "matches": self.policy_decision.get("matches") or [],
            },
        )

    def _persist_registry(self):
        """Persist the manifest to the shared SQLite registry (CI-aware).

        Returns ``None`` normally, or an int exit code for an early
        ``--strict-registry`` failure (mirrors the historical CLI behavior
        of failing before any output artifacts are written).
        """
        from safeai.kya import registry as kya_registry

        self.registry_status = {"state": "skipped", "path": None, "reason": None, "stats": None}
        in_ci = os.environ.get("CI", "").lower() in {"1", "true", "yes"}
        # An explicit registry configuration (--registry or SAFEAI_REGISTRY)
        # overrides CI auto-disable; a bare CI job never writes local state.
        registry_explicit = bool(
            self.args.registry or os.environ.get(kya_registry.SAFEAI_REGISTRY_ENV)
        )
        registry_disabled = self.args.no_registry or (in_ci and not registry_explicit)
        if in_ci and not registry_explicit and not self.args.no_registry:
            self.registry_status["reason"] = (
                "CI environment detected; use --registry PATH or the SAFEAI_REGISTRY "
                "environment variable to enable explicitly"
            )

        if not registry_disabled:
            registry_path = self.args.registry or kya_registry.shared_registry_path()
            self.registry_status["path"] = registry_path
            try:
                conn, created = kya_registry.init_registry(registry_path)
                try:
                    stats = kya_registry.persist_scan(conn, self.manifest)
                finally:
                    conn.close()
                self.registry_status["state"] = "initialized" if created else "updated"
                self.registry_status["stats"] = stats
                if created:
                    print(f"Initialized KYA registry at {registry_path}")
                    print(
                        "Tip: scans from all projects accumulate here; point SAFEAI_REGISTRY "
                        "at a team-shared path to unify registries across machines."
                    )
            except kya_registry.RegistryError as exc:
                self.registry_status["state"] = "failed"
                self.registry_status["reason"] = str(exc)
                print(f"warning: registry persistence failed: {exc}", file=sys.stderr)
                if self.args.strict_registry:
                    print("error: --strict-registry is set; failing scan", file=sys.stderr)
                    self.report["registry"] = self.registry_status
                    return 2
        else:
            self.registry_status["reason"] = (
                self.registry_status["reason"] or "disabled by --no-registry"
            )

        self.report["registry"] = self.registry_status
        return None

    def _write_outputs(self):
        from safeai.kya.manifest import write_digest_sidecar, write_manifest

        if self.args.manifest_path:
            write_manifest(self.manifest, self.args.manifest_path)
            if getattr(self.args, "digest_file", None):
                write_digest_sidecar(self.manifest, self.args.manifest_path,
                                     self.args.digest_file)

        if self.args.sarif:
            from safeai.report.sarif import write_sarif
            write_sarif(self.report, self.args.sarif)

        if self.args.json_path:
            from safeai.report.json_report import write_json
            write_json(self.report, self.args.json_path)

        if self.args.html_path:
            from safeai.report.html import write_html
            write_html(
                self.report,
                self.args.html_path,
                include_architecture=getattr(self.args, "architecture", True),
                include_mermaid=getattr(self.args, "architecture_mermaid", False),
            )

        # --- Reviewer-facing PR comment (written locally; never posted) ---
        if self.args.pr_comment_path or self.args.pr_comment_stdout or self.args.pr_comment_post:
            from safeai.kya.ci_context import detect_ci_context
            from safeai.report.pr_comment import render_pr_comment

            ci_context = detect_ci_context()
            comment = render_pr_comment(self.report, ci_context=ci_context)
            if self.args.pr_comment_path:
                with open(self.args.pr_comment_path, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(comment)
            if self.args.pr_comment_stdout:
                sys.stdout.write(comment)
            if self.args.pr_comment_post:
                from safeai.report.pr_comment import post_pr_comment
                url = post_pr_comment(self.report, ci_context=ci_context)
                if url:
                    sys.stderr.write(f"safeai: PR comment posted: {url}\n")
                else:
                    sys.stderr.write("safeai: failed to post PR comment (check GITHUB_TOKEN "
                                     "and CI context)\n")

        # --- SafeAI Security Scorecard ---
        scorecard_requested = any([
            self.args.scorecard_path,
            self.args.scorecard_json_path,
            self.args.scorecard_md_path,
            self.args.scorecard_summary_path,
            self.args.scorecard_fail_under is not None,
        ])
        if scorecard_requested:
            from safeai.scorecard import (
                build_scorecard,
                write_scorecard_json,
                write_scorecard_md,
                write_scorecard_summary,
            )
            self.scorecard = build_scorecard(
                self.report,
                self.scan_meta,
                self.policy_decision,
                scan_args={
                    "directory": self.args.directory,
                    "fail_on": self.args.fail_on,
                    "fail_on_new": self.args.fail_on_new,
                    "fail_on_escalation": self.args.fail_on_escalation,
                    "scorecard_fail_under": self.args.scorecard_fail_under,
                },
            )
            # --scorecard PATH: Markdown report (the canonical scorecard path).
            # --scorecard-md PATH: explicit Markdown alias.
            # --scorecard-json PATH: JSON report.
            # --scorecard-summary PATH: GitHub Actions job summary.
            if self.args.scorecard_path:
                write_scorecard_md(self.scorecard, self.args.scorecard_path)
            if self.args.scorecard_md_path:
                write_scorecard_md(self.scorecard, self.args.scorecard_md_path)
            if self.args.scorecard_json_path:
                write_scorecard_json(self.scorecard, self.args.scorecard_json_path)
            if self.args.scorecard_summary_path is not None:
                summary_path = self.args.scorecard_summary_path or None
                write_scorecard_summary(self.scorecard, path=summary_path)

        from safeai.report.terminal import print_summary
        print_summary(self.report)

    def _compute_exit_code(self):
        import fnmatch

        from safeai.severity import SEVERITIES

        LEVELS = list(SEVERITIES)

        # Suppressed findings never trigger failure. --fail-on-new restricts
        # the failing set to new/regressed findings (requires --baseline). A
        # policy 'block' outcome always fails the scan; documented behavior.
        active = [f for f in self.report["findings"] if f.get("status") != "suppressed"]
        threshold_index = LEVELS.index(self.args.fail_on)

        if self.args.fail_on_new:
            if not self.args.baseline:
                self.parser.error("--fail-on-new requires --baseline")
            candidates = [f for f in active if f.get("status") in {"new", "regressed"}]
        else:
            candidates = active

        fail = any(LEVELS.index(f["severity"]) >= threshold_index for f in candidates)
        if self.policy_decision["outcome"] == "block":
            fail = True

        # --fail-on-escalation is a separate axis from finding severity: a
        # change can add no new findings while still handing a named tool new
        # authority. It never relaxes the existing thresholds, only adds to
        # them, so default exit semantics are unchanged.
        if self.args.fail_on_escalation:
            if not self.args.baseline:
                self.parser.error("--fail-on-escalation requires --baseline")
            highest = (self.report.get("capability_diff") or {}).get("highest_escalation")
            if highest in LEVELS and LEVELS.index(highest) >= LEVELS.index(self.args.fail_on_escalation):
                fail = True

        # --fail-on-authority-change gates on material authority change
        # classes (Lane A deterministic). Inferred-only changes print as
        # review questions and never fail this gate; UNKNOWN never fails.
        fail_on_authority = getattr(self.args, "fail_on_authority_change", None)
        if fail_on_authority:
            if not self.args.baseline:
                self.parser.error("--fail-on-authority-change requires --baseline")
            from safeai.analysis.capability_diff import authority_gate_tripped

            tools = ((self.report.get("capability_diff") or {}).get("tools") or [])
            if authority_gate_tripped(tools, fail_on_authority):
                fail = True

        # --scorecard-fail-under is an additional score-based gate. It never
        # relaxes the existing thresholds, only adds to them. The score is
        # not changed by this gate; only the exit code is affected.
        scorecard_fail_under = self.args.scorecard_fail_under
        if scorecard_fail_under is not None:
            # Validate: numeric and in [0, 10]. The scorecard was built in
            # _write_outputs, so it exists when this gate is requested.
            if self.scorecard is None:
                # Should not happen, but fail safely as operational error.
                self.parser.error("--scorecard-fail-under requires a scorecard output")
            if not (0.0 <= scorecard_fail_under <= 10.0):
                self.parser.error(
                    f"--scorecard-fail-under must be between 0 and 10; got {scorecard_fail_under}"
                )
            score = self.scorecard["safeai_security_scorecard"]["summary"]["score"]
            if score < scorecard_fail_under:
                fail = True

        # --fail-on-rule: fail when any finding matches a rule ID pattern.
        # Patterns are glob-style (fnmatch): GOV_*, MCP_*, ESC_COMBO_*, etc.
        # Multiple patterns are OR'd (any match triggers failure).
        fail_on_rule = getattr(self.args, "fail_on_rule", None) or []
        if fail_on_rule:
            for finding in candidates:
                rule_id = finding.get("rule_id", "")
                for pattern in fail_on_rule:
                    if fnmatch.fnmatch(rule_id, pattern):
                        fail = True
                        break
                if fail:
                    break

        # --fail-on-category: fail when any finding belongs to a category.
        # Categories are mapped from rule_id prefixes. Multiple categories
        # are OR'd (any match triggers failure).
        fail_on_category = getattr(self.args, "fail_on_category", None) or []
        if fail_on_category:
            _CATEGORY_MAP = {
                "security": {"DATA_LEAKAGE", "DATAFLOW", "PROMPT", "PROMPT_FILE"},
                "governance": {"GOV_"},
                "capability": {"CAP_", "ESC_"},
                "dataflow": {"DATAFLOW", "TOXIC_FLOW"},
                "prompt": {"PROMPT", "PROMPT_FILE"},
                "mcp": {"MCP_"},
                "dependency": {"DEP_"},
            }
            for finding in candidates:
                rule_id = finding.get("rule_id", "")
                for cat in fail_on_category:
                    prefixes = _CATEGORY_MAP.get(cat, set())
                    for prefix in prefixes:
                        if rule_id.startswith(prefix):
                            fail = True
                            break
                    if fail:
                        break
                if fail:
                    break

        return 1 if fail else 0
