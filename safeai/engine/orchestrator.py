"""Scan orchestration engine for SafeAI.

Drives the entire pipeline as discrete, individually callable stages (see
:class:`ScanOrchestrator`):

  1. :meth:`ScanOrchestrator.prepare` — file collection (Python, YAML,
     JSON, dependency manifests), rules loading, dependency extraction,
     parser discovery
  2. :meth:`ScanOrchestrator.load_sources` — read files, build semantic
     documents (AST), construct the import graph
  3. :meth:`ScanOrchestrator.parse_frameworks` — run all framework
     parsers on all files (no mutual exclusion), capture provenance
  4. :meth:`ScanOrchestrator.extract_components` — component-level
     extraction, parser aggregation, capability normalization
  5. :meth:`ScanOrchestrator.analyze` — multi-analyzer pipeline
     (capability, prompt, data leakage, MCP, Claude Code, and the
     component analyzers)
  6. :meth:`ScanOrchestrator.assemble` — relativize paths, score the
     report, build the tool surface and assurance boundary

The module-level :func:`run_scan` is the historical entry point and a thin
wrapper over :class:`ScanOrchestrator`; ``safeai.engine.scan`` re-exports
both for backward compatibility.
"""

import logging
import os

from safeai.analysis.aggregation import aggregate_capabilities, aggregate_parser_models
from safeai.analysis.components import extract_components
from safeai.analysis.import_graph import build_import_graph, module_name_from_path
from safeai.analysis.project_graph import build_project_graph
from safeai.analysis.semantic import build_semantic_document
from safeai.analysis.tool_surface import build_tool_surface
from safeai.frameworks import discover_parsers
from safeai.kya.assurance import build_assurance_boundary
from safeai.rules.loader import load_rules
from safeai.scoring.engine import score_report
from safeai.severity import SEVERITIES

logger = logging.getLogger("safeai")

# Directories that are never scanned (version control, dependency caches,
# virtual environments, build outputs, SafeAI's own local state).
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules",
    "__pycache__",
    ".venv", "venv", "env",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", ".eggs",
    ".idea", ".vscode",
    ".safeai",
}

# SafeAI's own canonical artifacts are never re-scanned: scanning a
# previously generated manifest would create a findings feedback loop.
_EXCLUDED_FILES = {"safeai-manifest.json"}

# Files larger than this are skipped to avoid excessive memory use.
MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_scannable_file(filename):
    """Return whether a file is source, configuration, or AI instructions."""
    lower = filename.lower()
    if lower.endswith((".py", ".json", ".yaml", ".yml", ".prompt")):
        return True
    return lower in {
        "claude.md", "prompt.md", "system_prompt.md", ".cursorrules", ".windsurfrules",
        "copilot-instructions.md",
    } or lower.endswith((".prompt.md", ".prompt.txt"))


#: Additional extensions read inside a ``.claude/`` directory. Claude Code
#: keeps real agent authority in markdown (slash commands, subagents) and
#: shell hooks, which the generic source allowlist above does not cover.
_CLAUDE_CONFIG_EXTS = (".md", ".markdown", ".sh", ".bash", ".toml")


def _is_claude_config_file(full_path):
    """True for Claude Code configuration inside the scanned repository.

    Only paths under a repository-local ``.claude/`` directory qualify.
    User-level configuration is never reached: this predicate is applied
    to files already discovered by walking the scan root.
    """
    normalized = str(full_path).replace("\\", "/")
    if "/.claude/" not in normalized:
        return False
    return normalized.lower().endswith(_CLAUDE_CONFIG_EXTS)


def _is_copilot_config_file(full_path):
    """True for Markdown instructions below a repository's ``.copilot/``."""
    normalized = str(full_path).replace("\\", "/").lower()
    return normalized.endswith("/.copilot/instructions.md")


def _is_within_root(root, path):
    """True when ``path`` resolves inside ``root`` after symlink expansion."""
    root_real = os.path.normcase(os.path.realpath(root))
    path_real = os.path.normcase(os.path.realpath(path))
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False


def _is_canonical_manifest_path(path, root):
    """True for the canonical root-level manifest filename only."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return False
    return rel.replace("\\", "/") in _EXCLUDED_FILES


def collect_files(root, skipped=None, excluded_paths=None):
    """Collect scannable files, pruning excluded directories and oversized files.

    ``skipped`` is an optional dict that accumulates ``reason -> count`` for
    files the walk declined to read. It feeds the assurance boundary, which
    has to state honestly what the scan did not look at. Passing nothing
    keeps the historical single-return behaviour.
    """
    files = []
    counters = skipped if skipped is not None else {}

    def note(reason):
        counters[reason] = counters.get(reason, 0) + 1

    excluded = {
        os.path.normcase(os.path.realpath(os.path.abspath(path)))
        for path in (excluded_paths or [])
        if path
    }

    for d, dirs, fs in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS)
        for f in sorted(fs):
            full = os.path.join(d, f)

            full_real = os.path.normcase(os.path.realpath(full))
            if full_real in excluded:
                continue

            if _is_canonical_manifest_path(full, root):
                continue

            if not _is_within_root(root, full):
                note("outside scan root (symlink or path traversal)")
                continue

            if not (
                _is_scannable_file(f)
                or _is_claude_config_file(full)
                or _is_copilot_config_file(full)
            ):
                extension = os.path.splitext(f)[1].lower() or "(no extension)"
                note(f"unsupported file type {extension}")
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    logger.debug("Skipping oversized file: %s", full)
                    note("larger than the 2 MiB read limit")
                    continue
            except OSError:
                note("unreadable")
                continue
            files.append(full)
    return sorted(files)


def collect_dependency_files(root):
    files = []
    for filename in ["requirements.txt", "pyproject.toml", "Pipfile", "package.json"]:
        path = os.path.join(root, filename)
        if os.path.exists(path):
            files.append(path)
    return files


def extract_dependencies(paths):
    """Parse dependency manifests into a set of package names.

    Handles requirements.txt, Pipfile, pyproject.toml, and package.json.
    For structured manifests only known AI framework tokens are extracted.
    """
    deps = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        low = content.lower()
        if path.endswith(("requirements.txt", "Pipfile")):
            for line in content.splitlines():
                raw = line.strip().split("#", 1)[0]
                if not raw:
                    continue
                name = raw.split("==", 1)[0].split(">=", 1)[0].split("<=", 1)[0].strip().lower()
                if name:
                    deps.add(name)
        elif path.endswith("pyproject.toml"):
            for token in [
                "langgraph",
                "crewai",
                "langchain",
                "semantic-kernel",
                "openai-agents",
                "azure-ai-agents",
                "azure-ai-projects",
                "google-adk",
                "haystack-ai",
                "llama-index",
                "mastra",
                "dify",
                "n8n",
            ]:
                if token in low:
                    deps.add(token)
        elif path.endswith("package.json"):
            for token in [
                "langchain", "openai", "@azure/ai-projects", "@microsoft/agents",
                "@mastra/core", "n8n",
            ]:
                if token in low:
                    deps.add(token)
    return deps


def _relativize(path, root):
    """Convert an absolute path to a root-relative, forward-slash path.

    Paths outside the scan root and sentinel values (e.g. ``<scan>``)
    are returned unchanged. Relative paths keep report output portable
    and allow GitHub code scanning to map SARIF results to files.
    """
    if not path or path.startswith("<"):
        return path
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return path
    if rel.startswith(".."):
        return path
    return rel.replace("\\", "/")


class ScanOrchestrator:
    """Runs the static-analysis pipeline as discrete, testable stages.

    Stage methods are intentionally independent so individual steps can be
    exercised or replaced in tests; :meth:`run` chains them in order and
    returns the assembled report.
    """

    def __init__(self, directory, rules_dir=None, baseline_report=None, excluded_paths=None,
                 mcp_ide_scopes=False):
        self.directory = os.path.abspath(directory)
        self.rules_dir = rules_dir
        self.baseline_report = baseline_report
        self.excluded_paths = excluded_paths
        self.mcp_ide_scopes = mcp_ide_scopes

        self.skipped_files = {}
        self.files = []
        self.rules = []
        self.dependencies = set()
        self.parsers = []
        self.file_cache = {}
        self.module_by_file = {}
        self.semantic_docs = {}
        self.import_graph = None
        self.scan_ctx = {}
        self.agent_models = []
        self.detected_frameworks = []
        self.framework_methods = {}
        self.parser_results_by_file = {}
        self.parse_provenance = []
        self.diagnostics = []
        self.components = []
        self.unified_models = []
        self.normalized_capabilities = []
        self.findings = []
        self.mcp_assets = []
        self.mcp_capabilities = []
        self.env_inventory = []
        self.dependency_correlation = None
        self.iac_graph = None
        self.iac_meta = None
        self.iac_correlation = None
        self.counts = {}
        self.trust_score = {}
        self.project_graph = {}
        self.report = {}

    def prepare(self):
        """Stage 1: resolve the root, collect files, load rules/deps/parsers."""
        self.files = collect_files(
            self.directory, skipped=self.skipped_files, excluded_paths=self.excluded_paths
        )
        logger.info("Collected %d scannable files in %s", len(self.files), self.directory)
        self.rules, _ = load_rules(self.rules_dir, scan_root=self.directory)
        self.dependencies = extract_dependencies(collect_dependency_files(self.directory))
        self.parsers = discover_parsers()

    def load_sources(self):
        """Stage 2: read files into cache and build semantic docs + import graph."""
        for path in self.files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as exc:
                logger.debug("Failed to read %s: %s", path, exc)
                continue

            self.file_cache[path] = content
            if path.endswith(".py"):
                module_name = module_name_from_path(self.directory, path)
                self.module_by_file[path] = module_name
                self.semantic_docs[path] = build_semantic_document(
                    path, content, module_name=module_name
                )

        if self.mcp_ide_scopes:
            self._inject_ide_mcp_configs()

        self.import_graph = build_import_graph(self.directory, self.files, self.semantic_docs)
        self.scan_ctx = {
            "root": self.directory,
            "files": self.files,
            "file_cache": self.file_cache,
            "dependencies": self.dependencies,
            "module_by_file": self.module_by_file,
            "semantic_docs": self.semantic_docs,
            "import_graph": self.import_graph,
        }

    _IDE_MCP_CONFIGS = [
        (".cursor", "mcp.json"),
        (".windsurf", "mcp.json"),
        (".vscode", "mcp.json"),
    ]

    def _inject_ide_mcp_configs(self):
        """Inject IDE-specific MCP config files into file_cache.

        When ``--mcp-ide-scopes`` is enabled, known IDE MCP config paths
        (``.cursor/mcp.json``, ``.windsurf/mcp.json``, ``.vscode/mcp.json``)
        are read and added to the file cache so the MCP analyzer can discover
        them. These directories are normally excluded from scanning.
        """
        for ide_dir, filename in self._IDE_MCP_CONFIGS:
            path = os.path.join(self.directory, ide_dir, filename)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except Exception as exc:
                logger.debug("Failed to read IDE MCP config %s: %s", path, exc)
                continue
            if path not in self.file_cache:
                self.file_cache[path] = content
                self.files.append(path)
                logger.info("Injected IDE MCP config: %s", path)

    def parse_frameworks(self):
        """Stage 3: run all framework parsers on all files, no mutual exclusion."""
        for path in self.files:
            content = self.file_cache.get(path, "")
            for parser in self.parsers:
                if parser.detect(path, content, scan_ctx=self.scan_ctx):
                    parsed = parser.parse(path, content, scan_ctx=self.scan_ctx)
                    if parsed is None:
                        continue
                    framework = parsed.get("framework")
                    if not framework:
                        continue
                    self.agent_models.append({
                        "file": path,
                        "framework": framework,
                        "data": parsed,
                    })
                    self.parser_results_by_file.setdefault(path, []).append(parsed)
                    self.parse_provenance.append({
                        "file": path,
                        "framework": framework,
                        "confidence": parsed.get("parser_confidence", 0.65),
                        "source": parsed.get("discovery_method", "regex"),
                        "evidence": parsed.get("detection_evidence", []),
                    })
                    if framework and framework not in self.detected_frameworks:
                        self.detected_frameworks.append(framework)
                    self.framework_methods.setdefault(framework, set()).add(
                        parsed.get("discovery_method", "regex")
                    )

    def extract_components(self):
        """Stage 4: component-level extraction, aggregation, normalization."""
        self.diagnostics = []
        self.components = extract_components(
            self.files, self.file_cache, self.semantic_docs, diagnostics=self.diagnostics
        )
        logger.info("Extracted %d AI components", len(self.components))

        self.unified_models = aggregate_parser_models(self.parser_results_by_file)
        logger.info(
            "Detected frameworks: %s", ", ".join(self.detected_frameworks) or "none"
        )

        capabilities = []
        for model in self.agent_models:
            capabilities.extend(model.get("data", {}).get("capabilities") or [])
        self.normalized_capabilities = aggregate_capabilities(capabilities)

    def analyze(self):
        """Stage 5: run the core + component analyzers over sources and components.

        Analyzers come from the ``safeai.analyzers`` registry
        (built-ins in legacy run order, then ``safeai.analyzers``
        entry-point plugins).  Third-party analyzers run isolated: a
        raising plugin is skipped with a warning and never fails a scan.
        """
        from safeai.analyzers import discover_analyzers

        builtin_core = [
            a
            for a in discover_analyzers(phase="core", include_external=False)
            if not getattr(a, "_safeai_external", False)
        ]
        for analyzer in builtin_core:
            self.findings.extend(analyzer.run(self.file_cache, self.rules, self.agent_models))

        # --- Phase 1.5: component-level analyzers (built-ins + isolated plugins) ---
        builtin_component = [
            a
            for a in discover_analyzers(phase="component", include_external=False)
            if not getattr(a, "_safeai_external", False)
        ]
        for analyzer in builtin_component:
            self.findings.extend(
                analyzer.run(
                    self.file_cache, self.rules, self.agent_models, components=self.components
                )
            )
        external = [
            a
            for a in discover_analyzers(phase="component", include_external=True)
            if getattr(a, "_safeai_external", False)
        ]
        for analyzer in external:
            try:
                self.findings.extend(
                    analyzer.run(
                        self.file_cache,
                        self.rules,
                        self.agent_models,
                        components=self.components,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Skipping analyzer plugin %s after error: %s",
                    getattr(analyzer, "name", type(analyzer).__name__),
                    exc,
                )
        self.findings.sort(key=lambda f: (
            str(f.get("file") or ""),
            int(f.get("line") or 0),
            str(f.get("rule_id") or ""),
            str(f.get("severity") or ""),
            str(f.get("message") or ""),
        ))
        logger.info("Analysis produced %d findings", len(self.findings))

    def _extract_mcp_assets(self):
        self.mcp_assets = []
        self.mcp_capabilities = []
        for finding in self.findings:
            if finding.get("rule_id") == "MCP_ASSETS_DISCOVERED":
                self.mcp_assets.extend(finding.get("mcp_assets") or [])
                self.mcp_capabilities.extend(finding.get("mcp_capabilities") or [])

    def _count_severities(self):
        self.counts = {severity: 0 for severity in reversed(SEVERITIES)}
        for finding in self.findings:
            sev = finding.get("severity", "medium")
            if sev not in self.counts:
                self.counts[sev] = 0
            self.counts[sev] += 1

    def _extract_env_inventory(self):
        """Extract the env-dependency inventory from the carrying finding."""
        self.env_inventory = []
        for finding in self.findings:
            if finding.get("rule_id") == "ENV_DEP_INVENTORY":
                self.env_inventory = finding.get("dep_inventory") or []
        return self.env_inventory

    def _relativize_report(self):
        # Normalize all paths in the report to be relative to the scanned
        # root so reports are portable and SARIF consumers (e.g. GitHub
        # code scanning) can map results back to repository files.
        for finding in self.findings:
            finding["file"] = _relativize(finding.get("file"), self.directory)
        # Relativize inventory source locations (paths only, never values).
        for entry in self.env_inventory:
            for source in entry.get("sources") or []:
                source["file"] = _relativize(source.get("file"), self.directory)
        for model in self.agent_models:
            model["file"] = _relativize(model.get("file"), self.directory)
        for entry in self.parse_provenance:
            entry["file"] = _relativize(entry.get("file"), self.directory)
        for asset in self.mcp_assets:
            asset["file"] = _relativize(asset.get("file"), self.directory)
        for model in self.unified_models:
            model["file"] = _relativize(model.get("file"), self.directory)
        for component in self.components:
            component["file"] = _relativize(component.get("file"), self.directory)
        for diagnostic in self.diagnostics:
            diagnostic["file"] = _relativize(diagnostic.get("file"), self.directory)

    def assemble(self):
        """Stage 6: correlate, build the tool surface, then a single
        score/relativize pass over the final finding set.

        Correlation (CE 1.5) must run before scoring so its findings are
        included in counts, the trust score, and path relativization —
        exactly once, avoiding a second pass over already-relativized data.
        """
        self._extract_mcp_assets()
        self._extract_env_inventory()
        self.project_graph = build_project_graph(
            self.agent_models, mcp_assets=self.mcp_assets, components=self.components
        )

        self.report = {
            "report_type": "safeai.scan",
            "findings": self.findings,
            "counts": self.counts,
            "files_scanned": len(self.files),
            "agent_models": self.agent_models,
            "detected_frameworks": sorted(self.detected_frameworks),
            "framework_discovery_methods": {
                k: sorted(v) for k, v in self.framework_methods.items()
            },
            "parser_provenance": self.parse_provenance,
            "unified_models": self.unified_models,
            "normalized_capabilities": self.normalized_capabilities,
            "dependencies": sorted(self.dependencies),
            "import_graph": {
                "modules": self.import_graph.module_to_file,
                "edges": {k: sorted(v) for k, v in self.import_graph.edges.items()},
            },
            "project_graph": self.project_graph,
            "mcp_assets": self.mcp_assets,
            "mcp_capabilities": self.mcp_capabilities,
            "components": self.components,
            "diagnostics": self.diagnostics,
            "skipped_files": dict(sorted(self.skipped_files.items())),
            "trust_score": self.trust_score,
        }
        # Scanner metadata (v2.0.1): machine-readable engine/schema/ruleset/adapter versions.
        from safeai.engine.metadata import build_scanner_metadata
        self.report["scanner_metadata"] = build_scanner_metadata(
            rules_dir=self.rules_dir,
            parsers=self.parsers,
            scan_root=self.directory,
        )
        # Per-tool capability surface (v1.4): the unit the diff compares and
        # the registry persists. Built from report data only — no extra file
        # access. Requires only agent_models/mcp_assets, so it runs before
        # scoring/counting below.
        self.report["tool_surface"] = build_tool_surface(self.report)
        # Component-change diffs (CE 1.6): detect changed components and
        # flag all consuming agents. Runs after component extraction and
        # before scoring so the diff is available in the report.
        from safeai.analysis.component_diff import compute_component_diff
        previous_components = (self.baseline_report or {}).get("components") or []
        self.report["component_diff"] = compute_component_diff(
            self.components, previous_components
        )
        # Dependency-to-capability correlation (CE 1.5): match the
        # env-dependency inventory against the declared tool surface. Findings
        # are appended BEFORE the single count/score/relativize pass so they
        # participate in severities, trust score, and path normalisation.
        from safeai.analysis.dependency_correlation import correlate_dependencies

        correlation_findings, self.dependency_correlation = correlate_dependencies(self.report)
        if correlation_findings:
            for finding in correlation_findings:
                finding["file"] = _relativize(finding.get("file"), self.directory)
                self.findings.append(finding)

        self.report["dependency_inventory"] = self.env_inventory
        self.report["dependency_correlation"] = self.dependency_correlation
        # IaC authority correlation (v2.5): match evidenced IaC grants
        # against the declared tool surface. Findings are review-only by
        # construction (ADR-0008) and join the single count/score/
        # relativize pass like every other correlation. Evidence comes
        # from collect_iac_evidence(); direct assemble() callers get an
        # empty graph (no IaC), never an error.
        from safeai.analysis.iac_correlation import correlate_iac_authority

        graph = dict(self.iac_graph or {})
        graph["meta"] = self.iac_meta or {}
        iac_findings, self.iac_correlation = correlate_iac_authority(
            self.report, graph
        )
        if iac_findings:
            for finding in iac_findings:
                finding["file"] = _relativize(finding.get("file"), self.directory)
                self.findings.append(finding)
        self.report["iac_correlations"] = self.iac_correlation
        # Tool ↔ implementation mapping (CE 1.5): correlate declared tools
        # with their implementations and surface orphan states.
        from safeai.analysis.tool_implementation import map_tool_implementations

        impl_findings, tool_impl_summary = map_tool_implementations(self.report)
        if impl_findings:
            for finding in impl_findings:
                self.findings.append(finding)
        self.report["tool_implementation"] = tool_impl_summary
        # Cross-component relationship graph (CE 1.8): analyze
        # skill→tool→workflow→MCP→model relationships, surface orphaned
        # references and unhealthy coupling patterns.
        from safeai.analysis.component_graph import analyze_component_health

        graph_findings, component_graph = analyze_component_health(self.components)
        if graph_findings:
            for finding in graph_findings:
                finding["file"] = _relativize(finding.get("file"), self.directory)
                self.findings.append(finding)
        self.report["component_graph"] = component_graph
        # Target taxonomy engine (CE 1.5): aggregate external-network
        # capabilities into destination buckets (Database, Object Storage,
        # SaaS APIs, Cloud Services, Messaging).
        from safeai.analysis.target_taxonomy import build_target_taxonomy

        self.report["target_taxonomy"] = build_target_taxonomy(self.report)
        # Single pass: counts, trust score, and relative paths, all over the
        # complete finding set (core + component + correlation).
        # Sort once after all findings are appended.
        self.findings.sort(key=lambda f: (
            str(f.get("file") or ""),
            int(f.get("line") or 0),
            str(f.get("rule_id") or ""),
        ))
        self.report["findings"] = self.findings
        self._count_severities()
        self.trust_score = score_report(self.findings)
        self.report["counts"] = self.counts
        self.report["trust_score"] = self.trust_score
        self._relativize_report()
        # Assurance boundary (v1.4): what this scan did and did not verify.
        # Derived from the run itself, never a fixed disclaimer string.
        self.report["assurance_boundary"] = build_assurance_boundary(self.report)
        if self.baseline_report is not None:
            from safeai.analysis.capability_diff import compute_capability_diff

            self.report["capability_diff"] = compute_capability_diff(
                self.report, self.baseline_report
            )
        return self.report

    def collect_iac_evidence(self):
        """Stage 5b: collect IaC authority evidence (v2.5 redesign).

        First-class scan-stage artifact: walks the scan root once for
        Terraform and Kubernetes sources, extracts the authority graph
        (identities, grants, bindings, workload refs), and resolves
        Agent→Identity links from explicit evidence. Respects scan root,
        exclusions, size caps, and deterministic ordering (see
        ``safeai.iac``). Never raises: failures yield an empty graph.
        """
        from safeai.iac import empty_graph, scan_iac

        try:
            graph, meta = scan_iac(self.directory, self.excluded_paths)
        except Exception:
            graph, meta = empty_graph(), {}
        self.iac_graph = graph
        self.iac_meta = meta
        return graph

    def run(self):
        """Execute all stages in order and return the assembled report."""
        self.prepare()
        self.load_sources()
        self.parse_frameworks()
        self.extract_components()
        self.analyze()
        self.collect_iac_evidence()
        return self.assemble()


def run_scan(directory, rules_dir=None, baseline_report=None, excluded_paths=None,
             mcp_ide_scopes=False):
    """Scan ``directory`` and return the assembled report (historical API)."""
    return ScanOrchestrator(
        directory,
        rules_dir=rules_dir,
        baseline_report=baseline_report,
        excluded_paths=excluded_paths,
        mcp_ide_scopes=mcp_ide_scopes,
    ).run()
