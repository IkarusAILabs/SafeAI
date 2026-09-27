# Contributing to SafeAI

Welcome, and thank you for considering contributing to SafeAI.

SafeAI is a **community-driven Static AI Capability & Risk Analyzer** — think SonarQube for AI agents and workflows. We believe that making AI systems safer should be open, collaborative, and accessible to everyone.

This guide will help you get started, whether you're adding your first rule or building a complete framework adapter.

---

## Project Vision

SafeAI is intentionally:

- **Lightweight** — no external services, no runtime, no LLM calls
- **Environment agnostic** — works in any CI/CD pipeline, on any OS
- **CI/CD friendly** — SARIF output, exit codes, GitHub Actions ready
- **Plugin based** — frameworks, analyzers, and rules are all pluggable
- **Community driven** — built by and for the AI security community

Our mission: **The lightweight, open-source Static AI Capability & Risk Analyzer for CI/CD pipelines.**

---

## Quick Start for Contributors

```bash
git clone https://github.com/ikaruscareer/SafeAI.git
cd SafeAI
pip install -e ".[dev]"
```

---

## Development Workflow

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-contribution
   ```
3. **Make your changes** — keep them focused and small
4. **Run tests**:
   ```bash
   python -m pytest
   ```
5. **Lint your code**:
   ```bash
   ruff check .
   ```
6. **Commit** using conventional commits (see below)
7. **Push** and open a Pull Request

---

## Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_semantic.py

# Run with verbose output
python -m pytest -v

# Run with coverage
python -m pytest --cov=safeai

# Verify release metadata, rules, changelog, and Action I/O consistency
python scripts/check_release.py
```

The release workflow runs the same checker before building or publishing
artifacts, so failures block the release at the pre-release checklist gate.

---

## Coding Standards

- Follow **PEP 8**
- Use **type hints** for all public functions and methods
- Keep functions small — one responsibility per function
- Prefer **clarity over cleverness**
- Avoid unnecessary abstractions
- Include **docstrings** for modules, classes, and public functions
- Use **f-strings** for string formatting

---

## Pull Request Process

1. Sign off every commit (`git commit -s`; see [DCO.md](./DCO.md))
2. Ensure all tests pass
3. Add tests for new functionality
4. Update documentation if needed
5. Fill out the PR template completely
6. Reference any related issues

All commits are checked for `Signed-off-by` trailers in CI. Note the
[Community/Corporate boundary](./docs/GOVERNANCE_AND_EDITIONS.md):
detection improvements always belong to the free Community core.

### What reviewers look for:

- **Correctness** — does the code do what it claims?
- **Simplicity** — can it be simpler?
- **Security** — does it introduce new risks?
- **Test coverage** — are edge cases covered?
- **Documentation** — will contributors understand this next month?

---

## Commit Message Recommendations

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add Docker capability detection
fix: correct false positive in prompt injection rule
docs: improve architecture documentation for contributors
test: add coverage for capability analyzer
refactor: simplify parser result merging
chore: update dependency versions
```

---

## Documentation Standards

- Keep explanations **simple and practical**
- Include **concrete examples** — not abstract descriptions
- Use **diagrams** where helpful (Mermaid preferred)
- Update documentation **in the same PR** as the code change
- Prefer **active voice** ("Run the scanner" not "The scanner should be run")

---

## Getting Help

- Open a [Discussion](https://github.com/ikaruscareer/SafeAI/discussions)
- Check [GOOD_FIRST_ISSUES.md](./GOOD_FIRST_ISSUES.md) for starter tasks
- Read [ARCHITECTURE_FOR_CONTRIBUTORS.md](./ARCHITECTURE_FOR_CONTRIBUTORS.md) to understand the codebase
---

## Community Contributors

We are grateful to the following community members for their contributions:

| Contributor | Contributions |
|-------------|---------------|
| [@i-safonoff](https://github.com/i-safonoff) | `.cursorrules` framework adapter, `rule_coverage_summary()`, RULES_REFERENCE.md, dataflow rule ID casing fix |
| [@ARAVIND281](https://github.com/ARAVIND281) | Claude Code permission evaluation order fix, interprocedural data-flow tracking |
| [@Solarthis](https://github.com/Solarthis) | MCP tool description injection detection |
| [@Aming9303](https://github.com/Aming9303) | `safeai registry components` CLI, `safeai init` command, GitHub Actions workflow example |
| [@adnqcr7-code](https://github.com/adnqcr7-code) | Framework detection tests (LangGraph, CrewAI, LlamaIndex, n8n, Claude Code), CI integration docs, SARIF review guidance |
| [@hadbiaghiles](https://github.com/hadbiaghiles) | AutoGen framework documentation |
| [@D05TL3](https://github.com/D05TL3) | GitHub Actions scanning example |
| [@mikemikimike](https://github.com/mikemikimike) | Adapter negative detection tests |
| [@mah](https://github.com/mahirhir) | Claude Code deep analysis documentation |
| [@asarakhatun17-lgtm](https://github.com/asarakhatun17-lgtm) | Supported frameworks consistency fix |
| [@yugaaank](https://github.com/yugaaank) | Capability detectors (Docker, Kubernetes, Redis, S3, GCP, Slack, Jira, browser automation) |
| [@burakeyler](https://github.com/burakeyler) | `--digest-file` manifest digest sidecar (PR #148) |
| [@YaoSong808](https://github.com/YaoSong808) | OpenClaw and GitHub Copilot config-file adapters (PR #159) |
| [@Teachmeplaycode](https://github.com/Teachmeplaycode) | Benchmark corpus expansion, static subprocess precision gap documentation (PR #174) |
| [@nikitajos7](https://github.com/nikitajos7) | Policy profile display in terminal and HTML reports (PR #175) |
| [@be-student](https://github.com/be-student) | Portable registry import, MCP tool-pattern golden fixtures, canonical release checklist (PRs #123, #124, #125) |
| [@Karthik9849309055](https://github.com/Karthik9849309055) | Multi-framework scan automation script (PR #161) |
| [@chenzeyan54-commits](https://github.com/chenzeyan54-commits) | Terminal output sanitization against ANSI/OSC injection (PR #203) |
| [@HarshRajSinghania](https://github.com/HarshRajSinghania) | PR comment markdown injection sanitization (PR #204) |
| [@thadidaniel-ctrl](https://github.com/thadidaniel-ctrl) | Release workflow supply-chain posture tests (PR #206) |

Your contributions help make AI safer for everyone. Thank you!

---

<img width="1024" height="1024" alt="SafeAI_Contribute_Everyone" src="https://github.com/user-attachments/assets/9d0efd4d-c52d-424a-bfaa-941272ce1f63" />


## Code of Conduct

Be respectful, inclusive, and constructive. We welcome contributors of all backgrounds and experience levels.

---

Thank you for making AI safer — one contribution at a time.

If SafeAI is useful to you, consider giving the repo a ⭐ — it helps other teams discover the project and is one of the easiest ways to support it besides code.
