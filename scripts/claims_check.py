"""C-8 claims ledger check: public wording must match the code and the evidence.

Reads ``research/credibility/claims.yml`` and fails when:

- a repository claim's ``quote`` no longer appears in its ``source``
  (whitespace and Markdown emphasis are normalised), so the ledger and
  the wording cannot drift apart silently;
- a ``count`` claim's number differs from the number recomputed from
  the code (frameworks, capability categories, escalation, governance
  and risk categories, and the release version). This holds for web
  claims too: a release or a new framework fails the check until the
  web claim is marked ``stale`` or the page is updated and re-quoted;
- the rule-coverage table in ``docs/reference/SUPPORT_MATRIX.md`` differs
  from the built-in rules, prefix by prefix;
- a ``tested`` claim names a test file or test that does not exist;
- a field is missing or a status is unknown.

Claims sourced from web pages (``https://``) are not fetched by default,
so the check in the test suite stays offline. ``--web`` fetches each page
once (with ``curl``) and also checks that every web quote is on it; run
it after the site changes, then update ``retrieved``.

Usage:
    python scripts/claims_check.py [--ledger research/credibility/claims.yml] [--summary]
    python scripts/claims_check.py --web

Exit codes: 0 consistent · 1 inconsistencies found · 2 usage error.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import sys
from collections import Counter
from typing import Any

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

STATUSES = ("counted", "tested", "unmeasured", "overclaim", "stale", "positioning",
            "limitation")
KINDS = ("count", "property", "quality", "positioning", "limitation")
SUPPORT_MATRIX = os.path.join("docs", "reference", "SUPPORT_MATRIX.md")


# --- what the code says ------------------------------------------------------------

def _rule_ids() -> list[str]:
    from safeai.rules.loader import load_rules

    return [r["id"] for r in load_rules()[0]]


def actual_counts() -> dict[str, Any]:
    from safeai.analysis.capabilities import CAPABILITY_CATEGORIES
    from safeai.analysis.escalation import ESCALATION_RULES
    from safeai.frameworks import discover_parsers
    from safeai.scoring.engine import CATEGORY_WEIGHTS
    from safeai.version import SAFEAI_VERSION

    return {
        "frameworks": len(discover_parsers(include_external=False)),
        "capability_categories": len(CAPABILITY_CATEGORIES),
        "escalation_rules": len(ESCALATION_RULES),
        "governance_rules": sum(i.startswith("GOV_") for i in _rule_ids()),
        "risk_categories": len(CATEGORY_WEIGHTS),
        "release": SAFEAI_VERSION,
    }


def rule_prefix_counts(ids: list[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for rule_id in ids:
        match = re.match(r"(PROMPT_FILE|[A-Z]+)_", rule_id)
        counts[match.group(1) if match else rule_id] += 1
    return dict(counts)


def support_matrix_counts(text: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"^\| `([A-Z_]+?)_\*` \| (\d+) \|", text, re.MULTILINE)}


# --- checks ------------------------------------------------------------------------

def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("*", "")).strip()


def page_text(raw: str) -> str:
    """Visible text of an HTML page, normalised like the quotes."""
    raw = re.sub(r"(?is)<(script|style|noscript)\b[^>]*>.*?</\1>", " ", raw)
    return _normalise(html.unescape(re.sub(r"(?s)<[^>]+>", " ", raw)))


def check_web(claims: list[dict[str, Any]], get: Any = None) -> list[str]:
    """Each web quote must be on its page (fetched once per page)."""
    if get is None:
        sys.path.insert(0, os.path.join(REPO, "scripts"))
        from study_common import fetch as get
    pages: dict[str, str] = {}
    problems = []
    for claim in claims:
        source = str(claim.get("source") or "")
        if not source.startswith("https://"):
            continue
        if source not in pages:
            try:
                pages[source] = page_text(get(source).decode("utf-8", "replace"))
            except Exception as exc:
                problems.append(f"{source}: could not fetch: {exc}")
                pages[source] = ""
                continue
        if pages[source] and _normalise(str(claim.get("quote"))) not in pages[source]:
            problems.append(f"{claim.get('id')}: quote no longer on {source}: "
                            f"{claim.get('quote')!r}")
    return problems


def _test_exists(ref: str) -> bool:
    path, _, name = ref.partition("::")
    full = os.path.join(REPO, path)
    if not os.path.isfile(full):
        return False
    if not name:
        return True
    with open(full, encoding="utf-8") as fh:
        return re.search(rf"^def {re.escape(name)}\(", fh.read(), re.MULTILINE) is not None


def check(ledger: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    claims = ledger.get("claims")
    if not isinstance(claims, list) or not claims:
        return ["ledger needs a non-empty 'claims' list"]
    counts = actual_counts()
    sources: dict[str, str] = {}
    seen: set[str] = set()
    for claim in claims:
        cid = claim.get("id", "?")
        missing = [k for k in ("id", "source", "quote", "kind", "status") if not claim.get(k)]
        if missing:
            problems.append(f"{cid}: lacks {', '.join(missing)}")
            continue
        if cid in seen:
            problems.append(f"{cid}: duplicate id")
        seen.add(cid)
        if claim["status"] not in STATUSES:
            problems.append(f"{cid}: status must be one of {', '.join(STATUSES)}")
        if claim["kind"] not in KINDS:
            problems.append(f"{cid}: kind must be one of {', '.join(KINDS)}")
        source = claim["source"]
        if source.startswith("https://"):
            if not claim.get("retrieved"):
                problems.append(f"{cid}: a web claim needs 'retrieved'")
        else:
            if source not in sources:
                path = os.path.join(REPO, source)
                if not os.path.isfile(path):
                    problems.append(f"{cid}: source {source} not found")
                    continue
                with open(path, encoding="utf-8") as fh:
                    sources[source] = _normalise(fh.read())
            if _normalise(claim["quote"]) not in sources[source]:
                problems.append(f"{cid}: quote no longer in {source}: {claim['quote']!r}")
        if claim["status"] == "counted":
            name = claim.get("count")
            if name not in counts:
                problems.append(f"{cid}: unknown count {name!r}")
            elif claim.get("claimed") != counts[name]:
                problems.append(f"{cid}: claims {claim.get('claimed')} {name}, the code has "
                                f"{counts[name]}")
        if claim["status"] == "tested":
            tests = (claim.get("backing") or {}).get("tests") or []
            if not tests:
                problems.append(f"{cid}: a tested claim needs backing.tests")
            problems += [f"{cid}: test {t} not found" for t in tests if not _test_exists(t)]
        if claim["status"] in ("unmeasured", "positioning") and claim["kind"] == "quality" \
                and not claim.get("study"):
            problems.append(f"{cid}: an unmeasured quality claim must name its study")
    with open(os.path.join(REPO, SUPPORT_MATRIX), encoding="utf-8") as fh:
        table = support_matrix_counts(fh.read())
    actual = rule_prefix_counts(_rule_ids())
    if table != actual:
        diff = sorted(f"{p}: table {table.get(p, '—')}, rules {actual.get(p, '—')}"
                      for p in set(table) | set(actual) if table.get(p) != actual.get(p))
        problems.append(f"{SUPPORT_MATRIX} rule coverage differs: " + "; ".join(diff))
    return problems


def summary(ledger: dict[str, Any]) -> str:
    by_status = Counter(c.get("status") for c in ledger.get("claims") or [])
    return ", ".join(f"{by_status[s]} {s}" for s in STATUSES if by_status[s])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="claims_check", description=__doc__.split("\n\n")[0])
    parser.add_argument("--ledger", default=os.path.join(REPO, "research", "credibility",
                                                         "claims.yml"))
    parser.add_argument("--summary", action="store_true", help="also print counts by status")
    parser.add_argument("--web", action="store_true",
                        help="also fetch web sources and check their quotes")
    args = parser.parse_args(argv)
    import yaml

    try:
        with open(args.ledger, encoding="utf-8") as fh:
            ledger = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"claims_check: {exc}", file=sys.stderr)
        return 2
    problems = check(ledger)
    if args.web:
        problems += check_web(ledger.get("claims") or [])
    for problem in problems:
        print(problem)
    if args.summary or not problems:
        print(f"{len(ledger.get('claims') or [])} claims: {summary(ledger)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
