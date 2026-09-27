"""IaC benchmark corpus harness (v2.5 redesign).

Loads ``tests/fixtures/iac/benchmark/catalog.yml``, runs extraction,
linking, and verdicts per case, asserts exact match with hand-verified
ground truth, and reports per-category precision/recall. This corpus —
not unit-test pass rates — is the precision boundary for any future
Lane-A graduation proposal (ADR-0008).
"""

import os

import yaml

from safeai.analysis.iac_correlation import correlate_iac_authority
from safeai.iac import scan_iac
from safeai.iac.k8s import parse_k8s_file
from safeai.iac.terraform import parse_terraform_file

BASE = os.path.join(os.path.dirname(__file__), "fixtures", "iac",
                    "benchmark")


def _load_catalog():
    with open(os.path.join(BASE, "catalog.yml"), encoding="utf-8") as fh:
        return yaml.safe_load(fh)["cases"]


CASES = _load_catalog()


def _read(rel):
    with open(os.path.join(BASE, rel), encoding="utf-8") as fh:
        return fh.read()


def _check_identities(case, identities):
    expected = {(e.get("kind"), e.get("name"), e.get("namespace") or "")
                for e in case.get("identities") or []}
    got = {(i.get("kind"), i.get("name"), i.get("namespace") or "")
           for i in identities}
    assert got == expected, f"{case['id']}: identities {got} != {expected}"
    return len(expected), len(got)


def _check_grants(case, grants):
    matched = 0
    for expected in case.get("grants") or []:
        candidates = [g for g in grants
                      if (g.get("identity") or {}).get("name")
                      == expected.get("identity")]
        assert candidates, \
            f"{case['id']}: no grant for {expected.get('identity')}"
        grant = candidates[0]
        if "actions" in expected:
            assert sorted(grant["actions"]["values"]) == \
                sorted(expected["actions"]), \
                f"{case['id']}: actions {grant['actions']['values']}"
        if "resources" in expected:
            assert sorted(grant["resources"]["values"]) == \
                sorted(expected["resources"]), \
                f"{case['id']}: resources {grant['resources']['values']}"
        if "resolution" in expected:
            assert grant["actions"]["resolution"] == expected["resolution"], \
                f"{case['id']}: resolution {grant['actions']['resolution']}"
        if "fidelity" in expected:
            for note in expected["fidelity"]:
                assert note in grant["fidelity"], \
                    f"{case['id']}: missing fidelity {note}"
        matched += 1
    return matched, len(grants)


def _check_case(case):
    """Run one catalog case; return (expected_items, matched_items)."""
    kind = case["kind"]
    if kind == "terraform":
        assert len(case["files"]) == 1
        identities, grants, bindings, meta = parse_terraform_file(
            case["files"][0], _read(case["files"][0]))
        exp_i, _ = _check_identities(case, identities)
        matched_g, _got_g = _check_grants(case, grants)
        assert len(bindings) == case.get("bindings", 0), \
            f"{case['id']}: bindings {len(bindings)}"
        assert sorted(meta.get("detached_policies") or []) == \
            sorted(case.get("detached") or []), f"{case['id']}: detached"
        assert sorted(meta.get("module_refs") or []) == \
            sorted(case.get("modules") or []), f"{case['id']}: modules"
        assert bool(meta.get("unparsed")) == bool(case.get("unparsed", False)), \
            f"{case['id']}: unparsed"
        return exp_i + len(case.get("grants") or []), \
            exp_i + matched_g
    if kind == "kubernetes":
        identities, grants, bindings, _, meta = parse_k8s_file(
            case["files"][0], _read(case["files"][0]))
        exp_i, _ = _check_identities(case, identities)
        matched_g, _got_g = _check_grants(case, grants)
        assert len(bindings) == case.get("bindings", 0), \
            f"{case['id']}: bindings {len(bindings)}"
        assert bool(meta.get("unparsed")) == bool(case.get("unparsed", False)), \
            f"{case['id']}: unparsed"
        return exp_i + len(case.get("grants") or []), \
            exp_i + matched_g
    if kind == "linking":
        graph, _ = scan_iac(os.path.join(BASE, case["dir"]))
        links = graph["agent_links"]
        assert len(links) == case.get("links", 0), \
            f"{case['id']}: links {len(links)}"
        if case.get("links"):
            assert all(l["confidence"] == case["link_confidence"]
                       for l in links), f"{case['id']}: confidence"
            for link in links:
                assert link["evidence"], f"{case['id']}: link needs evidence"
        return case.get("links", 0), len(links)
    if kind == "verdict":
        graph, meta = scan_iac(os.path.join(BASE, case["dir"]))
        graph["meta"] = meta
        report = {"tool_surface": [
            {"tool_key": item["tool"],
             "capabilities": [{"name": item["cap"], "access_mode": "read"}]}
            for item in case.get("declared") or []], "findings": []}
        findings, summary = correlate_iac_authority(report, graph)
        actual = {v["domain"]: v["verdict"]
                  for v in summary.get("verdicts") or []}
        expected = dict(case.get("verdicts") or {})
        for domain, name in expected.items():
            assert actual.get(domain) == name, \
                f"{case['id']}: {domain} is {actual.get(domain)}"
        strict_actual = {d: v for d, v in actual.items() if v != "UNKNOWN"}
        strict_expected = {d: v for d, v in expected.items()
                           if v != "UNKNOWN"}
        assert strict_actual == strict_expected, \
            f"{case['id']}: non-UNKNOWN verdicts {strict_actual}"
        actual_rules = sorted(f["rule_id"] for f in findings)
        assert actual_rules == sorted(case.get("findings") or []), \
            f"{case['id']}: findings {actual_rules}"
        for finding in findings:
            assert finding["gateability"] == "review-only"
        return len(expected), len(expected)
    raise AssertionError(f"unknown kind {kind}")


def test_benchmark_terraform_cases():
    for case in CASES:
        if case["kind"] == "terraform":
            _check_case(case)


def test_benchmark_kubernetes_cases():
    for case in CASES:
        if case["kind"] == "kubernetes":
            _check_case(case)


def test_benchmark_linking_cases():
    for case in CASES:
        if case["kind"] == "linking":
            _check_case(case)


def test_benchmark_verdict_cases():
    for case in CASES:
        if case["kind"] == "verdict":
            _check_case(case)


def test_benchmark_metrics_at_precision_boundary():
    """Aggregate corpus metrics: extraction, linking, verdicts.

    Every rate below is 1.0 by construction (ground truth) — the test
    pins the boundary and prints it for the record. UNVERIFIED_LINK
    dominance and UNKNOWN coverage are asserted to prove the corpus
    exercises restraint, not just detection.
    """
    exp_total = matched_total = 0
    link_exp = link_got = 0
    verdict_names = []
    for case in CASES:
        kind = case["kind"]
        if kind in ("terraform", "kubernetes"):
            exp, matched = _check_case(case)
            exp_total += exp
            matched_total += matched
        elif kind == "linking":
            link_exp += case.get("links", 0)
            graph, _ = scan_iac(os.path.join(BASE, case["dir"]))
            link_got += len(graph["agent_links"])
        elif kind == "verdict":
            _check_case(case)
            verdict_names.extend((case.get("verdicts") or {}).values())
    extraction = matched_total / exp_total
    linking = (link_got / link_exp) if link_exp else 1.0
    print(f"\nbenchmark: extraction precision/recall {extraction:.3f} "
          f"({matched_total}/{exp_total})")
    print(f"benchmark: identity-link precision/recall {linking:.3f} "
          f"({link_got}/{link_exp})")
    print(f"benchmark: verdicts exercised {sorted(set(verdict_names))}")
    assert extraction == 1.0
    assert linking == 1.0
    assert "UNVERIFIED_LINK" in verdict_names
    assert "UNKNOWN" in verdict_names
    assert "MATCH" in verdict_names
