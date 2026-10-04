"""Benchmark metrics: precision/recall/F1, attribution, change, Lane-A checks.

All functions are pure and deterministic. Counts never mix aspirational
targets with measured values: thresholds live in LANE_A_TARGETS,
clearly labeled PROPOSED (per ADR-0008 they require maintainer
ratification before any gate consumes them).
"""

#: Materiality mapping: observed change_class (+status) -> brief vocabulary.
#: UNKNOWN is preserved, never coerced (conservative by design).
MATERIALITY_MAP = {
    ("unchanged", "NO_CHANGE"): "NO_CHANGE",
    ("unchanged", "LOW_CHANGE"): "NON_MATERIAL_CHANGE",
    ("changed", "LOW_CHANGE"): "NON_MATERIAL_CHANGE",
    ("new", "LOW_CHANGE"): "NON_MATERIAL_CHANGE",
    ("removed", "LOW_CHANGE"): "NON_MATERIAL_CHANGE",
    ("new", "NO_CHANGE"): "NO_CHANGE",
    ("removed", "NO_CHANGE"): "NO_CHANGE",
    ("changed", "NO_CHANGE"): "NO_CHANGE",
    ("new", "MATERIAL_CHANGE"): "MATERIAL_CHANGE",
    ("changed", "MATERIAL_CHANGE"): "MATERIAL_CHANGE",
    ("removed", "MATERIAL_CHANGE"): "AUTHORITY_REDUCTION",
    ("new", "HIGH_RISK_CHANGE"): "AUTHORITY_ESCALATION",
    ("changed", "HIGH_RISK_CHANGE"): "AUTHORITY_ESCALATION",
    ("removed", "HIGH_RISK_CHANGE"): "AUTHORITY_REDUCTION",
    ("escalated", "MATERIAL_CHANGE"): "MATERIAL_CHANGE",
    ("escalated", "HIGH_RISK_CHANGE"): "AUTHORITY_ESCALATION",
    ("escalated", "LOW_CHANGE"): "NON_MATERIAL_CHANGE",
    ("escalated", "NO_CHANGE"): "NO_CHANGE",
}

MATERIAL_SET = {"MATERIAL_CHANGE", "AUTHORITY_ESCALATION"}
ESCALATION_SET = {"AUTHORITY_ESCALATION"}

#: Proposed Lane-A graduation targets. PROPOSED ONLY — ADR-0008
#: requires maintainer ratification; no gate reads these today.
LANE_A_TARGETS = {
    "_status": "PROPOSED — not ratified, not consumed by any gate",
    "precision": 0.95,
    "recall": 0.90,
    "false_escalation_rate_max": 0.05,
    "attribution_accuracy_min": 0.95,
    "evidence_completeness_min": 0.95,
    "determinism_required": 1.0,
}


def prf(true_positives, false_positives, false_negatives):
    """Precision/recall/F1 from counts. Zero-division yields 0.0, never NaN."""
    tp, fp, fn = float(true_positives), float(false_positives), float(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": int(true_positives),
        "false_positives": int(false_positives),
        "false_negatives": int(false_negatives),
    }


def materiality(status, change_class):
    """Map observed (status, change_class) to brief materiality vocabulary."""
    if str(change_class or "").upper() == "UNKNOWN":
        return "UNKNOWN_CHANGE"
    return MATERIALITY_MAP.get(
        (str(status or "").lower(), str(change_class or "").upper()), "UNKNOWN_CHANGE"
    )


def rate(numerator, denominator):
    """Bounded rate in [0, 1]; empty denominator yields 0.0, never NaN."""
    if denominator <= 0:
        return 0.0
    return round(max(0.0, min(1.0, numerator / denominator)), 4)


def aggregate(case_results):
    """Aggregate per-case ``parts`` into corpus metrics + Lane-A report.

    ``case_results`` are the dicts returned by
    ``safeai.benchmark.compare.compare_case`` (with ``id``/``category``
    attached by the runner). Never raises on missing keys: absent
    parts count as zero, never as success.
    """
    totals = {
        "tool_exp": 0,
        "tool_hit": 0,
        "cap_exp": 0,
        "cap_hit": 0,
        "attrib_exp": 0,
        "attrib_hit": 0,
        "able_exp": 0,
        "able_hit": 0,
        "fire_exp": 0,
        "fire_hit": 0,
        "fire_fp": 0,
        "ev_exp": 0,
        "ev_hit": 0,
        "unc_exp": 0,
        "unc_hit": 0,
        "obs_esc": 0,
        "false_esc": 0,
        "unknown_obs": 0,
        "unresolved_obs": 0,
        "det_checked": 0,
        "det_clean": 0,
    }
    for result in case_results:
        parts = result.get("parts") or {}
        tools = parts.get("tools") or {}
        caps = parts.get("capabilities") or {}
        attrib = parts.get("attribution") or {}
        fire = parts.get("must_fire") or {}
        ev = parts.get("evidence") or {}
        unc = parts.get("uncertainty") or {}
        esc = parts.get("escalations") or {}
        uobs = parts.get("uncertainty_observed") or {}
        totals["tool_exp"] += int(tools.get("expected") or 0)
        totals["tool_hit"] += int(tools.get("matched") or 0)
        totals["cap_exp"] += int(caps.get("expected") or 0)
        totals["cap_hit"] += int(caps.get("matched") or 0)
        totals["attrib_exp"] += int(attrib.get("expected") or 0)
        totals["attrib_hit"] += int(attrib.get("matched") or 0)
        totals["able_exp"] += int(attrib.get("attributable_expected") or 0)
        totals["able_hit"] += int(attrib.get("attributable_matched") or 0)
        totals["fire_exp"] += int(fire.get("expected") or 0)
        totals["fire_hit"] += int(fire.get("matched") or 0)
        totals["fire_fp"] += int(fire.get("false_positives") or 0)
        totals["ev_exp"] += int(ev.get("expected") or 0)
        totals["ev_hit"] += int(ev.get("matched") or 0)
        totals["unc_exp"] += int(unc.get("expected") or 0)
        totals["unc_hit"] += int(unc.get("matched") or 0)
        totals["obs_esc"] += int(esc.get("observed") or 0)
        totals["false_esc"] += int(esc.get("false") or 0)
        totals["unknown_obs"] += int(uobs.get("unknown") or 0)
        totals["unresolved_obs"] += int(uobs.get("unresolved") or 0)
        det = result.get("determinism") or {}
        if det.get("checked"):
            totals["det_checked"] += 1
            if not det.get("violations"):
                totals["det_clean"] += 1

    discovery = prf(
        totals["fire_hit"], totals["fire_fp"], totals["fire_exp"] - totals["fire_hit"]
    )
    metrics = {
        "cases": len(case_results),
        "passed": sum(1 for r in case_results if r.get("passed")),
        "discovery": discovery,
        "tool_recall": rate(totals["tool_hit"], totals["tool_exp"]),
        "capability_recall": rate(totals["cap_hit"], totals["cap_exp"]),
        "attribution": {
            "expected": totals["attrib_exp"],
            "matched": totals["attrib_hit"],
            "end_to_end": rate(totals["attrib_hit"], totals["attrib_exp"]),
            "attributable_expected": totals["able_exp"],
            "attributable_matched": totals["able_hit"],
            "attributable_accuracy": rate(totals["able_hit"],
                                          totals["able_exp"]),
        },
        "change": {
            "observed_escalations": totals["obs_esc"],
            "false_escalations": totals["false_esc"],
            "false_escalation_rate": rate(totals["false_esc"], totals["obs_esc"] or 0),
        },
        "evidence_completeness": {
            "expected": totals["ev_exp"],
            "matched": totals["ev_hit"],
            "completeness": rate(totals["ev_hit"], totals["ev_exp"]),
        },
        "uncertainty_expression": {
            "expected": totals["unc_exp"],
            "matched": totals["unc_hit"],
            "recall": rate(totals["unc_hit"], totals["unc_exp"]),
        },
        "determinism": {
            "checked": totals["det_checked"],
            "clean": totals["det_clean"],
            "rate": rate(totals["det_clean"], totals["det_checked"]),
        },
        "unknown_unresolved_count": (totals["unknown_obs"] + totals["unresolved_obs"]),
    }
    lane_a = check_lane_a(metrics)
    return {
        "cases": case_results,
        "summary": {
            "total": len(case_results),
            "passed": metrics["passed"],
            "failed": len(case_results) - metrics["passed"],
        },
        "metrics": metrics,
        "lane_a": lane_a,
    }


def check_lane_a(metrics, targets=None):
    """Evaluate measured metrics against Lane-A graduation targets.

    Returns {"eligible": bool, "gates": [...], "notes": [...]}.
    Eligibility requires every gate to pass; unknown verdicts and
    unresolved evidence veto eligibility for the affected class.
    This function only REPORTS — no policy or gate consumes it.
    """
    targets = targets or LANE_A_TARGETS
    gates = []
    notes = ["Targets are PROPOSED per ADR-0008; no gate consumes this output."]

    def gate(name, value, threshold, higher_is_better=True):
        passed = (value >= threshold) if higher_is_better else (value <= threshold)
        gates.append(
            {
                "name": name,
                "value": value,
                "threshold": threshold,
                "passed": bool(passed),
            }
        )
        return bool(passed)

    discovery = metrics.get("discovery", {})
    attribution = metrics.get("attribution", {})
    change = metrics.get("change", {})
    evidence = metrics.get("evidence_completeness", {})
    determinism = metrics.get("determinism", {})

    results = [
        gate(
            "discovery_precision", discovery.get("precision", 0.0), targets["precision"]
        ),
        gate("discovery_recall", discovery.get("recall", 0.0), targets["recall"]),
        gate(
            "attribution_accuracy",
            attribution.get("end_to_end", 0.0),
            targets["attribution_accuracy_min"],
        ),
        gate(
            "false_escalation_rate",
            change.get("false_escalation_rate", 1.0),
            targets["false_escalation_rate_max"],
            higher_is_better=False,
        ),
        gate(
            "evidence_completeness",
            evidence.get("completeness", 0.0),
            targets["evidence_completeness_min"],
        ),
        gate(
            "determinism", determinism.get("rate", 0.0), targets["determinism_required"]
        ),
    ]
    if metrics.get("unknown_unresolved_count", 0) > 0:
        notes.append(
            "Unresolved/unknown items veto class-level graduation "
            "until resolved or explicitly scoped."
        )
    return {"eligible": all(results), "gates": gates, "notes": notes}
