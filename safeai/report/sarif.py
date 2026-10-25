"""SARIF 2.1.0 report writer.

Converts SafeAI findings into the SARIF format compatible with
GitHub Advanced Security, Azure DevOps, and other SARIF consumers.
Each finding becomes a SARIF result with OWASP LLM attribution
and SafeAI-specific properties (risk category, confidence,
remediation, etc.).
"""

import json


def write_sarif(report, path):
    findings = report["findings"]

    # Stable rule metadata with remediation help text where available.
    rules_meta = {}
    for finding in findings:
        rule_id = finding.get("rule_id")
        if rule_id and rule_id not in rules_meta:
            entry = {"id": rule_id}
            if finding.get("remediation"):
                entry["help"] = {"text": finding["remediation"]}
            if finding.get("message"):
                entry["shortDescription"] = {"text": str(finding["message"]).split("\n")[0][:160]}
            rules_meta[rule_id] = entry

    results = []
    for f in findings:
        result = {
            "ruleId": f["rule_id"],
            "message": {"text": f["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f["line"]},
                    }
                }
            ],
            "properties": {"owasp_llm": f.get("owasp_llm")},
        }
        if f.get("fingerprint"):
            result["partialFingerprints"] = {"safeaiFindingFingerprint": f["fingerprint"]}
        if f.get("status"):
            result.setdefault("properties", {})["status"] = f["status"]
        results.append(result)

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "safeai", "rules": list(rules_meta.values())}},
                "results": results,
            }
        ],
    }

    for result, finding in zip(sarif["runs"][0]["results"], findings):
        props = result.setdefault("properties", {})
        for key in [
            "risk_category",
            "affected_framework",
            "affected_capability",
            "score_contribution",
            "confidence",
            "confidence_label",
            "evidence_type",
            "resolved_definition",
            "schema_version",
            "validation_rule",
            "affected_object",
        ]:
            if key in finding:
                props[key] = finding.get(key)
        if finding.get("evidence"):
            props["evidence"] = finding.get("evidence")
        if finding.get("reason"):
            props["reason"] = finding.get("reason")
        if finding.get("remediation"):
            props["remediation"] = finding.get("remediation")

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
