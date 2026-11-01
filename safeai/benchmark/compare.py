"""Structural comparison: expected truth vs observed scan output.

Two layers run on every case:

- Legacy section checks (agents/tools/identities/grants/links/verdicts,
  changes channels, must_fire, evidence refs, uncertainty pools).
- Canonical comparison (``safeai.benchmark.canonical``):
  implementation-independent gold truth vs a neutral projection of
  the scan output — entity discovery, 8 attribution levels, change /
  escalation PRF, unknown preservation. Missing gold sections report
  ``insufficient_evidence``, never 0/1.
"""

import os


def _edge_key(source, target, exceeds):
    """Comparable delegation edge: ``exceeds`` None means "not evaluated"."""
    return (str(source), str(target),
            None if exceeds is None else ",".join(sorted(exceeds)))


def _compare_delegation_edges(truth, graph, failures):
    """Exact-set comparison of delegation edges by ``framework:name`` (v2.11)."""
    names = {n.get("id"): f"{n.get('framework')}:{n.get('name')}"
             for n in graph.get("nodes") or [] if isinstance(n, dict)}
    obs = {_edge_key(names.get(e.get("from")), names.get(e.get("to")), e.get("exceeds"))
           for e in graph.get("edges") or [] if isinstance(e, dict)}
    exp = {_edge_key(e.get("from"), e.get("to"), e.get("exceeds")) for e in truth}
    if exp != obs:
        failures.append(f"delegation_edges: missing {sorted(exp - obs, key=str)}, "
                        f"unexpected {sorted(obs - exp, key=str)}")
    return {"expected": len(exp), "matched": len(exp & obs), "observed": len(obs)}


def _workload_identity_sets(block):
    """Observed workload-identity facts as comparable sets (v2.10)."""
    assignments = {
        (str(a.get("workload")), str(a.get("spiffe_id")), str(a.get("resolution")))
        for a in block.get("assignments") or [] if isinstance(a, dict)}
    unknown = {
        str(w.get("workload")) for w in block.get("workloads") or []
        if isinstance(w, dict) and w.get("identity_state") == "unknown"}
    callers = set()
    for policy in block.get("authorization_policies") or []:
        if not isinstance(policy, dict):
            continue
        label = f"{policy.get('namespace')}/{policy.get('name')}"
        for principal in policy.get("principals") or []:
            if principal.get("negated"):
                continue
            for caller in principal.get("callers") or []:
                callers.add((label, str(principal.get("principal")),
                             str(caller.get("workload")), str(caller.get("basis"))))
    static = {str(s.get("workload")) for s in block.get("static_credentials") or []
              if isinstance(s, dict)}
    federations = {
        (str(a.get("workload")), str(domain))
        for a in block.get("assignments") or [] if isinstance(a, dict)
        for domain in a.get("federates_with") or []}
    return {"assignments": assignments, "unknown": unknown, "callers": callers,
            "static_credentials": static, "federations": federations}


def _compare_workload_identity(truth, block, failures):
    """Exact-set comparison of the ``workload_identity`` truth section.

    Each listed key is compared as a set; a key absent from the truth is
    not checked. Returns the part record (expected / matched per key).
    """
    observed = _workload_identity_sets(block if isinstance(block, dict) else {})
    expected = {
        "assignments": {(str(a.get("workload")), str(a.get("spiffe_id")),
                         str(a.get("resolution") or "resolved"))
                        for a in truth.get("assignments") or []},
        "unknown": {str(w) for w in truth.get("unknown") or []},
        "callers": {(str(c.get("policy")), str(c.get("principal")),
                     str(c.get("workload")), str(c.get("basis") or "spiffe-assignment"))
                    for c in truth.get("callers") or []},
        "static_credentials": {str(w) for w in truth.get("static_credentials") or []},
        "federations": {(str(f.get("workload")), str(f.get("trust_domain")))
                        for f in truth.get("federations") or []},
    }
    part = {}
    for key, exp in expected.items():
        if key not in truth:
            continue
        obs = observed[key]
        if exp != obs:
            failures.append(
                f"workload_identity {key}: missing {sorted(exp - obs)}, "
                f"unexpected {sorted(obs - exp)}")
        part[key] = {"expected": len(exp), "matched": len(exp & obs),
                     "observed": len(obs)}
    return part


def _surface_index(report):
    index = {}
    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict):
            continue
        key = str(tool.get("tool_key") or "")
        caps = {}
        for cap in tool.get("capabilities") or []:
            if not isinstance(cap, dict):
                continue
            caps[str(cap.get("name") or "")] = {
                "access_mode": str(cap.get("access_mode") or ""),
                "inferred": bool(
                    cap.get("inferred") or cap.get("access_mode_inferred")
                ),
            }
        index[key] = caps
    return index


def _finding_rules(report):
    return {
        str(f.get("rule_id"))
        for f in report.get("findings") or []
        if isinstance(f, dict)
    }


def _new_rule_ids(report):
    return {
        str(f.get("rule_id"))
        for f in report.get("findings") or []
        if isinstance(f, dict) and f.get("status") == "new"
    }


def _evidence_basenames(report):
    """Every basename any evidence reference points at."""
    names = set()
    import os

    def add(path):
        if path and isinstance(path, str) and not path.startswith("<"):
            names.add(os.path.basename(path.replace("\\", "/")))

    for finding in report.get("findings") or []:
        if isinstance(finding, dict):
            add(finding.get("file"))
    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict):
            continue
        for cap in tool.get("capabilities") or []:
            if not isinstance(cap, dict):
                continue
            for ev in cap.get("evidence") or []:
                if isinstance(ev, dict):
                    add(ev.get("path"))
    iac = report.get("iac_correlations") or {}
    if isinstance(iac, dict):
        for identity in iac.get("identities") or []:
            if isinstance(identity, dict):
                add(str(identity.get("source_ref") or "").rsplit(":", 1)[0])
        for grant in iac.get("grants") or []:
            if isinstance(grant, dict):
                add(grant.get("source_file"))
        for verdict in iac.get("verdicts") or []:
            if not isinstance(verdict, dict):
                continue
            for ref in (verdict.get("grant_evidence_refs") or []) + (
                verdict.get("link_evidence_refs") or []
            ):
                add(str(ref).rsplit(":", 1)[0])
        for link in iac.get("agent_identity_links") or []:
            if not isinstance(link, dict):
                continue
            for ev in link.get("evidence") or []:
                if isinstance(ev, dict):
                    add(ev.get("file"))
    return names


def _surface_evidence_files(report):
    """Basenames any surface capability cites as evidence."""
    import os

    names = set()
    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict):
            continue
        for cap in tool.get("capabilities") or []:
            if not isinstance(cap, dict):
                continue
            for ev in cap.get("evidence") or []:
                if isinstance(ev, dict):
                    path = ev.get("path")
                    if path and isinstance(path, str) and not path.startswith("<"):
                        names.add(os.path.basename(path.replace("\\", "/")))
    return names


def _uncertainty_pools(report):
    """Searchable pools per uncertainty kind.

    Pools are search indexes, not partitions: an UNKNOWN IaC verdict
    is both an undeterminable authority (``unknown``) and a grant with
    no workload link (``unlinked``). Likewise a capability finding on
    a file no surface capability cites is unattributed evidence
    (``unlinked``) even though the rule itself fired cleanly.
    """
    inferred, unresolved, unknown, unlinked = set(), set(), set(), set()
    for tool in report.get("tool_surface") or []:
        if not isinstance(tool, dict):
            continue
        key = str(tool.get("tool_key") or "")
        for cap in tool.get("capabilities") or []:
            if not isinstance(cap, dict):
                continue
            name = str(cap.get("name") or "")
            if cap.get("inferred") or cap.get("access_mode_inferred"):
                inferred.add(f"{key}:{name}")
                inferred.add(name)
            if key == "unknown:unattributed":
                unlinked.add(name)
    iac = report.get("iac_correlations") or {}
    if isinstance(iac, dict):
        for grant in iac.get("grants") or []:
            if not isinstance(grant, dict):
                continue
            actions = grant.get("actions") or {}
            resources = grant.get("resources") or {}
            ident = (grant.get("identity") or {}).get("name", "")
            if (
                actions.get("resolution") != "resolved"
                or resources.get("resolution") != "resolved"
            ):
                unresolved.add(str(ident))
        for verdict in iac.get("verdicts") or []:
            if not isinstance(verdict, dict):
                continue
            domain = str(verdict.get("domain") or "")
            if verdict.get("verdict") == "UNKNOWN":
                unknown.add(domain)
                # A grant no workload links to is unlinked by definition.
                unlinked.add(domain)
            if verdict.get("verdict") == "UNVERIFIED_LINK":
                unlinked.add(domain)
    cited = _surface_evidence_files(report)
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        rule = str(finding.get("rule_id") or "")
        if not rule.startswith("CAP_"):
            continue
        path = finding.get("file") or ""
        if isinstance(path, str) and not path.startswith("<"):
            base = os.path.basename(path.replace("\\", "/"))
            if base not in cited:
                # Capability evidence the surface attributes to no tool.
                unlinked.add(rule)
                unlinked.add(base)
    return {
        "inferred": inferred,
        "unresolved": unresolved,
        "unknown": unknown,
        "unlinked": unlinked,
    }


def compare_case(expected, current, baseline=None):
    """Compare one case; return result dict with failures[] and metrics parts."""
    failures = []
    parts = {}

    # --- agents ---
    agent_models = current.get("agent_models") or []
    exp_agents = expected.get("agents", [])
    exp_set = {(a.get("framework"), a.get("name")) for a in exp_agents}
    got_set = set()
    for model in agent_models:
        if not isinstance(model, dict):
            continue
        for agent in (model.get("data") or {}).get("agents") or []:
            if isinstance(agent, dict):
                got_set.add((model.get("framework"), agent.get("name")))
    if exp_set - got_set:
        failures.append(f"agents missing: {sorted(exp_set - got_set)}")
    if got_set - exp_set:
        failures.append(f"agents unexpected: {sorted(got_set - exp_set)}")
    parts["agents"] = {"expected": len(exp_set), "matched": len(exp_set & got_set)}

    # --- tools + capabilities ---
    surface = _surface_index(current)
    tool_hits = tool_total = 0
    cap_hits = cap_total = 0
    attrib_hits = attrib_total = 0
    able_exp = able_hit = 0
    for tool in expected.get("tools", []):
        key = str(tool.get("tool_key") or "")
        tool_total += 1
        if key not in surface:
            failures.append(f"tool missing from surface: {key}")
            continue
        tool_hits += 1
        observed_caps = surface[key]
        for cap in tool.get("capabilities") or []:
            name = str(cap.get("name") or "")
            cap_total += 1
            attrib_total += 1
            actual = observed_caps.get(name)
            if actual is None:
                failures.append(f"capability missing: {key}:{name}")
                continue
            if str(cap.get("access_mode") or "") and actual["access_mode"] != str(
                cap.get("access_mode")
            ):
                failures.append(
                    f"access mode mismatch: {key}:{name} "
                    f"expected {cap.get('access_mode')}, "
                    f"got {actual['access_mode']}"
                )
                continue
            cap_hits += 1
            if key != "unknown:unattributed":
                attrib_hits += 1
                able_exp += 1
                able_hit += 1
            else:
                # Unattributed bucket: recorded in end-to-end totals,
                # never counted as attribution accuracy.
                pass
        if key != "unknown:unattributed":
            extra = set(observed_caps) - {
                str(c.get("name") or "") for c in tool.get("capabilities") or []
            }
            if extra:
                failures.append(f"unexpected capabilities on {key}: {sorted(extra)}")
    parts["tools"] = {"expected": tool_total, "matched": tool_hits}
    parts["capabilities"] = {"expected": cap_total, "matched": cap_hits}
    parts["attribution"] = {
        "expected": attrib_total,
        "matched": attrib_hits,
        "attributable_expected": able_exp,
        "attributable_matched": able_hit,
    }

    # --- identities / grants / links / verdicts ---
    iac = current.get("iac_correlations") or {}
    if not isinstance(iac, dict):
        iac = {}
    obs_idents = {
        (str(i.get("kind")), str(i.get("name")), str(i.get("namespace") or ""))
        for i in iac.get("identities") or []
        if isinstance(i, dict)
    }
    exp_idents = {
        (str(i.get("kind")), str(i.get("name")), str(i.get("namespace") or ""))
        for i in expected.get("identities", [])
    }
    if exp_idents != obs_idents and ("identities" in expected):
        if exp_idents - obs_idents:
            failures.append(f"identities missing: {sorted(exp_idents - obs_idents)}")
        if obs_idents - exp_idents:
            failures.append(f"identities unexpected: {sorted(obs_idents - exp_idents)}")
    parts["identities"] = {
        "expected": len(exp_idents),
        "matched": len(exp_idents & obs_idents),
    }

    obs_grants = iac.get("grants") or []
    grant_hits = grant_total = 0
    for grant in expected.get("grants", []):
        grant_total += 1
        name = grant.get("identity")
        candidates = [
            g
            for g in obs_grants
            if isinstance(g, dict) and (g.get("identity") or {}).get("name") == name
        ]
        if not candidates:
            failures.append(f"grant missing for identity: {name}")
            continue
        matched = False
        for candidate in candidates:
            actions = (candidate.get("actions") or {}).get("values") or []
            resources = (candidate.get("resources") or {}).get("values") or []
            ok = True
            if "actions" in grant and sorted(actions) != sorted(grant["actions"]):
                ok = False
            if "resources" in grant and sorted(resources) != sorted(grant["resources"]):
                ok = False
            if (
                "resolution" in grant
                and (candidate.get("actions") or {}).get("resolution")
                != grant["resolution"]
            ):
                ok = False
            if ok:
                matched = True
                break
        if not matched:
            failures.append(f"grant mismatch for identity: {name}")
            continue
        grant_hits += 1
    parts["grants"] = {"expected": grant_total, "matched": grant_hits}

    if "links" in expected:
        obs_links = {
            (
                str((l.get("identity") or {}).get("name")),
                str((l.get("identity") or {}).get("namespace") or ""),
            )
            for l in iac.get("agent_identity_links") or []
            if isinstance(l, dict)
        }
        exp_links = {
            (str(l.get("identity")), str(l.get("namespace") or ""))
            for l in expected.get("links") or []
        }
        if obs_links != exp_links:
            failures.append(
                f"links mismatch: expected {sorted(exp_links)}, got {sorted(obs_links)}"
            )
        parts["links"] = {
            "expected": len(exp_links),
            "matched": len(exp_links & obs_links),
        }
    else:
        parts["links"] = {"expected": 0, "matched": 0}

    if "verdicts" in expected:
        obs_verdicts = {
            str(v.get("domain")): str(v.get("verdict"))
            for v in iac.get("verdicts") or []
            if isinstance(v, dict)
        }
        if obs_verdicts != dict(expected.get("verdicts") or {}):
            failures.append(
                f"verdicts mismatch: expected {expected.get('verdicts')}, "
                f"got {obs_verdicts}"
            )
        parts["verdicts"] = {
            "expected": len(expected.get("verdicts") or {}),
            "matched": sum(
                1
                for d, v in (expected.get("verdicts") or {}).items()
                if obs_verdicts.get(d) == v
            ),
        }

    if "sod_conflicts" in expected:
        block = current.get("separation_of_duties") or {}
        obs = {(str(c.get("holder")), str(c.get("pair")))
               for c in block.get("conflicts") or [] if isinstance(c, dict)}
        exp = {(str(c.get("holder")), str(c.get("pair")))
               for c in expected.get("sod_conflicts") or []}
        if exp != obs:
            failures.append(f"sod_conflicts: missing {sorted(exp - obs)}, "
                            f"unexpected {sorted(obs - exp)}")
        parts["sod_conflicts"] = {"expected": len(exp), "matched": len(exp & obs),
                                  "observed": len(obs)}
    if "delegation_edges" in expected:
        parts["delegation_edges"] = _compare_delegation_edges(
            expected.get("delegation_edges") or [], current.get("delegation_graph") or {},
            failures)
    if "delegation_unresolved" in expected:
        graph = current.get("delegation_graph") or {}
        observed = len(graph.get("unresolved") or [])
        if observed != int(expected["delegation_unresolved"]):
            failures.append(f"delegation_unresolved: expected "
                            f"{expected['delegation_unresolved']}, got {observed}")
    if "delegation_changes" in expected:
        block = (current.get("capability_diff") or {}).get("delegation_changes") or {}
        obs = {(str(c.get("type")), str(c.get("subject")))
               for c in block.get("changes") or [] if isinstance(c, dict)}
        exp = {(str(c.get("type")), str(c.get("subject")))
               for c in expected.get("delegation_changes") or []}
        if exp != obs:
            failures.append(f"delegation_changes: missing {sorted(exp - obs)}, "
                            f"unexpected {sorted(obs - exp)}")
        parts["delegation_changes"] = {"expected": len(exp), "matched": len(exp & obs),
                                       "observed": len(obs)}

    if "identity_changes" in expected:
        diff = current.get("capability_diff") or {}
        block = diff.get("workload_identity_changes") or {}
        obs = {(str(c.get("type")), str(c.get("workload")), str(c.get("subject")))
               for c in block.get("changes") or [] if isinstance(c, dict)}
        exp = {(str(c.get("type")), str(c.get("workload") or ""), str(c.get("subject")))
               for c in expected.get("identity_changes") or []}
        if exp != obs:
            failures.append(
                f"identity_changes: missing {sorted(exp - obs)}, "
                f"unexpected {sorted(obs - exp)}")
        parts["identity_changes"] = {"expected": len(exp), "matched": len(exp & obs),
                                     "observed": len(obs)}

    if "workload_identity" in expected:
        parts["workload_identity"] = _compare_workload_identity(
            expected.get("workload_identity") or {},
            iac.get("workload_identity") or {}, failures)

    # --- changes ---
    # Entries carry no tool_key by design (descriptive label only): the
    # scanner cannot attribute these, so per-channel detection claims
    # are enforced and everything else is measured, never asserted.
    observed_rules = _finding_rules(current)
    new_rules = _new_rule_ids(current)
    summary = current.get("baseline") or {}
    if not isinstance(summary, dict):
        summary = {}
    diff_tools = (current.get("capability_diff") or {}).get("tools") or []
    observed_escalations = sum(
        1
        for t in diff_tools
        if isinstance(t, dict)
        and str(t.get("change_class") or "").upper() == "HIGH_RISK_CHANGE"
        and str(t.get("status") or "").lower() in ("new", "changed", "escalated")
    )
    expected_escalations = len({
        (str(e.get("materiality") or e.get("kind") or ""),
         str(e.get("status") or "").lower(),
         str(e.get("tool") or e.get("subject") or ""))
        for e in list(expected.get("changes", []) or [])
        + list((expected.get("canonical") or {}).get("changes") or [])
        if isinstance(e, dict)
        and str(e.get("materiality") or e.get("kind") or "")
        == "AUTHORITY_ESCALATION"
        and str(e.get("status") or "").lower() in ("new", "changed")
    })
    change_hits = change_total = unmeasurable = 0
    for entry in expected.get("changes", []):
        if not isinstance(entry, dict):
            continue
        change_total += 1
        label = str(entry.get("tool") or "<?>")
        channels = entry.get("channels") or []
        new_expected = entry.get("new_findings") or []
        if not channels:
            # No channel claim: documentary only (e.g. identity swap,
            # wildcard grant). Hard truth for these lives in the
            # identities/grants/must_fire sections above.
            unmeasurable += 1
            continue
        entry_ok = True
        if "findings" in channels:
            for rule in new_expected:
                if str(rule) not in new_rules:
                    failures.append(
                        f"change '{label}': expected new finding "
                        f"{rule}; observed new: {sorted(new_rules)}"
                    )
                    entry_ok = False
        if "summary" in channels:
            if str(entry.get("status") or "").lower() == "removed":
                if int(summary.get("resolved") or 0) <= 0:
                    failures.append(
                        f"change '{label}': expected resolved count in baseline summary"
                    )
                    entry_ok = False
            elif new_expected:
                for rule in new_expected:
                    if str(rule) not in observed_rules:
                        failures.append(
                            f"change '{label}': expected finding {rule} not observed"
                        )
                        entry_ok = False
        if "surface" in channels:
            # Claimed only when the diff names the tool. No entry in
            # this corpus claims it (known attribution gap).
            failures.append(
                f"change '{label}': surface channel claimed but no "
                f"tool_key carried — truth cannot name the tool"
            )
            entry_ok = False
        if entry_ok:
            change_hits += 1
    parts["changes"] = {
        "expected": change_total,
        "matched": change_hits,
        "unmeasurable": unmeasurable,
    }
    parts["escalations"] = {
        "observed": observed_escalations,
        "expected": expected_escalations,
        "false": max(0, observed_escalations - expected_escalations),
    }
    if observed_escalations > expected_escalations:
        failures.append(
            f"possible false escalation: observed "
            f"{observed_escalations} HIGH_RISK diff tool(s), expected "
            f"{expected_escalations}"
        )

    # --- must_fire / must_not_fire ---
    fire_hits = fire_total = 0
    for rule in expected.get("must_fire", []):
        fire_total += 1
        if str(rule) in observed_rules:
            fire_hits += 1
        else:
            failures.append(f"must_fire rule silent: {rule}")
    fp_total = 0
    for rule in expected.get("must_not_fire", []):
        if str(rule) in observed_rules:
            failures.append(f"must_not_fire rule fired: {rule}")
            fp_total += 1
    parts["must_fire"] = {
        "expected": fire_total,
        "matched": fire_hits,
        "false_positives": fp_total,
    }

    # --- evidence_refs ---
    basenames = _evidence_basenames(current)
    ev_hits = ev_total = 0
    for ref in expected.get("evidence_refs", []):
        ev_total += 1
        if str(ref) in basenames:
            ev_hits += 1
        else:
            failures.append(f"evidence ref not cited: {ref}")
    parts["evidence"] = {"expected": ev_total, "matched": ev_hits}

    # --- uncertainty ---
    pools = _uncertainty_pools(current)
    unc_hits = unc_total = 0
    for item in expected.get("uncertainty", []):
        if not isinstance(item, dict):
            continue
        unc_total += 1
        kind = str(item.get("kind") or "")
        match = str(item.get("match") or "")
        pool = pools.get(kind, set())
        if any(match in candidate for candidate in pool):
            unc_hits += 1
        else:
            failures.append(
                f"uncertainty not expressed: kind={kind} match={match} "
                f"(pool has {len(pool)} item(s))"
            )
    parts["uncertainty"] = {"expected": unc_total, "matched": unc_hits}
    parts["uncertainty_observed"] = {
        "unknown": len(pools["unknown"]),
        "unresolved": len(pools["unresolved"]),
    }

    # --- canonical (implementation-independent) comparison ---
    from safeai.benchmark import canonical as canon_mod

    gold, gold_notes = canon_mod.gold_from_expected(expected)
    schema_problems = canon_mod.validate_gold(gold)
    if schema_problems:
        failures.append(
            "canonical gold invalid: " + "; ".join(schema_problems))
    for contradiction in canon_mod.check_consistency(expected):
        failures.append(f"gold contradiction: {contradiction}")
    obs = canon_mod.project_report(current)
    canon_result = canon_mod.compare_all(gold, obs, current, baseline)
    failures.extend(canon_result["failures"])
    parts["canonical"] = canon_result["parts"]
    parts["canonical"]["gold_derived_from_legacy"] = gold.get(
        "derived_from_legacy", False)
    parts["canonical"]["gold_notes"] = gold_notes

    return {"passed": not failures, "failures": failures, "parts": parts}
