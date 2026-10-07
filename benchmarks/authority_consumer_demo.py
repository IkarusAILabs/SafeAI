#!/usr/bin/env python3
"""
Independent consumer demonstration for the Agent Authority Evidence Contract.

This script demonstrates how to:
1. Load and validate the authority_evidence section of a KYA manifest
2. Reconstruct delegation chains from delegation evidence
3. Output authority statements in a human-readable format
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional


def load_manifest(manifest_path: Path) -> Dict[str, Any]:
    """Load a KYA manifest from JSON file."""
    with open(manifest_path, 'r') as f:
        return json.load(f)


def validate_authority_evidence_schema(authority_evidence: Dict[str, Any]) -> List[str]:
    """
    Validate the authority_evidence section against the expected schema.
    
    Returns a list of validation errors (empty if valid).
    """
    errors = []
    
    # Check required top-level fields
    required_fields = [
        "contract_identity",
        "subject_agents", 
        "principal_evidence",
        "delegation_evidence",
        "authority_statements",
        "evidence_references",
        "uncertainty_summary",
        "assurance_boundary",
        "source_revision",
        "safeai_version",
        "ruleset_version",
        "change_context"
    ]
    
    for field in required_fields:
        if field not in authority_evidence:
            errors.append(f"Missing required field: {field}")
    
    if errors:
        return errors
        
    # Validate contract_identity
    contract_identity = authority_evidence.get("contract_identity", {})
    if not isinstance(contract_identity, dict):
        errors.append("contract_identity must be an object")
    else:
        if "name" not in contract_identity or not isinstance(contract_identity.get("name"), str):
            errors.append("contract_identity.name must be a string")
        if "version" not in contract_identity or not isinstance(contract_identity.get("version"), str):
            errors.append("contract_identity.version must be a string")
    
    # Validate subject_agents
    subject_agents = authority_evidence.get("subject_agents", [])
    if not isinstance(subject_agents, list):
        errors.append("subject_agents must be an array")
    else:
        for i, agent in enumerate(subject_agents):
            if not isinstance(agent, dict):
                errors.append(f"subject_agents[{i}] must be an object")
                continue
            if "agent_id" not in agent or not isinstance(agent.get("agent_id"), str):
                errors.append(f"subject_agents[{i}].agent_id must be a string")
            if "framework" not in agent or not isinstance(agent.get("framework"), str):
                errors.append(f"subject_agents[{i}].framework must be a string")
    
    # Validate delegation_evidence
    delegation_evidence = authority_evidence.get("delegation_evidence", [])
    if not isinstance(delegation_evidence, list):
        errors.append("delegation_evidence must be an array")
    else:
        for i, delegation in enumerate(delegation_evidence):
            if not isinstance(delegation, dict):
                errors.append(f"delegation_evidence[{i}] must be an object")
                continue
            # Check required fields
            for field in ["source_agent", "target_agent", "delegation_type"]:
                if field not in delegation:
                    errors.append(f"delegation_evidence[{i}].{field} is required")
                elif not isinstance(delegation.get(field), str):
                    errors.append(f"delegation_evidence[{i}].{field} must be a string")
            
            # Validate delegation_type enum
            valid_types = ["explicit_sub_agent", "framework_delegation", "workflow_delegation", "mcp_delegation", "unknown"]
            if "delegation_type" in delegation and delegation["delegation_type"] not in valid_types:
                errors.append(f"delegation_evidence[{i}].delegation_type must be one of {valid_types}")
    
    # Validate authority_statements
    authority_statements = authority_evidence.get("authority_statements", [])
    if not isinstance(authority_statements, list):
        errors.append("authority_statements must be an array")
    else:
        for i, stmt in enumerate(authority_statements):
            if not isinstance(stmt, dict):
                errors.append(f"authority_statements[{i}] must be an object")
                continue
            # Check required fields
            for field in ["statement_id", "agent_id", "capability", "provenance"]:
                if field not in stmt:
                    errors.append(f"authority_statements[{i}].{field} is required")
                elif not isinstance(stmt.get(field), str):
                    errors.append(f"authority_statements[{i}].{field} must be a string")
            
            # Validate provenance enum
            provenances = ["declared", "detected", "inferred", "unknown", "repo-iac-observed"]
            if "provenance" in stmt and stmt["provenance"] not in provenances:
                errors.append(f"authority_statements[{i}].provenance must be one of {provenances}")
                
            # Validate access_mode enum
            access_modes = ["none", "read", "write", "mutate", "execute", "unknown"]
            if "access_mode" in stmt and stmt["access_mode"] not in access_modes:
                errors.append(f"authority_statements[{i}].access_mode must be one of {access_modes}")
                
            # Validate resolution enum
            resolutions = ["resolved", "unresolved", "contradicted", "unknown"]
            if "resolution" in stmt and stmt["resolution"] not in resolutions:
                errors.append(f"authority_statements[{i}].resolution must be one of {resolutions}")
    
    # Validate uncertainty_summary
    uncertainty_summary = authority_evidence.get("uncertainty_summary", {})
    if not isinstance(uncertainty_summary, dict):
        errors.append("uncertainty_summary must be an object")
    else:
        uncertainty_fields = [
            "authority_statement_count",
            "resolved_count", 
            "unresolved_count",
            "unknown_count",
            "inferred_count",
            "evidence_backed_count"
        ]
        for field in uncertainty_fields:
            if field in uncertainty_summary and not isinstance(uncertainty_summary.get(field), int):
                errors.append(f"uncertainty_summary.{field} must be an integer")
    
    # Validate assurance_boundary
    assurance_boundary = authority_evidence.get("assurance_boundary", [])
    if not isinstance(assurance_boundary, list):
        errors.append("assurance_boundary must be an array")
    else:
        for i, item in enumerate(assurance_boundary):
            if not isinstance(item, str):
                errors.append(f"assurance_boundary[{i}] must be a string")
    
    # Validate source_revision
    source_revision = authority_evidence.get("source_revision", {})
    if not isinstance(source_revision, dict):
        errors.append("source_revision must be an object")
    else:
        if "commit" in source_revision and not isinstance(source_revision.get("commit"), str):
            errors.append("source_revision.commit must be a string")
        if "repository" in source_revision and not isinstance(source_revision.get("repository"), str):
            errors.append("source_revision.repository must be a string")
    
    # Validate safeai_version and ruleset_version
    if not isinstance(authority_evidence.get("safeai_version"), str):
        errors.append("safeai_version must be a string")
    if not isinstance(authority_evidence.get("ruleset_version"), str):
        errors.append("ruleset_version must be a string")
        
    # Validate change_context
    change_context = authority_evidence.get("change_context", {})
    if not isinstance(change_context, dict):
        errors.append("change_context must be an object")
    else:
        if "baseline_ref" in change_context and not isinstance(change_context.get("baseline_ref"), str):
            errors.append("change_context.baseline_ref must be a string")
        if "current_revision" in change_context and not isinstance(change_context.get("current_revision"), str):
            errors.append("change_context.current_revision must be a string")
        valid_change_classes = ["NO_CHANGE", "LOW_CHANGE", "MATERIAL_CHANGE", "HIGH_RISK_CHANGE", "UNKNOWN"]
        if "change_class" in change_context and change_context["change_class"] not in valid_change_classes:
            errors.append(f"change_context.change_class must be one of {valid_change_classes}")
    
    return errors


def reconstruct_delegation_chains(delegation_evidence: List[Dict[str, Any]]) -> List[List[str]]:
    """
    Reconstruct delegation chains from delegation evidence.
    
    Returns a list of chains, where each chain is a list of agent IDs
    representing a delegation path (e.g., ["AgentA", "AgentB", "AgentC"]).
    """
    # Build adjacency list
    graph = {}
    in_degree = {}
    
    for delegation in delegation_evidence:
        source = delegation.get("source_agent")
        target = delegation.get("target_agent")
        
        if not source or not target:
            continue
            
        if source not in graph:
            graph[source] = []
        if target not in graph:
            graph[target] = []
            
        graph[source].append(target)
        
        # Track in-degree for topological sort
        in_degree[target] = in_degree.get(target, 0) + 1
        if source not in in_degree:
            in_degree[source] = 0
    
    # Find all possible chains (simplified - just direct delegations for now)
    chains = []
    visited = set()
    
    def dfs(node: str, path: List[str]):
        if node in visited:
            # Avoid cycles
            return
        visited.add(node)
        path.append(node)
        
        # If this is a leaf node (no outgoing edges), save the path
        if node not in graph or not graph[node]:
            chains.append(path.copy())
        else:
            # Continue exploring
            for neighbor in graph[node]:
                dfs(neighbor, path)
        
        # Backtrack
        path.pop()
        visited.remove(node)
    
    # Start DFS from nodes with no incoming edges (potential roots)
    for node in graph:
        if in_degree.get(node, 0) == 0:
            dfs(node, [])
    
    # Also add direct delegations as simple chains
    for delegation in delegation_evidence:
        source = delegation.get("source_agent")
        target = delegation.get("target_agent")
        if source and target:
            chains.append([source, target])
    
    # Deduplicate chains
    unique_chains = []
    seen = set()
    for chain in chains:
        chain_tuple = tuple(chain)
        if chain_tuple not in seen:
            seen.add(chain_tuple)
            unique_chains.append(chain)
    
    return unique_chains


def output_authority_statements(authority_statements: List[Dict[str, Any]]) -> None:
    """Output authority statements in a human-readable format."""
    if not authority_statements:
        print("No authority statements found.")
        return
        
    print(f"\nFound {len(authority_statements)} authority statement(s):")
    print("-" * 60)
    
    for i, stmt in enumerate(authority_statements, 1):
        print(f"{i}. Statement ID: {stmt.get('statement_id', 'N/A')}")
        print(f"   Agent: {stmt.get('agent_id', 'N/A')}")
        print(f"   Capability: {stmt.get('capability', 'N/A')}")
        print(f"   Access Mode: {stmt.get('access_mode', 'N/A')}")
        print(f"   Provenance: {stmt.get('provenance', 'N/A')}")
        print(f"   Resolution: {stmt.get('resolution', 'N/A')}")
        print(f"   Confidence: {stmt.get('confidence', 'N/A')}")
        
        # Show references if any
        evidence_refs = stmt.get("evidence_refs", [])
        if evidence_refs:
            print(f"   Evidence Refs: {', '.join(evidence_refs)}")
            
        print()


def main() -> None:
    """Main demonstration function."""
    if len(sys.argv) < 2:
        print("Usage: python authority_consumer_demo.py <manifest_file>")
        print("Example: python authority_consumer_demo.py safeai-manifest.json")
        sys.exit(1)
    
    manifest_path = Path(sys.argv[1])
    if not manifest_path.exists():
        print(f"Error: Manifest file not found: {manifest_path}")
        sys.exit(1)
    
    try:
        # Load manifest
        print(f"Loading manifest: {manifest_path}")
        manifest = load_manifest(manifest_path)
        
        # Extract authority_evidence section
        authority_evidence = manifest.get("authority_evidence")
        if not authority_evidence:
            print("Error: No authority_evidence section found in manifest")
            sys.exit(1)
        
        print("\n" + "="*60)
        print("AGENT AUTHORITY EVIDENCE CONTRACT CONSUMER DEMONSTRATION")
        print("="*60)
        
        # 1. Validate schema
        print("\n1. Validating authority_evidence schema...")
        validation_errors = validate_authority_evidence_schema(authority_evidence)
        if validation_errors:
            print("[FAIL] Schema validation failed:")
            for error in validation_errors:
                print(f"   - {error}")
        else:
            print("[PASS] Schema validation passed")
        
        # 2. Output basic info
        print("\n2. Basic Information:")
        print(f"   Contract: {authority_evidence.get('contract_identity', {}).get('name', 'N/A')} "
              f"v{authority_evidence.get('contract_identity', {}).get('version', 'N/A')}")
        print(f"   SafeAI Version: {authority_evidence.get('safeai_version', 'N/A')}")
        print(f"   Ruleset Version: {authority_evidence.get('ruleset_version', 'N/A')}")
        print(f"   Subject Agents: {len(authority_evidence.get('subject_agents', []))}")
        
        # 3. Reconstruct delegation chains
        print("\n3. Delegation Chain Analysis:")
        delegation_evidence = authority_evidence.get("delegation_evidence", [])
        if delegation_evidence:
            chains = reconstruct_delegation_chains(delegation_evidence)
            print(f"   Found {len(delegation_evidence)} delegation(s)")
            print(f"   Reconstructed {len(chains)} delegation chain(s):")
            for i, chain in enumerate(chains, 1):
                print(f"     {i}. {' -> '.join(chain)}")
        else:
            print("   No delegation evidence found")
        
        # 4. Output authority statements
        print("\n4. Authority Statements:")
        authority_statements = authority_evidence.get("authority_statements", [])
        output_authority_statements(authority_statements)
        
        # 5. Summary
        print("\n5. Summary:")
        uncertainty = authority_evidence.get("uncertainty_summary", {})
        print(f"   Authority Statements: {uncertainty.get('authority_statement_count', 0)}")
        print(f"   Resolved: {uncertainty.get('resolved_count', 0)}")
        print(f"   Unresolved: {uncertainty.get('unresolved_count', 0)}")
        print(f"   Unknown: {uncertainty.get('unknown_count', 0)}")
        print(f"   Inferred: {uncertainty.get('inferred_count', 0)}")
        print(f"   Evidence Backed: {uncertainty.get('evidence_backed_count', 0)}")
        
        print("\n" + "="*60)
        print("Demonstration completed successfully!")
        print("="*60)
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in manifest file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()