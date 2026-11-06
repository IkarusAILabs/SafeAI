"""Serverless Framework authority extraction (v2.16, plan 2.16-2).

Reads ``serverless.yml`` / ``serverless.yaml`` and emits the grants of
the service's Lambda execution role:

- ``provider.iam.role.statements`` (Serverless v3) and
  ``provider.iamRoleStatements`` (v1 / v2) are grants of the provider
  role. Its name is ``provider.iam.role.name`` when literal, otherwise
  ``<service>-lambdaRole`` noted ``serverless-default-role-name`` (the
  framework adds stage and region at deploy time).
- ``provider.iam.role`` given as a string (an existing role's ARN or
  name) means the framework creates no role: a binding to that external
  role is recorded, never a grant.
- ``functions.<name>.iamRoleStatements`` (the per-function roles plugin)
  are grants of a role per function, ``<service>-<function>-lambdaRole``.

``${...}`` variables are never resolved: a value that contains one is
dropped from ``values`` and degrades the field (``serverless-variable``).
"""

import re

import yaml

from safeai.iac.model import (
    PARTIALLY_RESOLVED,
    RESOLVED,
    UNRESOLVED,
    field,
    grant,
    grant_binding,
    identity,
)

FILENAMES = ("serverless.yml", "serverless.yaml")
_VARIABLE = re.compile(r"\$\{[^}]*\}")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _valued(raw):
    items = _as_list(raw)
    literal = [str(v) for v in items if isinstance(v, (str, int)) and not _VARIABLE.search(str(v))]
    notes = []
    if len(literal) != len(items):
        notes.append("serverless-variable")
    if any(v == "*" for v in literal):
        notes.append("admin-wildcard")
    elif any("*" in v for v in literal):
        notes.append("wildcard-pattern")
    if not items:
        return field([], UNRESOLVED, ["empty-statement"])
    if not literal:
        return field([], UNRESOLVED, notes)
    return field(literal, PARTIALLY_RESOLVED if "serverless-variable" in notes else RESOLVED,
                 notes)


def _line_of(text, key):
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:")
    for number, line in enumerate(text.splitlines(), 1):
        if pattern.match(line):
            return number
    return 1


def _emit(principal, statements, rel_path, line, notes, grants):
    for statement in _as_list(statements):
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect") or "Allow") != "Allow":
            continue
        if "NotAction" in statement or "NotResource" in statement:
            continue
        actions, resources = _valued(statement.get("Action")), _valued(statement.get("Resource"))
        grants.append(grant(principal, actions, resources, source="serverless",
                            source_file=rel_path, line=line,
                            fidelity=sorted(set(actions["notes"] + resources["notes"] + notes)),
                            family="cloud"))


def parse_serverless(rel_path, text):
    """Extract ``(identities, grants, grant_bindings, meta)`` from one serverless file."""
    identities, grants, bindings = [], [], []
    meta = {"service": None, "unparsed": False}
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        meta["unparsed"] = True
        return identities, grants, bindings, meta
    if not isinstance(document, dict):
        return identities, grants, bindings, meta
    service = document.get("service")
    if isinstance(service, dict):
        service = service.get("name")
    service = str(service or "service")
    meta["service"] = service
    provider = document.get("provider") if isinstance(document.get("provider"), dict) else {}
    iam = provider.get("iam") if isinstance(provider.get("iam"), dict) else {}
    role = iam.get("role")
    provider_line = _line_of(text, "provider")

    if isinstance(role, str):
        bindings.append(grant_binding(
            {"kind": "aws_iam_role", "name": role}, binding_kind="provider.iam.role",
            binding_name=service, role=f"external-role/{role}", source_file=rel_path,
            line=_line_of(text, "role"),
            notes=["external-role"] + (["serverless-variable"] if _VARIABLE.search(role)
                                       else [])))
    else:
        role = role if isinstance(role, dict) else {}
        statements = _as_list(role.get("statements")) + _as_list(
            provider.get("iamRoleStatements"))
        if statements:
            name = role.get("name")
            notes = []
            if not (isinstance(name, str) and name and not _VARIABLE.search(name)):
                name, notes = f"{service}-lambdaRole", ["serverless-default-role-name"]
            line = _line_of(text, "statements" if role.get("statements") else
                            "iamRoleStatements")
            identities.append(identity("aws_iam_role", name, source_ref=f"{rel_path}:{line}"))
            _emit({"kind": "aws_iam_role", "name": name}, statements, rel_path, line, notes,
                  grants)
        for arn in _as_list(role.get("managedPolicies")):
            label = arn if isinstance(arn, str) else "<variable>"
            bindings.append(grant_binding(
                {"kind": "aws_iam_role", "name": f"{service}-lambdaRole"},
                binding_kind="managedPolicies", binding_name=service, role=f"policy/{label}",
                source_file=rel_path, line=provider_line,
                notes=["managed-policy" if ":aws:policy/" in str(arn) else "external-policy"]))

    functions = document.get("functions") if isinstance(document.get("functions"), dict) else {}
    for function, spec in sorted(functions.items()):
        if not isinstance(spec, dict) or not spec.get("iamRoleStatements"):
            continue
        name = f"{service}-{function}-lambdaRole"
        line = _line_of(text, str(function))
        identities.append(identity("aws_iam_role", name, source_ref=f"{rel_path}:{line}"))
        _emit({"kind": "aws_iam_role", "name": name}, spec["iamRoleStatements"], rel_path, line,
              ["serverless-per-function-role"], grants)
    return identities, grants, bindings, meta
