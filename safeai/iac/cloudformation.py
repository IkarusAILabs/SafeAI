"""CloudFormation authority extraction (v2.16, plan 2.16-1).

Reads in-repo CloudFormation templates (YAML, including the short-form
intrinsic tags ``!Ref``, ``!Sub``, ``!GetAtt``…, and JSON) and emits the
same authority graph as the Terraform collector:

- **Identities** from ``AWS::IAM::Role`` (``RoleName`` when literal,
  otherwise the logical ID, noted ``logical-id-name``).
- **Grants** from each ``Allow`` statement of a role's inline
  ``Policies`` and of ``AWS::IAM::Policy`` / ``AWS::IAM::ManagedPolicy``
  resources attached to roles of the same template through ``Roles``.
- **GrantBindings** for ``ManagedPolicyArns`` (an AWS managed or
  external policy is a relationship, never a fabricated grant).

Intrinsic functions are never evaluated. A value built by one is dropped
from ``values`` and degrades the field to ``partially-resolved`` (some
literal values remain) or ``unresolved`` (none do), with the
``intrinsic-function`` note. ``Deny`` statements and ``NotAction`` /
``NotResource`` are noted and not turned into grants. Repository IaC is
evidence of declared grants, never proof of deployed permission.
"""

import json
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

_ROLE = "AWS::IAM::Role"
_POLICIES = ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy")
_INTRINSIC_KEYS = ("Ref", "Condition")
_MAX_RESOURCES = 2000


class _Intrinsic(dict):
    """A CloudFormation intrinsic function, kept as data and never evaluated."""


class _Loader(yaml.SafeLoader):
    """SafeLoader that turns ``!Ref x`` / ``!Sub ...`` tags into intrinsic markers."""


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    name = tag_suffix if tag_suffix in _INTRINSIC_KEYS else f"Fn::{tag_suffix}"
    return _Intrinsic({name: value})


_Loader.add_multi_constructor("!", _construct_intrinsic)


def _is_intrinsic(value):
    return isinstance(value, dict) and len(value) == 1 and (
        next(iter(value)).startswith("Fn::") or next(iter(value)) in _INTRINSIC_KEYS)


def _load_yaml(text):
    loader = _Loader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load_template(text, is_json=False):
    """The template dict, or ``None`` when ``text`` is not a CloudFormation template."""
    try:
        document = json.loads(text) if is_json else _load_yaml(text)
    except (ValueError, yaml.YAMLError):
        return None
    if not isinstance(document, dict):
        return None
    resources = document.get("Resources")
    if not isinstance(resources, dict) or not resources:
        return None
    typed = [r for r in resources.values()
             if isinstance(r, dict) and str(r.get("Type") or "").startswith("AWS::")]
    if not typed and "AWSTemplateFormatVersion" not in document:
        return None
    return document


def _line_of(text, logical_id):
    pattern = re.compile(rf'^\s*"?{re.escape(logical_id)}"?\s*:')
    for number, line in enumerate(text.splitlines(), 1):
        if pattern.match(line):
            return number
    return 1


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _valued(raw):
    """Per-field resolution for an Action or Resource value (string, list or intrinsic)."""
    items = _as_list(raw)
    literal = [str(v) for v in items if isinstance(v, (str, int)) and not _is_intrinsic(v)]
    notes = []
    if len(literal) != len(items):
        notes.append("intrinsic-function")
    if any(v == "*" for v in literal):
        notes.append("admin-wildcard")
    elif any("*" in v for v in literal):
        notes.append("wildcard-pattern")
    if not items:
        return field([], UNRESOLVED, ["empty-statement"])
    if not literal:
        return field([], UNRESOLVED, notes)
    return field(literal, PARTIALLY_RESOLVED if "intrinsic-function" in notes else RESOLVED,
                 notes)


def _statements(document):
    """``[(statement, notes)]`` for the Allow statements of a policy document."""
    if _is_intrinsic(document) or not isinstance(document, dict):
        return None
    found = []
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect") or "Allow") != "Allow":
            continue
        if "NotAction" in statement or "NotResource" in statement:
            continue
        found.append(statement)
    return found


def _role_identity(logical_id, props, ref):
    name = props.get("RoleName")
    if isinstance(name, str) and name:
        return identity("aws_iam_role", name, source_ref=ref), []
    return identity("aws_iam_role", logical_id, source_ref=ref), ["logical-id-name"]


def _role_ref(value, roles):
    """The role a ``Roles`` entry names: ``!Ref Logical`` or a literal role name."""
    if isinstance(value, dict) and set(value) == {"Ref"} and value["Ref"] in roles:
        return roles[value["Ref"]]
    if isinstance(value, str):
        for role in roles.values():
            if role["name"] == value:
                return role
    return None


def parse_cloudformation(rel_path, text):
    """Extract ``(identities, grants, grant_bindings, meta)`` from one template.

    ``meta["template"]`` is False when the file is not a CloudFormation
    template (nothing is extracted then). Never raises.
    """
    identities, grants, bindings = [], [], []
    meta = {"template": False, "unresolved_roles": 0}
    try:
        document = load_template(text, is_json=rel_path.lower().endswith((".json", ".template")))
    except Exception:
        document = None
    if document is None:
        return identities, grants, bindings, meta
    meta["template"] = True
    resources = [(lid, r) for lid, r in list(document["Resources"].items())[:_MAX_RESOURCES]
                 if isinstance(r, dict)]

    roles = {}
    for logical_id, resource in resources:
        if resource.get("Type") != _ROLE:
            continue
        props = resource.get("Properties") if isinstance(resource.get("Properties"), dict) else {}
        line = _line_of(text, logical_id)
        role, notes = _role_identity(logical_id, props, f"{rel_path}:{line}")
        identities.append(role)
        roles[logical_id] = {"kind": "aws_iam_role", "name": role["name"], "notes": notes}
        for policy in _as_list(props.get("Policies")):
            if not isinstance(policy, dict):
                continue
            _emit(roles[logical_id], policy.get("PolicyDocument"), rel_path, line,
                  "inline-policy-statement", grants)
        for arn in _as_list(props.get("ManagedPolicyArns")):
            label = arn if isinstance(arn, str) else "<intrinsic>"
            bindings.append(grant_binding(
                {"kind": "aws_iam_role", "name": role["name"]},
                binding_kind="ManagedPolicyArns", binding_name=logical_id,
                role=f"policy/{label}", source_file=rel_path, line=line,
                notes=["managed-policy" if isinstance(arn, str) and ":aws:policy/" in arn
                       else "external-policy"] + ([] if isinstance(arn, str)
                                                  else ["intrinsic-function"])))

    for logical_id, resource in resources:
        if resource.get("Type") not in _POLICIES:
            continue
        props = resource.get("Properties") if isinstance(resource.get("Properties"), dict) else {}
        line = _line_of(text, logical_id)
        targets = [_role_ref(value, roles) for value in _as_list(props.get("Roles"))]
        if not targets:
            meta["unresolved_roles"] += 1
        for target in targets:
            if target is None:
                meta["unresolved_roles"] += 1
                continue
            bindings.append(grant_binding(
                {"kind": "aws_iam_role", "name": target["name"]},
                binding_kind=resource["Type"], binding_name=logical_id,
                role=f"policy/{logical_id}", source_file=rel_path, line=line))
            _emit(target, props.get("PolicyDocument"), rel_path, line,
                  "attached-policy-statement", grants)
    return identities, grants, bindings, meta


def _emit(role, document, rel_path, line, origin, grants):
    principal = {"kind": "aws_iam_role", "name": role["name"]}
    statements = _statements(document)
    if statements is None:
        grants.append(grant(principal, field([], UNRESOLVED, ["intrinsic-function"]),
                            field([], UNRESOLVED, ["intrinsic-function"]),
                            source="cloudformation", source_file=rel_path, line=line,
                            fidelity=["opaque-policy-document"] + role["notes"],
                            family="cloud"))
        return
    for statement in statements:
        actions, resources = _valued(statement.get("Action")), _valued(statement.get("Resource"))
        fidelity = sorted(set(actions["notes"] + resources["notes"] + role["notes"]
                              + [origin]))
        grants.append(grant(principal, actions, resources, source="cloudformation",
                            source_file=rel_path, line=line, fidelity=fidelity,
                            family="cloud"))
