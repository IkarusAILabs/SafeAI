"""Terraform authority extraction (v2.5 redesign).

Parses in-repo ``*.tf`` files with a stdlib-only brace-block scanner
(no HCL dependency — ADR-0006) and emits an explicit authority graph:

- **Identities** from ``aws_iam_role`` blocks (name attribute preferred;
  interpolated names stay unresolved, never guessed).
- **Policy statements** from ``aws_iam_policy``,
  ``aws_iam_role_policy``, and ``aws_iam_policy_document`` blocks, with
  per-field resolution (``resolved | partially-resolved | unresolved``).
- **GrantBindings** for attachments (``aws_iam_policy_attachment``,
  ``aws_iam_role_policy_attachment``): Role → policy → statement chains
  stay represented as relationships. Attachments never become fake
  permission grants.

Trust policies (``assume_role_policy``) are identity metadata, never
permission grants — who may assume a role is not what the role may do.

Fidelity ceiling: variable interpolation, modules, ``for_each`` /
``dynamic`` / ``count``, ``jsonencode(`` / ``file(`` / ``templatefile(``
payloads, and external/managed policies are preserved as unresolved
markers. Repository IaC is evidence of declared grants, never proof of
deployed permission.
"""

import re

from safeai.iac.model import (
    PARTIALLY_RESOLVED,
    RESOLVED,
    UNRESOLVED,
    field,
    grant,
    grant_binding,
    identity,
)

#: Terraform resource types with authority meaning.
_ROLE = "aws_iam_role"
_POLICY = "aws_iam_policy"
_ROLE_POLICY = "aws_iam_role_policy"
_POLICY_DOCUMENT = "aws_iam_policy_document"
_ATTACHMENTS = {
    "aws_iam_policy_attachment",
    "aws_iam_role_policy_attachment",
}

_WATCHED = {_ROLE, _POLICY, _ROLE_POLICY, _POLICY_DOCUMENT} | _ATTACHMENTS

#: Markers forcing unresolved content (never evaluated).
_UNRESOLVED_MARKERS = ("${", "for_each", "dynamic", "count", "jsonencode(",
                       "file(", "templatefile(", "var.", "local.", "module.")

#: String-list statements (HCL bare keys, JSON quoted keys, JSON-colon
#: payloads embedded as strings).
_STATEMENT_RES = (
    re.compile(r'''(?i)\bactions?"?\s*[:=]\s*\[(?P<body>[^\]]*)\]'''),
    re.compile(r'''(?i)\bresources?"?\s*[:=]\s*\[(?P<body>[^\]]*)\]'''),
)

_QUOTED = re.compile(r'''"([^"\\]*(?:\\.[^"\\]*)*)"''')

_NAME_RE = re.compile(r'''(?i)\bname\s*=\s*"([^"]+)"''')
_ROLE_REF_RE = re.compile(r'''(?i)\broles\s*=\s*\[(?P<body>[^\]]*)\]''')
_ROLE_SINGLE_RE = re.compile(r'''(?i)\brole\s*=\s*(?P<ref>[^\s,\n\]]+)''')
_POLICY_ARN_RE = re.compile(r'''(?i)\bpolicy_arn\s*=\s*(?P<ref>[^\s,\n\]]+)''')
_DATA_DOC_RE = re.compile(r"data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)")
_MANAGED_POLICY_RE = re.compile(r"^arn:aws:iam::aws:policy/")

_MAX_BLOCK_DEPTH = 32


def _strip_comments(text):
    """Remove ``#`` and ``//`` comments outside quoted strings."""
    out = []
    in_str = False
    escaped = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" or (ch == "/" and i + 1 < len(text) and text[i + 1] == "/"):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _iter_blocks(text):
    """Yield ``(kind, type, name, body, start_line)`` for top-level blocks.

    Brace matching is depth-capped; unbalanced input ends the scan
    (fail-closed: unparseable tail is skipped, never guessed).
    """
    header = re.compile(
        r'''(?m)^\s*(?P<kind>resource|data|module)\s+\"(?P<type>[^\"]+)\"'''
        r'''(?:\s+\"(?P<name>[^\"]+)\")?\s*\{''')
    for match in header.finditer(text):
        depth = 1
        i = match.end()
        in_str = False
        escaped = False
        exceeded = False
        while i < len(text) and depth > 0:
            ch = text[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
                if depth > _MAX_BLOCK_DEPTH:
                    exceeded = True
                    break
            elif ch == "}":
                depth -= 1
            i += 1
        if exceeded or depth != 0:
            continue
        body = text[match.end():i - 1]
        start_line = text.count("\n", 0, match.start()) + 1
        yield (match.group("kind"), match.group("type"),
               match.group("name") or "", body, start_line)


def _line_of(scan, pos, base_line):
    """Best-effort 1-indexed line of ``pos`` within a scanned body."""
    return base_line + scan.count("\n", 0, pos)


def _valued_field(raw_values, extra_notes=()):
    """Per-field resolution: split literal vs unresolvable values."""
    notes = list(extra_notes)
    if not raw_values:
        return field([], UNRESOLVED, notes + ["empty-statement"])
    resolved_vals = [v for v in raw_values if "${" not in v]
    if len(resolved_vals) != len(raw_values):
        notes.append("unresolved-interpolation")
    if not resolved_vals:
        return field([], UNRESOLVED, notes)
    if notes:
        return field(resolved_vals, PARTIALLY_RESOLVED, notes)
    return field(resolved_vals, RESOLVED)


def _wildcard_notes(values):
    """Breadth flags: wildcards are observed, never uncertainty."""
    notes = []
    if any(v == "*" for v in values):
        notes.append("admin-wildcard")
    elif any("*" in v for v in values):
        notes.append("wildcard-pattern")
    return notes


def _split_objects(body):
    """Split a ``[...]`` body into top-level ``{...}`` object spans.

    Depth-aware with string tracking; unbalanced tails are dropped
    (fail-closed). Returns ``[(start, text)]``.
    """
    objects = []
    depth = 0
    start = None
    in_str = False
    escaped = False
    for i, ch in enumerate(body):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                objects.append((start, body[start:i + 1]))
                start = None
            elif depth < 0:
                depth = 0
    return objects


def _statement_fields(text):
    """Extract (actions_field, resources_field) from one statement object."""
    action_vals, resource_vals = [], []
    for match in _STATEMENT_RES[0].finditer(text):
        action_vals.extend(_QUOTED.findall(match.group("body")))
    for match in _STATEMENT_RES[1].finditer(text):
        resource_vals.extend(_QUOTED.findall(match.group("body")))
    actions = _valued_field(action_vals)
    resources = _valued_field(resource_vals)
    actions["notes"].extend(_wildcard_notes(actions["values"]))
    resources["notes"].extend(_wildcard_notes(resources["values"]))
    return actions, resources


def _extract_statements(scan, base_line):
    """Return ``[(actions_field, resources_field, line)]`` per statement.

    Statements inside a ``Statement = [...]`` array are paired by
    object; stray top-level actions/resources fall back to a single
    positional statement.
    """
    statements = []
    array = re.search(r"(?i)\bstatement\s*[:=]\s*\[(?P<body>.*)\]",
                      scan, re.DOTALL)
    if array:
        for start, obj in _split_objects(array.group("body")):
            actions, resources = _statement_fields(obj)
            if actions["values"] or resources["values"]:
                statements.append((
                    actions, resources,
                    _line_of(scan, array.start() + start, base_line)))
        if statements:
            return statements
    actions, resources = _statement_fields(scan)
    if actions["values"] or resources["values"]:
        anchor = None
        match = _STATEMENT_RES[0].search(scan) or _STATEMENT_RES[1].search(scan)
        if match:
            anchor = match.start()
        statements.append((
            actions, resources,
            _line_of(scan, anchor or 0, base_line)))
    return statements


def _has_unevaluated_content(body):
    """True when statements may hide in content we never evaluate.

    Covers external payloads (``jsonencode(``, ``file(``,
    ``templatefile(``) and generated configuration (``for_each``,
    ``dynamic``, ``count``, variable/local/module references). Such
    blocks yield opaque (unresolved) grants so absence claims degrade
    to UNKNOWN instead of false mismatch.
    """
    return any(m in body for m in
               ("jsonencode(", "file(", "templatefile(", "for_each",
                "dynamic", "count", "var.", "local.", "module."))


def parse_terraform_file(rel_path, text):
    """Extract ``(identities, grants, grant_bindings, meta)`` from one file.

    ``rel_path`` is the root-relative forward-slash path used in all
    evidence refs. Never raises: unparseable content yields empty
    collections (and ``meta["unparsed"]`` when nothing was extractable
    from a watched block).
    """
    identities, grants, bindings = [], [], []
    meta = {"module_refs": [], "detached_policies": [], "unparsed": False}
    try:
        clean = _strip_comments(text)
        blocks = list(_iter_blocks(clean))
    except Exception:
        meta["unparsed"] = True
        return identities, grants, bindings, meta

    # Pass 1: identities (roles) and policy documents.
    roles = {}
    documents = {}
    policies = {}
    try:
        watched_headers = len(re.findall(
            r'''(?m)^\s*(?:resource|data)\s+"aws_iam_\w+"''', clean))
    except Exception:
        watched_headers = 0
    for kind, rtype, name, body, start_line in blocks:
        if kind == "module":
            meta["module_refs"].append(name or rtype)
            continue
        if rtype not in _WATCHED:
            continue
        ref = f"{rel_path}:{start_line}"
        if rtype == _ROLE:
            resolved_name, resolution = name, RESOLVED
            name_match = _NAME_RE.search(body)
            if name_match:
                if "${" in name_match.group(1):
                    resolved_name, resolution = name, UNRESOLVED
                else:
                    resolved_name = name_match.group(1)
            ident = identity("aws_iam_role", resolved_name or name,
                             source_ref=ref)
            ident["resolution"] = resolution
            identities.append(ident)
            roles[name] = ident
        elif rtype in (_POLICY_DOCUMENT,):
            scan = body.replace('\\"', '"')
            statements = _extract_statements(scan, start_line)
            documents[name] = {
                "statements": statements, "ref": ref, "body": body,
            }

    # Pass 2: collect every managed policy's statements first, so
    # attachments resolve regardless of block order in the file.
    policies = {}
    for kind, rtype, name, body, start_line in blocks:
        if rtype != _POLICY or name in policies:
            continue
        scan = body.replace('\\"', '"')
        display = name
        name_match = _NAME_RE.search(body)
        if name_match and "${" not in name_match.group(1):
            display = name_match.group(1)
        statements = [(a, r, ln, False)
                      for a, r, ln in _extract_statements(scan, start_line)]
        for doc_label in _DATA_DOC_RE.findall(body):
            doc = documents.get(doc_label)
            if doc:
                for actions, resources, line in doc["statements"]:
                    statements.append((actions, resources, line, True))
        policies[name] = {
            "statements": statements,
            "display": display,
            "opaque": not statements and _has_unevaluated_content(body),
            "attached": False,
        }

    # Pass 3: grants (inline policies) and bindings (attachments).
    for kind, rtype, name, body, start_line in blocks:
        if rtype not in _WATCHED:
            continue
        ref = f"{rel_path}:{start_line}"
        scan = body.replace('\\"', '"')
        if rtype == _ROLE_POLICY:
            # (actions, resources, line, via_doc)
            statements = [(a, r, ln, False)
                          for a, r, ln in _extract_statements(scan, start_line)]
            for doc_label in _DATA_DOC_RE.findall(body):
                doc = documents.get(doc_label)
                if doc:
                    for actions, resources, line in doc["statements"]:
                        statements.append((actions, resources, line, True))
            if not statements:
                if _has_unevaluated_content(body):
                    role_ref = None
                    opaque_match = _ROLE_SINGLE_RE.search(body)
                    if opaque_match:
                        role_ref = _resolve_role_ref(
                            opaque_match.group("ref").strip().strip('"'),
                            roles)
                    grants.append(grant(
                        role_ref or {"kind": "aws_iam_role", "name": name},
                        field([], UNRESOLVED, ["external-payload"]),
                        field([], UNRESOLVED, ["external-payload"]),
                        source="terraform", source_file=rel_path,
                        line=start_line,
                        fidelity=["opaque-policy-document"],
                        family="cloud"))
                continue
            role_ref = None
            role_match = _ROLE_SINGLE_RE.search(body)
            if role_match:
                role_ref = _resolve_role_ref(role_match.group("ref").strip().strip('"'),
                                             roles)
            principal = role_ref or {"kind": "aws_iam_role", "name": name}
            for actions, resources, line, via_doc in statements:
                fidelity = list(actions["notes"]) + list(resources["notes"])
                fidelity.append("via-data-document" if via_doc
                                else "inline-policy-statement")
                grants.append(grant(
                    principal, actions, resources, source="terraform",
                    source_file=rel_path, line=line,
                    fidelity=sorted(set(fidelity)), family="cloud"))
        elif rtype in _ATTACHMENTS:
            _extract_attachment(name, body, start_line, rel_path, roles,
                                documents, policies, grants, bindings)
    meta["detached_policies"] = sorted(
        policies[label]["display"]
        for label in policies if not policies[label]["attached"])
    extracted = (len(identities) + len(grants) + len(bindings)
                 + len(meta["detached_policies"]))
    if watched_headers and not extracted:
        # Watched IAM blocks were seen but nothing was extractable
        # (truncated/unbalanced input): mark unparsed, never guessed.
        meta["unparsed"] = True
    return identities, grants, bindings, meta


def _resolve_role_ref(ref, roles):
    """Resolve ``aws_iam_role.<label>.name`` to a role identity, if known."""
    match = re.fullmatch(r"aws_iam_role\.([A-Za-z0-9_-]+)\.name", ref or "")
    if match and match.group(1) in roles:
        return {"kind": "aws_iam_role",
                "name": roles[match.group(1)]["name"]}
    if match:
        return {"kind": "aws_iam_role", "name": ref}
    if ref and ref not in ("<unattached>",):
        return {"kind": "aws_iam_role", "name": ref.strip('"')}
    return None


def _resolve_policy_statements(policy_ref, name, body, documents, policies):
    """Resolve an attachment's policy to statements + chain description.

    Returns ``(statements, chain, opaque_note)``. Resolution order:
    AWS-managed policies (never guessed), in-repo ``aws_iam_policy``
    resource blocks, ``aws_iam_policy_document`` data blocks. Anything
    else yields no statements with an explicit opaque note — external
    permissions are never guessed.
    """
    arn_match = _POLICY_ARN_RE.search(body)
    arn = arn_match.group("ref").strip().strip('"') if arn_match else ""
    if arn and _MANAGED_POLICY_RE.match(arn):
        return [], f"managed-policy:{arn}", "managed-policy-content"
    if arn:
        resource_match = re.fullmatch(
            r"aws_iam_policy\.([A-Za-z0-9_-]+)\.arn", arn)
        if resource_match and resource_match.group(1) in policies:
            policy = policies[resource_match.group(1)]
            policy["attached"] = True
            if policy["statements"]:
                return (policy["statements"],
                        f"policy:{policy['display']}", "")
            if policy["opaque"]:
                return ([], f"policy:{policy['display']}",
                        "opaque-policy-content")
            return ([], f"policy:{policy['display']}",
                    "empty-policy-document")
        tail = arn.rstrip("/").split("/")[-1]
        for label in list(documents):
            if label == tail or tail.endswith(label):
                doc = documents[label]
                return (doc["statements"],
                        f"policy-document:{label}", "")
        return [], f"policy-arn:{arn}", "unresolved-policy-reference"
    quoted = _QUOTED.findall(body)
    for candidate in quoted:
        for label in list(policies):
            if candidate == label:
                policy = policies[label]
                policy["attached"] = True
                if policy["statements"]:
                    return (policy["statements"],
                            f"policy:{policy['display']}", "")
                if policy["opaque"]:
                    return ([], f"policy:{policy['display']}",
                            "opaque-policy-content")
                return ([], f"policy:{policy['display']}",
                        "empty-policy-document")
        for label in list(documents):
            if candidate == label or candidate.endswith("/" + label):
                doc = documents[label]
                return (doc["statements"],
                        f"policy-document:{label}", "")
    return [], "policy:unknown", "unresolved-policy-reference"


def _extract_attachment(name, body, start_line, rel_path, roles, documents,
                        policies, grants, bindings):
    """Build the Role → policy → statement chain for one attachment."""
    attached = []
    for match in _ROLE_REF_RE.finditer(body):
        attached.extend(_QUOTED.findall(match.group("body")))
    single = _ROLE_SINGLE_RE.search(body)
    if single:
        attached.append(single.group("ref").strip().strip('"'))
    if not attached:
        bindings.append(grant_binding(
            {"kind": "aws_iam_role", "name": "<unattached>"},
            binding_kind="attachment", binding_name=name,
            role="<unattached>", source_file=rel_path, line=start_line))
        return
    statements, chain, opaque = _resolve_policy_statements(
        None, name, body, documents, policies)
    for role_ref in attached:
        principal = _resolve_role_ref(role_ref, roles)
        if principal is None:
            continue
        bindings.append(grant_binding(
            principal, binding_kind="attachment", binding_name=name,
            role=chain, source_file=rel_path, line=start_line))
        if opaque:
            grants.append(grant(
                principal,
                field([], UNRESOLVED, [opaque]),
                field([], UNRESOLVED, [opaque]),
                source="terraform", source_file=rel_path, line=start_line,
                fidelity=[opaque, f"via-{chain.split(':')[0]}"],
                family="cloud"))
            continue
        # Statements arrive as (actions, resources, line[, via_doc]).
        for stmt in statements:
            actions, resources, line = stmt[0], stmt[1], stmt[2]
            via_doc = len(stmt) > 3 and stmt[3]
            via = "via-data-document" if via_doc else \
                f"via-{chain.split(':')[0]}"
            fidelity = (list(actions["notes"]) + list(resources["notes"])
                        + [via])
            grants.append(grant(
                principal, actions, resources, source="terraform",
                source_file=rel_path, line=line,
                fidelity=sorted(set(fidelity)), family="cloud"))
