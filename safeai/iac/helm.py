"""Helm chart templates as Kubernetes RBAC evidence (v2.16, plan 2.16-3).

A YAML file under ``<chart>/templates/`` (a directory with ``Chart.yaml``)
is Go-templated, so it is not YAML until rendered. It is never rendered
here, and ``values.yaml`` is never merged. Instead:

* a line that holds only template actions (``{{- if ... }}``,
  ``{{ end }}``, ``{{- include "x.labels" . | nindent 4 }}``) is blanked,
  keeping line numbers;
* every other action is replaced by a placeholder derived from its
  expression text, so the same expression stays the same token (a
  ServiceAccount named ``{{ include "app.sa" . }}`` and a binding
  subject with the same expression still meet, as they would when
  rendered with one set of values);

and the result goes through the Kubernetes RBAC parser. A verb or
resource that came from a template is dropped from ``values`` and
degrades its field (``helm-template-value``); a name that came from one
is shown as the expression (``{{ include "app.sa" . }}``) and the grant
is noted ``helm-templated-name``. Control flow (``if`` / ``range``) is
not evaluated: a rule inside ``{{ if }}`` is reported as if enabled, and
noted ``helm-conditional``. A template that still does not parse is
listed as unparsed.
"""

import hashlib
import re

from safeai.iac.k8s import parse_k8s_file
from safeai.iac.model import PARTIALLY_RESOLVED, RESOLVED, UNRESOLVED

_ACTION = re.compile(r"\{\{-?(.*?)-?\}\}")
_CONTROL = re.compile(r"^\s*(if|else|range|with|end|define|block)\b")
_PLACEHOLDER = re.compile(r"__helm_[0-9a-f]{8}__")


def blank_templates(text):
    """``(yaml_text, {placeholder: "{{ expr }}"}, has_control_flow)``."""
    mapping, control = {}, False
    lines = []
    for line in text.splitlines():
        actions = _ACTION.findall(line)
        if actions and not _ACTION.sub("", line).strip():
            control = control or any(_CONTROL.match(a) for a in actions)
            lines.append("")
            continue

        def placeholder(match):
            expr = " ".join(match.group(1).split())
            token = "__helm_" + hashlib.sha256(expr.encode("utf-8")).hexdigest()[:8] + "__"
            mapping[token] = "{{ " + expr + " }}"
            return token

        lines.append(_ACTION.sub(placeholder, line))
    return "\n".join(lines) + "\n", mapping, control


def _restore(text, mapping):
    return _PLACEHOLDER.sub(lambda m: mapping.get(m.group(0), m.group(0)), str(text))


def _degrade(value_field):
    values = value_field.get("values") or []
    kept = [v for v in values if not _PLACEHOLDER.search(str(v))]
    if len(kept) == len(values):
        return value_field
    notes = sorted(set(value_field.get("notes") or []) | {"helm-template-value"})
    resolution = UNRESOLVED if not kept else (
        PARTIALLY_RESOLVED if value_field.get("resolution") == RESOLVED
        else value_field.get("resolution"))
    return dict(value_field, values=kept, resolution=resolution, notes=notes)


def parse_helm_template(rel_path, text):
    """Like ``parse_k8s_file``, for one chart template (see module docstring)."""
    yaml_text, mapping, control = blank_templates(text)
    identities, grants, bindings, workloads, meta = parse_k8s_file(rel_path, yaml_text)
    meta = dict(meta, helm_placeholders=len(mapping), helm_control_flow=control)
    for ident in identities:
        ident["name"] = _restore(ident["name"], mapping)
        ident["namespace"] = _restore(ident["namespace"], mapping)
    for item in grants + bindings:
        ref = item.get("identity") or {}
        templated = any(_PLACEHOLDER.search(str(ref.get(k) or "")) for k in ("name", "namespace"))
        item["identity"] = {k: _restore(v, mapping) if isinstance(v, str) else v
                            for k, v in ref.items()}
        if "actions" in item:
            item["actions"] = _degrade(item["actions"])
            item["resources"] = _degrade(item["resources"])
            notes = set(item.get("fidelity") or [])
            if templated:
                notes.add("helm-templated-name")
            if control:
                notes.add("helm-conditional")
            item["fidelity"] = sorted(_restore(n, mapping) for n in notes)
        else:
            item["binding_name"] = _restore(item.get("binding_name", ""), mapping)
            item["role"] = _restore(item.get("role", ""), mapping)
    for workload in workloads:
        for key in ("name", "namespace", "service_account"):
            if isinstance(workload.get(key), str):
                workload[key] = _restore(workload[key], mapping)
    return identities, grants, bindings, workloads, meta
