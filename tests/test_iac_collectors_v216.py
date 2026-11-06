"""CloudFormation, Serverless Framework and Helm collectors (v2.16, plans 2.16-1 to 2.16-3)."""

import json

import pytest

from safeai.iac import scan_iac
from safeai.iac.cloudformation import load_template, parse_cloudformation
from safeai.iac.helm import blank_templates, parse_helm_template
from safeai.iac.serverless import parse_serverless


def _grants(grants):
    return sorted((g["identity"]["name"], tuple(g["actions"]["values"]),
                   g["actions"]["resolution"], tuple(g["resources"]["values"]),
                   g["resources"]["resolution"]) for g in grants)


# --- CloudFormation -------------------------------------------------------------

CFN = """Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "${Env}-role"
      Policies:
        - PolicyName: p
          PolicyDocument: !If [Cond, {Statement: []}, !Ref AWS::NoValue]
        - PolicyName: q
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: [s3:GetObject, !Ref ExtraAction]
                Resource: arn:aws:s3:::bucket/*
              - Effect: Allow
                NotAction: iam:*
                Resource: "*"
  Orphan:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Roles: [!Ref Elsewhere]
      PolicyDocument: {Statement: [{Effect: Allow, Action: "*", Resource: "*"}]}
"""


def test_cloudformation_intrinsics_are_never_evaluated():
    identities, grants, bindings, meta = parse_cloudformation("t.yaml", CFN)
    assert meta == {"template": True, "unresolved_roles": 1}
    assert [(i["name"], i["source_ref"]) for i in identities] == [("R", "t.yaml:2")]
    assert _grants(grants) == [
        ("R", (), "unresolved", (), "unresolved"),
        ("R", ("s3:GetObject",), "partially-resolved", ("arn:aws:s3:::bucket/*",), "resolved"),
    ]
    opaque = next(g for g in grants if not g["actions"]["values"])
    assert "opaque-policy-document" in opaque["fidelity"]
    assert all("logical-id-name" in g["fidelity"] for g in grants)
    assert bindings == []


@pytest.mark.parametrize(("text", "is_template"), [
    ("Resources:\n  B:\n    Type: AWS::S3::Bucket\n", True),
    ('{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"X": {"Type": "Custom::Y"}}}', True),
    ("apiVersion: v1\nkind: ServiceAccount\n", False),
    ("Resources: []\n", False),
    ("key: [unclosed\n", False),
])
def test_template_detection(text, is_template):
    assert (load_template(text, is_json=text.startswith("{")) is not None) is is_template


# --- Serverless ------------------------------------------------------------------

def test_serverless_named_role_v1_statements_and_external_role():
    named = parse_serverless("serverless.yml", (
        "service: {name: billing}\nprovider:\n  iamRoleStatements:\n"
        "    - {Effect: Allow, Action: [s3:GetObject], Resource: '*'}\n"
        "  iam:\n    role:\n      name: billing-exec\n"
        "      statements:\n        - {Effect: Deny, Action: '*', Resource: '*'}\n"))
    identities, grants, _bindings, meta = named
    assert meta["service"] == "billing"
    assert [i["name"] for i in identities] == ["billing-exec"]
    assert _grants(grants) == [("billing-exec", ("s3:GetObject",), "resolved", ("*",),
                                "resolved")]
    external = parse_serverless("serverless.yml", (
        "service: x\nprovider:\n  iam:\n    role: arn:aws:iam::123456789012:role/shared\n"))
    assert external[0] == [] and external[1] == []
    assert external[2][0]["notes"] == ["external-role"]


def test_serverless_variables_degrade_and_bad_yaml_is_unparsed():
    _i, grants, _b, _m = parse_serverless("serverless.yml", (
        "service: x\nprovider:\n  iam:\n    role:\n      statements:\n"
        "        - {Effect: Allow, Action: ['${self:custom.action}', sqs:SendMessage],"
        " Resource: '${env:QUEUE}'}\n"))
    assert _grants(grants) == [("x-lambdaRole", ("sqs:SendMessage",), "partially-resolved", (),
                                "unresolved")]
    assert parse_serverless("serverless.yml", "service: [\n")[3]["unparsed"] is True


# --- Helm -------------------------------------------------------------------------

def test_blanking_keeps_lines_and_maps_expressions():
    text = ('{{- if .Values.on }}\nmetadata:\n  name: {{ .Release.Name }}-sa\n'
            '  other: {{.Release.Name}}\n{{- end }}\n')
    blanked, mapping, control = blank_templates(text)
    lines = blanked.splitlines()
    assert lines[0] == "" and lines[4] == "" and len(lines) == 5
    assert lines[2].split(": ")[1].endswith("-sa")
    assert lines[2].split(": ")[1][:-3] == lines[3].split(": ")[1]
    assert control is True
    assert set(mapping.values()) == {"{{ .Release.Name }}"}


def test_helm_template_that_still_does_not_parse_is_unparsed():
    _i, _g, _b, _w, meta = parse_helm_template("t.yaml", "kind: Role\nrules: {{ x }\n  - [\n")
    assert meta["unparsed"] is True


def test_scan_routes_files_to_the_right_collector(tmp_path):
    (tmp_path / "chart" / "templates").mkdir(parents=True)
    (tmp_path / "chart" / "Chart.yaml").write_text("name: c\n", encoding="utf-8")
    (tmp_path / "chart" / "templates" / "sa.yaml").write_text(
        "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ .Values.sa }}\n",
        encoding="utf-8")
    (tmp_path / "cfn.yaml").write_text(CFN, encoding="utf-8")
    (tmp_path / "serverless.yml").write_text(
        "service: s\nprovider:\n  iam:\n    role:\n      statements:\n"
        "        - {Effect: Allow, Action: sqs:SendMessage, Resource: '*'}\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
    graph, meta = scan_iac(str(tmp_path))
    files = meta["files"]
    assert (files["cloudformation"], files["serverless"], files["helm"]) == (
        ["cfn.yaml"], ["serverless.yml"], ["chart/templates/sa.yaml"])
    assert files["unparsed"] == []
    assert {i["name"] for i in graph["identities"]} == {"R", "s-lambdaRole",
                                                         "{{ .Values.sa }}"}
