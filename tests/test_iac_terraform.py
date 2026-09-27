"""Tests for Terraform relationship extraction (v2.5 redesign)."""

import os

from safeai.iac.terraform import parse_terraform_file

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "iac", "terraform",
    "representative", "main.tf")


def _read_fixture():
    with open(FIXTURE, encoding="utf-8") as handle:
        return handle.read()


def _parse(text, name="main.tf"):
    return parse_terraform_file(name, text)


def test_representative_fixture_graph():
    identities, grants, bindings, meta = _parse(_read_fixture())
    assert meta["module_refs"] == []
    assert meta["detached_policies"] == []
    assert [i["name"] for i in identities] == ["agent-role"]
    assert identities[0]["kind"] == "aws_iam_role"
    # One grant: the attached policy's statements attributed to the
    # role (no standalone policy grant, no fake attachment grant).
    assert len(grants) == 1
    grant = grants[0]
    assert grant["identity"] == {"kind": "aws_iam_role",
                                 "name": "agent-role"}
    assert grant["actions"]["values"] == ["s3:GetObject", "s3:PutObject"]
    assert grant["actions"]["resolution"] == "resolved"
    assert grant["resources"]["values"] == ["arn:aws:s3:::agent-bucket/*"]
    assert grant["source_file"] == "main.tf"
    assert grant["line"] >= 1
    assert grant["family"] == "cloud"
    assert any("via-" in note for note in grant["fidelity"])
    assert len(bindings) == 1
    binding = bindings[0]
    assert binding["binding_kind"] == "attachment"
    assert binding["identity"]["name"] == "agent-role"
    assert "agent_s3" in binding["role"] or "policy" in binding["role"]


def test_inline_policy_binds_directly_to_role():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy" "inline" {
  name = "inline"
  role = aws_iam_role.app.name
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
'''
    identities, grants, bindings, _ = _parse(text)
    assert [i["name"] for i in identities] == ["app-role"]
    assert len(grants) == 1
    assert grants[0]["identity"] == {"kind": "aws_iam_role",
                                     "name": "app-role"}
    assert grants[0]["actions"]["values"] == ["s3:GetObject"]
    assert "inline-policy-statement" in grants[0]["fidelity"]
    assert bindings == []


def test_attachment_is_relationship_not_permission():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.p.arn
}
resource "aws_iam_policy" "p" {
  name = "p"
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
}
'''
    _, grants, bindings, _ = _parse(text)
    # No fake action="attached-policy" grant may exist.
    assert all(g["actions"].get("values") != ["attached-policy"]
               for g in grants)
    assert len(bindings) == 1
    assert bindings[0]["identity"]["name"] == "app-role"
    assert len(grants) == 1
    assert grants[0]["identity"]["name"] == "app-role"
    assert grants[0]["actions"]["values"] == ["ec2:DescribeInstances"]
    assert any("via-" in note for note in grants[0]["fidelity"])


def test_managed_policy_never_guessed():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
'''
    _, grants, bindings, _ = _parse(text)
    assert len(bindings) == 1
    assert len(grants) == 1
    assert grants[0]["actions"]["resolution"] == "unresolved"
    assert "managed-policy-content" in grants[0]["actions"]["notes"]


def test_interpolation_splits_field_resolution():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_policy" "dyn" {
  name = "dyn"
  statement {
    actions   = ["s3:ListBucket", "s3:${var.extra}"]
    resources = ["arn:aws:s3:::${var.bucket}/*"]
  }
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.dyn.arn
}
'''
    _, grants, _, _ = _parse(text)
    assert len(grants) == 1
    actions = grants[0]["actions"]
    assert actions["values"] == ["s3:ListBucket"]
    assert actions["resolution"] == "partially-resolved"
    assert grants[0]["resources"]["resolution"] == "unresolved"


def test_data_document_statements_inherited():
    text = '''
data "aws_iam_policy_document" "base" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "p" {
  name   = "p"
  policy = data.aws_iam_policy_document.base.json
}
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.p.arn
}
'''
    _, grants, _, _ = _parse(text)
    assert len(grants) == 1
    assert grants[0]["identity"]["name"] == "app-role"
    assert grants[0]["actions"]["values"] == ["s3:GetObject"]
    assert "via-data-document" in grants[0]["fidelity"]


def test_detached_policies_recorded_not_granted():
    text = '''
resource "aws_iam_policy" "loose" {
  name = "loose"
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
'''
    _, grants, bindings, meta = _parse(text)
    assert grants == []
    assert bindings == []
    assert meta["detached_policies"] == ["loose"]


def test_external_payload_yields_opaque_grant():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
}
resource "aws_iam_role_policy" "inline" {
  name   = "inline"
  role   = aws_iam_role.app.name
  policy = file("policy.json")
}
'''
    _, grants, _, _ = _parse(text)
    assert len(grants) == 1
    assert grants[0]["actions"]["resolution"] == "unresolved"
    assert "opaque-policy-document" in grants[0]["fidelity"]


def test_unattached_opaque_policy_is_detached_not_granted():
    text = '''
resource "aws_iam_policy" "p" {
  name   = "p"
  policy = file("policy.json")
}
'''
    _, grants, _, meta = _parse(text)
    assert grants == []
    assert meta["detached_policies"] == ["p"]


def test_modules_recorded_not_expanded():
    text = '''
module "vpc" {
  source = "./modules/vpc"
}
'''
    _, _, _, meta = _parse(text)
    assert meta["module_refs"] == ["vpc"]


def test_assume_role_policy_is_not_a_grant():
    text = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Statement = [{
      Action = ["sts:AssumeRole"]
      Resource = ["*"]
    }]
  })
}
'''
    identities, grants, _, _ = _parse(text)
    assert [i["name"] for i in identities] == ["app-role"]
    assert grants == []


def test_unbalanced_tail_skipped():
    text = 'resource "aws_iam_policy" "broken" {\n  statement {\n'
    identities, grants, bindings, meta = _parse(text)
    assert (identities, grants, bindings) == ([], [], [])
    # A watched IAM header with nothing extractable is unparsed, not silent.
    assert meta["unparsed"] is True


def test_never_raises_on_pathological_input():
    assert _parse("\x00\x01\x02 {{{")[0] == []
    assert _parse("resource " * 10000)[0] == []
    assert _parse("")[0] == []
