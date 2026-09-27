"""Tests for authority semantic normalization (v2.5 redesign)."""

from safeai.iac import semantics


def test_camelcase_verbs_classify():
    assert semantics.ops_class("GetObject") == "read"
    assert semantics.ops_class("PutObject") == "write"
    assert semantics.ops_class("DescribeInstances") == "read"
    assert semantics.ops_class("list") == "read"
    assert semantics.ops_class("*") == "admin"


def test_delegation_verbs_are_admin():
    assert semantics.ops_class("PassRole") == "admin"
    assert semantics.ops_class("AssumeRole") == "admin"


def test_unknown_verbs_stay_unknown():
    assert semantics.ops_class("Frobnicicate") is None
    assert semantics.ops_class("") is None


def test_wildcard_action_covers_same_service():
    grant = {"provider": "aws", "service": "s3",
             "ops": {"read", "write", "admin"}, "wildcard": True}
    req = {"provider": "aws", "service": "s3", "ops": {"read"}}
    covered, excess, notes = semantics.compatible(grant, req)
    assert covered is True
    assert excess == {"write", "admin"}
    assert "grant-wildcard" in notes


def test_getobject_is_not_iam_star():
    narrow = {"provider": "aws", "service": "s3", "ops": {"read"},
              "wildcard": False}
    req = {"provider": "aws", "service": "s3", "ops": {"read"}}
    covered, excess, _ = semantics.compatible(narrow, req)
    assert covered is True
    assert excess == set()
    admin = {"provider": "aws", "service": "iam", "ops": {"read"},
             "wildcard": False}
    covered, _, notes = semantics.compatible(admin, req)
    assert covered is False
    assert "service-mismatch" in notes


def test_put_does_not_imply_get():
    grant = {"provider": "aws", "service": "s3", "ops": {"write"},
             "wildcard": False}
    req = {"provider": "aws", "service": "s3", "ops": {"read"}}
    covered, _, _ = semantics.compatible(grant, req)
    assert covered is False


def test_kubernetes_pods_are_not_wildcard():
    pods = {"provider": "kubernetes", "service": "*",
            "ops": {"read"}, "wildcard": False}
    req = {"provider": "kubernetes", "service": "*",
           "ops": {"read", "write"}}
    covered, _, _ = semantics.compatible(pods, req)
    assert covered is False


def test_requirement_domains():
    assert semantics.normalize_requirement("s3", "read") == {
        "provider": "aws", "service": "s3", "ops": {"read"}}
    assert semantics.normalize_requirement("s3", "write")["ops"] == {
        "read", "write"}
    assert semantics.normalize_requirement("kubernetes", "execute") == {
        "provider": "kubernetes", "service": "*",
        "ops": {"read", "write"}}
    assert semantics.normalize_requirement("shell", "execute") is None
    assert semantics.normalize_requirement("s3", "none") is None


def test_grant_descriptor_flags_unresolvable():
    grant = {"actions": {"values": [], "resolution": "unresolved",
                         "notes": []},
             "resources": {"values": [], "resolution": "unresolved",
                           "notes": []},
             "source": "terraform"}
    descriptor, unresolvable = semantics.grant_descriptor(grant)
    assert unresolvable is True
    grant2 = {"actions": {"values": ["s3:GetObject"],
                          "resolution": "resolved", "notes": []},
              "resources": {"values": ["*"], "resolution": "resolved",
                            "notes": []},
              "source": "terraform"}
    descriptor, unresolvable = semantics.grant_descriptor(grant2)
    assert unresolvable is False
    assert (descriptor["provider"], descriptor["service"]) == ("aws", "s3")
    assert descriptor["ops"] == {"read"}
