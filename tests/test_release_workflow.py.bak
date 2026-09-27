"""Static validation of the release workflow's security posture.

Asserts on `.github/workflows/release.yml` (parsed, not executed):
every third-party action pinned to an immutable commit SHA, no mutable
refs, the Cosign version explicitly pinned, and a fail-closed signature
verification stage between signing and asset preparation.
"""

import os
import re

import yaml

WORKFLOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".github", "workflows", "release.yml",
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _load():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _walk_steps(workflow):
    for job in (workflow.get("jobs") or {}).values():
        yield from job.get("steps") or []


def test_all_actions_pinned_to_sha():
    workflow = _load()
    uses_refs = [
        step["uses"] for step in _walk_steps(workflow) if step.get("uses")
    ]
    assert uses_refs, "no action references found"
    for ref in uses_refs:
        assert "@" in ref, f"unpinned action reference: {ref}"
        _repo, pin = ref.rsplit("@", 1)
        assert _SHA_RE.match(pin), f"mutable action pin (want 40-hex SHA): {ref}"


def test_no_mutable_refs_in_raw_text():
    with open(WORKFLOW, encoding="utf-8") as fh:
        text = fh.read()
    for line in text.splitlines():
        stripped = line.split("#", 1)[0]
        if "uses:" not in stripped:
            continue
        assert "@main" not in stripped, f"mutable @main ref: {line.strip()}"
        assert not re.search(r"@(v\d|latest|stable)", stripped), \
            f"mutable version ref: {line.strip()}"


def test_cosign_release_explicitly_pinned():
    workflow = _load()
    found = False
    for step in _walk_steps(workflow):
        uses = str(step.get("uses") or "")
        if "cosign-installer" not in uses:
            continue
        release = (step.get("with") or {}).get("cosign-release")
        assert release, "cosign-installer must pin cosign-release explicitly"
        assert re.match(r"^v\d+\.\d+\.\d+$", str(release)), \
            f"cosign-release must be a version tag, got {release!r}"
        found = True
    assert found, "cosign-installer step missing"


def test_verify_stage_between_sign_and_prepare():
    workflow = _load()
    sign_job = (workflow.get("jobs") or {}).get("sign")
    assert sign_job is not None, "sign job missing"
    names = [str(s.get("name") or "") for s in sign_job.get("steps") or []]
    sign_idx = next(i for i, n in enumerate(names) if n.startswith("Sign artifacts"))
    verify_idx = next(
        (i for i, n in enumerate(names) if "erify signature" in n), None)
    prepare_idx = next(
        (i for i, n in enumerate(names) if n.startswith("Prepare release assets")), None)
    assert verify_idx is not None, "fail-closed verify stage missing from sign job"
    assert sign_idx < verify_idx < prepare_idx, \
        "verify stage must run after signing and before asset preparation"


def test_verify_uses_expected_identity_and_fails_closed():
    workflow = _load()
    sign_job = (workflow.get("jobs") or {}).get("sign")
    verify = next(
        s for s in sign_job.get("steps") or []
        if "erify signature" in str(s.get("name") or ""))
    body = str(verify.get("run") or "")
    assert "verify-blob" in body
    assert "certificate-identity-regexp" in body
    assert "certificate-oidc-issuer" in body
    # Exact-match (not substring): the OIDC issuer must be precisely the
    # GitHub Actions issuer. Equality comparison also keeps CodeQL's
    # incomplete-URL-substring-sanitization query quiet: this asserts
    # workflow text, it sanitizes no URL.
    import re as _re

    issuer = _re.search(r"--certificate-oidc-issuer\s+\"([^\"]+)\"", body)
    assert issuer is not None, "verify step must pin --certificate-oidc-issuer"
    assert issuer.group(1) == "https://token.actions.githubusercontent.com"
    # No `|| true`, no `continue-on-error`: verification failure fails the job.
    assert "|| true" not in body
    assert verify.get("continue-on-error") is not True


def test_publish_and_release_depend_on_sign():
    workflow = _load()
    jobs = workflow.get("jobs") or {}
    for job_name in ("publish", "release"):
        needs = jobs[job_name].get("needs") or []
        assert "sign" in needs, f"{job_name} must depend on the sign job"
