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


def test_release_workflow_no_fault_tolerance():
    """
    Verify checklist, build, attest, sign, publish, release jobs have no:
      - continue-on-error: true
      - || true, || echo, or similar shell continuations
    
    If signing or publishing fails, the pipeline MUST stop.
    """
    workflow = _load()
    critical_jobs = ['checklist', 'build', 'attest', 'sign', 'publish', 'release']
    jobs = workflow.get("jobs") or {}
    
    for job_name in critical_jobs:
        if job_name not in jobs:
            continue
        job = jobs[job_name]
        steps = job.get("steps") or []
        
        for i, step in enumerate(steps):
            # Check continue-on-error: true
            if step.get("continue-on-error") is True:
                raise AssertionError(
                    f"Job '{job_name}', step {i+1}: continue-on-error: true found. "
                    f"Critical jobs must fail fast on errors."
                )
            
            # Check for run command containing || true or || echo
            if "run" in step and isinstance(step["run"], str):
                cmd = step["run"]
                if "|| true" in cmd or "|| echo" in cmd or "|| :" in cmd:
                    raise AssertionError(
                        f"Job '{job_name}', step {i+1}: fault-tolerant pattern found in run command. "
                        f"Command: {cmd[:100]}..."
                    )


def test_release_workflow_no_artifact_rebuild_after_sign():
    """
    Verify publish and release jobs do NOT rebuild or re-download artifacts.
    They should only use signed artifacts from the "sign" job's upload-artifact.
    """
    workflow = _load()
    jobs = workflow.get("jobs") or {}
    
    # Get artifact name from sign job's upload-artifact
    sign_job = jobs.get("sign")
    if not sign_job:
        raise AssertionError("sign job missing")
    
    sign_steps = sign_job.get("steps") or []
    upload_step = None
    for step in sign_steps:
        if step.get("uses", "").startswith("actions/upload-artifact"):
            upload_step = step
            break
    
    if not upload_step:
        raise AssertionError("sign job missing upload-artifact step")
    
    # Extract artifact name from upload-artifact step
    artifact_name = None
    if isinstance(upload_step.get("with"), dict):
        artifact_name = upload_step["with"].get("name")
    if not artifact_name:
        # Default name if not specified
        artifact_name = "signed"
    
    # Check publish job
    publish_job = jobs.get("publish")
    if publish_job:
        publish_steps = publish_job.get("steps") or []
        
        # Must have download-artifact step
        has_download = False
        for step in publish_steps:
            if step.get("uses", "").startswith("actions/download-artifact"):
                with_dict = step.get("with", {})
                if isinstance(with_dict, dict) and with_dict.get("name") == artifact_name:
                    has_download = True
                    break
        
        if not has_download:
            raise AssertionError(
                f"publish job must download-artifact with name='{artifact_name}' from sign job"
            )
        
        # Must NOT have rebuild/compile steps
        for step in publish_steps:
            if "run" in step and isinstance(step["run"], str):
                cmd = step["run"].lower()
                if any(pattern in cmd for pattern in [
                    "python -m build",
                    "pip install",
                    "python setup.py",
                    "cargo build",
                    "make",
                    "npm run build",
                    "yarn build",
                    "gradle",
                    "maven"
                ]):
                    raise AssertionError(
                        f"publish job contains rebuild command: {step['run'][:100]}..."
                    )
            
# Must NOT have upload-artifact after download (no re-uploading)
        if step.get("uses", "").startswith("actions/upload-artifact"):
            # Check if this comes after a download-artifact step
            # Simple check: if we see upload-artifact, flag it unless it's the only one
            upload_count = sum(1 for s in publish_steps if s.get("uses", "").startswith("actions/upload-artifact"))
            if upload_count > 1:
                raise AssertionError(
                    "publish job has multiple upload-artifact steps - potential re-upload after signing"
                )
    
    # Check release job
    release_job = jobs.get("release")
    if release_job:
        release_steps = release_job.get("steps") or []
        
        # Must NOT have build/compile steps
        for step in release_steps:
            if "run" in step and isinstance(step["run"], str):
                cmd = step["run"].lower()
                if any(pattern in cmd for pattern in [
                    "python -m build",
                    "pip install",
                    "python setup.py",
                    "cargo build",
                    "make",
                    "npm run build",
                    "yarn build",
                    "gradle",
                    "maven",
                    "gh release create"  # This is ok if it just creates the release, but check if building
                ]):
                    # Allow gh release create as it's just creating the GitHub release
                    if "gh release create" in cmd and "--generate-notes" in cmd:
                        continue  # This is ok
                    raise AssertionError(
                        f"release job contains rebuild command: {step['run'][:100]}..."
                    )
            
            # Must NOT have upload-artifact (uses what's already signed)
            if step.get("uses", "").startswith("actions/upload-artifact"):
                raise AssertionError(
                    "release job has upload-artifact step - should only download signed assets"
                )


def test_release_workflow_id_token_permissions_scoped():
    """
    Verify id-token: write is only granted to sign and publish jobs.
    Build and other jobs should have no OIDC token access or read-only.
    """
    workflow = _load()
    jobs = workflow.get("jobs") or {}
    
    # Jobs that should NOT have id-token: write
    no_write_jobs = ['checklist', 'build', 'attest']
    
    # Jobs that MUST have id-token: write
    must_have_write = ['sign', 'publish']
    
    # release job should have read or none (doesn't create tokens)
    
    for job_name, job_config in jobs.items():
        if not isinstance(job_config, dict):
            continue
            
        permissions = job_config.get("permissions", {})
        if isinstance(permissions, str):
            # If permissions is a string like "read-all", convert to dict
            # For simplicity, we'll check if it contains id-token later
            continue
            
        id_token_perms = permissions.get("id-token") if isinstance(permissions, dict) else None
        
        if job_name in no_write_jobs and id_token_perms == "write":
            raise AssertionError(
                f"Job '{job_name}' has id-token: write but should not. "
                f"Only sign and publish jobs need write access to OIDC tokens."
            )
        elif job_name in must_have_write and id_token_perms != "write":
            raise AssertionError(
                f"Job '{job_name}' must have id-token: write for signing/publishing, got {id_token_perms!r}"
            )
        # For other jobs (like release), we're flexible - could be read, write, or None
