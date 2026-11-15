"""The release verification page matches what the release workflow does (G-3).

`docs/reference/VERIFICATION.md` described v2.3.0 under the repository's
earlier address, and a `slsa-verifier` step that cannot work on the file
the release ships. These checks are static; the `verify-release`
workflow runs `scripts/verify_release.sh` against the real release.
"""

import os
import re

import yaml

from safeai.version import SAFEAI_VERSION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "reference", "VERIFICATION.md")
SCRIPT = os.path.join(ROOT, "scripts", "verify_release.sh")
RELEASE = os.path.join(ROOT, ".github", "workflows", "release.yml")
VERIFY = os.path.join(ROOT, ".github", "workflows", "verify-release.yml")

REPO = "IkarusAILabs/SafeAI"
ISSUER = "https://token.actions.githubusercontent.com"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_doc_names_the_current_release_and_no_other():
    text = _read(DOC)
    assert f"Current release: **v{SAFEAI_VERSION}**" in text
    versions = set(re.findall(r"\b\d+\.\d+\.\d+\b", text))
    # 2.6.1 is the pinned cosign release, not a SafeAI version.
    assert versions - {"2.6.1"} == {SAFEAI_VERSION}


def test_doc_uses_the_current_repository_address():
    text = _read(DOC)
    assert f"github.com/{REPO}" in text
    # The earlier address appears once, in the section that explains it.
    assert text.count("ikaruscareer/SafeAI") == 1


def test_doc_does_not_offer_checks_that_cannot_work():
    text = _read(DOC)
    # The provenance file is unsigned; the page must say so and must not
    # tell the reader to run slsa-verifier on it.
    assert "not a verifiable SLSA" in text
    assert "slsa-verifier verify-artifact" not in text
    # Tags are lightweight; there is nothing for verify-tag to check.
    assert "git verify-tag v" not in text


def test_doc_and_script_run_the_same_checks():
    doc, script = _read(DOC), _read(SCRIPT)
    for needle in (
        "sha256sum -c SHA256SUMS",
        "cosign verify-blob",
        "--certificate-identity",
        "/.github/workflows/release.yml@refs/tags/",
        f'--certificate-oidc-issuer "{ISSUER}"',
        "gh attestation verify",
        "--signer-workflow",
        "--source-ref",
        "pip download",
    ):
        assert needle in doc, f"not in the page: {needle}"
    for needle in (
        "sha256sum -c SHA256SUMS",
        "cosign verify-blob",
        '--certificate-identity "$IDENTITY"',
        "/.github/workflows/release.yml@refs/tags/${TAG}",
        ISSUER,
        "gh attestation verify",
        "--signer-workflow",
        "--source-ref",
        "pip download",
    ):
        assert needle in script, f"not in the script: {needle}"
    assert f'REPO="{REPO}"' in script
    assert "set -euo pipefail" in script


def test_script_checks_what_the_release_workflow_produces():
    release = _read(RELEASE)
    # The release signs with cosign and attests build provenance; those
    # are the two things the script verifies beyond checksums.
    assert "cosign sign-blob" in release
    assert "actions/attest-build-provenance@" in release
    assert "sha256sum -- * > SHA256SUMS" in release


def test_verify_workflow_is_read_only_and_pinned():
    workflow = yaml.safe_load(_read(VERIFY))
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["verify"]
    assert job["permissions"] == {"contents": "read", "attestations": "read"}
    uses = [step["uses"] for step in job["steps"] if step.get("uses")]
    assert uses
    for ref in uses:
        assert _SHA_RE.match(ref.rsplit("@", 1)[1]), f"mutable action pin: {ref}"
    runs = [step["run"] for step in job["steps"] if step.get("run")]
    assert runs == ['bash scripts/verify_release.sh "$VERSION"']
    # PyYAML reads the key ``on`` as the boolean True.
    triggers = workflow.get("on") or workflow.get(True)
    assert "schedule" in triggers


def test_verify_workflow_pins_the_same_cosign_as_the_release():
    def cosign_pin(path):
        for job in yaml.safe_load(_read(path))["jobs"].values():
            for step in job.get("steps") or []:
                if "cosign-installer" in str(step.get("uses")):
                    return step["uses"], step["with"]["cosign-release"]
        raise AssertionError(f"no cosign installer in {path}")

    assert cosign_pin(VERIFY) == cosign_pin(RELEASE)
