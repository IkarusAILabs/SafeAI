# SafeAI — Release Verification

How to check that a SafeAI release is the one this repository built.

Current release: **v2.16.0**. Releases are at
https://github.com/IkarusAILabs/SafeAI/releases.

Every step below is run against the latest release by the
`verify-release` workflow (weekly, and on any change to this page or
the script), using [`scripts/verify_release.sh`](../../scripts/verify_release.sh).
If a step stops working, that workflow fails.

## What a release contains

| Asset | What it is | How it is protected |
|---|---|---|
| `safeai_static_analyzer-X.Y.Z-py3-none-any.whl` | Python wheel | Checksum, Cosign signature, Sigstore build-provenance attestation |
| `safeai_static_analyzer-X.Y.Z.tar.gz` | Source distribution | Checksum, Cosign signature, Sigstore build-provenance attestation |
| `*.sig`, `*.pem` | Cosign keyless signature and certificate for the wheel and the sdist | — |
| `safeai-X.Y.Z-sbom.spdx.json` | SPDX SBOM | Checksum only |
| `safeai-X.Y.Z-slsa-provenance.json` | A descriptive statement written by the release workflow | Checksum only; **not signed, see below** |
| `SHA256SUMS` | SHA-256 of the wheel, the sdist, the SBOM and the statement | Not signed itself |

## What is not verifiable today

Read this before relying on a check that does not exist.

- **`safeai-X.Y.Z-slsa-provenance.json` is not a verifiable SLSA
  provenance.** The release workflow writes it by hand. It is unsigned,
  its subject is the git commit and not an artifact digest, and it
  still names the repository's earlier address. `slsa-verifier` cannot
  verify it. The verifiable provenance is the Sigstore attestation in
  step 4.
- **`SHA256SUMS` and the SBOM are not signed.** A checksum shows that a
  download is intact. It does not show who produced it. The wheel and
  the sdist are the signed artifacts; trust for the SBOM rests on the
  release page.
- **Release tags are not signed.** They are lightweight tags, so
  `git verify-tag` has nothing to check.
- **Builds are not reproducible.** Rebuilding from the tag is not
  expected to give a byte-identical wheel.

## Verify everything

Needs [`gh`](https://cli.github.com) (signed in),
[`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/),
`sha256sum` and Python with `pip`.

```bash
git clone https://github.com/IkarusAILabs/SafeAI.git
bash SafeAI/scripts/verify_release.sh 2.16.0
# Expected last line: All checks passed for v2.16.0.
```

With no version, the script verifies the latest release.

## The steps by hand

Set the version once:

```bash
VERSION=2.16.0
REPO=IkarusAILabs/SafeAI
```

### 1. Download

```bash
mkdir safeai-release && cd safeai-release
gh release download "v${VERSION}" --repo "$REPO"
```

Without `gh`, download each asset from
`https://github.com/IkarusAILabs/SafeAI/releases/download/v${VERSION}/<asset>`.

### 2. Checksums

```bash
sha256sum -c SHA256SUMS
# Expected: four lines ending in ": OK"
```

On macOS use `shasum -a 256 -c SHA256SUMS`. On Windows (PowerShell):

```powershell
$VERSION = "2.16.0"
$wheel = "safeai_static_analyzer-$VERSION-py3-none-any.whl"
$hash = (Get-FileHash -Algorithm SHA256 $wheel).Hash.ToLower()
$expected = (Get-Content SHA256SUMS | Select-String $wheel).Line.Split()[0]
if ($hash -eq $expected) { "Checksum OK" } else { "MISMATCH" }
```

### 3. Cosign signatures

The wheel and the sdist are signed keyless by the release workflow. The
certificate identity names the workflow and the tag.

```bash
for artifact in \
  "safeai_static_analyzer-${VERSION}-py3-none-any.whl" \
  "safeai_static_analyzer-${VERSION}.tar.gz"; do
  cosign verify-blob \
    --certificate "${artifact}.pem" \
    --signature "${artifact}.sig" \
    --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$artifact"
done
# Expected, twice: Verified OK
```

### 4. Build provenance

The release workflow records a Sigstore build-provenance attestation
for the wheel and the sdist. This check ties each file to the workflow
and the tag that built it.

```bash
for artifact in \
  "safeai_static_analyzer-${VERSION}-py3-none-any.whl" \
  "safeai_static_analyzer-${VERSION}.tar.gz"; do
  gh attestation verify "$artifact" \
    --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/v${VERSION}"
done
# Expected: exit code 0 for both
```

### 5. PyPI

The wheel on PyPI should be the wheel in the release.

```bash
python -m pip download --no-deps --only-binary :all: --dest pypi "SafeAI-Static-Analyzer==${VERSION}"
sha256sum "pypi/safeai_static_analyzer-${VERSION}-py3-none-any.whl" "safeai_static_analyzer-${VERSION}-py3-none-any.whl"
# Expected: the same hash on both lines
```

To install with the hash pinned:

```bash
pip install --require-hashes --hash=sha256:<HASH> "SafeAI-Static-Analyzer==${VERSION}"
```

### 6. Installed version

```bash
safeai --version
```

## Releases before the repository moved

The repository was `ikaruscareer/SafeAI` before it became
`IkarusAILabs/SafeAI`. A release signed under the earlier address
carries that address in its certificate identity. To find the identity
a release was signed with, read it from the certificate:

```bash
base64 -d "safeai_static_analyzer-${VERSION}-py3-none-any.whl.pem" | openssl x509 -noout -ext subjectAltName
```

Only v2.16.0 has been checked against this page.

## Troubleshooting

- **404 on an asset.** Asset names can change between releases; check
  the release page.
- **Cosign identity mismatch.** The identity must name the tag you are
  verifying, including the leading `v`.
- **Checksum mismatch.** Download again. If it persists, report it
  under [SECURITY.md](../../SECURITY.md).

## Release signing (maintainers)

**Why Cosign is pinned.** `sigstore/cosign-installer` is pinned to an
immutable commit SHA, and `cosign-release` is pinned explicitly to
v2.6.1: the installer's own default fails its version validation and
falls back to building cosign from HEAD, whose CLI breaks `sign-blob`.
The pin (with rationale in `release.yml`) survives Dependabot bumps of
the installer action itself.

**What is signed.** Every `dist/*.whl` and `dist/*.tar.gz` gets a
detached `.sig` signature and `.pem` certificate (keyless OIDC via
GitHub Actions) and a Sigstore build-provenance attestation. The SBOM,
the provenance statement and `SHA256SUMS` ship alongside unsigned.

**How maintainers detect signing failures.** The pipeline signs, then
*verifies* (`cosign verify-blob` against the artifact with the expected
repository identity and OIDC issuer) before preparing release assets.
Verification failure fails the step and blocks publish/release jobs via
job dependencies. "The signing command completed" is never treated as
integrity evidence. `tests/test_release_workflow.py` statically asserts
the verify stage, SHA pins, and cosign pin on every CI run.
