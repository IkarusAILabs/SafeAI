#!/usr/bin/env bash
# Verify a SafeAI release the way docs/reference/VERIFICATION.md describes.
#
#   scripts/verify_release.sh            # the latest release
#   scripts/verify_release.sh 2.16.0     # a named release
#
# Needs: gh (signed in, or GH_TOKEN set), cosign, sha256sum, python with pip.
# Downloads the release assets into a new temporary directory. Nothing
# that is downloaded is installed or run.
#
# Exits non-zero at the first check that fails. The verify-release
# workflow runs this script, so the documented steps are tested against
# the latest release.
set -euo pipefail

REPO="IkarusAILabs/SafeAI"
PACKAGE="SafeAI-Static-Analyzer"
ISSUER="https://token.actions.githubusercontent.com"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(gh release view --repo "$REPO" --json tagName --jq .tagName)"
fi
VERSION="${VERSION#v}"
TAG="v${VERSION}"
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"

WORK="$(mktemp -d)"
cd "$WORK"
echo "Verifying ${REPO} ${TAG} in ${WORK}"

echo "== 1. Download the release assets"
gh release download "$TAG" --repo "$REPO"

echo "== 2. Checksums (SHA256SUMS lists the wheel, the sdist, the SBOM and the provenance statement)"
sha256sum -c SHA256SUMS
for name in \
  "safeai_static_analyzer-${VERSION}-py3-none-any.whl" \
  "safeai_static_analyzer-${VERSION}.tar.gz" \
  "safeai-${VERSION}-sbom.spdx.json"; do
  grep -q "  ${name}\$" SHA256SUMS || { echo "SHA256SUMS does not list ${name}"; exit 1; }
done

echo "== 3. Cosign keyless signatures (wheel and sdist)"
for artifact in \
  "safeai_static_analyzer-${VERSION}-py3-none-any.whl" \
  "safeai_static_analyzer-${VERSION}.tar.gz"; do
  cosign verify-blob \
    --certificate "${artifact}.pem" \
    --signature "${artifact}.sig" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$artifact"
done

echo "== 4. Build provenance (Sigstore attestation, wheel and sdist)"
for artifact in \
  "safeai_static_analyzer-${VERSION}-py3-none-any.whl" \
  "safeai_static_analyzer-${VERSION}.tar.gz"; do
  gh attestation verify "$artifact" \
    --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${TAG}"
  echo "Attestation verified: ${artifact}"
done

echo "== 5. The wheel on PyPI is the wheel in the release"
mkdir pypi
python -m pip download --quiet --no-deps --only-binary :all: --dest pypi "${PACKAGE}==${VERSION}"
release_hash="$(sha256sum "safeai_static_analyzer-${VERSION}-py3-none-any.whl" | cut -c1-64)"
pypi_hash="$(sha256sum "pypi/safeai_static_analyzer-${VERSION}-py3-none-any.whl" | cut -c1-64)"
if [ "$release_hash" != "$pypi_hash" ]; then
  echo "PyPI wheel ${pypi_hash} differs from the release wheel ${release_hash}"
  exit 1
fi
echo "PyPI wheel matches: ${pypi_hash}"

echo "All checks passed for ${TAG}."
