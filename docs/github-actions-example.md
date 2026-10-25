# Minimal GitHub Actions Example

A small CI integration should scan the agent manifest that is actually being reviewed and publish the machine-readable report as an artifact. Keep the policy decision explicit: teams may fail on new findings, capability escalations, or only on selected severities.

The example below is intentionally schematic so it does not prescribe a repository-specific command or hide a version pin:

```yaml
name: SafeAI scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Install SafeAI
        run: pip install SafeAI-Static-Analyzer==<reviewed-version>
      - name: Scan manifest
        run: safeai scan path/to/manifest --sarif safeai.sarif
      - uses: actions/upload-artifact@v4
        with:
          name: safeai-report
          path: safeai.sarif
```

Do not place credentials in the manifest or echo private prompts into CI logs. Review the generated report as evidence, and keep baseline changes separate from unrelated implementation changes.

## Trust boundary and permissions

Keep the workflow's authority narrow and explicit:

- `contents: read` is enough for the minimal scan-and-upload pattern above.
- The scan step reads the checked-out workspace and writes local report files; it should not need repository write permissions.
- Installing from PyPI and uploading an artifact are network operations performed by the CI environment, not by the scanned agent. Pin the SafeAI version you review so this boundary is reproducible.
- If you enable PR comments through the composite action's `pr-comment-post` option, grant only the additional permission required for that job, for example `pull-requests: write`, and treat the resulting comment as generated report output.
- Do not pass broad tokens through `extra-args` or environment variables unless a specific integration requires them and the workflow documents why.

This keeps the evidence boundary clear: SafeAI reports what it can infer from the repository under review, while GitHub Actions handles checkout, package installation, artifact upload, and any optional PR comment publishing.
