"""``safeai manifest`` subcommands — local manifest contract operations.

All operations are offline: read a JSON file, validate or verify it
against the local contract, print deterministic results. No network,
no execution of scanned code.
"""

from __future__ import annotations

import json

from safeai.kya.contract import validate_manifest


def run_manifest_command(args):
    """Dispatch ``safeai manifest <validate|verify>``. Returns exit code."""
    sub = getattr(args, "manifest_command", None)
    if sub == "validate":
        return _validate(args.file)
    if sub == "verify":
        if getattr(args, "attestation", None):
            return _verify_attestation(args.file, args.attestation)
        from safeai.kya.integrity import verify_manifest_file
        return verify_manifest_file(args.file)
    if sub == "export":
        return _export(args)
    print("Usage: safeai manifest {validate|verify|export} <file>")
    return 2


def _verify_attestation(manifest_path, statement_path):
    from safeai.kya.attestation import ATTESTATION_OK, verify_attestation

    try:
        with open(manifest_path, "rb") as fh:
            manifest_bytes = fh.read()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        with open(statement_path, encoding="utf-8") as fh:
            statement = json.load(fh)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"error: unable to read manifest or attestation: {exc}")
        return 1
    status, detail = verify_attestation(manifest_bytes, manifest, statement)
    if status == ATTESTATION_OK:
        print(f"verified: {manifest_path} with attestation {statement_path} ({detail})")
        return 0
    print(f"{status}: {statement_path} ({detail})")
    return 1


def _export(args):
    """Write an export from a manifest whose integrity digest verifies."""
    from safeai.kya.integrity import OK, verify_document
    from safeai.report.exports import write_export

    try:
        with open(args.file, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: unable to read {args.file}: {exc}")
        return 1
    status, detail = verify_document(manifest)
    if status != OK:
        print(f"{status}: {args.file} ({detail}); not exported")
        return 1
    count = write_export(args.format, manifest, args.output,
                         issuer=args.ssf_issuer, audience=args.ssf_audience)
    print(f"exported: {count} {args.format} record(s) to {args.output}")
    return 0


def _validate(path):
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid: unable to read {path}: {exc}")
        return 1
    errors, warnings = validate_manifest(document)
    for warning in warnings:
        print(f"warning: {warning}")
    if errors:
        print(f"invalid: {path} ({len(errors)} error(s))")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"valid: {path} (contract safeai-manifest v1, "
          f"schema_version {document.get('schema_version')})")
    return 0
