"""Dispatch for the file-only interoperability exports (v2.13; ROADMAP B4).

Both formats are built from a manifest and written as JSON Lines. None
of them opens a network connection: ``--pr-comment-post`` stays the
Community Edition's one network path.
"""

import json
from datetime import datetime

EXPORT_FORMATS = ("ocsf", "ssf-set")


def build_export(fmt, manifest, issuer=None, audience=None):
    """The records of export ``fmt`` for ``manifest``."""
    if fmt == "ocsf":
        from safeai.report.ocsf import build_events
        return build_events(manifest)
    if fmt == "ssf-set":
        from safeai.report.ssf import build_payloads
        return build_payloads(manifest, issuer=issuer, audience=audience)
    raise ValueError(f"unknown export format {fmt!r}; expected one of {EXPORT_FORMATS}")


def write_export(fmt, manifest, path, issuer=None, audience=None):
    """Write export ``fmt`` of ``manifest`` to ``path``. Returns the record count."""
    records = build_export(fmt, manifest, issuer=issuer, audience=audience)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(json.dumps(record, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False) + "\n" for record in records)
    return len(records)


def epoch_seconds(timestamp):
    """Seconds since the epoch for a manifest ``YYYY-MM-DDTHH:MM:SSZ`` time (0 if absent)."""
    if not timestamp:
        return 0
    return int(datetime.strptime(str(timestamp), "%Y-%m-%dT%H:%M:%S%z").timestamp())
