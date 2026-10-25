"""JSON report writer.

Writes the full scan report as pretty-printed JSON for machine
consumption and integration with external tooling.
"""

import json


def write_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
