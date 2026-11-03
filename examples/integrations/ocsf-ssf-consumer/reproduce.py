# SPDX-License-Identifier: Apache-2.0
"""Reproduce the reference integration end to end (plan 2.13-3).

Scans ``fixture/baseline``, then ``fixture/current`` against it, writes
both exports, verifies the manifest, runs ``consumer.py`` and compares
its queue with ``expected/review_queue.json``. Every step is offline.

    python examples/integrations/ocsf-ssf-consumer/reproduce.py [--update]

Exit code 0 when the queue matches; ``--update`` rewrites the expected
file instead.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMAS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "schemas"))
EXPECTED = os.path.join(HERE, "expected", "review_queue.json")


def _safeai(*args):
    subprocess.run([sys.executable, "-m", "safeai", *args], check=True,
                   stdout=subprocess.DEVNULL)


def run(workdir):
    """Run the pipeline in ``workdir``; returns the consumer's queue."""
    sys.path.insert(0, HERE)
    import consumer

    out = {name: os.path.join(workdir, name) for name in
           ("baseline.json", "manifest.json", "events.ocsf.jsonl", "events.set.jsonl",
            "b.sarif", "c.sarif")}
    _safeai("scan", os.path.join(HERE, "fixture", "baseline"), "--no-registry",
            "--manifest", out["baseline.json"], "--sarif", out["b.sarif"])
    _safeai("scan", os.path.join(HERE, "fixture", "current"), "--no-registry",
            "--baseline", out["baseline.json"], "--manifest", out["manifest.json"],
            "--sarif", out["c.sarif"])
    _safeai("manifest", "verify", out["manifest.json"])
    _safeai("manifest", "export", out["manifest.json"], "--format", "ocsf",
            "--output", out["events.ocsf.jsonl"])
    _safeai("manifest", "export", out["manifest.json"], "--format", "ssf-set",
            "--ssf-audience", "https://receiver.example", "--output", out["events.set.jsonl"])
    with open(out["manifest.json"], encoding="utf-8") as handle:
        digest = json.load(handle)["integrity"]["payload_sha256"]
    ocsf_events = consumer.load_jsonl(out["events.ocsf.jsonl"])
    set_payloads = consumer.load_jsonl(out["events.set.jsonl"])
    errors = consumer.validate(ocsf_events, set_payloads, SCHEMAS)
    if errors:
        raise SystemExit("schema errors:\n" + "\n".join(errors))
    return consumer.review_queue(ocsf_events, set_payloads, digest)


def main(argv=None):
    update = "--update" in (argv if argv is not None else sys.argv[1:])
    with tempfile.TemporaryDirectory() as workdir:
        queue = run(workdir)
    text = json.dumps(queue, indent=2, sort_keys=True) + "\n"
    if update:
        with open(EXPECTED, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        print(f"updated {EXPECTED}")
        return 0
    with open(EXPECTED, encoding="utf-8") as handle:
        expected = handle.read()
    if text != expected:
        sys.stdout.write(text)
        print("review queue differs from expected/review_queue.json", file=sys.stderr)
        return 1
    print("reproduced: review queue matches expected/review_queue.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
