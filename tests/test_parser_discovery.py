"""Every built-in framework parser is registered by discover_parsers().

Regression for the AutoGen parser, which was never imported by
discover_parsers(): a real `safeai scan` reported no AutoGen agents,
while pytest workers that had imported the parser module for another test
reported them, so results depended on test order.
"""

import os
import subprocess
import sys

from safeai import frameworks

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAMEWORKS = os.path.join(ROOT, "safeai", "frameworks")


def _parser_packages():
    return sorted(name for name in os.listdir(FRAMEWORKS)
                  if os.path.isfile(os.path.join(FRAMEWORKS, name, "parser.py")))


def test_every_parser_package_is_imported_by_discovery():
    with open(os.path.join(FRAMEWORKS, "__init__.py"), encoding="utf-8") as fh:
        source = fh.read()
    missing = [n for n in _parser_packages() if f"safeai.frameworks.{n}.parser import" not in source]
    assert missing == []


def test_a_fresh_process_discovers_every_builtin_parser():
    """Run in a child process so no test's earlier import can register a parser."""
    code = ("import safeai.frameworks as f; "
            "print(','.join(sorted(p.name for p in f.discover_parsers(include_external=False))))")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                         check=True).stdout.strip().split(",")
    assert "autogen" in out
    assert len(out) == len(_parser_packages())


def test_discovery_in_process_includes_autogen():
    assert "autogen" in {p.name for p in frameworks.discover_parsers(include_external=False)}
