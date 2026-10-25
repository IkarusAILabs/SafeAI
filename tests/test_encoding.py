"""Text files must be read and written as UTF-8 regardless of the platform locale.

On machines whose default encoding is not UTF-8 (e.g. Windows with a Chinese
locale using GBK), an implicit ``open()`` raises ``UnicodeDecodeError`` on
repository or report files that contain non-ASCII characters. The surrounding
error handling then swallows the failure and reports wrong values (a rule
count of 0 instead of 83).
"""

from __future__ import annotations

import builtins

from safeai.engine.metadata import _ruleset_version


def test_ruleset_version_under_non_utf8_default(monkeypatch):
    """``_ruleset_version`` must still count rules when the default locale is GBK."""
    real_open = builtins.open

    def gbk_open(file, mode="r", *args, **kwargs):
        if "b" not in mode and "encoding" not in kwargs:
            kwargs["encoding"] = "gbk"
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", gbk_open)

    result = _ruleset_version(None)
    assert result["rule_count"] > 0, (
        "rule_count must stay positive under a non-UTF-8 default locale"
    )
