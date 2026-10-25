"""Text files are UTF-8 regardless of the machine's locale default (#263)."""

import builtins

from safeai.engine.metadata import _ruleset_version


def test_ruleset_version_survives_a_non_utf8_locale(monkeypatch):
    real_open = builtins.open

    def gbk_open(file, mode="r", *args, **kwargs):
        if "b" not in mode and "encoding" not in kwargs and not args:
            kwargs["encoding"] = "gbk"
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", gbk_open)

    assert _ruleset_version(None)["rule_count"] > 0
