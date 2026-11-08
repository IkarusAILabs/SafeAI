"""A scan opens no network connection and starts no process (claims ledger C-8).

The README and website say SafeAI scans offline and never executes the
code it scans. This checks it at run time, not by reading source: every
socket connection, DNS lookup and process launch raises during a scan of
each framework fixture.
"""

import json
import os
import shutil
import socket
import subprocess

import pytest

from safeai.engine.orchestrator import run_scan

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def _fixture_dirs():
    return sorted(
        os.path.join(FIXTURES, name, "representative")
        for name in os.listdir(FIXTURES)
        if os.path.isdir(os.path.join(FIXTURES, name, "representative"))
    )


class Forbidden(AssertionError):
    pass


@pytest.fixture
def no_network_no_processes(monkeypatch):
    def refuse(what):
        def _raise(*args, **kwargs):
            raise Forbidden(f"scan attempted {what}: {args[:2]!r}")
        return _raise

    monkeypatch.setattr(socket.socket, "connect", refuse("a socket connection"))
    monkeypatch.setattr(socket.socket, "connect_ex", refuse("a socket connection"))
    monkeypatch.setattr(socket, "create_connection", refuse("a connection"))
    monkeypatch.setattr(socket, "getaddrinfo", refuse("a DNS lookup"))
    monkeypatch.setattr(subprocess.Popen, "__init__", refuse("a process launch"))
    monkeypatch.setattr(os, "system", refuse("os.system"))
    if hasattr(os, "startfile"):
        monkeypatch.setattr(os, "startfile", refuse("os.startfile"))


def test_there_are_framework_fixtures_to_scan():
    assert len(_fixture_dirs()) >= 10


@pytest.mark.parametrize("fixture", _fixture_dirs(), ids=lambda p: os.path.basename(
    os.path.dirname(p)))
def test_scan_is_offline_and_executes_nothing(fixture, no_network_no_processes):
    report = run_scan(fixture)
    assert report["files_scanned"] >= 1


GIT_METADATA_COMMANDS = (
    ["git", "config", "--get", "remote.origin.url"],
    ["git", "rev-parse", "HEAD"],
    ["git", "rev-parse", "--abbrev-ref", "HEAD"],
    ["git", "describe", "--tags", "--exact-match", "HEAD"],
)


def test_cli_scan_runs_only_read_only_git_metadata_commands(tmp_path, monkeypatch):
    """``safeai scan`` reads Git metadata with four fixed read-only commands; nothing else.

    The claim "never executes the scanned code" holds; "starts no process"
    does not, for the CLI: it runs local ``git`` for the commit SHA, branch,
    tag and a one-way remote fingerprint. This pins exactly which.
    """
    from safeai.cmd.cli import main

    launched = []
    real_run = subprocess.run

    def record(argv, *args, **kwargs):
        launched.append(list(argv))
        assert list(argv) in [list(c) for c in GIT_METADATA_COMMANDS], argv
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(
        Forbidden("socket connection")))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(
        Forbidden("DNS lookup")))
    project = tmp_path / "project"
    shutil.copytree(os.path.join(FIXTURES, "claude_code", "compatibility"), project)
    out = tmp_path / "r.json"
    main(["scan", str(project), "--no-registry", "--json", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["files_scanned"] >= 1
    assert launched and all(argv[0] == "git" for argv in launched)


@pytest.mark.parametrize("target", ["missing", "a_file.json"])
def test_cli_scan_of_a_bad_path_fails_and_creates_nothing(tmp_path, capsys, target):
    """A mistyped path must not pass a CI gate as an empty, clean scan."""
    from safeai.cmd.cli import main

    (tmp_path / "a_file.json").write_text("{}", encoding="utf-8")
    path = tmp_path / target
    before = sorted(p.name for p in tmp_path.iterdir())
    assert main(["scan", str(path), "--no-registry"]) == 2
    assert "give the project directory" in capsys.readouterr().err
    assert sorted(p.name for p in tmp_path.iterdir()) == before
