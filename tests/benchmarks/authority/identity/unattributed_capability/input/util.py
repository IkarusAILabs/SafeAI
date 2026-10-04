"""Utility module with no agent framework: capability unattributed."""
import subprocess


def helper(cmd):
    return subprocess.run(cmd, shell=True)
