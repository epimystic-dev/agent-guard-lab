"""Shared test helpers for saferun.

Keeps temp-file scratch under a dot-prefixed, gitignored directory
and gives tests a stable workdir on the real filesystem (so the
subprocess runner is exercised end-to-end). Also provides a
cross-platform helper that returns the current Python interpreter's
argv-friendly form, so tests do not depend on any shell builtin.
"""

from __future__ import annotations

import os
import sys
import tempfile

_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def python_argv0() -> str:
    """Return the Python interpreter path for argv[0].

    Tests use this (rather than hardcoding 'python') so saferun's
    allowlist can be constructed with either a basename or the
    absolute interpreter path, and the subprocess always resolves
    to the running interpreter.
    """
    return sys.executable


def python_basename() -> str:
    return os.path.basename(sys.executable)


def new_workdir() -> str:
    d = tempfile.mkdtemp(prefix="saferun_wd_")
    return d


def shell_metachar_argv() -> list:
    """An argv whose later elements carry shell metacharacters.

    The metacharacters are assembled at runtime so no raw contiguous
    shell-looking string appears in source.
    """
    pipe = "|"
    semi = ";"
    tick = "`"
    return [python_basename(), "-c", "print(1)" + pipe + "echo x" + semi + "ls" + tick]
