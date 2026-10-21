"""Shared test helpers for budgetgov.

Temp files go under a project-local, git-ignored directory so an
endpoint scanner watching the user profile Temp folder cannot
quarantine a fixture mid-write. The directory is dot-prefixed and
listed in .gitignore.
"""

from __future__ import annotations

import os
import tempfile

_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def temp_record_path(name: str = "record.jsonl") -> str:
    d = tempfile.mkdtemp(prefix="budgetgov_")
    return os.path.join(d, name)
