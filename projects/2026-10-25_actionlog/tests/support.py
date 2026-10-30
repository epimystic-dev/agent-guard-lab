"""Shared test helpers for actionlog.

Keeps temp-file scratch under a dot-prefixed, gitignored directory
and gives tests a fixed-clock helper so hash values are stable
across test runs.
"""

from __future__ import annotations

import os
import tempfile
from typing import List

_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


class FixedClock:
    """Deterministic clock for test stability.

    Each call returns a monotonically increasing ISO-8601 string
    starting from 2026-10-25T00:00:00Z.
    """

    def __init__(self, start: int = 0) -> None:
        self._n = start

    def __call__(self) -> str:
        v = self._n
        self._n += 1
        # Encode as a trailing seconds offset so values are distinct
        # and all parse as valid ISO-8601.
        return "2026-10-25T00:00:{:02d}Z".format(v % 60)


def new_log_path() -> str:
    f = tempfile.NamedTemporaryFile(
        suffix=".jsonl", delete=False, dir=_LOCAL_TMP,
    )
    path = f.name
    f.close()
    # Delete the empty file; the log creates it on first append.
    try:
        os.unlink(path)
    except OSError:
        pass
    return path
