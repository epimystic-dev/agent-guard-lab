"""saferun - argv-allowlisted, shell-free, confined subprocess
runner for autonomous agents.

Public surface:

- ``__version__``                 semantic version
- ``Severity``                    enum: HIGH / MEDIUM / LOW / INFO
- ``Verdict``                     enum: healthy / needs-attention / unhealthy / unknown
- ``Finding`` / ``ScanResult``    the shape-check result types
- ``Rule`` / ``ALL_RULES``        rule registry
- ``SafeRunner``                  the policy-carrying runner
- ``RunResult``                   a completed run
- ``RunRefused``                  shape-check refusal (fail-closed)
- ``RunTimedOut``                 timeout kill
- ``RunOverLimit``                output-cap kill (opt-in)
"""

from __future__ import annotations

__version__ = "0.1.0"

from .rules import ALL_RULES
from .runner import SafeRunner
from .types import (
    Finding,
    Rule,
    RunOverLimit,
    RunRefused,
    RunResult,
    RunTimedOut,
    SafeRunError,
    ScanResult,
    Severity,
    Verdict,
)

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "SafeRunner",
    "RunResult",
    "RunRefused",
    "RunTimedOut",
    "RunOverLimit",
    "SafeRunError",
]
