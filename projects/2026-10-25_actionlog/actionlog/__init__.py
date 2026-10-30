"""actionlog - append-only, SHA-256 hash-chained action audit log
for autonomous agents.

Public surface:

- ``__version__``                 semantic version
- ``Severity``                    enum: HIGH / MEDIUM / LOW / INFO
- ``Verdict``                     enum: healthy / needs-attention / unhealthy / unknown
- ``Finding`` / ``ScanResult``    shared verify-result types
- ``Rule`` / ``ALL_RULES``        rule registry (AL-001..AL-009)
- ``ActionLog``                   the chain
- ``Record``                      one entry on the chain
- ``VerifyResult``                verify() return
- ``TamperKind``                  the taxonomy of chain breaks
- ``LogError`` / ``LogClosed``    append-side error types
"""

from __future__ import annotations

__version__ = "0.1.0"

from .log import ActionLog
from .rules import ALL_RULES
from .types import (
    GENESIS_PREV,
    Finding,
    LogClosed,
    LogError,
    LogIntegrityError,
    Record,
    Rule,
    ScanResult,
    Severity,
    TamperKind,
    Verdict,
    VerifyResult,
)

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "ActionLog",
    "Record",
    "VerifyResult",
    "TamperKind",
    "LogError",
    "LogClosed",
    "LogIntegrityError",
    "GENESIS_PREV",
]
