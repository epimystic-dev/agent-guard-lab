"""budgetgov - a runtime budget governor for autonomous agents.

A reusable library that enforces four caps on an agent loop: tokens,
time, call-count and spend. Fail-closed: a reservation that cannot be
evaluated against a configured cap is refused. One-way seal: once a
cap trips, the session stays locked.

Public surface (lab shared contract):

- ``__version__``                 semantic version
- ``Severity``                    enum: HIGH / MEDIUM / LOW / INFO
- ``Verdict``                     enum: healthy / needs-attention / unhealthy / unknown
- ``Finding``                     dataclass (one verify finding)
- ``ScanResult``                  dataclass (verify findings + verdict)
- ``Rule``                        dataclass (one verify rule)
- ``ALL_RULES``                   verify rule registry
- ``BudgetError`` / ``BudgetExceeded`` / ``SessionLocked``   runtime errors
- ``TokenCap`` / ``TimeCap`` / ``CallCap`` / ``SpendCap``    cap types
- ``Governor``                    the governor itself
- ``Session``                     the per-run handle
- ``RecordEntry``                 one line of the record
- ``load_record(path)`` / ``verify_record(path)``            readers
"""

from __future__ import annotations

__version__ = "0.1.0"

from .types import (
    BudgetError,
    BudgetExceeded,
    Finding,
    RecordEntry,
    Rule,
    ScanResult,
    SessionLocked,
    Severity,
    Verdict,
)
from .caps import CallCap, SpendCap, TimeCap, TokenCap
from .governor import Governor, Session
from .record import ALL_RULES, load_record, verify_record

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "BudgetError",
    "BudgetExceeded",
    "SessionLocked",
    "TokenCap",
    "TimeCap",
    "CallCap",
    "SpendCap",
    "Governor",
    "Session",
    "RecordEntry",
    "load_record",
    "verify_record",
]
