"""Shared types for budgetgov.

The lab's package surface (see docs/CONVENTIONS.md) names a stable set
of exports every project exposes. For a library-kind project the
mandatory names are ``__version__`` and a documented public API; the
``Severity`` / ``Verdict`` / ``Finding`` / ``ScanResult`` / ``Rule`` /
``ALL_RULES`` names are optional but useful when a library has a
verify-style surface. budgetgov includes them because ``verify``
inspects a record file for integrity defects and reports findings.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


class Severity(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, enum.Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    where: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    summary: str


@dataclass
class ScanResult:
    findings: Tuple[Finding, ...]
    verdict: Verdict

    def to_json(self) -> Dict[str, Any]:
        return {
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "where": f.where,
                }
                for f in self.findings
            ],
            "verdict": self.verdict.value,
        }


class BudgetError(Exception):
    """Base class for all budgetgov-side errors."""


class BudgetExceeded(BudgetError):
    """Raised when a reservation or reconciliation would exceed a cap.

    The attribute ``cap_name`` names which cap tripped
    (``token`` / ``time`` / ``call`` / ``spend``); ``reserved`` is the
    amount the caller tried to reserve (if any); ``used`` is the
    counter at the moment of refusal; ``cap`` is the configured limit.
    """

    def __init__(
        self,
        cap_name: str,
        used: float,
        cap: float,
        reserved: float = 0.0,
        message: Optional[str] = None,
    ) -> None:
        self.cap_name = cap_name
        self.used = used
        self.cap = cap
        self.reserved = reserved
        if message is None:
            message = (
                "{name}-cap exceeded: used={used} reserved={reserved} "
                "cap={cap}".format(
                    name=cap_name, used=used, reserved=reserved, cap=cap,
                )
            )
        super().__init__(message)


class SessionLocked(BudgetError):
    """Raised when a locked session is asked to reserve again.

    Once a cap trips, the session is sealed; a subsequent reservation
    MUST NOT be permitted. The lab's rule is 'fail closed - a stop
    cannot be argued past'.
    """


@dataclass(frozen=True)
class RecordEntry:
    """One line of the append-only record."""

    seq: int
    ts: float
    kind: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "payload": self.payload,
        }
