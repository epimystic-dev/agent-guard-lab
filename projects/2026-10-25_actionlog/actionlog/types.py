"""Shared types for actionlog.

Exposes the lab's shared package surface (Severity, Verdict,
Finding, ScanResult, Rule) alongside actionlog's own Record and
VerifyResult types.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Chain genesis prev_hash. 64 zero hex chars so it has the same shape
# as a real SHA-256 hex digest; a verifier that treats "prev_hash !=
# previous.self_hash" as an error must special-case the first entry.
GENESIS_PREV = "0" * 64


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


class TamperKind(str, enum.Enum):
    HASH_MISMATCH = "hash-mismatch"
    PREV_LINK_BROKEN = "prev-link-broken"
    SEQ_SKIP = "seq-skip"
    HEAD_MISMATCH = "head-mismatch"
    TRAILING_GARBAGE = "trailing-garbage"
    GENESIS_PREV_NONZERO = "genesis-prev-nonzero"
    EMPTY_LINE = "empty-line"
    MALFORMED_JSON = "malformed-json"
    MISSING_FIELD = "missing-field"


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    summary: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    where: str = ""


@dataclass
class ScanResult:
    """Shared Finding/Verdict rollup over a verify() pass."""

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
                } for f in self.findings
            ],
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True)
class Record:
    """One entry on the chain.

    - ``seq``                monotonic 0-based sequence number
    - ``ts``                 ISO-8601 UTC timestamp as a string
                             (callers wanting a monotonic clock
                             should pass it via payload)
    - ``action``             a short action label (e.g. 'tool.call')
    - ``payload``            arbitrary JSON-serialisable dict
    - ``prev_hash``          hex SHA-256 of the previous record's
                             canonical form; GENESIS_PREV for seq 0
    - ``self_hash``          hex SHA-256 of this record's canonical
                             form (excluding self_hash itself)
    """

    seq: int
    ts: str
    action: str
    payload: Dict[str, Any]
    prev_hash: str
    self_hash: str

    def to_json(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "action": self.action,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "self_hash": self.self_hash,
        }


@dataclass
class VerifyResult:
    """The output of ``ActionLog.verify()``.

    - ``ok``                 True if no tamper signal fired
    - ``n_records``          number of records actually read from the
                             log (useful when ``break_seq`` is None
                             and the caller wants to know the depth)
    - ``break_seq``          seq of the first record where a break
                             was detected, or None if ok
    - ``break_kind``         TamperKind of the first break, or None
    - ``break_detail``       human-readable string naming the break
    - ``scan``               ScanResult built from the above
    """

    ok: bool
    n_records: int
    break_seq: Optional[int]
    break_kind: Optional[TamperKind]
    break_detail: str
    scan: ScanResult

    def to_json(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "n_records": self.n_records,
            "break_seq": self.break_seq,
            "break_kind": self.break_kind.value if self.break_kind else None,
            "break_detail": self.break_detail,
            "scan": self.scan.to_json(),
        }


class LogError(Exception):
    """Base for actionlog-side errors (vs. verify-side findings)."""


class LogClosed(LogError):
    """Attempt to append to a closed log."""


class LogIntegrityError(LogError):
    """Loading an existing file detected a break before any append."""
