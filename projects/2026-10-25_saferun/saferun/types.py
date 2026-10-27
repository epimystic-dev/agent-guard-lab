"""Shared types for saferun.

Exposes the lab's shared package surface (Severity, Verdict, Finding,
ScanResult, Rule) alongside saferun's own result and error types
(RunResult, RunRefused, RunTimedOut, RunOverLimit).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


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


@dataclass
class RunResult:
    """The return value of a completed SafeRunner.run(argv).

    - ``argv``                   the argv that was executed, byte-for-byte
    - ``rc``                     the subprocess return code
    - ``stdout`` / ``stderr``    captured output, possibly truncated
    - ``stdout_truncated``       True if the stdout stream exceeded
                                 ``max_output_bytes`` and was truncated
    - ``stderr_truncated``       same for stderr
    - ``elapsed_sec``            wall-clock elapsed (monotonic)
    - ``killed``                 True if the runner killed the process
                                 (timeout or output cap)
    """

    argv: Tuple[str, ...]
    rc: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_sec: float
    killed: bool = False

    def to_json(self) -> Dict[str, Any]:
        return {
            "argv": list(self.argv),
            "rc": self.rc,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "elapsed_sec": self.elapsed_sec,
            "killed": self.killed,
        }


class SafeRunError(Exception):
    """Base for every runner-side refusal / failure."""


@dataclass
class RunRefused(SafeRunError):
    """Fail-closed refusal before anything is executed.

    Carries the ScanResult that caused the refusal; a caller can
    inspect result.findings to learn which rule tripped.
    """

    scan: ScanResult
    message: str = ""

    def __str__(self) -> str:
        bits = [f.rule_id for f in self.scan.findings]
        return "saferun refused: " + ", ".join(bits) + (
            (": " + self.message) if self.message else ""
        )


class RunTimedOut(SafeRunError):
    """The subprocess exceeded the configured timeout and was killed."""


class RunOverLimit(SafeRunError):
    """The subprocess exceeded an output-size cap and was killed.

    This exception is only raised when ``kill_on_output_cap=True``.
    By default saferun returns a truncated RunResult instead, which
    composes better with callers that want to inspect what the
    process said before the cap tripped.
    """
