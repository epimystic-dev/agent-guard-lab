"""Append-only record of what the governor did.

The record is a JSONL file. Each line is one entry: seq, timestamp,
kind, and a payload. Only four kinds are written:

- ``opened``       the session started
- ``reservation``  a call was reserved (and allowed to proceed)
- ``refused``      a reservation was refused by a cap
- ``closed``       the session closed cleanly, or was sealed by a cap

A single writer appends per session. Readers may ``load_record`` and
``verify_record`` at any point - the record is append-only JSONL and
makes no cryptographic claim; a separate hash-chained audit (e.g. a
governance-lab-style ledger) is a composable choice, not a dependency.

The point of the record here is not forensic integrity. It is
*explainability*: when the governor refused a call, which cap, with
what reservation, against what counter.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .types import Finding, RecordEntry, ScanResult, Severity, Verdict


_VALID_KINDS = frozenset({"opened", "reservation", "refused", "closed"})


class _RecordWriter:
    """Serialised single-writer appender for a record file.

    This is private - callers reach it only through Governor. The
    writer is reentrant-locked so two threads in the same session
    cannot interleave a line, and it ``flush``es after each write so a
    crash leaves a well-formed partial file (one line, possibly, if
    the OS wrote some bytes and not others; verify flags that).
    """

    def __init__(self, path: Optional[str]) -> None:
        self._path = path
        self._seq = 0
        self._lock = threading.RLock()
        self._fh: Optional[io.TextIOBase] = None

    def _ensure_open(self) -> None:
        if self._path is None:
            return
        if self._fh is None:
            d = os.path.dirname(self._path)
            if d:
                os.makedirs(d, exist_ok=True)
            self._fh = open(self._path, "a", encoding="utf-8")

    def write(self, kind: str, payload: Dict[str, Any]) -> RecordEntry:
        if kind not in _VALID_KINDS:
            raise ValueError("unknown record kind: " + str(kind))
        with self._lock:
            self._seq += 1
            entry = RecordEntry(
                seq=self._seq, ts=time.time(), kind=kind, payload=dict(payload),
            )
            if self._path is not None:
                self._ensure_open()
                assert self._fh is not None
                self._fh.write(
                    json.dumps(entry.to_json(), sort_keys=True) + "\n"
                )
                self._fh.flush()
            return entry

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                finally:
                    self._fh = None


def load_record(path: str) -> List[RecordEntry]:
    """Read a JSONL record file into entries.

    Lines that fail to parse are not silently dropped - they raise
    ValueError at the offending line number so the caller cannot
    confuse 'empty' with 'corrupt'. verify_record is the diagnostic
    front door; load_record is strict.
    """
    out: List[RecordEntry] = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            s = raw.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError as e:
                raise ValueError(
                    "record line " + str(lineno) + " is not JSON: " + str(e)
                )
            for key in ("seq", "ts", "kind", "payload"):
                if key not in obj:
                    raise ValueError(
                        "record line " + str(lineno) + " missing " + key
                    )
            if not isinstance(obj["seq"], int):
                raise ValueError(
                    "record line " + str(lineno) + " seq is not int"
                )
            if not isinstance(obj["payload"], dict):
                raise ValueError(
                    "record line " + str(lineno) + " payload is not object"
                )
            out.append(
                RecordEntry(
                    seq=obj["seq"],
                    ts=float(obj["ts"]),
                    kind=str(obj["kind"]),
                    payload=obj["payload"],
                )
            )
    return out


def verify_record(path: str) -> ScanResult:
    """Non-cryptographic structural verify.

    Flags: unparseable lines (via load_record raising); seq gaps and
    non-monotonic seq numbers; a session that opened but never closed;
    unknown kinds. A refused line is normal and does not fire.
    """
    findings: List[Finding] = []
    try:
        entries = load_record(path)
    except (OSError, ValueError) as e:
        findings.append(
            Finding(
                rule_id="BGR-001",
                severity=Severity.HIGH,
                message="record is unreadable or malformed: " + str(e),
                where=path,
            )
        )
        return ScanResult(tuple(findings), Verdict.UNHEALTHY)

    if not entries:
        findings.append(
            Finding(
                rule_id="BGR-002",
                severity=Severity.MEDIUM,
                message="record is empty",
                where=path,
            )
        )
        return ScanResult(tuple(findings), Verdict.NEEDS_ATTENTION)

    expected = 1
    for e in entries:
        if e.seq != expected:
            findings.append(
                Finding(
                    rule_id="BGR-003",
                    severity=Severity.HIGH,
                    message=(
                        "seq gap or disorder: expected "
                        + str(expected) + " got " + str(e.seq)
                    ),
                    where=path,
                )
            )
            break
        expected += 1
        if e.kind not in _VALID_KINDS:
            findings.append(
                Finding(
                    rule_id="BGR-004",
                    severity=Severity.MEDIUM,
                    message="unknown record kind: " + str(e.kind),
                    where=path,
                )
            )

    opens = sum(1 for e in entries if e.kind == "opened")
    closes = sum(1 for e in entries if e.kind == "closed")
    if opens == 0:
        findings.append(
            Finding(
                rule_id="BGR-005",
                severity=Severity.MEDIUM,
                message="no opened entry",
                where=path,
            )
        )
    if closes < opens:
        findings.append(
            Finding(
                rule_id="BGR-006",
                severity=Severity.MEDIUM,
                message=(
                    "session opened but never closed ("
                    + str(opens) + " opened, " + str(closes) + " closed)"
                ),
                where=path,
            )
        )

    verdict = Verdict.HEALTHY
    for f in findings:
        if f.severity == Severity.HIGH:
            verdict = Verdict.UNHEALTHY
            break
        if f.severity == Severity.MEDIUM and verdict == Verdict.HEALTHY:
            verdict = Verdict.NEEDS_ATTENTION

    return ScanResult(tuple(findings), verdict)


# The verify-side rule registry; the governor-side exceptions are not
# rules in this sense. Shared-contract tests reach this through
# ``budgetgov.ALL_RULES``.
_RULES: Tuple = (
    (
        "BGR-001", Severity.HIGH,
        "record is unreadable or malformed",
    ),
    (
        "BGR-002", Severity.MEDIUM,
        "record is empty",
    ),
    (
        "BGR-003", Severity.HIGH,
        "seq numbers are not a monotonic 1..N sequence",
    ),
    (
        "BGR-004", Severity.MEDIUM,
        "unknown record kind",
    ),
    (
        "BGR-005", Severity.MEDIUM,
        "no opened entry in record",
    ),
    (
        "BGR-006", Severity.MEDIUM,
        "a session was opened but never closed",
    ),
)


def _as_rule_tuple() -> Tuple:
    from .types import Rule
    return tuple(Rule(id=rid, severity=sev, summary=sm) for rid, sev, sm in _RULES)


ALL_RULES = _as_rule_tuple()
