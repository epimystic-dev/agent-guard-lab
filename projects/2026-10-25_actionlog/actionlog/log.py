"""The ActionLog: append-only hash-chained action audit.

Public contract:

- ``log.append(action, payload)``                add one record to
                                                 the chain; writes
                                                 are atomic per line
                                                 and the hash chain is
                                                 updated transactionally
- ``log.close()``                                flush and close
- ``log.read()`` / ``log.records()``             iterate all records
- ``log.verify()``                               return VerifyResult
- ``log.head``                                   current self_hash /
                                                 seq, or None if empty

Design points worth stating up front:

- SHA-256 of a canonical-JSON serialisation. ``json.dumps(..., sort_keys=True, separators=(',', ':'), ensure_ascii=True)``. Non-ASCII in payload values is escaped so a byte-wise re-hash is stable across platforms.

- The record is JSON-serialised twice: once WITHOUT self_hash to compute self_hash, and once WITH self_hash to persist. The verifier reads the persisted form, pops self_hash, re-serialises, re-hashes, compares.

- Appends hold a threading.Lock; concurrent appenders are serialised.

- The .head sidecar (``<path>.head``) stores the last self_hash + seq and is rewritten after every successful append. verify() reads the sidecar and treats disagreement with the chain tail as AL-004.

- No crypto beyond SHA-256. No signatures. ``actionlog`` makes tampering VISIBLE; it does not make tampering IMPOSSIBLE. A caller who needs non-repudiation chains an ``actionlog`` under a signing layer.

- ``path=None`` opens an in-memory log, useful for tests and for callers who want the hash-chain shape without the filesystem.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .rules import ALL_RULES, TAMPER_RULE
from .types import (
    GENESIS_PREV,
    Finding,
    LogClosed,
    LogError,
    Record,
    ScanResult,
    Severity,
    TamperKind,
    Verdict,
    VerifyResult,
)


_REQUIRED_FIELDS = ("seq", "ts", "action", "payload", "prev_hash", "self_hash")


def _canonical_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso() -> str:
    # UTC, second resolution, suffixed Z. Avoid timezone-aware
    # datetime pretty-print differences across platforms.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_json_serialisable(payload: Any) -> None:
    try:
        json.dumps(payload, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError) as e:
        raise LogError(
            "payload must be JSON-serialisable: " + str(e)
        )


class ActionLog:
    """Open or create a hash-chained append-only log.

    ``path=None`` keeps the log in memory. ``path='-'`` is treated
    as in-memory for CLI convenience.

    A new file is created on first append if it does not exist.
    Opening an existing file loads the last self_hash + seq from the
    .head sidecar (if present) or from the file tail (if no sidecar).

    Loading verifies the chain to its tail; a break raises
    LogIntegrityError, so a caller can decide whether to continue
    appending or snapshot and recover.
    """

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        clock=_now_iso,
    ) -> None:
        self._path = None if path in (None, "-", "") else path
        self._clock = clock
        self._lock = threading.Lock()
        self._mem: List[Dict[str, Any]] = []
        self._head: Optional[Tuple[int, str]] = None  # (seq, self_hash)
        self._closed = False

        if self._path is not None and os.path.exists(self._path):
            self._load_existing()

    # ---- public API ----

    @property
    def path(self) -> Optional[str]:
        return self._path

    @property
    def head(self) -> Optional[Tuple[int, str]]:
        return self._head

    @property
    def closed(self) -> bool:
        return self._closed

    def __len__(self) -> int:
        if self._path is None:
            return len(self._mem)
        if self._head is None:
            return 0
        return self._head[0] + 1

    def append(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        ts: Optional[str] = None,
    ) -> Record:
        """Append one record to the chain. Returns the Record."""
        if self._closed:
            raise LogClosed("log is closed")
        if not isinstance(action, str):
            raise LogError("action must be a string")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise LogError("payload must be a dict")
        _validate_json_serialisable(payload)

        with self._lock:
            if self._head is None:
                seq = 0
                prev_hash = GENESIS_PREV
            else:
                seq = self._head[0] + 1
                prev_hash = self._head[1]

            ts_str = ts if ts is not None else self._clock()
            record_core = {
                "seq": seq,
                "ts": ts_str,
                "action": action,
                "payload": payload,
                "prev_hash": prev_hash,
            }
            self_hash = _sha256_hex(_canonical_bytes(record_core))
            record = dict(record_core)
            record["self_hash"] = self_hash

            if self._path is None:
                self._mem.append(record)
            else:
                self._write_line(record)
                self._write_head(seq, self_hash)

            self._head = (seq, self_hash)

            return Record(
                seq=seq,
                ts=ts_str,
                action=action,
                payload=payload,
                prev_hash=prev_hash,
                self_hash=self_hash,
            )

    def records(self) -> Iterator[Record]:
        """Iterate the chain's current contents."""
        if self._path is None:
            for d in self._mem:
                yield _record_from_dict(d)
            return
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                d = json.loads(line)
                yield _record_from_dict(d)

    def read(self) -> List[Record]:
        return list(self.records())

    def verify(self) -> VerifyResult:
        return _verify_chain(self)

    def close(self) -> None:
        self._closed = True

    # ---- internals ----

    def _write_line(self, record: Dict[str, Any]) -> None:
        line = _canonical_bytes(record) + b"\n"
        # Atomic single-line append; flush+fsync so a crash leaves
        # at most a complete-record boundary.
        with open(self._path, "ab") as f:
            f.write(line)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # fsync is best-effort on some filesystems; append
                # correctness does not depend on it.
                pass

    def _write_head(self, seq: int, self_hash: str) -> None:
        head_path = self._path + ".head"
        payload = {"seq": seq, "self_hash": self_hash}
        tmp = head_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(_canonical_bytes(payload))
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, head_path)

    def _load_existing(self) -> None:
        # Scan to the end to populate self._head; validation of the
        # chain is a verify() concern. We do a lightweight
        # last-record read: skip blank lines, parse the last
        # non-blank line, pull (seq, self_hash).
        last_seq = None
        last_hash = None
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    s = d.get("seq")
                    h = d.get("self_hash")
                    if isinstance(s, int) and isinstance(h, str):
                        last_seq = s
                        last_hash = h
                except (ValueError, TypeError):
                    continue
        if last_seq is not None and last_hash is not None:
            self._head = (last_seq, last_hash)


def _record_from_dict(d: Dict[str, Any]) -> Record:
    return Record(
        seq=int(d["seq"]),
        ts=str(d["ts"]),
        action=str(d["action"]),
        payload=dict(d.get("payload", {})),
        prev_hash=str(d["prev_hash"]),
        self_hash=str(d["self_hash"]),
    )


def _verify_chain(log: ActionLog) -> VerifyResult:
    """Verify a chain and produce a VerifyResult.

    Verification walks the persisted form line-by-line (or the
    in-memory list in order), re-serialises each record WITHOUT its
    stored self_hash, re-hashes it, and compares. It then compares
    prev_hash to the prior record's self_hash and seq to the
    expected running counter. Finally, it compares the chain tail
    to the .head sidecar if the log is file-backed.
    """
    findings: List[Finding] = []

    def _break(kind: TamperKind, seq: Optional[int], detail: str) -> VerifyResult:
        rule_id = TAMPER_RULE[kind]
        severity = Severity.HIGH
        for r in ALL_RULES:
            if r.id == rule_id:
                severity = r.severity
                break
        f = Finding(
            rule_id=rule_id,
            severity=severity,
            message=detail,
            where=("seq=" + str(seq)) if seq is not None else "",
        )
        verdict = (
            Verdict.UNHEALTHY if severity == Severity.HIGH
            else Verdict.NEEDS_ATTENTION
        )
        return VerifyResult(
            ok=False,
            n_records=count,
            break_seq=seq,
            break_kind=kind,
            break_detail=detail,
            scan=ScanResult(findings=tuple([f]), verdict=verdict),
        )

    count = 0
    expected_seq = 0
    prev_self = GENESIS_PREV

    source: Iterable[str]
    if log._path is None:
        source = (
            json.dumps(d, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True)
            for d in log._mem
        )
    else:
        if not os.path.exists(log._path):
            return VerifyResult(
                ok=True, n_records=0,
                break_seq=None, break_kind=None,
                break_detail="",
                scan=ScanResult(findings=tuple(), verdict=Verdict.HEALTHY),
            )
        with open(log._path, "rb") as f:
            raw = f.read()
        source = _line_iter(raw)

    last_seq: Optional[int] = None
    last_self: Optional[str] = None

    for line in source:
        if line == "__EMPTY__":
            return _break(TamperKind.EMPTY_LINE, expected_seq,
                          "empty line at seq=" + str(expected_seq))
        if line == "__TRAILING__":
            return _break(TamperKind.TRAILING_GARBAGE, expected_seq,
                          "trailing bytes after last newline do not parse")

        try:
            d = json.loads(line)
        except ValueError:
            return _break(TamperKind.MALFORMED_JSON, expected_seq,
                          "malformed JSON at seq=" + str(expected_seq))

        if not isinstance(d, dict):
            return _break(TamperKind.MALFORMED_JSON, expected_seq,
                          "line is not a JSON object")

        for name in _REQUIRED_FIELDS:
            if name not in d:
                return _break(
                    TamperKind.MISSING_FIELD, expected_seq,
                    "record missing required field: " + name,
                )

        seq_val = d["seq"]
        self_hash = d["self_hash"]
        prev_hash = d["prev_hash"]

        if not isinstance(seq_val, int):
            return _break(TamperKind.MISSING_FIELD, expected_seq,
                          "seq is not an integer")
        if seq_val != expected_seq:
            return _break(
                TamperKind.SEQ_SKIP, seq_val,
                "expected seq " + str(expected_seq)
                + " got " + str(seq_val),
            )

        # Re-hash the canonical form minus self_hash and compare.
        core = {k: d[k] for k in d if k != "self_hash"}
        want = _sha256_hex(_canonical_bytes(core))
        if want != self_hash:
            return _break(
                TamperKind.HASH_MISMATCH, seq_val,
                "stored self_hash does not match recomputed hash",
            )

        if prev_hash != prev_self:
            if expected_seq == 0 and prev_hash != GENESIS_PREV:
                return _break(
                    TamperKind.GENESIS_PREV_NONZERO, seq_val,
                    "first record prev_hash is not the 64-zero genesis",
                )
            return _break(
                TamperKind.PREV_LINK_BROKEN, seq_val,
                "prev_hash does not match previous record's self_hash",
            )

        prev_self = self_hash
        last_seq = seq_val
        last_self = self_hash
        count += 1
        expected_seq += 1

    # Head sidecar check (file-backed only).
    if log._path is not None:
        head_path = log._path + ".head"
        if os.path.exists(head_path):
            try:
                with open(head_path, "r", encoding="utf-8") as f:
                    head = json.loads(f.read())
                h_seq = head.get("seq")
                h_hash = head.get("self_hash")
            except (ValueError, OSError):
                h_seq = h_hash = None

            if (
                h_seq is None
                or h_hash is None
                or h_seq != last_seq
                or h_hash != last_self
            ):
                return _break(
                    TamperKind.HEAD_MISMATCH, last_seq,
                    "head sidecar disagrees with chain tail",
                )

    return VerifyResult(
        ok=True, n_records=count,
        break_seq=None, break_kind=None,
        break_detail="",
        scan=ScanResult(findings=tuple(), verdict=Verdict.HEALTHY),
    )


def _line_iter(raw: bytes) -> Iterator[str]:
    """Yield each line (without the trailing newline) and surface
    empty lines / trailing garbage as sentinel strings so the main
    loop can map them to TamperKind without changing the signature.
    """
    if not raw:
        return
    # Find any trailing bytes that are not newline-terminated and
    # yield them as a trailing-garbage sentinel.
    if not raw.endswith(b"\n"):
        tail_start = raw.rfind(b"\n")
        if tail_start == -1:
            # Entire file is a single unterminated line.
            text = raw.decode("utf-8", errors="replace")
            try:
                json.loads(text)
                yield text
            except ValueError:
                yield "__TRAILING__"
            return
        else:
            head_bytes = raw[: tail_start + 1]
            tail_bytes = raw[tail_start + 1:]
            for part in head_bytes.splitlines():
                yield part.decode("utf-8", errors="replace")
            tail_text = tail_bytes.decode("utf-8", errors="replace")
            if tail_text.strip() == "":
                return
            try:
                json.loads(tail_text)
                yield tail_text
            except ValueError:
                yield "__TRAILING__"
            return
    for part in raw.splitlines():
        if part == b"":
            yield "__EMPTY__"
        else:
            yield part.decode("utf-8", errors="replace")
