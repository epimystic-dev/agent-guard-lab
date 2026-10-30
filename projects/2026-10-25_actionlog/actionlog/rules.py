"""The actionlog verify-side rule registry.

Rules fire during ``ActionLog.verify()`` when the chain shows a
tamper signal. Every rule_id maps 1:1 to a TamperKind so a caller
holding either knows which the other is.
"""

from __future__ import annotations

from typing import Tuple

from .types import Rule, Severity, TamperKind


ALL_RULES: Tuple[Rule, ...] = (
    Rule("AL-001", Severity.HIGH,
         "hash-mismatch: a record's stored self_hash does not match "
         "the SHA-256 of its canonical form - the record was edited "
         "after it was written"),
    Rule("AL-002", Severity.HIGH,
         "prev-link-broken: a record's prev_hash does not match the "
         "previous record's self_hash - a record was inserted, "
         "deleted or reordered"),
    Rule("AL-003", Severity.HIGH,
         "seq-skip: seq numbers are not consecutive 0..N-1 - a "
         "record was deleted or forged"),
    Rule("AL-004", Severity.HIGH,
         "head-mismatch: the .head sidecar disagrees with the chain "
         "tail - the chain was truncated or the sidecar was tampered"),
    Rule("AL-005", Severity.MEDIUM,
         "trailing-garbage: bytes after the last newline that do not "
         "parse as JSON - a crash during append may have left a "
         "half-record, or the file was appended to by a non-actionlog "
         "writer"),
    Rule("AL-006", Severity.MEDIUM,
         "genesis-prev-nonzero: the first record's prev_hash is not "
         "the 64-zero genesis - the chain was pre-pended or the "
         "writer was buggy"),
    Rule("AL-007", Severity.MEDIUM,
         "empty-line: an empty line was found in the log - a crash "
         "during append may have left it, or the file was mutated "
         "externally"),
    Rule("AL-008", Severity.HIGH,
         "malformed-json: a line failed to parse as JSON - the file "
         "was mutated externally or the writer failed mid-line"),
    Rule("AL-009", Severity.HIGH,
         "missing-field: a parsed record is missing one of the "
         "required fields (seq, ts, action, payload, prev_hash, "
         "self_hash) - the record was tampered with or truncated"),
)


# TamperKind -> rule id. The CLI prints rule ids; callers who want
# the shared taxonomy use TamperKind.
TAMPER_RULE: dict = {
    TamperKind.HASH_MISMATCH: "AL-001",
    TamperKind.PREV_LINK_BROKEN: "AL-002",
    TamperKind.SEQ_SKIP: "AL-003",
    TamperKind.HEAD_MISMATCH: "AL-004",
    TamperKind.TRAILING_GARBAGE: "AL-005",
    TamperKind.GENESIS_PREV_NONZERO: "AL-006",
    TamperKind.EMPTY_LINE: "AL-007",
    TamperKind.MALFORMED_JSON: "AL-008",
    TamperKind.MISSING_FIELD: "AL-009",
}


def rule_for(kind: TamperKind) -> Rule:
    rid = TAMPER_RULE[kind]
    for r in ALL_RULES:
        if r.id == rid:
            return r
    raise KeyError(rid)
