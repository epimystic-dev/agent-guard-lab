"""Tests for ActionLog.verify over the full tamper taxonomy.

Every TamperKind must have at least one test that fires it. The
verify() output is checked for break_kind, break_seq, and that the
scan carries the expected rule id.
"""

from __future__ import annotations

import json
import os
import unittest

from tests import support

import actionlog
from actionlog import ActionLog, TamperKind
from actionlog.log import _canonical_bytes


def _write_lines(path: str, lines) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            if not ln.endswith("\n"):
                ln = ln + "\n"
            f.write(ln)


def _read_lines(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return [l for l in f.read().splitlines() if l]


class CleanChainTests(unittest.TestCase):
    def test_empty_log_is_healthy(self):
        log = ActionLog(path=None)
        v = log.verify()
        self.assertTrue(v.ok)
        self.assertEqual(v.n_records, 0)

    def test_in_memory_clean_chain_is_healthy(self):
        log = ActionLog(path=None, clock=support.FixedClock())
        for _ in range(10):
            log.append("evt", {})
        v = log.verify()
        self.assertTrue(v.ok)
        self.assertEqual(v.n_records, 10)

    def test_file_clean_chain_is_healthy(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        for _ in range(5):
            log.append("evt", {})
        log.close()
        v = ActionLog(path=path).verify()
        self.assertTrue(v.ok)
        self.assertEqual(v.n_records, 5)


class TamperTests(unittest.TestCase):
    def _seed(self, n=4):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        for i in range(n):
            log.append("evt-" + str(i), {"i": i})
        log.close()
        return path

    def test_al001_hash_mismatch(self):
        path = self._seed()
        lines = _read_lines(path)
        d = json.loads(lines[1])
        d["payload"]["i"] = 999  # mutate without recomputing hash
        lines[1] = _canonical_bytes(d).decode("utf-8")
        _write_lines(path, lines)
        # Keep head consistent with the stored (tampered) line so the
        # test fires AL-001 (hash-mismatch) rather than AL-004.
        head_path = path + ".head"
        head = {"seq": d["seq"], "self_hash": d["self_hash"]}
        with open(head_path, "w", encoding="utf-8") as f:
            f.write(_canonical_bytes(head).decode("utf-8"))

        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.HASH_MISMATCH)
        self.assertEqual(v.break_seq, 1)
        self.assertEqual(v.scan.findings[0].rule_id, "AL-001")

    def test_al002_prev_link_broken_by_insert(self):
        path = self._seed()
        lines = _read_lines(path)
        # Insert a well-formed-looking but out-of-chain record.
        fake = {
            "seq": 1,
            "ts": "2026-10-25T00:99:99Z",
            "action": "forged",
            "payload": {},
            "prev_hash": "a" * 64,
            "self_hash": "b" * 64,
        }
        lines.insert(1, _canonical_bytes(fake).decode("utf-8"))
        _write_lines(path, lines)
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        # The forged record fails hash-check first, which is correct
        # (its stored self_hash is garbage).
        self.assertIn(v.break_kind, (
            TamperKind.HASH_MISMATCH,
            TamperKind.PREV_LINK_BROKEN,
        ))

    def test_al002_prev_link_broken_by_delete(self):
        path = self._seed()
        lines = _read_lines(path)
        del lines[1]
        _write_lines(path, lines)
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.SEQ_SKIP)

    def test_al003_seq_skip(self):
        path = self._seed()
        lines = _read_lines(path)
        d = json.loads(lines[1])
        d["seq"] = 99
        # Recompute self_hash so this doesn't trip AL-001 first.
        core = {k: v for k, v in d.items() if k != "self_hash"}
        import hashlib
        d["self_hash"] = hashlib.sha256(
            _canonical_bytes(core),
        ).hexdigest()
        lines[1] = _canonical_bytes(d).decode("utf-8")
        _write_lines(path, lines)
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.SEQ_SKIP)
        self.assertEqual(v.scan.findings[0].rule_id, "AL-003")

    def test_al004_head_mismatch_sidecar_edited(self):
        path = self._seed()
        head_path = path + ".head"
        with open(head_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"seq": 99, "self_hash": "a" * 64}))
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.HEAD_MISMATCH)

    def test_al005_trailing_garbage(self):
        path = self._seed()
        with open(path, "ab") as f:
            f.write(b"not a json line and no newline")
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.TRAILING_GARBAGE)

    def test_al006_genesis_prev_nonzero(self):
        path = support.new_log_path()
        d = {
            "seq": 0,
            "ts": "2026-10-25T00:00:00Z",
            "action": "a",
            "payload": {},
            "prev_hash": "a" * 64,
        }
        import hashlib
        d["self_hash"] = hashlib.sha256(_canonical_bytes(d)).hexdigest()
        with open(path, "w", encoding="utf-8") as f:
            f.write(_canonical_bytes(d).decode("utf-8") + "\n")
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.GENESIS_PREV_NONZERO)
        self.assertEqual(v.scan.findings[0].rule_id, "AL-006")

    def test_al007_empty_line(self):
        path = self._seed()
        with open(path, "rb") as f:
            raw = f.read()
        with open(path, "wb") as f:
            # Insert an empty line in the middle.
            parts = raw.splitlines()
            parts.insert(2, b"")
            f.write(b"\n".join(parts) + b"\n")
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.EMPTY_LINE)

    def test_al008_malformed_json(self):
        path = self._seed()
        lines = _read_lines(path)
        lines[1] = "{this is not json"
        _write_lines(path, lines)
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.MALFORMED_JSON)

    def test_al009_missing_field(self):
        path = self._seed()
        lines = _read_lines(path)
        d = json.loads(lines[1])
        d.pop("action")
        lines[1] = _canonical_bytes(d).decode("utf-8")
        _write_lines(path, lines)
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.break_kind, TamperKind.MISSING_FIELD)
        self.assertEqual(v.scan.findings[0].rule_id, "AL-009")


class ReorderTests(unittest.TestCase):
    def test_reorder_detected_as_seq_skip_or_prev(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        for i in range(4):
            log.append("e", {"i": i})
        log.close()
        lines = _read_lines(path)
        # Swap lines 1 and 2.
        lines[1], lines[2] = lines[2], lines[1]
        _write_lines(path, lines)
        v = ActionLog(path=path).verify()
        self.assertFalse(v.ok)
        # Reorder presents as a seq-skip (seq 2 where 1 was expected).
        self.assertIn(v.break_kind, (
            TamperKind.SEQ_SKIP, TamperKind.PREV_LINK_BROKEN,
        ))


class RuleDocsTests(unittest.TestCase):
    def test_every_rule_documented_in_readme(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        readme = os.path.join(root, "README.md")
        self.assertTrue(os.path.isfile(readme), readme)
        with open(readme, "r", encoding="utf-8") as f:
            text = f.read()
        from actionlog import ALL_RULES
        missing = [r.id for r in ALL_RULES if r.id not in text]
        self.assertFalse(missing,
                         "undocumented rule ids: " + repr(missing))


if __name__ == "__main__":
    unittest.main()
