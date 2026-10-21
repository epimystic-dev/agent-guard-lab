from __future__ import annotations

import json
import os
import unittest

from tests import support

from budgetgov import (
    CallCap,
    Governor,
    TokenCap,
    Verdict,
    load_record,
    verify_record,
)


class RecordWriterShape(unittest.TestCase):
    def test_record_has_opened_and_closed(self):
        path = support.temp_record_path()
        gov = Governor(call_cap=CallCap(3), record_path=path)
        with gov.session(label="smoke") as s:
            s.before_call()
            s.after_call()
        entries = load_record(path)
        kinds = [e.kind for e in entries]
        self.assertEqual(kinds[0], "opened")
        self.assertEqual(kinds[-1], "closed")
        self.assertIn("reservation", kinds)

    def test_refusal_recorded(self):
        path = support.temp_record_path()
        gov = Governor(call_cap=CallCap(1), record_path=path)
        with gov.session() as s:
            s.before_call()
            s.after_call()
            try:
                s.before_call()
            except Exception:  # noqa: BLE001
                pass
        entries = load_record(path)
        kinds = [e.kind for e in entries]
        self.assertIn("refused", kinds)
        refused = [e for e in entries if e.kind == "refused"][0]
        self.assertEqual(refused.payload["cap"], "call")
        self.assertEqual(refused.payload["cap_limit"], 1)

    def test_seq_is_monotonic(self):
        path = support.temp_record_path()
        gov = Governor(record_path=path)
        with gov.session() as s:
            s.before_call()
            s.after_call()
            s.before_call()
            s.after_call()
        entries = load_record(path)
        seqs = [e.seq for e in entries]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


class VerifyRecord(unittest.TestCase):
    def test_healthy_record(self):
        path = support.temp_record_path()
        gov = Governor(call_cap=CallCap(3), record_path=path)
        with gov.session() as s:
            for _ in range(2):
                s.before_call()
                s.after_call()
        result = verify_record(path)
        self.assertEqual(result.verdict, Verdict.HEALTHY)
        self.assertEqual(result.findings, ())

    def test_empty_record_flagged(self):
        path = support.temp_record_path()
        open(path, "w", encoding="utf-8").close()
        result = verify_record(path)
        self.assertEqual(result.verdict, Verdict.NEEDS_ATTENTION)
        self.assertIn("BGR-002", [f.rule_id for f in result.findings])

    def test_unreadable_record_flagged(self):
        path = support.temp_record_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json\n")
        result = verify_record(path)
        self.assertEqual(result.verdict, Verdict.UNHEALTHY)
        self.assertIn("BGR-001", [f.rule_id for f in result.findings])

    def test_seq_gap_flagged(self):
        path = support.temp_record_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "seq": 1, "ts": 0.0, "kind": "opened", "payload": {},
            }, sort_keys=True) + "\n")
            f.write(json.dumps({
                "seq": 3, "ts": 1.0, "kind": "closed", "payload": {},
            }, sort_keys=True) + "\n")
        result = verify_record(path)
        self.assertEqual(result.verdict, Verdict.UNHEALTHY)
        self.assertIn("BGR-003", [f.rule_id for f in result.findings])

    def test_opened_never_closed_flagged(self):
        path = support.temp_record_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "seq": 1, "ts": 0.0, "kind": "opened", "payload": {},
            }, sort_keys=True) + "\n")
        result = verify_record(path)
        rids = [f.rule_id for f in result.findings]
        self.assertIn("BGR-006", rids)

    def test_absent_file_is_unhealthy(self):
        missing = support.temp_record_path("does_not_exist.jsonl")
        self.assertFalse(os.path.exists(missing))
        result = verify_record(missing)
        self.assertEqual(result.verdict, Verdict.UNHEALTHY)


if __name__ == "__main__":
    unittest.main()
