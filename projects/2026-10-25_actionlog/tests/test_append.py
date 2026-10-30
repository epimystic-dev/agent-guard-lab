"""Tests for ActionLog.append and in-memory + file-backed round trips.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import unittest

from tests import support

import actionlog
from actionlog import (
    ActionLog,
    GENESIS_PREV,
    LogClosed,
    LogError,
)


class AppendShapeTests(unittest.TestCase):
    def test_first_record_has_genesis_prev(self):
        log = ActionLog(path=None, clock=support.FixedClock())
        rec = log.append("evt.open", {"n": 1})
        self.assertEqual(rec.seq, 0)
        self.assertEqual(rec.prev_hash, GENESIS_PREV)
        self.assertEqual(len(rec.self_hash), 64)
        int(rec.self_hash, 16)  # valid hex

    def test_second_record_links_to_first(self):
        log = ActionLog(path=None, clock=support.FixedClock())
        a = log.append("a", {})
        b = log.append("b", {})
        self.assertEqual(b.seq, 1)
        self.assertEqual(b.prev_hash, a.self_hash)

    def test_self_hash_is_sha256_of_canonical_form(self):
        log = ActionLog(path=None, clock=support.FixedClock())
        rec = log.append("a", {"x": 1})
        core = {
            "seq": rec.seq,
            "ts": rec.ts,
            "action": rec.action,
            "payload": rec.payload,
            "prev_hash": rec.prev_hash,
        }
        canonical = json.dumps(
            core, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        want = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(rec.self_hash, want)

    def test_append_rejects_non_string_action(self):
        log = ActionLog(path=None)
        with self.assertRaises(LogError):
            log.append(42, {})

    def test_append_rejects_non_dict_payload(self):
        log = ActionLog(path=None)
        with self.assertRaises(LogError):
            log.append("a", "not a dict")

    def test_append_rejects_unserialisable_payload(self):
        log = ActionLog(path=None)
        with self.assertRaises(LogError):
            log.append("a", {"blob": object()})

    def test_append_on_closed_raises(self):
        log = ActionLog(path=None)
        log.close()
        with self.assertRaises(LogClosed):
            log.append("a", {})


class FileBackedTests(unittest.TestCase):
    def test_file_round_trip(self):
        path = support.new_log_path()
        clock = support.FixedClock()
        log = ActionLog(path=path, clock=clock)
        for i in range(5):
            log.append("evt-" + str(i), {"i": i})
        log.close()

        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8") as f:
            lines = [l for l in f.read().splitlines() if l]
        self.assertEqual(len(lines), 5)
        for i, line in enumerate(lines):
            d = json.loads(line)
            self.assertEqual(d["seq"], i)

    def test_head_sidecar_written(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        rec = log.append("a", {})
        log.close()

        head_path = path + ".head"
        self.assertTrue(os.path.isfile(head_path))
        with open(head_path, "r", encoding="utf-8") as f:
            head = json.loads(f.read())
        self.assertEqual(head["seq"], rec.seq)
        self.assertEqual(head["self_hash"], rec.self_hash)

    def test_reopen_resumes_at_tail(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        a = log.append("a", {})
        b = log.append("b", {})
        log.close()

        log2 = ActionLog(path=path, clock=support.FixedClock(10))
        self.assertIsNotNone(log2.head)
        self.assertEqual(log2.head[0], b.seq)
        c = log2.append("c", {})
        self.assertEqual(c.seq, 2)
        self.assertEqual(c.prev_hash, b.self_hash)

    def test_records_round_trip(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("a", {"n": 1})
        log.append("b", {"n": 2})
        log.close()

        records = list(ActionLog(path=path).records())
        self.assertEqual([r.action for r in records], ["a", "b"])
        self.assertEqual([r.payload["n"] for r in records], [1, 2])


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_appends_are_sequenced(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())

        N = 50
        threads = []

        def worker(i):
            log.append("evt", {"i": i})

        for i in range(N):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        log.close()
        records = list(ActionLog(path=path).records())
        self.assertEqual(len(records), N)
        self.assertEqual([r.seq for r in records], list(range(N)))


if __name__ == "__main__":
    unittest.main()
