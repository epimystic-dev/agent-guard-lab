from __future__ import annotations

import io
import json
import os
import unittest

from tests import support

from budgetgov import CallCap, Governor
from budgetgov.cli import main


def _run(*argv):
    out = io.StringIO()
    err = io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


class CliHelpVersion(unittest.TestCase):
    def test_help_returns_zero(self):
        rc, out, _ = _run("--help")
        self.assertEqual(rc, 0)
        self.assertIn("budgetgov", out)

    def test_version_returns_zero(self):
        rc, out, _ = _run("--version")
        self.assertEqual(rc, 0)
        self.assertTrue(out.strip().startswith("budgetgov "))

    def test_no_args_prints_help(self):
        rc, out, _ = _run()
        self.assertEqual(rc, 0)
        self.assertIn("budgetgov", out)


class CliVerify(unittest.TestCase):
    def test_verify_healthy(self):
        path = support.temp_record_path()
        gov = Governor(call_cap=CallCap(2), record_path=path)
        with gov.session() as s:
            s.before_call()
            s.after_call()

        rc, out, _ = _run("verify", path)
        self.assertEqual(rc, 0, out)
        self.assertIn("healthy", out)

    def test_verify_unhealthy_returns_two(self):
        path = support.temp_record_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write("not json\n")

        rc, out, _ = _run("verify", path)
        self.assertEqual(rc, 2, out)

    def test_verify_json_output(self):
        path = support.temp_record_path()
        gov = Governor(record_path=path)
        with gov.session() as s:
            s.before_call()
            s.after_call()
        rc, out, _ = _run("verify", "--json", path)
        self.assertEqual(rc, 0, out)
        obj = json.loads(out)
        self.assertIn("verdict", obj)
        self.assertIn("findings", obj)


class CliTail(unittest.TestCase):
    def test_tail_default(self):
        path = support.temp_record_path()
        gov = Governor(record_path=path)
        with gov.session() as s:
            for _ in range(3):
                s.before_call()
                s.after_call()
        rc, out, _ = _run("tail", path)
        self.assertEqual(rc, 0, out)
        # Last line should be JSON parseable.
        for line in out.strip().splitlines():
            json.loads(line)

    def test_tail_missing_file_returns_two(self):
        rc, _, err = _run("tail", "no_such_file.jsonl")
        self.assertEqual(rc, 2)
        self.assertIn("budgetgov", err)


class CliRenderingSafety(unittest.TestCase):
    def test_text_report_renders_non_ascii_as_escape(self):
        # Craft a valid JSONL record whose 'kind' field contains a
        # non-ASCII character; verify fires BGR-004 ('unknown kind')
        # and the text report must render the character as <U+XXXX>,
        # never raw - a reporter crashing or re-concealing a hidden
        # character would be exactly the input a careful reader is
        # trying to see.
        import json as _json
        path = support.temp_record_path()
        kind_with_zwsp = "opened" + chr(0x200B)
        with open(path, "w", encoding="utf-8") as f:
            f.write(_json.dumps({
                "seq": 1, "ts": 0.0, "kind": kind_with_zwsp,
                "payload": {},
            }, ensure_ascii=False) + "\n")
            f.write(_json.dumps({
                "seq": 2, "ts": 1.0, "kind": "closed",
                "payload": {},
            }, sort_keys=True) + "\n")
        rc, out, _ = _run("verify", path)
        # BGR-004 is MEDIUM, so verdict is needs-attention -> rc 1.
        self.assertEqual(rc, 1, out)
        self.assertNotIn(chr(0x200B), out)
        self.assertIn("<U+200B>", out)


if __name__ == "__main__":
    unittest.main()
