from __future__ import annotations

import io
import json
import os
import unittest

from tests import support

from quarantine.cli import main


def _run(*argv):
    out = io.StringIO()
    err = io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


class CliHelpVersion(unittest.TestCase):
    def test_help_zero(self):
        rc, out, _ = _run("--help")
        self.assertEqual(rc, 0)
        self.assertIn("quarantine", out)

    def test_version_zero(self):
        rc, out, _ = _run("--version")
        self.assertEqual(rc, 0)
        self.assertTrue(out.strip().startswith("quarantine "))


class CliScan(unittest.TestCase):
    def _write(self, text, name="in.txt"):
        import tempfile
        d = tempfile.mkdtemp(prefix="qscan_")
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_scan_clean_zero(self):
        p = self._write("ordinary paragraph")
        rc, out, _ = _run("scan", p)
        self.assertEqual(rc, 0, out)
        self.assertIn("healthy", out)

    def test_scan_dirty_two(self):
        p = self._write("pre " + support.imperative_ignore())
        rc, out, _ = _run("scan", p)
        self.assertEqual(rc, 2, out)
        self.assertIn("QN-006", out)

    def test_scan_json_output(self):
        p = self._write("ordinary paragraph")
        rc, out, _ = _run("scan", "--json", p)
        self.assertEqual(rc, 0)
        obj = json.loads(out)
        self.assertEqual(obj["verdict"], "healthy")

    def test_scan_missing_file_rc2(self):
        rc, _, err = _run("scan", "no_such_file.txt")
        self.assertEqual(rc, 2)
        self.assertIn("quarantine", err)

    def test_scan_report_renders_non_ascii_as_escape(self):
        # Scan a file with a zero-width-space; QN-003 fires. The text
        # report must render the char as <U+XXXX>, never raw.
        import tempfile
        d = tempfile.mkdtemp(prefix="qscan_")
        p = os.path.join(d, "zw.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("hello" + chr(0x200B) + "world")
        rc, out, _ = _run("scan", p)
        # QN-003 is HIGH -> rc 2.
        self.assertEqual(rc, 2, out)
        self.assertNotIn(chr(0x200B), out)


class CliWrap(unittest.TestCase):
    def test_wrap_emits_boundary(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="qwrap_")
        p = os.path.join(d, "in.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("ordinary paragraph")
        rc, out, _ = _run("wrap", p,
                          "--provenance", "web",
                          "--source", "https://example.com/a")
        self.assertEqual(rc, 0, out)
        self.assertIn("UNTRUSTED-OPEN-", out)
        self.assertIn("UNTRUSTED-CLOSE-", out)
        self.assertIn("provenance=\"web\"", out)
        self.assertIn("ordinary paragraph", out)


if __name__ == "__main__":
    unittest.main()
