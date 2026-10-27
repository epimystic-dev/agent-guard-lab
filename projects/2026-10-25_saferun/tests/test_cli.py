"""Tests for the saferun CLI.

Invokes ``python -m saferun`` as a subprocess and asserts the
documented exit codes and shapes. Tests do NOT use the current
process (so the CLI's own argparse and sys.exit path are exercised).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args, **kwargs):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env.update(kwargs.pop("env", {}) or {})
    return subprocess.run(
        [sys.executable, "-m", "saferun", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        **kwargs,
    )


class CliSmokeTests(unittest.TestCase):
    def test_help(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("saferun", r.stdout)

    def test_version(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unknown_flag_is_nonzero(self):
        r = _run("--nope-not-a-flag")
        self.assertNotEqual(r.returncode, 0)


class CliVerifyTests(unittest.TestCase):
    def test_verify_healthy(self):
        wd = support.new_workdir()
        base = support.python_basename()
        r = _run(
            "verify",
            "--allowed", base,
            "--workdir", wd,
            "--",
            base, "-c", "print(1)",
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("healthy", r.stdout)

    def test_verify_bad_rc2(self):
        wd = support.new_workdir()
        r = _run(
            "verify",
            "--allowed", "python",
            "--workdir", wd,
            "--",
            "rm", "-rf", "/",
        )
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("SR-002", r.stdout)

    def test_verify_json(self):
        wd = support.new_workdir()
        base = support.python_basename()
        r = _run(
            "verify",
            "--allowed", base,
            "--workdir", wd,
            "--json",
            "--",
            base, "-c", "print(1)",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["verdict"], "healthy")

    def test_text_report_escapes_non_ascii(self):
        """CP-1252 Windows console must not crash on a non-ASCII char
        in a finding message; the renderer must emit <U+...>.
        """
        wd = support.new_workdir()
        # argv[0] carries a zero-width space; must not crash the
        # reporter even under cp1252.
        bad0 = "python" + chr(0x200B)
        env = {"PYTHONIOENCODING": "cp1252"}
        r = _run(
            "verify",
            "--allowed", "python",
            "--workdir", wd,
            "--",
            bad0, "-c", "print(1)",
            env=env,
        )
        self.assertNotIn("Traceback", r.stderr)
        # Will emit SR-002 (unknown command) and possibly SR-004.
        self.assertIn("SR-", r.stdout)
        self.assertIn("<U+", r.stdout)


class CliRunTests(unittest.TestCase):
    def test_run_prints_subprocess_stdout(self):
        wd = support.new_workdir()
        base = support.python_basename()
        r = _run(
            "run",
            "--allowed", base,
            "--workdir", wd,
            "--",
            base, "-c", "print('hello-cli')",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("hello-cli", r.stdout)

    def test_run_refusal_rc2(self):
        wd = support.new_workdir()
        r = _run(
            "run",
            "--allowed", "python",
            "--workdir", wd,
            "--",
            "rm", "-rf", "/",
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("SR-", r.stderr)

    def test_run_json(self):
        wd = support.new_workdir()
        base = support.python_basename()
        r = _run(
            "run",
            "--allowed", base,
            "--workdir", wd,
            "--json",
            "--",
            base, "-c", "print('json-mode')",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["rc"], 0)
        self.assertIn("json-mode", doc["stdout"])


if __name__ == "__main__":
    unittest.main()
