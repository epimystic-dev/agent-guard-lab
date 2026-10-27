"""Shared-contract tests for saferun.

Two contracts are locked:

1. Package surface (lab shared contract): __version__, Severity,
   Verdict, Finding, ScanResult, Rule, ALL_RULES.
2. ``python -m saferun`` subprocess invariants: --help rc 0,
   --version rc 0, verify on a healthy argv emits ``healthy``,
   verify on a bad argv emits a non-zero rc and names an SR rule id.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support

import saferun
from saferun import ALL_RULES, Rule
from saferun.cli import main


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "saferun", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(saferun.__version__, str)
        self.assertRegex(saferun.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(saferun, name), name)

    def test_rules_use_sr_prefix(self):
        self.assertTrue(ALL_RULES)
        for r in ALL_RULES:
            self.assertIsInstance(r, Rule)
            self.assertTrue(r.id.startswith("SR-"), r.id)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))


class SharedContractInvariants(unittest.TestCase):
    def test_help_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("saferun", r.stdout)

    def test_version_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "saferun " + saferun.__version__,
        )

    def test_verify_healthy_rc_zero(self):
        wd = support.new_workdir()
        base = support.python_basename()
        r = _run(
            "verify",
            "--allowed", base,
            "--workdir", wd,
            "--timeout", "5",
            "--",
            base, "-c", "print(1)",
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("healthy", r.stdout)

    def test_verify_bad_rc_nonzero(self):
        wd = support.new_workdir()
        r = _run(
            "verify",
            "--allowed", "python",
            "--workdir", wd,
            "--",
            "rm", "-rf", "/",
        )
        self.assertNotEqual(r.returncode, 0,
                            "saferun exited 0 on a disallowed argv[0]")
        self.assertIn("SR-", r.stdout,
                      "expected SR-* diagnostic; stdout: " + repr(r.stdout))


class ReadmeExampleRuns(unittest.TestCase):
    """The library-kind shared contract requires the README's quick
    example to actually run under the tests.
    """

    def test_quick_example(self):
        wd = support.new_workdir()
        runner = saferun.SafeRunner(
            allowed_commands=[support.python_basename()],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
        )
        result = runner.run([
            support.python_argv0(),
            "-c",
            "print('hello from saferun')",
        ])
        self.assertEqual(result.rc, 0)
        self.assertIn(b"hello from saferun", result.stdout)
        self.assertFalse(result.stdout_truncated)
        self.assertFalse(result.killed)


if __name__ == "__main__":
    unittest.main()
