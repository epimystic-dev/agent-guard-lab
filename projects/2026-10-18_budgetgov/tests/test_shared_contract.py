"""Shared-contract tests for budgetgov.

Two contracts are locked here:

1. Package surface invariants (lab shared contract): __version__,
   Severity, Verdict, Finding, ScanResult, Rule, ALL_RULES exported;
   __version__ is semantic; ALL_RULES is a list of Rule objects.

2. ``python -m budgetgov`` CI invariants: --help rc 0, --version rc 0.
   The budgetgov CLI is small (verify / tail); the clean/dirty known
   examples live in examples/.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401

import budgetgov
from budgetgov import ALL_RULES, Rule
from budgetgov.cli import main


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "budgetgov", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(budgetgov.__version__, str)
        self.assertRegex(budgetgov.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(budgetgov, name), name)

    def test_all_rules_is_tuple_of_rule_objects(self):
        self.assertTrue(ALL_RULES, "ALL_RULES is empty")
        for r in ALL_RULES:
            self.assertIsInstance(r, Rule)
            self.assertTrue(r.id.startswith("BGR-"), r.id)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))


class SharedContractInvariants(unittest.TestCase):
    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("budgetgov", r.stdout)

    def test_version_returns_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "budgetgov " + budgetgov.__version__,
        )

    def test_known_clean_example_verifies_healthy(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_record.jsonl")
        self.assertTrue(os.path.isfile(path), path)
        r = _run("verify", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_known_dirty_example_verifies_nonzero(self):
        path = os.path.join(EXAMPLES_DIR, "broken_record.jsonl")
        self.assertTrue(os.path.isfile(path), path)
        r = _run("verify", path)
        self.assertNotEqual(
            r.returncode, 0,
            "budgetgov exited 0 on a known-broken record",
        )


class ReadmeExampleRuns(unittest.TestCase):
    """The library-kind shared contract requires the README's quick
    example to actually run under the tests. We import the smallest
    runnable form here.
    """

    def test_quick_example(self):
        import budgetgov
        gov = budgetgov.Governor(
            token_cap=budgetgov.TokenCap(1000),
            call_cap=budgetgov.CallCap(2),
            spend_cap=budgetgov.SpendCap(0.10),
            time_cap=budgetgov.TimeCap(60.0),
        )
        with gov.session(label="readme") as s:
            s.before_call(estimated_tokens=200, estimated_cost_usd=0.02)
            s.after_call(actual_tokens=200, actual_cost_usd=0.02)
            s.before_call(estimated_tokens=200, estimated_cost_usd=0.02)
            s.after_call(actual_tokens=200, actual_cost_usd=0.02)
            # Third call would exceed CallCap(2):
            with self.assertRaises(budgetgov.BudgetExceeded) as cm:
                s.before_call(estimated_tokens=200, estimated_cost_usd=0.02)
            self.assertEqual(cm.exception.cap_name, "call")


if __name__ == "__main__":
    unittest.main()
