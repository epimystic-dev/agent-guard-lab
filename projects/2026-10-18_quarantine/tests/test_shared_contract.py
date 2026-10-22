"""Shared-contract tests for quarantine.

Two contracts are locked:

1. Package surface (lab shared contract): __version__, Severity,
   Verdict, Finding, ScanResult, Rule, ALL_RULES.
2. ``python -m quarantine`` subprocess invariants: --help rc 0,
   --version rc 0, a known-clean example scans healthy, a known-dirty
   example scans non-zero and names a QN rule id.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401

import quarantine
from quarantine import ALL_RULES, Rule
from quarantine.cli import main


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "quarantine", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(quarantine.__version__, str)
        self.assertRegex(quarantine.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(quarantine, name), name)

    def test_rules_use_qn_prefix(self):
        self.assertTrue(ALL_RULES)
        for r in ALL_RULES:
            self.assertIsInstance(r, Rule)
            self.assertTrue(r.id.startswith("QN-"), r.id)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))


class SharedContractInvariants(unittest.TestCase):
    def test_help_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("quarantine", r.stdout)

    def test_version_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "quarantine " + quarantine.__version__,
        )

    def test_known_clean_scans_healthy(self):
        p = os.path.join(EXAMPLES_DIR, "healthy_input.txt")
        self.assertTrue(os.path.isfile(p), p)
        r = _run("scan", p)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("healthy", r.stdout)

    def test_known_dirty_scans_nonzero(self):
        p = os.path.join(EXAMPLES_DIR, "dirty_input.txt")
        self.assertTrue(os.path.isfile(p), p)
        r = _run("scan", p)
        self.assertNotEqual(
            r.returncode, 0,
            "quarantine exited 0 on a known-dirty input",
        )
        self.assertIn("QN-", r.stdout,
                      "expected QN-* diagnostic; stdout: " + repr(r.stdout))


class ReadmeExampleRuns(unittest.TestCase):
    """The library-kind shared contract requires the README's quick
    example to actually run under the tests.
    """

    def test_quick_example(self):
        import quarantine as q
        text = (
            "Interesting article. "
            + support.imperative_ignore()
            + " Thanks."
        )
        wrapped = q.wrap(
            text,
            provenance=q.Provenance.WEB,
            source="https://example.com/post",
        )
        self.assertIn("[neutralised-imperative]", wrapped.safe_text)
        rendered = wrapped.render_for_prompt()
        self.assertIn(wrapped.open_marker, rendered)
        self.assertIn(wrapped.close_marker, rendered)
        rules = {h.rule_id for h in wrapped.hits}
        self.assertIn("QN-006", rules)


if __name__ == "__main__":
    unittest.main()
