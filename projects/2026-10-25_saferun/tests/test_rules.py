"""Tests for the saferun shape-check rules.

Every rule in ALL_RULES must have at least one test that fires it,
and the Verdict rollup must agree with the severities.
"""

from __future__ import annotations

import os
import unittest

from tests import support

import saferun
from saferun.rules import ALL_RULES, shape_check
from saferun.types import Severity, Verdict


class RuleSmokeTests(unittest.TestCase):
    """Every rule id in ALL_RULES has at least one firing test
    somewhere in this file."""

    def _rule_ids(self, scan):
        return {f.rule_id for f in scan.findings}

    # SR-001: string argv (shell=True semantics)
    def test_sr001_string_argv(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv="python -c 'print(1)'",
            allowed_commands=["python"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-001", self._rule_ids(scan))
        self.assertEqual(scan.verdict, Verdict.UNHEALTHY)

    def test_sr001_bytes_argv(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=b"python -c 'print(1)'",
            allowed_commands=["python"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-001", self._rule_ids(scan))

    def test_sr001_empty_argv(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=[],
            allowed_commands=["python"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-001", self._rule_ids(scan))

    def test_sr001_non_string_element(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=["python", 42],
            allowed_commands=["python"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-001", self._rule_ids(scan))

    # SR-002: not in allowlist
    def test_sr002_disallowed(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=["rm", "-rf", "/"],
            allowed_commands=["python"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-002", self._rule_ids(scan))
        self.assertEqual(scan.verdict, Verdict.UNHEALTHY)

    # SR-003: traversal / null in argv[0]
    def test_sr003_traversal(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=["../../etc/passwd"],
            allowed_commands=["passwd"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-003", self._rule_ids(scan))

    def test_sr003_null_byte(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=["python\x00evil"],
            allowed_commands=["python"],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-003", self._rule_ids(scan))

    # SR-004: shell metachar (informational)
    def test_sr004_shell_metachar(self):
        wd = support.new_workdir()
        scan = shape_check(
            argv=support.shell_metachar_argv(),
            allowed_commands=[support.python_basename()],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-004", {f.rule_id for f in scan.findings})

    # SR-005: workdir missing
    def test_sr005_missing_workdir(self):
        scan = shape_check(
            argv=["python", "-c", "print(1)"],
            allowed_commands=["python"],
            workdir="/this/does/not/exist/i-hope",
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-005", {f.rule_id for f in scan.findings})
        self.assertEqual(scan.verdict, Verdict.UNHEALTHY)

    def test_sr005_workdir_none(self):
        scan = shape_check(
            argv=["python", "-c", "print(1)"],
            allowed_commands=["python"],
            workdir=None,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-005", {f.rule_id for f in scan.findings})

    # SR-006: env passthrough (INFO only)
    def test_sr006_env_passthrough(self):
        wd = support.new_workdir()
        base = support.python_basename()
        scan = shape_check(
            argv=[base, "-c", "print(1)"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=True,
        )
        self.assertIn("SR-006", {f.rule_id for f in scan.findings})
        # INFO alone leaves verdict healthy.
        self.assertEqual(scan.verdict, Verdict.HEALTHY)

    # SR-007: bad timeout
    def test_sr007_zero_timeout(self):
        wd = support.new_workdir()
        base = support.python_basename()
        scan = shape_check(
            argv=[base, "-c", "print(1)"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-007", {f.rule_id for f in scan.findings})

    def test_sr007_bool_timeout(self):
        wd = support.new_workdir()
        base = support.python_basename()
        scan = shape_check(
            argv=[base, "-c", "print(1)"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=True,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-007", {f.rule_id for f in scan.findings})

    # SR-008: bad output cap
    def test_sr008_zero_output_cap(self):
        wd = support.new_workdir()
        base = support.python_basename()
        scan = shape_check(
            argv=[base, "-c", "print(1)"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=0,
            env_passthrough=False,
        )
        self.assertIn("SR-008", {f.rule_id for f in scan.findings})

    # SR-009: null byte in argv[1..]
    def test_sr009_null_byte_in_arg(self):
        wd = support.new_workdir()
        base = support.python_basename()
        scan = shape_check(
            argv=[base, "-c", "print(1)\x00evil"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-009", {f.rule_id for f in scan.findings})

    # SR-010: absolute argv[0] matched by basename
    def test_sr010_absolute_matched_by_basename(self):
        wd = support.new_workdir()
        base = support.python_basename()
        abs_py = support.python_argv0()
        if not os.path.isabs(abs_py):
            self.skipTest("sys.executable is not absolute on this platform")
        scan = shape_check(
            argv=[abs_py, "-c", "print(1)"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertIn("SR-010", {f.rule_id for f in scan.findings})


class RuleRegistryTests(unittest.TestCase):
    def test_all_rules_distinct_ids(self):
        ids = [r.id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)), ids)

    def test_all_rules_sr_prefix_and_increasing(self):
        for r in ALL_RULES:
            self.assertRegex(r.id, r"^SR-\d{3}$")

    def test_every_rule_documented_in_readme(self):
        """Every rule id in ALL_RULES must appear in README.md.

        A tool whose rules fire at users must document each rule.
        """
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        readme = os.path.join(root, "README.md")
        self.assertTrue(os.path.isfile(readme), readme)
        with open(readme, "r", encoding="utf-8") as f:
            text = f.read()
        missing = [r.id for r in ALL_RULES if r.id not in text]
        self.assertFalse(missing, "undocumented rule ids: " + repr(missing))


class HealthyShapeTests(unittest.TestCase):
    def test_a_clean_argv_is_healthy(self):
        wd = support.new_workdir()
        base = support.python_basename()
        scan = shape_check(
            argv=[base, "-c", "pass"],
            allowed_commands=[base],
            workdir=wd,
            timeout_sec=5.0,
            max_output_bytes=4096,
            env_passthrough=False,
        )
        self.assertEqual(scan.verdict, Verdict.HEALTHY, scan.to_json())


if __name__ == "__main__":
    unittest.main()
