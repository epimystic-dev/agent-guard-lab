"""Tests for the SafeRunner end-to-end.

Exercises an actual subprocess (the current Python interpreter), so
the runner's shell=False, timeout, output cap and env policy are
tested against a real OS, not mocked.
"""

from __future__ import annotations

import os
import unittest

from tests import support

import saferun
from saferun import RunRefused, RunTimedOut, SafeRunner
from saferun.types import Severity


class RunnerSmokeTests(unittest.TestCase):
    def _runner(self, **overrides):
        wd = overrides.pop("workdir", support.new_workdir())
        allowed = overrides.pop(
            "allowed_commands",
            [support.python_basename()],
        )
        return SafeRunner(
            allowed_commands=allowed,
            workdir=wd,
            timeout_sec=overrides.pop("timeout_sec", 5.0),
            max_output_bytes=overrides.pop("max_output_bytes", 65_536),
            env=overrides.pop("env", None),
            env_passthrough=overrides.pop("env_passthrough", False),
            kill_on_output_cap=overrides.pop("kill_on_output_cap", False),
        )

    def test_simple_run_returns_stdout(self):
        r = self._runner().run(
            [support.python_argv0(), "-c", "print('ok')"],
        )
        self.assertEqual(r.rc, 0)
        self.assertIn(b"ok", r.stdout)
        self.assertEqual(r.stderr, b"")
        self.assertFalse(r.stdout_truncated)
        self.assertFalse(r.killed)

    def test_stderr_captured_separately(self):
        r = self._runner().run([
            support.python_argv0(),
            "-c",
            "import sys; sys.stderr.write('err\\n')",
        ])
        self.assertEqual(r.rc, 0)
        self.assertIn(b"err", r.stderr)
        self.assertEqual(r.stdout, b"")

    def test_nonzero_exit_is_passed_through(self):
        r = self._runner().run([
            support.python_argv0(), "-c", "import sys; sys.exit(7)",
        ])
        self.assertEqual(r.rc, 7)


class RefusalTests(unittest.TestCase):
    def test_string_argv_is_refused(self):
        wd = support.new_workdir()
        runner = SafeRunner(
            allowed_commands=["python"], workdir=wd,
        )
        with self.assertRaises(RunRefused) as cx:
            runner.run("python -c 'print(1)'")
        rule_ids = {f.rule_id for f in cx.exception.scan.findings}
        self.assertIn("SR-001", rule_ids)

    def test_disallowed_command_is_refused(self):
        wd = support.new_workdir()
        runner = SafeRunner(
            allowed_commands=["python"], workdir=wd,
        )
        with self.assertRaises(RunRefused) as cx:
            runner.run(["rm", "-rf", "/"])
        rule_ids = {f.rule_id for f in cx.exception.scan.findings}
        self.assertIn("SR-002", rule_ids)

    def test_absolute_path_matched_by_basename(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
        )
        # Absolute interpreter path should match by basename and run.
        r = runner.run([support.python_argv0(), "-c", "print('ok')"])
        self.assertEqual(r.rc, 0)

    def test_absolute_path_allowlist_matches(self):
        wd = support.new_workdir()
        abs_py = support.python_argv0()
        runner = SafeRunner(
            allowed_commands=[abs_py], workdir=wd,
        )
        r = runner.run([abs_py, "-c", "print('ok')"])
        self.assertEqual(r.rc, 0)

    def test_missing_workdir_is_refused(self):
        runner = SafeRunner(
            allowed_commands=["python"],
            workdir="/this/does/not/exist/i-hope",
        )
        with self.assertRaises(RunRefused) as cx:
            runner.run(["python", "-c", "pass"])
        rule_ids = {f.rule_id for f in cx.exception.scan.findings}
        self.assertIn("SR-005", rule_ids)


class TimeoutTests(unittest.TestCase):
    def test_timeout_kills_subprocess(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
            timeout_sec=0.5,
        )
        with self.assertRaises(RunTimedOut):
            runner.run([
                support.python_argv0(),
                "-c",
                "import time; time.sleep(30)",
            ])


class OutputCapTests(unittest.TestCase):
    def test_output_cap_truncates_by_default(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
            timeout_sec=10.0,
            max_output_bytes=64,
        )
        r = runner.run([
            support.python_argv0(),
            "-c",
            "print('x' * 1000)",
        ])
        self.assertTrue(r.stdout_truncated)
        self.assertLessEqual(len(r.stdout), 64)

    def test_output_cap_kill_mode_raises(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
            timeout_sec=10.0,
            max_output_bytes=64,
            kill_on_output_cap=True,
        )
        from saferun import RunOverLimit
        with self.assertRaises(RunOverLimit):
            runner.run([
                support.python_argv0(),
                "-c",
                # Keep writing until killed.
                "import sys, time\n"
                "while True:\n"
                "    sys.stdout.write('x' * 1024)\n"
                "    sys.stdout.flush()\n"
                "    time.sleep(0.01)\n",
            ])


class EnvPolicyTests(unittest.TestCase):
    def test_default_env_does_not_leak_parent_secrets(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
        )
        # Place a fake "secret" in our own env; it must NOT be visible
        # inside the subprocess by default.
        key = "SAFERUN_TEST_FAKE_SECRET"
        value = "a-synthetic-token-only-set-for-this-test"
        os.environ[key] = value
        try:
            r = runner.run([
                support.python_argv0(),
                "-c",
                "import os; print(os.environ.get('"
                + key + "', '__ABSENT__'))",
            ])
            self.assertIn(b"__ABSENT__", r.stdout)
            self.assertNotIn(value.encode("utf-8"), r.stdout)
        finally:
            os.environ.pop(key, None)

    def test_explicit_env_passed_through(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
            env={"PATH": os.environ.get("PATH", ""),
                 "SAFERUN_EXPLICIT": "value"},
        )
        r = runner.run([
            support.python_argv0(),
            "-c",
            "import os; print(os.environ.get('SAFERUN_EXPLICIT', ''))",
        ])
        self.assertIn(b"value", r.stdout)

    def test_env_passthrough_opt_in(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
            env_passthrough=True,
        )
        key = "SAFERUN_TEST_PASSTHROUGH"
        value = "passed-through-value"
        os.environ[key] = value
        try:
            r = runner.run([
                support.python_argv0(),
                "-c",
                "import os; print(os.environ.get('" + key + "', '__ABSENT__'))",
            ])
            self.assertIn(value.encode("utf-8"), r.stdout)
        finally:
            os.environ.pop(key, None)


class ReservedShapeTests(unittest.TestCase):
    def test_cwd_is_the_configured_workdir(self):
        wd = support.new_workdir()
        base = support.python_basename()
        runner = SafeRunner(
            allowed_commands=[base], workdir=wd,
        )
        r = runner.run([
            support.python_argv0(),
            "-c",
            "import os; print(os.path.realpath(os.getcwd()))",
        ])
        self.assertIn(
            os.path.realpath(wd).encode("utf-8"), r.stdout,
        )


if __name__ == "__main__":
    unittest.main()
