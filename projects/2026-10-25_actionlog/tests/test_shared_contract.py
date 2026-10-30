"""Shared-contract tests for actionlog.

Two contracts are locked:

1. Package surface (lab shared contract): __version__, Severity,
   Verdict, Finding, ScanResult, Rule, ALL_RULES.
2. ``python -m actionlog`` subprocess invariants: --help rc 0,
   --version rc 0, verify on an untampered chain rc 0, verify on a
   tampered chain rc 2 and names an AL rule id.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support

import actionlog
from actionlog import ALL_RULES, ActionLog, Rule
from actionlog.cli import main


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "actionlog", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(actionlog.__version__, str)
        self.assertRegex(actionlog.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule"):
            self.assertTrue(hasattr(actionlog, name), name)

    def test_rules_use_al_prefix(self):
        self.assertTrue(ALL_RULES)
        for r in ALL_RULES:
            self.assertIsInstance(r, Rule)
            self.assertTrue(r.id.startswith("AL-"), r.id)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))


class SharedContractInvariants(unittest.TestCase):
    def test_help_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("actionlog", r.stdout)

    def test_version_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "actionlog " + actionlog.__version__,
        )

    def test_verify_clean_rc_zero(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("tool.call", {"name": "search"})
        log.append("tool.result", {"ok": True})
        log.close()

        r = _run("verify", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("true", r.stdout)

    def test_verify_tampered_rc_nonzero(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("tool.call", {"name": "search"})
        log.append("tool.result", {"ok": True})
        log.close()

        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        d = json.loads(lines[0])
        d["payload"]["name"] = "malicious"
        lines[0] = json.dumps(
            d, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True,
        ) + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        r = _run("verify", path)
        self.assertNotEqual(r.returncode, 0,
                            "actionlog verify exited 0 on tampered chain")
        self.assertIn("AL-", r.stdout,
                      "expected AL-* diagnostic; stdout: " + repr(r.stdout))


class ReadmeExampleRuns(unittest.TestCase):
    """The library-kind shared contract requires the README's quick
    example to actually run under the tests.
    """

    def test_quick_example(self):
        path = support.new_log_path()
        log = actionlog.ActionLog(path=path, clock=support.FixedClock())
        rec = log.append("tool.call",
                         {"name": "search", "args": {"q": "example"}})
        log.append("tool.result", {"ok": True})
        log.close()

        self.assertEqual(rec.seq, 0)
        self.assertEqual(rec.prev_hash, actionlog.GENESIS_PREV)

        v = actionlog.ActionLog(path=path).verify()
        self.assertTrue(v.ok)
        self.assertEqual(v.n_records, 2)


if __name__ == "__main__":
    unittest.main()
