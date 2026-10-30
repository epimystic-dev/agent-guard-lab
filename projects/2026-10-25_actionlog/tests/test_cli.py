"""Tests for the actionlog CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support

import actionlog
from actionlog import ActionLog


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args, env_overrides=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-m", "actionlog", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class CliSmokeTests(unittest.TestCase):
    def test_help(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("actionlog", r.stdout)

    def test_version(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unknown_flag(self):
        r = _run("--nope-not-a-flag")
        self.assertNotEqual(r.returncode, 0)


class CliVerifyTests(unittest.TestCase):
    def test_verify_clean(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("a", {})
        log.append("b", {})
        log.close()

        r = _run("verify", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok: true", r.stdout)

    def test_verify_tampered(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("a", {})
        log.append("b", {})
        log.close()

        # Mutate the file.
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        d = json.loads(lines[0])
        d["action"] = "malicious"
        lines[0] = json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        r = _run("verify", path)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("AL-", r.stdout)

    def test_verify_json(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("a", {})
        log.close()

        r = _run("verify", "--json", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        doc = json.loads(r.stdout)
        self.assertTrue(doc["ok"])
        self.assertEqual(doc["n_records"], 1)

    def test_verify_missing_file_rc2(self):
        r = _run("verify", "/does/not/exist/file.jsonl")
        self.assertEqual(r.returncode, 2)

    def test_text_report_escapes_non_ascii(self):
        """CP-1252 console must not crash on a non-ASCII character
        in a finding message."""
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("evt", {"zws": chr(0x200B)})
        log.close()

        # Tamper so a finding fires with the ZWS visible in the message.
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        d = json.loads(lines[0])
        d["action"] = "evt" + chr(0x200B)
        lines[0] = json.dumps(d, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True) + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        r = _run("verify", path, env_overrides={"PYTHONIOENCODING": "cp1252"})
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("AL-", r.stdout)


class CliShowAppendTests(unittest.TestCase):
    def test_show(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("a", {})
        log.append("b", {})
        log.close()

        r = _run("show", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("seq=0", r.stdout)
        self.assertIn("seq=1", r.stdout)

    def test_show_json(self):
        path = support.new_log_path()
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("a", {})
        log.close()

        r = _run("show", "--json", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(len(doc), 1)

    def test_append(self):
        path = support.new_log_path()
        # Create a seed record so the chain exists.
        log = ActionLog(path=path, clock=support.FixedClock())
        log.append("seed", {})
        log.close()

        r = _run("append", path,
                 "--action", "cli.appended",
                 "--payload", json.dumps({"k": "v"}))
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["action"], "cli.appended")
        self.assertEqual(doc["seq"], 1)

        v = ActionLog(path=path).verify()
        self.assertTrue(v.ok)

    def test_append_rejects_non_json_payload(self):
        path = support.new_log_path()
        r = _run("append", path,
                 "--action", "a", "--payload", "not-json")
        self.assertEqual(r.returncode, 2)

    def test_append_rejects_non_dict_payload(self):
        path = support.new_log_path()
        r = _run("append", path,
                 "--action", "a", "--payload", "[1, 2]")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
