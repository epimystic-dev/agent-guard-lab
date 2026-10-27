"""The SafeRunner.

A single class holds the configuration (allowlist, workdir, timeout,
output cap, env policy) and provides two entry points:

- ``verify(argv)``   returns a ScanResult, raises nothing
- ``run(argv)``      returns a RunResult or raises RunRefused /
                     RunTimedOut

Design points worth stating up front:

- shell=False, always. The runner never accepts a string argv, never
  calls out to /bin/sh or cmd.exe. If a caller wants a shell, they do
  not get it here.

- Allowlist on argv[0]. The basename is matched; absolute paths are
  resolved to realpath for the comparison. A caller may put either
  basenames or absolute paths in ``allowed_commands``.

- Fail-closed on shape errors. Any HIGH finding from ``shape_check``
  refuses the run. The caller gets a ``RunRefused`` carrying the full
  ScanResult.

- Hard timeout and output caps. The subprocess is read in a separate
  thread so a stream that passes the cap can be stopped without
  waiting for the process to exit.

- Minimal env by default. Only ``PATH`` is set, to a conservative
  default per platform. A caller who needs ``PATH`` extensions sets
  ``env={'PATH': ...}``; a caller who really wants the parent
  environment sets ``env_passthrough=True`` and takes the SR-006
  finding.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from .rules import shape_check
from .types import (
    RunOverLimit,
    RunRefused,
    RunResult,
    RunTimedOut,
    ScanResult,
    Severity,
)


_DEFAULT_PATH_POSIX = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
_DEFAULT_PATH_WINDOWS_FALLBACK = r"C:\Windows\system32;C:\Windows"


def _default_env() -> Dict[str, str]:
    if os.name == "nt":
        # Keep whatever %SystemRoot% is, so system DLL resolution works,
        # then compose a PATH from the standard Windows subdirs.
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        path = ";".join([
            os.path.join(system_root, "system32"),
            system_root,
        ])
        return {
            "SystemRoot": system_root,
            "PATH": path,
            "ComSpec": os.environ.get(
                "ComSpec", os.path.join(system_root, "system32", "cmd.exe"),
            ),
        }
    return {"PATH": _DEFAULT_PATH_POSIX}


class SafeRunner:
    """Policy-carrying runner. One instance per policy.

    Construction never spawns anything; call ``run()`` to execute,
    ``verify()`` for a dry shape check.
    """

    def __init__(
        self,
        allowed_commands: Sequence[str],
        workdir: str,
        timeout_sec: float = 5.0,
        max_output_bytes: int = 65_536,
        env: Optional[Dict[str, str]] = None,
        env_passthrough: bool = False,
        kill_on_output_cap: bool = False,
    ) -> None:
        self.allowed_commands: Tuple[str, ...] = tuple(allowed_commands)
        self.workdir: str = workdir
        self.timeout_sec: float = float(timeout_sec)
        self.max_output_bytes: int = int(max_output_bytes)
        self._explicit_env: Optional[Dict[str, str]] = (
            None if env is None else dict(env)
        )
        self.env_passthrough: bool = bool(env_passthrough)
        self.kill_on_output_cap: bool = bool(kill_on_output_cap)

    # ---- public API ----

    def verify(self, argv: Any) -> ScanResult:
        return shape_check(
            argv=argv,
            allowed_commands=self.allowed_commands,
            workdir=self.workdir,
            timeout_sec=self.timeout_sec,
            max_output_bytes=self.max_output_bytes,
            env_passthrough=self.env_passthrough,
        )

    def run(self, argv: Any) -> RunResult:
        scan = self.verify(argv)
        for f in scan.findings:
            if f.severity == Severity.HIGH:
                raise RunRefused(scan=scan, message=f.message)

        # argv is now a valid list of strings; shape_check already
        # established that.
        arglist = list(argv)
        argv_t = tuple(arglist)

        env = self._compose_env()

        start = time.monotonic()
        proc = subprocess.Popen(  # noqa: S603 (allowlist enforced)
            arglist,
            cwd=self.workdir,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
        )

        stdout_buf = bytearray()
        stderr_buf = bytearray()
        stdout_trunc = {"flag": False}
        stderr_trunc = {"flag": False}
        cap_kill_flag = {"flag": False}

        kill_on_cap = self.kill_on_output_cap

        def _reader(stream, buf, trunc):
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    remaining = self.max_output_bytes - len(buf)
                    if remaining <= 0:
                        trunc["flag"] = True
                        if kill_on_cap and proc.poll() is None:
                            cap_kill_flag["flag"] = True
                            try:
                                proc.kill()
                            except OSError:
                                pass
                        continue
                    if len(chunk) > remaining:
                        buf.extend(chunk[:remaining])
                        trunc["flag"] = True
                        if kill_on_cap and proc.poll() is None:
                            cap_kill_flag["flag"] = True
                            try:
                                proc.kill()
                            except OSError:
                                pass
                    else:
                        buf.extend(chunk)
            except (OSError, ValueError):
                # Pipe closed on process kill.
                pass

        t_out = threading.Thread(
            target=_reader, args=(proc.stdout, stdout_buf, stdout_trunc),
            daemon=True,
        )
        t_err = threading.Thread(
            target=_reader, args=(proc.stderr, stderr_buf, stderr_trunc),
            daemon=True,
        )
        t_out.start()
        t_err.start()

        killed = False
        timed_out = False
        try:
            proc.wait(timeout=self.timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            killed = True
            timed_out = True
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                # Last-resort: cannot do more than kill() + wait().
                pass

        if cap_kill_flag["flag"]:
            killed = True

        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

        # Close the pipes so FDs do not leak.
        for s in (proc.stdout, proc.stderr):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

        elapsed = time.monotonic() - start

        # The cap-kill flag takes precedence: it names a definite
        # policy refusal rather than a time budget.
        if cap_kill_flag["flag"] and self.kill_on_output_cap:
            raise RunOverLimit(
                "subprocess killed on output cap: "
                + "stdout_truncated="
                + str(stdout_trunc["flag"])
                + " stderr_truncated="
                + str(stderr_trunc["flag"])
            )

        if timed_out:
            raise RunTimedOut(
                "subprocess exceeded timeout_sec="
                + str(self.timeout_sec)
                + " and was killed"
            )

        rc = proc.returncode if proc.returncode is not None else -1
        return RunResult(
            argv=argv_t,
            rc=rc,
            stdout=bytes(stdout_buf),
            stderr=bytes(stderr_buf),
            stdout_truncated=stdout_trunc["flag"],
            stderr_truncated=stderr_trunc["flag"],
            elapsed_sec=elapsed,
            killed=killed,
        )

    # ---- internals ----

    def _compose_env(self) -> Dict[str, str]:
        if self.env_passthrough:
            env = dict(os.environ)
            if self._explicit_env is not None:
                env.update(self._explicit_env)
            return env
        if self._explicit_env is not None:
            return dict(self._explicit_env)
        return _default_env()
