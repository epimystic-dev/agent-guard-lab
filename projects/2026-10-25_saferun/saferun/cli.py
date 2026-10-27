"""The saferun CLI.

- ``saferun --version``         prints version, rc 0.
- ``saferun --help``            rc 0.
- ``saferun verify ...``        shape-check an argv and print the
                                ScanResult. rc 0 clean, 1 for
                                MEDIUM-only, 2 for HIGH or unreadable.
- ``saferun run ...``           actually execute. rc = subprocess rc
                                when it exits cleanly; rc 2 on
                                refusal / timeout.
- Unknown flag                  rc 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence, TextIO

from . import __version__
from .runner import SafeRunner
from .types import (
    RunRefused,
    RunTimedOut,
    ScanResult,
    Severity,
    Verdict,
)


def _render_char(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 32 <= o < 127:
            out.append(c)
        else:
            out.append("<U+{:04X}>".format(o))
    return "".join(out)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="saferun",
        description=(
            "An argv-allowlisted, shell-free, confined subprocess "
            "runner. Use as a library; this CLI dry-checks or runs an "
            "argv with the given policy."
        ),
    )
    p.add_argument("--version", action="store_true",
                   help="print version and exit")
    sub = p.add_subparsers(dest="command")

    for name, help_text in (
        ("verify", "shape-check an argv and print the ScanResult"),
        ("run", "actually execute an argv under the policy"),
    ):
        s = sub.add_parser(name, help=help_text)
        s.add_argument("--allowed", action="append", default=[],
                       help="allowed command (basename or absolute path); "
                            "repeat for multiple")
        s.add_argument("--workdir", default=".",
                       help="working directory for the subprocess "
                            "(must exist)")
        s.add_argument("--timeout", type=float, default=5.0,
                       help="timeout in seconds (default 5.0)")
        s.add_argument("--max-output-bytes", type=int, default=65_536,
                       help="per-stream output cap in bytes "
                            "(default 65536)")
        s.add_argument("--env-passthrough", action="store_true",
                       help="inherit the parent environment (default: "
                            "minimal fail-closed env)")
        s.add_argument("--kill-on-output-cap", action="store_true",
                       help="kill the subprocess if a stream exceeds "
                            "max-output-bytes (default: truncate)")
        s.add_argument("--json", action="store_true",
                       help="emit a JSON report")
        s.add_argument("argv", nargs=argparse.REMAINDER,
                       help="argv to check / run; use '--' to separate")

    return p


def _render_scan_text(scan: ScanResult, out: TextIO) -> None:
    out.write("verdict: " + scan.verdict.value + "\n")
    for f in scan.findings:
        out.write(
            "  [{sev}] {rid}: {msg}\n".format(
                sev=_render_char(f.severity.value),
                rid=_render_char(f.rule_id),
                msg=_render_char(f.message),
            )
        )


def _normalise_argv(raw: Sequence[str]) -> List[str]:
    # argparse.REMAINDER with a leading '--' leaves the '--' in; strip it.
    args = list(raw)
    if args and args[0] == "--":
        args = args[1:]
    return args


def main(
    argv: Optional[List[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    args = list(sys.argv[1:]) if argv is None else list(argv)
    parser = _build_parser()

    if "--help" in args or "-h" in args:
        parser.print_help(file=out)
        return 0
    if "--version" in args:
        out.write("saferun " + __version__ + "\n")
        return 0

    try:
        ns = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0

    if ns.version:
        out.write("saferun " + __version__ + "\n")
        return 0

    if ns.command is None:
        parser.print_help(file=out)
        return 0

    sub_argv = _normalise_argv(ns.argv)

    runner = SafeRunner(
        allowed_commands=ns.allowed,
        workdir=ns.workdir,
        timeout_sec=ns.timeout,
        max_output_bytes=ns.max_output_bytes,
        env_passthrough=ns.env_passthrough,
        kill_on_output_cap=ns.kill_on_output_cap,
    )

    if ns.command == "verify":
        scan = runner.verify(sub_argv)
        if ns.json:
            out.write(json.dumps(scan.to_json(), sort_keys=True) + "\n")
        else:
            _render_scan_text(scan, out)
        return _rc_for_verdict(scan.verdict)

    if ns.command == "run":
        try:
            result = runner.run(sub_argv)
        except RunRefused as e:
            if ns.json:
                out.write(json.dumps({
                    "refused": True,
                    "scan": e.scan.to_json(),
                }, sort_keys=True) + "\n")
            else:
                err.write("saferun: refused\n")
                _render_scan_text(e.scan, err)
            return 2
        except RunTimedOut as e:
            if ns.json:
                out.write(json.dumps({
                    "timed_out": True,
                    "message": str(e),
                }, sort_keys=True) + "\n")
            else:
                err.write("saferun: timed out: " + str(e) + "\n")
            return 2

        if ns.json:
            doc = result.to_json()
            doc["stdout"] = result.stdout.decode(
                "utf-8", errors="replace",
            )
            doc["stderr"] = result.stderr.decode(
                "utf-8", errors="replace",
            )
            out.write(json.dumps(doc, sort_keys=True) + "\n")
        else:
            out.write(result.stdout.decode("utf-8", errors="replace"))
            err.write(result.stderr.decode("utf-8", errors="replace"))
        return result.rc

    err.write("saferun: unknown command " + str(ns.command) + "\n")
    return 2


def _rc_for_verdict(verdict: Verdict) -> int:
    if verdict == Verdict.HEALTHY:
        return 0
    if verdict == Verdict.NEEDS_ATTENTION:
        return 1
    return 2
