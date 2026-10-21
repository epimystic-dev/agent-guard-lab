"""The budgetgov CLI.

Primary use is as a library; the CLI is small and purposeful:

- ``budgetgov verify <path>``   verify a record file and print a report.
- ``budgetgov tail <path>``     print the last N entries as JSON.
- ``budgetgov --help``          exits 0.
- ``budgetgov --version``       exits 0.

Exit codes follow the lab's CLI contract: 0 for a clean verify, 1 for
NEEDS-ATTENTION, 2 for UNHEALTHY or an unreadable input, 2 for an
unknown flag.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, TextIO

from . import __version__
from .record import load_record, verify_record
from .types import Verdict


def _render_char(ch: str) -> str:
    """Render any non-printable-ASCII character as <U+XXXX> for the
    text report. The lab's rule: the text report must never echo a raw
    non-ASCII character.
    """
    out = []
    for c in ch:
        o = ord(c)
        if 32 <= o < 127:
            out.append(c)
        else:
            out.append("<U+{:04X}>".format(o))
    return "".join(out)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="budgetgov",
        description=(
            "Runtime budget governor for autonomous agents. "
            "Use as a library; this CLI inspects the record file."
        ),
    )
    p.add_argument("--version", action="store_true",
                   help="print version and exit")
    sub = p.add_subparsers(dest="command")

    v = sub.add_parser("verify",
                       help="verify a record file")
    v.add_argument("path", help="path to a budgetgov record (JSONL)")
    v.add_argument("--json", action="store_true",
                   help="emit a machine-readable JSON report")

    t = sub.add_parser("tail", help="print the last N entries")
    t.add_argument("path", help="path to a budgetgov record (JSONL)")
    t.add_argument("-n", "--count", type=int, default=5,
                   help="how many entries (default 5)")

    return p


def _print_report(result, path: str, as_json: bool, out: TextIO) -> int:
    if as_json:
        obj = {
            "path": path,
            "verdict": result.verdict.value,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "where": f.where,
                } for f in result.findings
            ],
        }
        out.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
    else:
        out.write("verdict: " + result.verdict.value + "\n")
        for f in result.findings:
            out.write(
                "  [{sev}] {rid}: {msg}\n".format(
                    sev=_render_char(f.severity.value),
                    rid=_render_char(f.rule_id),
                    msg=_render_char(f.message),
                )
            )

    if result.verdict == Verdict.HEALTHY:
        return 0
    if result.verdict == Verdict.UNHEALTHY:
        return 2
    if result.verdict == Verdict.NEEDS_ATTENTION:
        return 1
    return 2


def main(
    argv: Optional[List[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    parser = _build_parser()

    # argparse's own --help / --version paths call sys.exit() and
    # write to the real sys.stdout; intercept them before parse_args
    # so help / version respect our captured stdout.
    args = list(sys.argv[1:]) if argv is None else list(argv)
    if "--help" in args or "-h" in args:
        parser.print_help(file=out)
        return 0
    if "--version" in args:
        out.write("budgetgov " + __version__ + "\n")
        return 0

    try:
        ns = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0

    if ns.version:
        out.write("budgetgov " + __version__ + "\n")
        return 0

    if ns.command is None:
        parser.print_help(file=out)
        return 0

    if ns.command == "verify":
        result = verify_record(ns.path)
        return _print_report(result, ns.path, ns.json, out)

    if ns.command == "tail":
        try:
            entries = load_record(ns.path)
        except (OSError, ValueError) as e:
            err.write("budgetgov: cannot read " + ns.path + ": " + str(e) + "\n")
            return 2
        n = max(0, int(ns.count))
        for e in entries[-n:]:
            out.write(json.dumps(
                e.to_json(), ensure_ascii=False, sort_keys=True
            ) + "\n")
        return 0

    err.write("budgetgov: unknown command " + str(ns.command) + "\n")
    return 2
