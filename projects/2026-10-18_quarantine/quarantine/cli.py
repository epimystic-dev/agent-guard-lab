"""The quarantine CLI.

- ``quarantine scan <path>``       verify-style report (rule hits).
- ``quarantine wrap  <path>``      write the rendered-for-prompt form
                                   to stdout, with a header carrying
                                   provenance / source.
- ``quarantine --help``            exits 0.
- ``quarantine --version``         exits 0.

Exit codes: 0 clean (no hits), 1 for MEDIUM/LOW hits only, 2 for any
HIGH hit or unreadable input, 2 for an unknown flag.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, TextIO

from . import __version__
from .types import Provenance, Verdict
from .wrap import verify as _verify, wrap as _wrap


def _render_char(ch: str) -> str:
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
        prog="quarantine",
        description=(
            "Provenance-wrapping and heuristic imperative-neutralisation "
            "for untrusted ingested text. Use as a library; this CLI "
            "scans a file or writes the wrapped form to stdout."
        ),
    )
    p.add_argument("--version", action="store_true",
                   help="print version and exit")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a file and report hits")
    s.add_argument("path", help="path to a text file to scan")
    s.add_argument("--json", action="store_true",
                   help="emit a JSON report")

    w = sub.add_parser("wrap", help="write the wrapped-for-prompt form")
    w.add_argument("path", help="path to a text file to wrap")
    w.add_argument("--provenance", default="unknown",
                   choices=[p.value for p in Provenance],
                   help="declared provenance of the input (default: unknown)")
    w.add_argument("--source", default="",
                   help="optional source identifier (URL, path, id)")

    return p


def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main(
    argv: Optional[List[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    args = list(sys.argv[1:]) if argv is None else list(argv)
    parser = _build_parser()

    # argparse's --help / --version write to the real sys.stdout and
    # call sys.exit(); intercept them so the captured stdout is used.
    if "--help" in args or "-h" in args:
        parser.print_help(file=out)
        return 0
    if "--version" in args:
        out.write("quarantine " + __version__ + "\n")
        return 0

    try:
        ns = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0

    if ns.version:
        out.write("quarantine " + __version__ + "\n")
        return 0

    if ns.command is None:
        parser.print_help(file=out)
        return 0

    if ns.command == "scan":
        try:
            text = _read_file(ns.path)
        except OSError as e:
            err.write("quarantine: cannot read " + ns.path + ": " + str(e) + "\n")
            return 2
        result = _verify(text)
        if ns.json:
            out.write(json.dumps({
                "path": ns.path,
                "verdict": result.verdict.value,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "message": f.message,
                        "where": f.where,
                    } for f in result.findings
                ],
            }, ensure_ascii=False, sort_keys=True) + "\n")
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

    if ns.command == "wrap":
        try:
            text = _read_file(ns.path)
        except OSError as e:
            err.write("quarantine: cannot read " + ns.path + ": " + str(e) + "\n")
            return 2
        prov = Provenance(ns.provenance)
        q = _wrap(text, provenance=prov, source=ns.source)
        out.write(q.render_for_prompt() + "\n")
        return 0

    err.write("quarantine: unknown command " + str(ns.command) + "\n")
    return 2
