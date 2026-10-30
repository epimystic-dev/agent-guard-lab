"""The actionlog CLI.

- ``actionlog --version``        prints version, rc 0.
- ``actionlog --help``           rc 0.
- ``actionlog verify <path>``    verify the chain; rc 0 clean, rc 2
                                 on any HIGH finding, rc 1 on MEDIUM
                                 only, rc 2 on unreadable input.
- ``actionlog show <path>``      print each record one per line.
- ``actionlog append <path> --action <A> --payload <JSON>``
                                 append one record.
- Unknown flag                   rc 2.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, TextIO

from . import __version__
from .log import ActionLog
from .types import (
    LogError,
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
        prog="actionlog",
        description=(
            "An append-only SHA-256 hash-chained action audit log. "
            "Use as a library; this CLI verifies, shows, or appends "
            "to a chain."
        ),
    )
    p.add_argument("--version", action="store_true",
                   help="print version and exit")
    sub = p.add_subparsers(dest="command")

    v = sub.add_parser("verify", help="verify the chain at <path>")
    v.add_argument("path", help="path to the actionlog file")
    v.add_argument("--json", action="store_true",
                   help="emit a JSON report")

    s = sub.add_parser("show", help="show each record one per line")
    s.add_argument("path", help="path to the actionlog file")
    s.add_argument("--json", action="store_true",
                   help="emit a JSON array")

    a = sub.add_parser("append", help="append one record to the chain")
    a.add_argument("path", help="path to the actionlog file")
    a.add_argument("--action", required=True,
                   help="short action label (e.g. 'tool.call')")
    a.add_argument("--payload", default="{}",
                   help="JSON payload (default '{}'); must be a dict")

    return p


def _rc_for_verdict(verdict: Verdict) -> int:
    if verdict == Verdict.HEALTHY:
        return 0
    if verdict == Verdict.NEEDS_ATTENTION:
        return 1
    return 2


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
        out.write("actionlog " + __version__ + "\n")
        return 0

    try:
        ns = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 0

    if ns.version:
        out.write("actionlog " + __version__ + "\n")
        return 0

    if ns.command is None:
        parser.print_help(file=out)
        return 0

    if ns.command == "verify":
        if not os.path.isfile(ns.path):
            err.write("actionlog: cannot read " + ns.path + "\n")
            return 2
        try:
            log = ActionLog(path=ns.path)
            result = log.verify()
        except OSError as e:
            err.write("actionlog: cannot verify: " + str(e) + "\n")
            return 2

        if ns.json:
            out.write(json.dumps(result.to_json(), sort_keys=True) + "\n")
        else:
            out.write("ok: " + ("true" if result.ok else "false") + "\n")
            out.write("n_records: " + str(result.n_records) + "\n")
            if not result.ok:
                out.write(
                    "break_seq: " + str(result.break_seq) + "\n"
                )
                out.write(
                    "break_kind: " + _render_char(
                        result.break_kind.value if result.break_kind else "",
                    ) + "\n"
                )
                out.write(
                    "break_detail: " + _render_char(result.break_detail) + "\n"
                )
            for f in result.scan.findings:
                out.write(
                    "  [{sev}] {rid}: {msg}\n".format(
                        sev=_render_char(f.severity.value),
                        rid=_render_char(f.rule_id),
                        msg=_render_char(f.message),
                    )
                )
        return _rc_for_verdict(result.scan.verdict)

    if ns.command == "show":
        if not os.path.isfile(ns.path):
            err.write("actionlog: cannot read " + ns.path + "\n")
            return 2
        log = ActionLog(path=ns.path)
        records = list(log.records())
        if ns.json:
            out.write(json.dumps(
                [r.to_json() for r in records],
                sort_keys=True,
                ensure_ascii=True,
            ) + "\n")
        else:
            for r in records:
                out.write(
                    "seq=" + str(r.seq)
                    + " action=" + _render_char(r.action)
                    + " ts=" + _render_char(r.ts)
                    + "\n"
                )
        return 0

    if ns.command == "append":
        try:
            payload = json.loads(ns.payload)
        except ValueError as e:
            err.write("actionlog: --payload is not JSON: " + str(e) + "\n")
            return 2
        if not isinstance(payload, dict):
            err.write("actionlog: --payload must be a JSON object\n")
            return 2
        try:
            log = ActionLog(path=ns.path)
            rec = log.append(action=ns.action, payload=payload)
        except LogError as e:
            err.write("actionlog: cannot append: " + str(e) + "\n")
            return 2
        out.write(json.dumps(rec.to_json(), sort_keys=True) + "\n")
        return 0

    err.write("actionlog: unknown command " + str(ns.command) + "\n")
    return 2
