"""The saferun shape-check rule registry.

Rules are static invariants an argv + runner config must satisfy
before the subprocess is spawned. They are not a security claim about
what the subprocess does once it is running; they are a tripwire for
the specific class of mistakes that GuardFall-style agent-safety
filters are supposed to prevent but structurally cannot (string input,
shell=True, unbounded output, unbounded time, inherited environment).

A caller can run the shape check without executing anything via
``runner.verify(argv)``. A refusal from ``runner.run(argv)`` always
carries the same ScanResult.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .types import Finding, Rule, ScanResult, Severity, Verdict


# Shell metacharacters that would be interpreted by sh/bash/cmd if
# an argv were ever joined into a string and fed through shell=True.
# saferun never does that, but we still surface them so a caller
# notices if upstream code is building argv from untrusted text.
#
# This set is narrow by design: only the control / substitution
# operators that CHANGE control flow or substitute values under a
# shell. Parentheses, quotes, asterisks, question marks, brackets,
# braces, hash, tilde and exclamation are omitted because they
# appear routinely in benign non-shell argv elements (python
# expressions, SQL, globs the program itself expands).
_SHELL_METACHARS = set("|&;<>$`\n\r")


ALL_RULES: Tuple[Rule, ...] = (
    Rule("SR-001", Severity.HIGH,
         "argv must be a list / tuple of strings, not a string "
         "(a string implies shell=True semantics; forbidden)"),
    Rule("SR-002", Severity.HIGH,
         "argv[0] (resolved to its basename) is not in the "
         "configured allowed_commands allowlist"),
    Rule("SR-003", Severity.HIGH,
         "argv[0] contains a path traversal segment ('..') or a "
         "null byte"),
    Rule("SR-004", Severity.MEDIUM,
         "an argv element contains a shell metacharacter; harmless "
         "under saferun (shell=False) but a signal upstream argv "
         "construction may be building from untrusted text"),
    Rule("SR-005", Severity.HIGH,
         "workdir is missing or is not an existing directory"),
    Rule("SR-006", Severity.INFO,
         "env is set to inherit the parent process environment; "
         "default is a minimal env for fail-closed hygiene"),
    Rule("SR-007", Severity.HIGH,
         "timeout_sec must be a positive finite number"),
    Rule("SR-008", Severity.HIGH,
         "max_output_bytes must be a positive integer"),
    Rule("SR-009", Severity.MEDIUM,
         "argv contains a null byte somewhere other than argv[0] "
         "(POSIX exec rejects it; signalled early)"),
    Rule("SR-010", Severity.MEDIUM,
         "argv[0] is an absolute path and allowed_commands contains "
         "only basenames; the resolution rule treated the basename "
         "as the match key"),
)


def _severity_of(rule_id: str) -> Severity:
    for r in ALL_RULES:
        if r.id == rule_id:
            return r.severity
    return Severity.INFO


def _finding(rule_id: str, message: str, where: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=_severity_of(rule_id),
        message=message,
        where=where,
    )


def _basename_of(cmd: str) -> str:
    # os.path.basename handles '/' and '\\' on Windows.
    return os.path.basename(cmd)


def _normalise_allowlist(allowed: Sequence[str]) -> Tuple[set, set]:
    """Return (basenames, absolute_paths) from the allowlist.

    An entry with a path separator becomes an absolute-path match
    key (realpath-normalised); any other entry is a basename match
    key.
    """
    basenames: set = set()
    abs_paths: set = set()
    for a in allowed:
        if not isinstance(a, str) or not a:
            continue
        has_sep = ("/" in a) or ("\\" in a)
        if has_sep:
            try:
                abs_paths.add(os.path.realpath(a))
            except (OSError, ValueError):
                abs_paths.add(a)
        else:
            basenames.add(a)
    return basenames, abs_paths


def shape_check(
    argv: Any,
    allowed_commands: Sequence[str],
    workdir: Optional[str],
    timeout_sec: Any,
    max_output_bytes: Any,
    env_passthrough: bool,
) -> ScanResult:
    """Run every static invariant against the given shape; return a
    ScanResult. Any HIGH finding yields verdict ``unhealthy``;
    MEDIUM-only yields ``needs-attention``; else ``healthy``.
    """
    findings: List[Finding] = []

    # SR-001: argv must be a list / tuple of str
    if isinstance(argv, str) or isinstance(argv, bytes):
        findings.append(_finding(
            "SR-001",
            "argv is a " + type(argv).__name__
            + "; saferun requires a list / tuple of strings",
            where="argv",
        ))
        # Can't check further without an iterable of strings.
        return _finalise(findings)

    try:
        arglist = list(argv)
    except TypeError:
        findings.append(_finding(
            "SR-001",
            "argv is not iterable; a list / tuple of strings is required",
            where="argv",
        ))
        return _finalise(findings)

    if not arglist:
        findings.append(_finding(
            "SR-001",
            "argv is empty; argv[0] is required",
            where="argv",
        ))
        return _finalise(findings)

    for i, a in enumerate(arglist):
        if not isinstance(a, str):
            findings.append(_finding(
                "SR-001",
                "argv[" + str(i) + "] is "
                + type(a).__name__ + "; strings required",
                where="argv[" + str(i) + "]",
            ))

    if any(f.rule_id == "SR-001" for f in findings):
        return _finalise(findings)

    cmd0 = arglist[0]
    base0 = _basename_of(cmd0)
    base_set, abs_set = _normalise_allowlist(allowed_commands or ())

    # SR-003: traversal / null bytes in argv[0].
    # Both '/' and '\\' are valid path separators on Windows, and
    # subprocess resolution honours either, so a mixed path like
    # 'x/..\\y' must be caught the same as 'x/../y' or 'x\\..\\y'.
    # Splitting on each separator independently misses the mixed
    # shape because '..' never ends up as a lone list element on
    # either split; normalise '\\' to '/' before the component
    # check so a single split sees both separator styles at once.
    cmd0_norm = cmd0.replace("\\", "/")
    if ".." in cmd0_norm.split("/") or "\x00" in cmd0:
        findings.append(_finding(
            "SR-003",
            "argv[0] contains a traversal segment or null byte",
            where="argv[0]",
        ))

    # SR-002 / SR-010: allowlist membership
    allowed = False
    if base0 in base_set:
        allowed = True
    else:
        # Absolute-path allowlist: compare realpath.
        try:
            resolved = os.path.realpath(cmd0)
        except (OSError, ValueError):
            resolved = cmd0
        if resolved in abs_set:
            allowed = True
        elif cmd0 in abs_set:
            allowed = True
    if not allowed:
        findings.append(_finding(
            "SR-002",
            "argv[0] basename '" + base0 + "' is not in the allowlist "
            "(allowed basenames: " + ",".join(sorted(base_set)) + ")",
            where="argv[0]",
        ))

    # SR-010: argv[0] is absolute and only basename matched
    is_absolute_argv0 = os.path.isabs(cmd0)
    if is_absolute_argv0 and base0 in base_set and not abs_set:
        findings.append(_finding(
            "SR-010",
            "argv[0] is absolute path '" + cmd0
            + "' but allowlist contains only basenames; matched by basename",
            where="argv[0]",
        ))

    # SR-009: null bytes anywhere else in argv
    for i, a in enumerate(arglist[1:], start=1):
        if "\x00" in a:
            findings.append(_finding(
                "SR-009",
                "argv[" + str(i) + "] contains a null byte",
                where="argv[" + str(i) + "]",
            ))

    # SR-004: shell metachars anywhere in argv (informational)
    for i, a in enumerate(arglist):
        if any((c in _SHELL_METACHARS) for c in a):
            findings.append(_finding(
                "SR-004",
                "argv[" + str(i)
                + "] contains a shell metacharacter; harmless "
                "under shell=False, flagged for upstream review",
                where="argv[" + str(i) + "]",
            ))

    # SR-005: workdir
    if workdir is None or not isinstance(workdir, str):
        findings.append(_finding(
            "SR-005",
            "workdir is required and must be a string path",
            where="workdir",
        ))
    else:
        if not os.path.isdir(workdir):
            findings.append(_finding(
                "SR-005",
                "workdir '" + workdir + "' is not an existing directory",
                where="workdir",
            ))

    # SR-007: timeout_sec
    if not isinstance(timeout_sec, (int, float)) or isinstance(timeout_sec, bool):
        findings.append(_finding(
            "SR-007",
            "timeout_sec must be a number, got " + type(timeout_sec).__name__,
            where="timeout_sec",
        ))
    else:
        import math
        if (
            not math.isfinite(timeout_sec)
            or timeout_sec <= 0
        ):
            findings.append(_finding(
                "SR-007",
                "timeout_sec must be a positive finite number",
                where="timeout_sec",
            ))

    # SR-008: max_output_bytes
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes <= 0
    ):
        findings.append(_finding(
            "SR-008",
            "max_output_bytes must be a positive int",
            where="max_output_bytes",
        ))

    # SR-006: env passthrough (informational)
    if env_passthrough:
        findings.append(_finding(
            "SR-006",
            "env_passthrough=True; the subprocess inherits the parent "
            "environment including any secret-shaped variables",
            where="env",
        ))

    return _finalise(findings)


def _finalise(findings: List[Finding]) -> ScanResult:
    verdict = Verdict.HEALTHY
    for f in findings:
        if f.severity == Severity.HIGH:
            verdict = Verdict.UNHEALTHY
            break
        if f.severity == Severity.MEDIUM and verdict == Verdict.HEALTHY:
            verdict = Verdict.NEEDS_ATTENTION
    return ScanResult(findings=tuple(findings), verdict=verdict)
