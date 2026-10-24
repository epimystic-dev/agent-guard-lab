"""The quarantine rule registry.

Rules are ordered by the character class or syntactic marker they
flatten. Each rule's ``apply`` returns the modified text and the
number of times it fired.

Fail-closed principle: the neutralised form of a hit is always a
visible, inert marker - never silent removal of a character the
author might legitimately have used. The caller sees exactly what
was changed and can audit the hit list.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Callable, List, Tuple

from .types import Hit, Rule, Severity


RULES_META = (
    Rule("QN-001", Severity.HIGH,
         "Plane 14 TAG characters (U+E0000-U+E007F) stripped"),
    Rule("QN-002", Severity.HIGH,
         "bidi override characters neutralised"),
    Rule("QN-003", Severity.HIGH,
         "zero-width and other invisible format characters "
         "(incl. SOFT HYPHEN, LTR/RTL MARK, invisible math "
         "operators) stripped"),
    Rule("QN-004", Severity.MEDIUM,
         "C0 / C1 control characters (except TAB / LF / CR) stripped"),
    Rule("QN-005", Severity.LOW,
         "private-use codepoints replaced with <U+XXXX>"),
    Rule("QN-006", Severity.HIGH,
         "'ignore / cancel / reset / delete / remove / erase / clear "
         "(all / previous / prior / your) instructions' imperative "
         "flattened"),
    Rule("QN-007", Severity.HIGH,
         "role-switch opening ('You are now ...', 'From now on you are "
         "...') flattened"),
    Rule("QN-008", Severity.MEDIUM,
         "markdown HTML comment (potential hidden instruction) stripped"),
    Rule("QN-009", Severity.MEDIUM,
         "'system:' / 'assistant:' / 'instruction:' injected role "
         "prefix flattened"),
    Rule("QN-010", Severity.MEDIUM,
         "pretend-tool-call JSON block ('tool_call', 'function_call') "
         "flattened"),
    Rule("QN-011", Severity.LOW,
         "excessive repeated characters (>= 32 of one char) compressed"),
    Rule("QN-012", Severity.HIGH,
         "'disregard / override your (system) prompt' imperative "
         "flattened"),
)


def _strip_class(
    text: str,
    predicate: Callable[[int], bool],
) -> Tuple[str, int]:
    out = []
    count = 0
    for ch in text:
        if predicate(ord(ch)):
            count += 1
        else:
            out.append(ch)
    return "".join(out), count


def _rule_qn001(text: str) -> Tuple[str, int]:
    """Plane 14 TAG characters."""
    return _strip_class(text, lambda cp: 0xE0000 <= cp <= 0xE007F)


def _rule_qn002(text: str) -> Tuple[str, int]:
    """Bidi overrides."""
    bidi = {
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2066, 0x2067, 0x2068, 0x2069,
    }
    return _strip_class(text, lambda cp: cp in bidi)


def _rule_qn003(text: str) -> Tuple[str, int]:
    """Zero-width and other invisible format characters.

    These codepoints are either literally zero-width or render only
    at line breaks and are therefore invisible mid-word to a human
    reviewer. An attacker who scatters one through a keyword
    ('i' + U+00AD + 'gnore') defeats word-level regexes while the
    tokenizer still sees the keyword. Stripping them here lets the
    imperative-form rules (QN-006/007/012) see the plain keyword.
    """
    zw = {
        # Original zero-width set.
        0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
        # SOFT HYPHEN - invisible mid-word, visible only at line break.
        0x00AD,
        # Non-override directional marks (overrides are QN-002).
        0x061C, 0x200E, 0x200F,
        # MONGOLIAN VOWEL SEPARATOR - zero-width since Unicode 6.3.
        0x180E,
        # Invisible mathematical operators.
        0x2061, 0x2062, 0x2063, 0x2064,
        # Deprecated inhibit/activate shaping and digit-shape controls.
        0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F,
        # Interlinear annotation anchors.
        0xFFF9, 0xFFFA, 0xFFFB,
    }
    return _strip_class(text, lambda cp: cp in zw)


def _rule_qn004(text: str) -> Tuple[str, int]:
    """C0 / C1 controls (except TAB U+0009, LF U+000A, CR U+000D)."""
    def is_ctrl(cp: int) -> bool:
        if cp in (0x09, 0x0A, 0x0D):
            return False
        return (0x00 <= cp <= 0x1F) or (0x7F <= cp <= 0x9F)
    return _strip_class(text, is_ctrl)


def _rule_qn005(text: str) -> Tuple[str, int]:
    """Private-use codepoints -> <U+XXXX>."""
    def is_pua(cp: int) -> bool:
        return (
            0xE000 <= cp <= 0xF8FF
            or 0xF0000 <= cp <= 0xFFFFD
            or 0x100000 <= cp <= 0x10FFFD
        )
    out = []
    count = 0
    for ch in text:
        cp = ord(ch)
        if is_pua(cp):
            out.append("<U+{:04X}>".format(cp))
            count += 1
        else:
            out.append(ch)
    return "".join(out), count


# --- Imperative-form flatteners ---

_IGNORE_RE = re.compile(
    r"\b(?:please\s+)?"
    r"(?:ignore|forget|disregard|cancel|erase|delete|remove|reset|clear)\s+"
    r"(?:all\s+|any\s+|the\s+|every\s+|your\s+|my\s+|our\s+|previous\s+|prior\s+|above\s+|earlier\s+)+"
    r"(?:instructions?|rules?|prompts?|directives?|guidelines?|constraints?|commands?)",
    re.IGNORECASE,
)

_ROLE_SWITCH_RE = re.compile(
    r"\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you\s+are|act\s+as(?:\s+if\s+you\s+are)?|"
    r"pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|you\s+will\s+now\s+be)"
    r"\s+(?:a\s+|an\s+|the\s+)?[A-Za-z]",
    re.IGNORECASE,
)

_OVERRIDE_RE = re.compile(
    r"\b(?:disregard|override|bypass|ignore|replace)\s+"
    r"(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|safety|guardrails?)",
    re.IGNORECASE,
)

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

_ROLE_PREFIX_RE = re.compile(
    r"(?m)^(?:system|assistant|user|instruction|developer)\s*:\s*",
    re.IGNORECASE,
)

_TOOL_BLOCK_RE = re.compile(
    r"\{\s*\"(?:tool_call|function_call|tool_use|function)\"\s*:",
)


def _flatten(text: str, pattern: "re.Pattern[str]", marker: str) -> Tuple[str, int]:
    count = 0

    def repl(m: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return marker

    return pattern.sub(repl, text), count


def _rule_qn006(text: str) -> Tuple[str, int]:
    return _flatten(text, _IGNORE_RE, "[neutralised-imperative]")


def _rule_qn007(text: str) -> Tuple[str, int]:
    def repl(m: "re.Match[str]") -> str:
        return "[neutralised-roleswitch]" + m.group(0)[-1]

    count = 0

    def _repl_count(m: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return repl(m)

    return _ROLE_SWITCH_RE.sub(_repl_count, text), count


def _rule_qn008(text: str) -> Tuple[str, int]:
    return _flatten(text, _HTML_COMMENT_RE, "[neutralised-html-comment]")


def _rule_qn009(text: str) -> Tuple[str, int]:
    return _flatten(text, _ROLE_PREFIX_RE, "[neutralised-role-prefix] ")


def _rule_qn010(text: str) -> Tuple[str, int]:
    def repl(m: "re.Match[str]") -> str:
        return "[neutralised-tool-block] {"

    count = 0

    def _repl_count(m: "re.Match[str]") -> str:
        nonlocal count
        count += 1
        return repl(m)

    return _TOOL_BLOCK_RE.sub(_repl_count, text), count


def _rule_qn011(text: str) -> Tuple[str, int]:
    # Compress any run of >= 32 of the same char into char * 32 + "..."
    count = 0
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        j = i
        while j < n and text[j] == text[i]:
            j += 1
        run = j - i
        if run >= 32:
            out.append(text[i] * 32)
            out.append("[...]")
            count += 1
        else:
            out.append(text[i:j])
        i = j
    return "".join(out), count


def _rule_qn012(text: str) -> Tuple[str, int]:
    return _flatten(text, _OVERRIDE_RE, "[neutralised-override]")


RULE_FUNCS = (
    ("QN-001", _rule_qn001),
    ("QN-002", _rule_qn002),
    ("QN-003", _rule_qn003),
    ("QN-004", _rule_qn004),
    ("QN-005", _rule_qn005),
    ("QN-006", _rule_qn006),
    ("QN-007", _rule_qn007),
    ("QN-008", _rule_qn008),
    ("QN-009", _rule_qn009),
    ("QN-010", _rule_qn010),
    ("QN-011", _rule_qn011),
    ("QN-012", _rule_qn012),
)


def apply_rules(text: str) -> Tuple[str, Tuple[Hit, ...]]:
    """Run every rule in order; return (safe_text, hits).

    Rules are composable: each takes the output of the previous. The
    character-class rules run before the regex rules so a regex sees
    the already-flattened codepoint space.
    """
    hits: List[Hit] = []
    s = text
    for rule_id, fn in RULE_FUNCS:
        s, count = fn(s)
        if count > 0:
            hits.append(Hit(rule_id=rule_id, count=count))
    return s, tuple(hits)


ALL_RULES: Tuple[Rule, ...] = RULES_META
