"""Shared types for quarantine.

A ``Hit`` records one neutralisation that fired on an input text: a
rule id, a count, and a short description. ``Quarantined`` is the
value returned to the caller: the raw text, the neutralised text, a
provenance tag, the randomised boundary markers used for rendering,
and the list of hits.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


class Severity(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, enum.Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class Provenance(str, enum.Enum):
    """Known provenance tags. The provenance field is label-only; the
    guard treats all of them as 'untrusted content that must be
    boundary-wrapped'. The caller declares which provenance a given
    text has.
    """

    WEB = "web"
    FILE = "file"
    EMAIL = "email"
    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool-output"
    USER = "user"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    summary: str


@dataclass(frozen=True)
class Hit:
    rule_id: str
    count: int
    detail: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "count": self.count,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Finding:
    """Alias of Hit for the lab's shared Finding surface."""

    rule_id: str
    severity: Severity
    message: str
    where: str = ""


@dataclass
class ScanResult:
    findings: Tuple[Finding, ...]
    verdict: Verdict

    def to_json(self) -> Dict[str, Any]:
        return {
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "where": f.where,
                } for f in self.findings
            ],
            "verdict": self.verdict.value,
        }


@dataclass
class Quarantined:
    """The wrapped, neutralised payload.

    - ``raw``                       the input, byte-for-byte
    - ``safe_text``                 the neutralised text (what to pass
                                    inside the provenance boundary)
    - ``provenance``                the caller-declared provenance tag
    - ``source``                    optional source id (URL / path / message-id)
    - ``open_marker``, ``close_marker``   randomised per call so an
                                    attacker in the content cannot
                                    emit a convincing closer
    - ``hits``                      which rules fired, and how many times
    """

    raw: str
    safe_text: str
    provenance: Provenance
    source: str
    open_marker: str
    close_marker: str
    hits: Tuple[Hit, ...] = field(default_factory=tuple)

    def render_for_prompt(self) -> str:
        """Render the wrapped boundary form the caller injects into
        the LLM prompt. The boundary markers are randomised at
        wrap-time; an attacker cannot predict them to inject a
        matching closer.
        """
        prov_line = (
            "<<" + self.open_marker + " provenance=\""
            + self.provenance.value + "\" source=\""
            + self.source + "\">>"
        )
        close = "<<" + self.close_marker + ">>"
        return prov_line + "\n" + self.safe_text + "\n" + close

    def to_json(self) -> Dict[str, Any]:
        return {
            "provenance": self.provenance.value,
            "source": self.source,
            "open_marker": self.open_marker,
            "close_marker": self.close_marker,
            "hits": [h.to_json() for h in self.hits],
            "raw_length": len(self.raw),
            "safe_length": len(self.safe_text),
        }
