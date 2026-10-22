"""The wrap() entry point and verify() surface.

``wrap(text, provenance, source)`` returns a Quarantined value.
``verify(text)`` returns a ScanResult: given a text, how many hits
would wrap() produce, and what verdict follows from the severities?
``verify`` does not modify; it is a reader-only diagnostic.

The boundary markers are randomised per call using ``secrets.token_hex``
so an attacker in the ingested content cannot emit a plausible
closer. The caller is responsible for passing the rendered form -
``q.render_for_prompt()`` - inside their prompt, and for instructing
the model to treat the boundary as untrusted.
"""

from __future__ import annotations

import secrets
from typing import Optional

from .rules import apply_rules, ALL_RULES
from .types import (
    Finding,
    Hit,
    Provenance,
    Quarantined,
    ScanResult,
    Severity,
    Verdict,
)


def _marker(prefix: str) -> str:
    # 24-hex = 96 bits of unguessable boundary.
    return prefix + "-" + secrets.token_hex(12)


def wrap(
    text: str,
    provenance: Provenance = Provenance.UNKNOWN,
    source: str = "",
) -> Quarantined:
    """Wrap untrusted text with a provenance boundary and apply the
    neutralisation rules.

    - ``text`` must be a str; bytes are rejected at the boundary (the
      caller must decide an encoding).
    - ``provenance`` is a label; the guard treats all provenance
      values as untrusted.
    - ``source`` is an optional identifier (URL, file path,
      message-id) and is NOT trusted - it is passed through sanitised
      against quote-injection so a crafted source string cannot escape
      the open-tag attribute.
    """
    if not isinstance(text, str):
        raise TypeError("quarantine.wrap: text must be str, not " + type(text).__name__)
    if not isinstance(provenance, Provenance):
        raise TypeError("quarantine.wrap: provenance must be a Provenance")

    safe_text, hits = apply_rules(text)
    safe_source = source.replace("\"", "'").replace("\n", " ").replace("\r", " ")

    return Quarantined(
        raw=text,
        safe_text=safe_text,
        provenance=provenance,
        source=safe_source,
        open_marker=_marker("UNTRUSTED-OPEN"),
        close_marker=_marker("UNTRUSTED-CLOSE"),
        hits=hits,
    )


def _severity_of(rule_id: str) -> Severity:
    for r in ALL_RULES:
        if r.id == rule_id:
            return r.severity
    return Severity.INFO


def verify(text: str) -> ScanResult:
    """Non-destructive scan: what would wrap() flag, and what is the
    verdict? Returns ScanResult with findings keyed by rule id and
    severity.
    """
    _safe, hits = apply_rules(text)
    findings = tuple(
        Finding(
            rule_id=h.rule_id,
            severity=_severity_of(h.rule_id),
            message=(
                "{rid} fired {n} time(s)".format(rid=h.rule_id, n=h.count)
            ),
            where="input",
        )
        for h in hits
    )
    verdict = Verdict.HEALTHY
    for f in findings:
        if f.severity == Severity.HIGH:
            verdict = Verdict.UNHEALTHY
            break
        if f.severity == Severity.MEDIUM and verdict == Verdict.HEALTHY:
            verdict = Verdict.NEEDS_ATTENTION
    return ScanResult(findings=findings, verdict=verdict)
