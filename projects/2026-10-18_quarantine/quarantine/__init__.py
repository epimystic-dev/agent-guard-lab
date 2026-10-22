"""quarantine - provenance-wrap and heuristically neutralise untrusted
text before it reaches an LLM or agent prompt.

Public surface:

- ``__version__``                 semantic version
- ``Severity``                    enum: HIGH / MEDIUM / LOW / INFO
- ``Verdict``                     enum: healthy / needs-attention / unhealthy / unknown
- ``Provenance``                  enum: web / file / email / retrieval / tool-output / user / unknown
- ``Hit``                         dataclass (one neutralisation that fired)
- ``Finding`` / ``ScanResult``    verify-side types
- ``Quarantined``                 return type of wrap()
- ``Rule``, ``ALL_RULES``         rule registry
- ``wrap(text, provenance, source)``   wrap and neutralise
- ``verify(text)``                non-destructive scan
"""

from __future__ import annotations

__version__ = "0.1.0"

from .rules import ALL_RULES
from .types import (
    Finding,
    Hit,
    Provenance,
    Quarantined,
    Rule,
    ScanResult,
    Severity,
    Verdict,
)
from .wrap import verify, wrap

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Provenance",
    "Hit",
    "Finding",
    "ScanResult",
    "Quarantined",
    "Rule",
    "ALL_RULES",
    "wrap",
    "verify",
]
