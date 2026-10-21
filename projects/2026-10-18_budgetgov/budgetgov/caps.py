"""Cap types for the four governed dimensions.

Each cap is an immutable dataclass that carries the configured limit
and a small amount of behavior: a name (used in records and
exceptions), a reservation preview and an update step. Behavior is
split out so the Governor can treat all caps uniformly.

A cap is a BOUND on a running counter. The Governor owns the counter;
caps know how to compare a proposed addition against the bound.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

Number = Union[int, float]


@dataclass(frozen=True)
class TokenCap:
    """Combined input + output tokens cap. Non-negative integer."""

    limit: int
    name: str = "token"

    def __post_init__(self) -> None:
        if not isinstance(self.limit, int):
            raise TypeError("TokenCap.limit must be int")
        if self.limit < 0:
            raise ValueError("TokenCap.limit must be >= 0")


@dataclass(frozen=True)
class TimeCap:
    """Wall-clock cap, in seconds from session start. Positive float."""

    seconds: float
    name: str = "time"

    def __post_init__(self) -> None:
        if not isinstance(self.seconds, (int, float)):
            raise TypeError("TimeCap.seconds must be a number")
        if self.seconds <= 0:
            raise ValueError("TimeCap.seconds must be > 0")


@dataclass(frozen=True)
class CallCap:
    """Count of model + tool calls across the session. Non-negative int."""

    limit: int
    name: str = "call"

    def __post_init__(self) -> None:
        if not isinstance(self.limit, int):
            raise TypeError("CallCap.limit must be int")
        if self.limit < 0:
            raise ValueError("CallCap.limit must be >= 0")


@dataclass(frozen=True)
class SpendCap:
    """Spend cap in a declared currency unit (default USD).

    The caller declares the unit; the governor does not convert or
    estimate. All reservations and reconciliations must use the same
    unit the caller declared.
    """

    usd: float
    name: str = "spend"

    def __post_init__(self) -> None:
        if not isinstance(self.usd, (int, float)):
            raise TypeError("SpendCap.usd must be a number")
        if self.usd < 0:
            raise ValueError("SpendCap.usd must be >= 0")
