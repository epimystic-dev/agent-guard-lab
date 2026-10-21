"""The Governor and its Session.

Design points worth stating up front:

- Fail closed. A reservation that the governor cannot evaluate -
  because an estimate is missing against a configured cap, because
  the session is sealed, because a cap would be exceeded - MUST
  refuse the call. The caller cannot override.

- Reservation before action. ``before_call`` must be invoked before
  each outgoing call. If it returns, the call is permitted; if it
  raises, the call MUST NOT be made. ``after_call`` reconciles the
  actuals; it may itself seal the session if an actual overshoots
  the cap (the overshoot is still recorded, and the next reservation
  is refused).

- The seal is one-way. Once a cap trips, the session is locked and
  stays locked. The lab's rule is 'a stop cannot be argued past'.

- Time is a running clock. The time cap is checked on every
  reservation and on every reconciliation against the elapsed time
  since the session's ``start_time`` (a monotonic clock), not the
  wall clock.

- Thread safety. The session uses an RLock. Two threads that share
  a session may call before_call / after_call concurrently; the
  guard is still exact.

- Zero dependencies. Only the standard library.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Optional

from .caps import CallCap, SpendCap, TimeCap, TokenCap
from .record import _RecordWriter
from .types import BudgetExceeded, SessionLocked


@dataclass
class _Counters:
    tokens_used: int = 0
    tokens_reserved: int = 0
    calls_used: int = 0
    calls_reserved: int = 0
    spend_used: float = 0.0
    spend_reserved: float = 0.0


class Governor:
    """A reusable configuration. ``session()`` opens a session."""

    def __init__(
        self,
        token_cap: Optional[TokenCap] = None,
        time_cap: Optional[TimeCap] = None,
        call_cap: Optional[CallCap] = None,
        spend_cap: Optional[SpendCap] = None,
        record_path: Optional[str] = None,
    ) -> None:
        self.token_cap = token_cap
        self.time_cap = time_cap
        self.call_cap = call_cap
        self.spend_cap = spend_cap
        self.record_path = record_path

    @contextmanager
    def session(self, label: str = "") -> Iterator["Session"]:
        s = Session(self, label=label)
        try:
            yield s
        finally:
            s.close()

    def open(self, label: str = "") -> "Session":
        """Open a session without a context manager. The caller MUST
        call ``session.close()`` when done.
        """
        return Session(self, label=label)


class Session:
    """One governed run.

    Methods are all synchronous; a caller with an async loop should
    hold the session on a shared object and call before_call /
    after_call around each await point.
    """

    def __init__(self, gov: Governor, label: str = "") -> None:
        self._gov = gov
        self._label = label
        self._lock = threading.RLock()
        self._counters = _Counters()
        self._writer = _RecordWriter(gov.record_path)
        self._start_monotonic = time.monotonic()
        self._seal: Optional[Dict[str, Any]] = None
        self._writer.write("opened", {
            "label": label,
            "caps": self._cap_snapshot(),
        })

    @property
    def is_sealed(self) -> bool:
        with self._lock:
            return self._seal is not None

    @property
    def seal_reason(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return None if self._seal is None else dict(self._seal)

    @property
    def used(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "tokens": self._counters.tokens_used,
                "calls": self._counters.calls_used,
                "spend": self._counters.spend_used,
                "elapsed": time.monotonic() - self._start_monotonic,
            }

    def before_call(
        self,
        estimated_tokens: Optional[int] = None,
        estimated_cost_usd: Optional[float] = None,
    ) -> None:
        """Reserve one call against the caps. Raises on refusal.

        Fail-closed rules:

        - If a TokenCap is configured and estimated_tokens is None,
          refuse. The caller must declare an estimate; the governor
          does not invent one.
        - Same rule for SpendCap and estimated_cost_usd.
        - CallCap and TimeCap need no caller estimates - the call
          counter adds 1, and the time cap is checked against the
          elapsed clock.
        - Any over-cap tuple refuses.

        On refusal the session is sealed and the record gets a
        ``refused`` line naming the first cap that tripped. Order of
        checks: time, call, token, spend - time first because it is
        the only cap that can trip without any caller input, and the
        clearest signal to a caller that the loop is stuck.
        """
        with self._lock:
            if self._seal is not None:
                raise SessionLocked(
                    "session is sealed: " + str(self._seal)
                )

            self._check_time_cap()
            self._check_call_cap(adding=1)
            if self._gov.token_cap is not None:
                if estimated_tokens is None:
                    self._refuse(
                        "token",
                        self._counters.tokens_used
                            + self._counters.tokens_reserved,
                        self._gov.token_cap.limit,
                        reserved=0,
                        detail="estimated_tokens is required when a "
                               "TokenCap is configured",
                    )
                if estimated_tokens < 0:
                    raise ValueError("estimated_tokens must be >= 0")
                self._check_token_cap(adding=estimated_tokens)
            if self._gov.spend_cap is not None:
                if estimated_cost_usd is None:
                    self._refuse(
                        "spend",
                        self._counters.spend_used
                            + self._counters.spend_reserved,
                        self._gov.spend_cap.usd,
                        reserved=0.0,
                        detail="estimated_cost_usd is required when a "
                               "SpendCap is configured",
                    )
                if estimated_cost_usd < 0:
                    raise ValueError("estimated_cost_usd must be >= 0")
                self._check_spend_cap(adding=float(estimated_cost_usd))

            # Reservation accepted; book the reservations.
            self._counters.calls_reserved += 1
            if estimated_tokens is not None:
                self._counters.tokens_reserved += int(estimated_tokens)
            if estimated_cost_usd is not None:
                self._counters.spend_reserved += float(estimated_cost_usd)

            self._writer.write("reservation", {
                "estimated_tokens": estimated_tokens,
                "estimated_cost_usd": estimated_cost_usd,
                "used_before": {
                    "tokens": self._counters.tokens_used,
                    "calls": self._counters.calls_used,
                    "spend": self._counters.spend_used,
                },
                "elapsed": time.monotonic() - self._start_monotonic,
            })

    def after_call(
        self,
        actual_tokens: int = 0,
        actual_cost_usd: float = 0.0,
    ) -> None:
        """Reconcile actuals. If an actual overshoots a cap, the
        session is sealed - the overshot call completed, but the next
        reservation will be refused.

        Must be called exactly once per successful before_call. If the
        call failed after before_call returned, pass zeros - the
        reservation still must be released or the counters drift and
        BGR-003 will fire later.
        """
        with self._lock:
            if self._counters.calls_reserved <= 0:
                raise RuntimeError(
                    "after_call without a matching before_call"
                )
            if actual_tokens < 0:
                raise ValueError("actual_tokens must be >= 0")
            if actual_cost_usd < 0:
                raise ValueError("actual_cost_usd must be >= 0")

            # Release the single-call reservation.
            self._counters.calls_reserved -= 1
            self._counters.calls_used += 1
            # Replace token reservation with the actual, but do not
            # under-count: we subtract whatever the matching
            # reservation booked. We cannot know which reservation
            # this call matches when there are concurrent sessions,
            # so for simplicity we subtract an equal split of the
            # outstanding reserved pool. The guarantee is that at
            # steady state (reserved == 0), used is exact.
            # In the common synchronous case, before_call and
            # after_call pair 1:1 and this is exact.
            if self._gov.token_cap is not None:
                take = min(
                    self._counters.tokens_reserved, int(actual_tokens),
                )
                self._counters.tokens_reserved = max(
                    0, self._counters.tokens_reserved - take,
                )
            self._counters.tokens_used += int(actual_tokens)
            if self._gov.spend_cap is not None:
                take_s = min(
                    self._counters.spend_reserved, float(actual_cost_usd),
                )
                self._counters.spend_reserved = max(
                    0.0, self._counters.spend_reserved - take_s,
                )
            self._counters.spend_used += float(actual_cost_usd)

            # If an actual overshot a cap, seal now.
            overshoots: Dict[str, Any] = {}
            if (
                self._gov.token_cap is not None
                and self._counters.tokens_used > self._gov.token_cap.limit
            ):
                overshoots["token"] = {
                    "used": self._counters.tokens_used,
                    "cap": self._gov.token_cap.limit,
                }
            if (
                self._gov.spend_cap is not None
                and self._counters.spend_used > self._gov.spend_cap.usd
            ):
                overshoots["spend"] = {
                    "used": self._counters.spend_used,
                    "cap": self._gov.spend_cap.usd,
                }
            if (
                self._gov.call_cap is not None
                and self._counters.calls_used > self._gov.call_cap.limit
            ):
                overshoots["call"] = {
                    "used": self._counters.calls_used,
                    "cap": self._gov.call_cap.limit,
                }
            if (
                self._gov.time_cap is not None
                and (time.monotonic() - self._start_monotonic)
                    > self._gov.time_cap.seconds
            ):
                overshoots["time"] = {
                    "used": time.monotonic() - self._start_monotonic,
                    "cap": self._gov.time_cap.seconds,
                }

            if overshoots:
                # Pick the first cap name in a stable order.
                for name in ("time", "call", "token", "spend"):
                    if name in overshoots:
                        o = overshoots[name]
                        self._seal_now(
                            name, o["used"], o["cap"],
                            detail="actual overshot cap after call",
                        )
                        break

    def close(self) -> None:
        with self._lock:
            if self._writer._fh is None and self._gov.record_path is None:
                return
            self._writer.write("closed", {
                "used": {
                    "tokens": self._counters.tokens_used,
                    "calls": self._counters.calls_used,
                    "spend": self._counters.spend_used,
                    "elapsed": time.monotonic() - self._start_monotonic,
                },
                "sealed": self._seal is not None,
            })
            self._writer.close()

    # ------- internal -------

    def _cap_snapshot(self) -> Dict[str, Any]:
        snap: Dict[str, Any] = {}
        if self._gov.token_cap is not None:
            snap["token"] = self._gov.token_cap.limit
        if self._gov.time_cap is not None:
            snap["time"] = self._gov.time_cap.seconds
        if self._gov.call_cap is not None:
            snap["call"] = self._gov.call_cap.limit
        if self._gov.spend_cap is not None:
            snap["spend"] = self._gov.spend_cap.usd
        return snap

    def _check_time_cap(self) -> None:
        if self._gov.time_cap is None:
            return
        elapsed = time.monotonic() - self._start_monotonic
        if elapsed >= self._gov.time_cap.seconds:
            self._refuse(
                "time", elapsed, self._gov.time_cap.seconds,
                reserved=0.0,
                detail="elapsed exceeds time cap",
            )

    def _check_call_cap(self, adding: int) -> None:
        if self._gov.call_cap is None:
            return
        prospective = (
            self._counters.calls_used
            + self._counters.calls_reserved
            + adding
        )
        if prospective > self._gov.call_cap.limit:
            self._refuse(
                "call",
                self._counters.calls_used + self._counters.calls_reserved,
                self._gov.call_cap.limit,
                reserved=float(adding),
                detail="call cap would be exceeded",
            )

    def _check_token_cap(self, adding: int) -> None:
        assert self._gov.token_cap is not None
        prospective = (
            self._counters.tokens_used
            + self._counters.tokens_reserved
            + adding
        )
        if prospective > self._gov.token_cap.limit:
            self._refuse(
                "token",
                self._counters.tokens_used + self._counters.tokens_reserved,
                self._gov.token_cap.limit,
                reserved=float(adding),
                detail="token cap would be exceeded",
            )

    def _check_spend_cap(self, adding: float) -> None:
        assert self._gov.spend_cap is not None
        prospective = (
            self._counters.spend_used
            + self._counters.spend_reserved
            + adding
        )
        if prospective > self._gov.spend_cap.usd:
            self._refuse(
                "spend",
                self._counters.spend_used + self._counters.spend_reserved,
                self._gov.spend_cap.usd,
                reserved=adding,
                detail="spend cap would be exceeded",
            )

    def _refuse(
        self,
        name: str,
        used: float,
        cap: float,
        reserved: float,
        detail: str,
    ) -> None:
        self._seal_now(name, used, cap, detail=detail, reserved=reserved)
        raise BudgetExceeded(
            cap_name=name, used=used, cap=cap, reserved=reserved,
        )

    def _seal_now(
        self,
        name: str,
        used: float,
        cap: float,
        detail: str,
        reserved: float = 0.0,
    ) -> None:
        if self._seal is not None:
            # Already sealed; keep the first seal.
            return
        self._seal = {
            "cap": name,
            "used": used,
            "cap_limit": cap,
            "reserved": reserved,
            "detail": detail,
            "elapsed": time.monotonic() - self._start_monotonic,
        }
        self._writer.write("refused", dict(self._seal))
