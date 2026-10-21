"""Example: wrap an agent loop with budgetgov.

Fake 'model' and 'tool' calls stand in for the real ones a caller
would make. The point is to show the shape - before_call before each
outgoing call, after_call to reconcile actuals, and a BudgetExceeded
that stops the loop.
"""

from __future__ import annotations

import random
import sys

from budgetgov import (
    BudgetExceeded,
    CallCap,
    Governor,
    SpendCap,
    TimeCap,
    TokenCap,
)


def fake_model_call(prompt_tokens: int):
    out_tokens = random.randint(100, 400)
    return out_tokens, 0.001 * (prompt_tokens + out_tokens)


def main() -> int:
    gov = Governor(
        token_cap=TokenCap(10_000),
        call_cap=CallCap(20),
        spend_cap=SpendCap(0.50),
        time_cap=TimeCap(60.0),
        record_path="budget.jsonl",
    )
    with gov.session(label="demo") as s:
        for i in range(100):
            prompt_tokens = random.randint(200, 600)
            try:
                s.before_call(
                    estimated_tokens=prompt_tokens + 500,
                    estimated_cost_usd=0.001 * (prompt_tokens + 500),
                )
            except BudgetExceeded as e:
                print("stopped at call", i, "by", e.cap_name, "cap")
                return 0
            out_tokens, cost = fake_model_call(prompt_tokens)
            s.after_call(
                actual_tokens=prompt_tokens + out_tokens,
                actual_cost_usd=cost,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
