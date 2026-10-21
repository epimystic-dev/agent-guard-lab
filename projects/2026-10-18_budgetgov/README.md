# budgetgov

A runtime budget governor for autonomous agents. Four caps - **tokens**, **time**, **call-count**, **spend** - evaluated as a hard, fail-closed stop with a tamper-visible record of what tripped. Zero dependencies, standard library only, Python 3.9+.

> Part of [agent-guard-lab](https://github.com/epimystic-dev/agent-guard-lab).
> One of the Epimystic labs: epimystic-lab / governance-lab / defense-lab / repro-lab / agent-guard-lab.

## The problem it addresses

OWASP's 2026 LLM Top 10 elevated **Unbounded Consumption** from LLM10 to **LLM06** - up four places - and the agent-era face of the risk is explicit in the release notes: runaway reasoning loops, unbounded tool calling, and Denial-of-Wallet. Dark Reading's 2026 piece *How AI Agents Can Trigger Runaway Costs for Enterprises* and OWASP's own agent-tool-fan-out simulation describe the same shape: an agent loop that keeps calling until something external stops it.

OWASP's recommended mitigations are "token-aware rate limits, hard spending caps, and agent circuit breakers." `budgetgov` is the smallest honest implementation of those three primitives as a reusable library.

## Install

```
pip install -e .
```

No runtime dependencies.

## Quick use

```python
from budgetgov import (
    Governor, TokenCap, TimeCap, CallCap, SpendCap, BudgetExceeded,
)

gov = Governor(
    token_cap=TokenCap(100_000),
    time_cap=TimeCap(300.0),       # seconds, monotonic
    call_cap=CallCap(50),
    spend_cap=SpendCap(5.00),      # dollars
    record_path="budget.jsonl",    # append-only JSONL
)

with gov.session(label="my-run") as s:
    for user_msg in queue:
        try:
            s.before_call(estimated_tokens=1200, estimated_cost_usd=0.012)
        except BudgetExceeded as e:
            # One-way seal: subsequent before_call also raises.
            print("stopped by", e.cap_name, "cap:", e)
            break
        tokens, cost = call_the_model(user_msg)
        s.after_call(actual_tokens=tokens, actual_cost_usd=cost)
```

## How the caps compose

- **Fail closed.** If a `TokenCap` is configured and `before_call` is called without `estimated_tokens`, the call is refused and the session is sealed - the governor does not invent an estimate. Same rule for `SpendCap` / `estimated_cost_usd`.
- **Reservation before action.** `before_call` reserves against each cap *before* the call runs. If the reservation would exceed a cap, the call is refused.
- **Reconcile after.** `after_call` replaces the reservation with the actual. If the actual overshot a cap, the session is sealed - the overshot call completed, but the next reservation is refused.
- **One-way seal.** Once sealed, `before_call` raises `SessionLocked`. There is no reset. The rule is from the lab's charter: a stop cannot be argued past.
- **Cap-order on simultaneous overrun:** time, call, token, spend. Time is checked first because it is the only cap that can trip without any caller input.

## The record

If `record_path` is set, every session writes an append-only JSONL file. Four kinds of entries: `opened`, `reservation`, `refused`, `closed`. A caller can inspect it after the fact:

```
python -m budgetgov verify budget.jsonl
python -m budgetgov tail budget.jsonl
```

`verify` returns rc 0 on healthy, rc 1 on needs-attention (e.g. opened-but-never-closed), rc 2 on unhealthy (unreadable, seq gaps). The record is not cryptographically chained - compose it with a hash-chained ledger (e.g. from `governance-lab`) if that is what you need.

## Rule registry (the `verify` surface)

| Rule | Severity | What it fires on |
|---|---|---|
| BGR-001 | HIGH | record is unreadable or malformed |
| BGR-002 | MEDIUM | record is empty |
| BGR-003 | HIGH | seq numbers are not a monotonic 1..N sequence |
| BGR-004 | MEDIUM | unknown record kind |
| BGR-005 | MEDIUM | no opened entry in record |
| BGR-006 | MEDIUM | a session was opened but never closed |

## Honest scope

**What `budgetgov` does.** Enforces the four caps the caller declares. Refuses calls fail-closed on missing estimates against configured caps. Seals the session on any trip. Writes an append-only record.

**What it does not do.** It is not a pricing oracle - it does not know what the next call costs; the caller declares the estimate and the actual. It is not a token counter - the caller declares token counts. It is not a scheduler, a retry policy, or a cost allocator. It makes no cryptographic claim about the record. It is not a defense against a caller who declares false estimates to defeat its own cap. Compose it with a tokenizer, a pricing table, and a hash-chained audit (e.g. a `governance-lab` ledger) for a full control.

**False-positive modes.** The record's `BGR-006` ("opened but never closed") fires if a session was killed mid-run; this is informational and may be expected during crash analysis.

**Clean run means.** A `verify` that returns `healthy` is origin-valid for the record file - it was written by one `budgetgov` session that opened, ran, and closed, with monotonic seq numbers and known kinds. It is not a statement about whether the caller's declared estimates were honest.

## How it is made

Produced by **a human-machine hybrid intelligence**, under a maker-checker protocol, from the public OWASP LLM06 2026 guidance and the public Dark Reading 2026 reporting. No reference implementation of any named gateway product was read, vendored, or mirrored. Independent implementation, **not affiliated with or endorsed by OWASP, Dark Reading, or any gateway vendor**.

## License

Apache-2.0.
