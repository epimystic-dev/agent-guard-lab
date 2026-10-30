# actionlog

An append-only, SHA-256 hash-chained action audit log for autonomous agents.

> Part of [agent-guard-lab](https://github.com/epimystic-dev/agent-guard-lab).
> One of the Epimystic labs: epimystic-lab / governance-lab / defense-lab / repro-lab / agent-guard-lab / ai-ethics-lab / convergent-disciplines-lab.

## Why

Three convergent 2026 arXiv papers --
[`2609.01931`](https://arxiv.org/abs/2609.01931) "Agent Flight Recorder" (Sept 2026),
[`2609.35659`](https://arxiv.org/abs/2609.35659) "Tracekit" (Sept 2026),
[`2609.04017`](https://arxiv.org/pdf/2609.04017) "A Black Box for Agentic Processes" --
plus the Hugging Face July 2026 breach post-mortem (roughly 17,600 attacker actions reconstructed from logs) all propose or require the same primitive: an append-only hash-chained ledger of every agent action, verifiable after the fact. OWASP's 2026 LLM Top 10 names "immutable logging" as a defense-in-depth control for both LLM01 (indirect injection) and the agent-era risks.

Without a tamper-evident chain, those logs are only as trustworthy as the host that wrote them. `actionlog` is the smallest vendor-neutral, standard-library primitive that implements the shape:

- **SHA-256 hash chain**. Each record carries `prev_hash` = previous record's `self_hash`; the first record uses a 64-zero genesis.
- **Canonical JSON serialisation**. `sort_keys=True, separators=(',',':'), ensure_ascii=True`, so a byte-wise re-hash is stable across platforms.
- **`.head` sidecar**. The last `(seq, self_hash)` is written atomically next to the chain file; a reader detects a truncated chain by comparing the sidecar to the actual tail.
- **A `verify()`** that walks the chain and names the first break with a `TamperKind` (one of nine) plus a rule id.
- **Zero dependencies**. Python 3.9 or later, standard library only.

## Install

```
python -m pip install -e .
```

## Quick example

```python
import actionlog

log = actionlog.ActionLog(path="agent-actions.jsonl")
log.append("tool.call", {"name": "search", "args": {"q": "example"}})
log.append("tool.result", {"ok": True, "n_hits": 3})
log.close()

v = actionlog.ActionLog(path="agent-actions.jsonl").verify()
assert v.ok, v.break_detail
```

A tampered chain fails fast and names what broke:

```python
# After an attacker edits one record's payload...
v = actionlog.ActionLog(path="agent-actions.jsonl").verify()
if not v.ok:
    print("tamper at seq", v.break_seq, ":", v.break_kind.value)
    # tamper at seq 1 : hash-mismatch
```

## CLI

```
python -m actionlog --help
python -m actionlog --version
python -m actionlog verify   <path>
python -m actionlog show     <path>
python -m actionlog append   <path> --action tool.call --payload '{"k":"v"}'
```

Exit codes:

- `0` -- `verify`: clean. `show`: always 0 if the file is readable.
- `1` -- `verify`: MEDIUM-only findings (currently only `AL-005` trailing-garbage and `AL-006` genesis-prev-nonzero and `AL-007` empty-line can rollup to this).
- `2` -- `verify`: HIGH finding, unreadable input, or unknown flag.

## Rules (the verify-side registry)

Every rule id maps 1:1 to a `TamperKind`. A caller holding either knows which the other is.

| id | severity | kind | summary |
|---|---|---|---|
| `AL-001` | HIGH | `hash-mismatch` | a record's stored `self_hash` does not match the SHA-256 of its canonical form -- the record was edited after it was written |
| `AL-002` | HIGH | `prev-link-broken` | a record's `prev_hash` does not match the previous record's `self_hash` -- a record was inserted, deleted or reordered |
| `AL-003` | HIGH | `seq-skip` | seq numbers are not consecutive `0..N-1` -- a record was deleted or forged |
| `AL-004` | HIGH | `head-mismatch` | the `.head` sidecar disagrees with the chain tail -- the chain was truncated or the sidecar was tampered |
| `AL-005` | MEDIUM | `trailing-garbage` | bytes after the last newline that do not parse as JSON -- a crash during append may have left a half-record, or the file was appended to by a non-actionlog writer |
| `AL-006` | MEDIUM | `genesis-prev-nonzero` | the first record's `prev_hash` is not the 64-zero genesis -- the chain was pre-pended or the writer was buggy |
| `AL-007` | MEDIUM | `empty-line` | an empty line was found in the log -- a crash during append may have left it, or the file was mutated externally |
| `AL-008` | HIGH | `malformed-json` | a line failed to parse as JSON -- the file was mutated externally or the writer failed mid-line |
| `AL-009` | HIGH | `missing-field` | a parsed record is missing one of the required fields (`seq`, `ts`, `action`, `payload`, `prev_hash`, `self_hash`) -- the record was tampered with or truncated |

## What actionlog does NOT prevent

A guard that over-claims is worse than no guard, so these are explicit:

- **Tampering** -- it only makes tampering **visible**. A diligent reader who runs `verify()` after every read catches edits, inserts, deletes and reorders; a reader who does not, does not.
- **An attacker who holds the current `head`** from **forking the chain**. A fork past the point of compromise re-hashes cleanly from a new genesis if the attacker regenerates every record; `actionlog` does not sign or anchor the chain.
- **Wholesale deletion** of the entire log file. If the file is gone, `verify()` sees an empty chain.
- **Refusal to append**. A compromised writer that silently refuses to log actions produces a chain that is internally consistent but incomplete; detect this with a separate liveness signal.
- **Replay against a replica**. Two replicas may each verify cleanly yet diverge; replication / consensus is a separate layer.
- **Semantic validation** of what is in a record. `actionlog` records whatever the caller passes to `payload`; it does not interpret it.

A clean `verify()` means **this chain is self-consistent and matches its sidecar** -- never **these actions were authorised** or **nothing was deleted before writing**.

## Composition

- With `budgetgov`: use `actionlog` as the record substrate; call `log.append("budget.refused", {...})` from the caller when the governor seals, so the audit chain is tamper-evident. `budgetgov`'s own `budget.jsonl` writer is NOT tamper-evident; it is a simple JSONL for inspection.
- With `saferun`: call `log.append("subprocess.run", {...})` before and after each `runner.run(argv)`.
- With `quarantine`: call `log.append("ingest.wrapped", {...})` with the hits list after each `wrap()`.

## How it is made

Produced by **a human-machine hybrid intelligence**, under a maker-checker protocol, from the convergence of arXiv papers 2609.01931 (Agent Flight Recorder), 2609.35659 (Tracekit), 2609.04017 (A Black Box for Agentic Processes) and 2607.05518 (aiAuthZ) as read from their public abstracts. No reference code from any of those projects was read, vendored, or mirrored. SHA-256 and the Python stdlib `hashlib` / `json` interfaces are canonical. The tamper taxonomy (edit / insert / delete / reorder / fork / head-mismatch) is read from the Agent Flight Recorder abstract and generalised; the specific rule-id numbering (`AL-001..AL-009`) is this project's own. Independent implementation, **not affiliated with or endorsed by any of the cited authors**.

## License

Apache-2.0.
