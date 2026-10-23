# agent-guard-lab

Runtime guards for autonomous agents: wrappers, interceptors and governors that enforce at execution time what a config linter can only check beforehand.

> Part of [Epimystic](https://epimystic.com) - a codex of the knowable and the unknowable.
> One of a family of labs: [`epimystic-lab`](https://github.com/epimystic-dev/epimystic-lab) / [`governance-lab`](https://github.com/epimystic-dev/governance-lab) / [`defense-lab`](https://github.com/epimystic-dev/defense-lab) / [`repro-lab`](https://github.com/epimystic-dev/repro-lab) / [`agent-guard-lab`](https://github.com/epimystic-dev/agent-guard-lab) / [`ai-ethics-lab`](https://github.com/epimystic-dev/ai-ethics-lab) / [`convergent-disciplines-lab`](https://github.com/epimystic-dev/convergent-disciplines-lab).

## What this is

A governed human-machine process scans the frontier each week and, *when something is
genuinely worth building*, produces one small, self-contained, tested artifact here. When
nothing clears the bar, it ships nothing but the radar entry - restraint is the quality gate.

- **`projects/`** - dated, self-contained micro-projects, each independently licensed,
  tested and documented.
- **`research-radar/`** - a dated digest of frontier signal: a few items each week with a
  one-line "why this matters", cited to source, and a note on what was built and why.

## What belongs here

Runtime guards for autonomous agents: wrappers, interceptors and governors that sit between
an agent and something it wants to do - the filesystem, a subprocess, the network, a tool,
its own budget - and make the permitted thing happen and the forbidden thing fail closed,
with a record. Filesystem write-verification, tool-call allowlists, budget governors, action
audit hooks, quarantine wrappers for ingested content, sandboxed runners, egress and
redaction shims, kill switches. Vendor-neutral by construction: guards wrap generic
interfaces, and no required name or key refers to any AI vendor or product. A guard enforces
one boundary and names what it does not prevent; none claims to make an agent safe.

## The tools currently published

Each folder has its own README, tests and LICENSE; click through for install and usage.

| Tool | What it does | Layer |
|---|---|---|
| [`budgetgov`](projects/2026-10-18_budgetgov/) | Runtime budget governor: token / time / call / spend caps with a fail-closed hard stop and a tamper-visible record of what tripped | library |
| [`quarantine`](projects/2026-10-18_quarantine/) | Provenance-wrap and heuristically neutralise untrusted ingested text (web pages, email, retrieval) before it reaches an LLM or agent prompt | library |

*The radar publishes every Monday.*

## How it is made (and what that means)

Every artifact here is produced by **a human-machine hybrid intelligence, rooted in ethics
and philosophy**, and passes - *before* it is published - an external, deterministic policy
gate and an independent maker-checker review: a de-brand / secret gate, a clean-room rule (a
paper's method is read, never the authors' code), tests green under the public CI command,
and a claims-substantiation pass. The gate runs *outside* the builder. A passing gate means
**origin-valid, content-unverified**, never **verified-safe**. The engineering contract every
project meets is in [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md).

## Honest scope

This is a research-and-utility lab, not a product. Artifacts are small by design;
reimplementations of published work are independent implementations, cited and **not
affiliated with or endorsed by the original authors**. Read each project's own README and
LICENSE.

## License

Each `projects/` artifact carries its own LICENSE (permissive; this lab's default is
Apache-2.0). The radar and this index are MIT.

---

*Produced by Epimystic, a human-machine hybrid intelligence, under maker-checker.*
