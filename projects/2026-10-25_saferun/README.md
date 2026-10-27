# saferun

An argv-allowlisted, shell-free, confined subprocess runner for autonomous agents.

> Part of [agent-guard-lab](https://github.com/epimystic-dev/agent-guard-lab).
> One of the Epimystic labs: epimystic-lab / governance-lab / defense-lab / repro-lab / agent-guard-lab / ai-ethics-lab / convergent-disciplines-lab.

## Why

GuardFall (Adversa, 2026-06-30; re-affirmed in the Cloud Security Alliance research note of 2026-10) showed that **ten of eleven popular open-source AI coding agents' command-safety filters are structurally bypassable**: the agent inspects raw command *text*, but the shell performs quote removal, variable expansion and word splitting *after* inspection, so a string that looks safe at check time becomes a destructive argv at exec time. The 2026-10 arXiv survey of agent execution-security research (`2607.05743`) names shell injection among the top execution-security failure classes alongside time-of-check-to-time-of-use.

The fix is well known but mis-applied again and again:

- never pass a string to a shell;
- use `shell=False` with an argv list;
- allowlist on the first token;
- confine the working directory;
- cap output;
- cap time;
- do not inherit the parent process environment by default.

`saferun` is the smallest vendor-neutral standard-library primitive that packages those invariants together, exposes a `verify()` mode so a caller can shape-check an argv before running it, and names explicitly what it does not prevent.

## Install

```
python -m pip install -e .
```

No runtime dependencies. Python 3.9 or later.

## Quick example

```python
import saferun

runner = saferun.SafeRunner(
    allowed_commands=["python"],   # basename allowlist
    workdir="./my_workdir",        # must exist
    timeout_sec=5.0,
    max_output_bytes=65_536,
)

# Dry shape-check without executing.
scan = runner.verify(["python", "-c", "print('ok')"])
assert scan.verdict == saferun.Verdict.HEALTHY

# Actually run (shell=False always; argv must be a list).
result = runner.run(["python", "-c", "print('ok')"])
assert result.rc == 0
assert b"ok" in result.stdout
```

A refusal fails closed and carries the full `ScanResult`:

```python
try:
    runner.run("python -c 'print(1)'")   # string argv => SR-001
except saferun.RunRefused as e:
    for f in e.scan.findings:
        print(f.rule_id, f.severity.value, f.message)
```

## CLI

```
python -m saferun --help
python -m saferun --version
python -m saferun verify --allowed python --workdir . -- python -c "print(1)"
python -m saferun run    --allowed python --workdir . -- python -c "print(1)"
```

Exit codes:

- `0` -- clean (verify: healthy; run: subprocess returned 0)
- subprocess's own rc on `run`, if the subprocess exited and output / time limits were not tripped
- `1` -- `verify` found MEDIUM-only findings
- `2` -- `verify` found a HIGH finding, or `run` was refused, or timed out, or hit an unknown flag

## Rules (the shape-check registry)

Every rule's id is stable and documented. A rule fires either on `verify()` or inside `run()` before the subprocess is spawned.

| id | severity | summary |
|---|---|---|
| `SR-001` | HIGH | argv must be a list / tuple of strings, not a string (a string implies shell=True semantics; forbidden) |
| `SR-002` | HIGH | argv[0] (resolved to its basename) is not in the configured allowed_commands allowlist |
| `SR-003` | HIGH | argv[0] contains a path traversal segment ('..') or a null byte |
| `SR-004` | MEDIUM | an argv element contains a shell metacharacter; harmless under saferun but a signal upstream argv construction may be building from untrusted text |
| `SR-005` | HIGH | workdir is missing or is not an existing directory |
| `SR-006` | INFO | env is set to inherit the parent process environment; default is a minimal env for fail-closed hygiene |
| `SR-007` | HIGH | timeout_sec must be a positive finite number |
| `SR-008` | HIGH | max_output_bytes must be a positive integer |
| `SR-009` | MEDIUM | argv contains a null byte somewhere other than argv[0] (POSIX exec rejects it; signalled early) |
| `SR-010` | MEDIUM | argv[0] is an absolute path and allowed_commands contains only basenames; the resolution rule treated the basename as the match key |

## What saferun does NOT prevent

A guard that over-claims is worse than no guard, so these are explicit:

- A **permitted command doing permitted things that happen to be destructive**. `python` is in the allowlist and `python -c "import shutil; shutil.rmtree('.')"` runs the whole command cleanly. The allowlist is argv[0]-shaped; semantic review of what the argv actually DOES is the caller's job.
- **Filesystem isolation beyond cwd**. Setting `workdir=./safe` sets the subprocess's current directory; the subprocess can still read `/etc/passwd` or write `/tmp/x`. Use OS-level sandboxing (chroot, namespaces, containers) for real filesystem isolation.
- **Network isolation**. The subprocess can still make outbound connections. Compose with an egress allowlist (see the lab's `egressgate` candidate).
- **Memory / CPU caps**. Enforce those at the OS layer (ulimit, cgroups).
- **Signature verification** on the binary at argv[0]. `allowed_commands=["python"]` matches any binary named `python` on PATH; if a caller cares about which binary, pin the absolute path and the allowlist entry is that absolute path.
- **TOCTOU against the binary**. Between the allowlist check and the exec, a race may swap the binary at argv[0]. saferun does not pin the inode. Pair with a filesystem-integrity check for high-trust runs.

A clean saferun run means **the shape was within policy, the subprocess ran within caps, and the output is complete up to the truncation flag** -- never **the action was safe**.

## False-positive modes

- `SR-004` (shell metacharacter) fires on any argv element containing one of the control / substitution operators `| & ; < > $ \` \n \r`. The set is narrow by design: parentheses, quotes, asterisks, question marks, brackets, braces, hash, tilde and exclamation are omitted because they appear routinely in benign non-shell argv elements (python expressions, SQL, globs the program itself expands). Under `shell=False` the flagged characters are also passed verbatim to the program, so a `python -c "print('a|b')"` triggers the finding even though it is semantically fine. `SR-004` is MEDIUM, and `verdict == needs-attention` is a signal to review the upstream argv builder, not an outright block.
- `SR-010` (absolute path matched by basename) is a MEDIUM when a caller sets an absolute `argv[0]` against a basename-only allowlist. The run proceeds; the finding is there so a caller who wants strict absolute-path matching sees the mismatch.

## Honesty floor

- No "verified safe" claim. A clean `verify()` is **origin-valid** (shape within policy) only.
- No benchmark. The runner's job is to refuse the bad shape and run the good one; its latency over `subprocess.run` is a few hundred microseconds of shape-check overhead and will not matter.
- No cross-platform guarantee for `/bin/sh`-shaped commands. saferun does not launch shells; a caller who passes `["bash", "-c", "..."]` with `bash` in the allowlist has opted back into shell interpretation and the GuardFall class returns.

## How it is made

Produced by **a human-machine hybrid intelligence**, under a maker-checker protocol, from the Adversa and Cloud Security Alliance public write-ups (2026-06-30, 2026-07, 2026-10) and the public abstract of arXiv 2607.05743. No reference code from any affected agent or from any disclosed mitigation was read, vendored, or mirrored. Independent implementation, **not affiliated with or endorsed by any of the cited sources**.

## License

Apache-2.0.
