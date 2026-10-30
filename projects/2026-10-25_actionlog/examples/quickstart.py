"""A minimal actionlog example.

Writes two records to a chain, then verifies the chain.
"""

from __future__ import annotations

import os
import tempfile

import actionlog


def main() -> int:
    path = os.path.join(tempfile.mkdtemp(), "agent-actions.jsonl")

    log = actionlog.ActionLog(path=path)
    log.append("tool.call", {"name": "search", "args": {"q": "example"}})
    log.append("tool.result", {"ok": True, "n_hits": 3})
    log.close()

    v = actionlog.ActionLog(path=path).verify()
    print("ok:", v.ok)
    print("records:", v.n_records)
    return 0 if v.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
