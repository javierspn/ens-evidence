#!/usr/bin/env python3
"""Reduce `ast-grep scan --json` to the warning lines a hook should report.

Its own file rather than an inline `python3 -c`: the f-strings need double
quotes, the shell wrapper needs single quotes, and nesting the two silently
produced a script that parsed but matched nothing — the hook looked like it was
passing when it was doing nothing at all.

`info` severity is dropped. Those rules (the seam audit) are advisory and belong
in a deliberate review, not an interruption mid-edit.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        hits = json.load(sys.stdin)
    except Exception:
        return 0  # unparseable output must never block an edit

    lines = []
    for hit in hits:
        if hit.get("severity") != "warning":
            continue
        line_no = hit.get("range", {}).get("start", {}).get("line", 0) + 1
        rule = hit.get("ruleId", "?")
        message = " ".join((hit.get("message") or "").split())
        lines.append(f"  {hit.get('file')}:{line_no} [{rule}] {message}")

    if lines:
        print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
