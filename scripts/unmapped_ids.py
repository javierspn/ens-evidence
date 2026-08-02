#!/usr/bin/env python3
"""List the rule ids in one or more stored runs that the mapping does not file anywhere.

Exists because constitution 1.4.0 requires a rules-SHA bump to go through the fixture loop:
new unmapped ids must be mapped before the bump merges, or mapping coverage decays quietly
with every upstream release. The unmapped signal is already in the data — the mapper files
such findings as `measures == ["unmapped"]` — so this is a filter, not new analysis.

It lives here rather than inline in a workflow so it can be unit-tested and run locally
before pushing. An inline `python -c` gate is how the previous scan.yml stub survived
unverified.

Usage:
    python scripts/unmapped_ids.py <findings.jsonl> [<findings.jsonl> ...]

Exit 0 when every rule id is mapped, 1 when any is not (with the ids on stdout, sorted and
de-duplicated), 2 on a usage or read error.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ens_evidence import MAPPING_DIR, mapper  # noqa: E402


def unmapped_ids(paths, rules):
    """Security findings whose rule id the mapping files nowhere.

    Non-security findings are skipped: the mapper never counts them toward a measure
    (`counts_toward_measures`), so an unmapped one is not lost coverage — it is a
    best-practice hint. Counting them would make the gate fail on noise and teach
    maintainers to bypass it.
    """
    ids = set()
    for path in paths:
        for line in Path(path).read_text("utf-8").splitlines():
            record = json.loads(line)
            if "rule" not in record:  # the schema marker line
                continue
            if not record.get("security"):
                continue
            measures, _, _ = mapper.classify(record["tool"], record["rule"], rules)
            if measures == ["unmapped"]:
                ids.add(f"{record['tool']}:{record['rule']}")
    return sorted(ids)


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        rules = mapper.load_rules(MAPPING_DIR / "ens_rd311.yml")
        ids = unmapped_ids(argv, rules)
    except (OSError, ValueError, KeyError) as exc:
        print(f"unmapped_ids: {exc}", file=sys.stderr)
        return 2

    if not ids:
        print(f"all rule ids in {len(argv)} run(s) are mapped", file=sys.stderr)
        return 0

    # Named, not counted: the maintainer's next action is editing the mapping, and for that
    # they need the ids themselves.
    print("\n".join(ids))
    print(
        f"unmapped_ids: {len(ids)} rule id(s) have no mapping entry — add them to "
        "src/ens_evidence/mapping/ens_rd311.yml before bumping the rules SHA",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
