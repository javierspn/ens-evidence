"""Canary for the ast-grep gate — DELIBERATELY defective. Do not fix it.

scripts/gates.sh scans every file in .ast-grep/canary/ and REQUIRES a finding from each.
ast-grep exits 0 on an unreadable rule dir, so without this file "no findings" and "scanner
dead" look the same and the gate passes forever.
"""
import logging

logger = logging.getLogger(__name__)


def swallowed(payload):
    try:
        return int(payload["value"])
    except Exception:
        logger.warning("could not parse")    # exception-discarded must fire here
        return None
