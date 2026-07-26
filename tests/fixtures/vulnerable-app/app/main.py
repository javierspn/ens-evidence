"""Deliberately vulnerable: exec of request data (semgrep
python.lang.security.audit.exec-detected, HIGH-ish) and dynamic urllib URL
(python.lang.security.audit.dynamic-urllib-use-detected, LOW CONFIDENCE —
exercises the severity confidence downgrade)."""

import urllib.request


def run_user_code(payload: str):
    exec(payload)  # noqa: S102


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url) as resp:  # noqa: S310
        return resp.read()
