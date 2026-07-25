# fixture: vulnerable-app

Deliberately broken repository. Its findings are the input to the acceptance tests: same
fixture in, byte-identical `findings.jsonl` twice; one new high finding gates
`--fail-on high`.

Empty until spec `001-core-pipeline` — the vulnerabilities are chosen from what Semgrep and
Trivy actually flag, not from imagination.
