# Contract — `ens-evidence rules fetch|status`

The bootstrap group Principle VI names. It exists because the Semgrep Rules License v1.0
forbids redistribution: the operator obtains their own copy, pinned to a commit SHA, with an
explicit acknowledgement.

## `rules fetch`

```
ens-evidence rules fetch --sha <commit> [--repo URL] [--rules-root DIR] --accept-rules-license
```

| Argument | Default | Meaning |
|---|---|---|
| `--sha` | *required* | upstream commit SHA to pin to |
| `--repo` | `https://github.com/semgrep/semgrep-rules` | upstream rules repository |
| `--rules-root` | `.ens-rules` | destination directory |
| `--accept-rules-license` | off | acknowledges the licence terms; also `ENS_EVIDENCE_ACCEPT_RULES_LICENSE=1` |

Behaviour: `git init` → `git remote add origin <repo>` → `git fetch --depth 1 origin <sha>` →
`git checkout FETCH_HEAD`, each a subprocess. On success prints the same payload as `status`.
Re-running against an existing root at a different SHA re-fetches and re-checks-out; the tool
never modifies, re-namespaces or copies rule files.

### Exit codes

| Code | When |
|---|---|
| 0 | rules root present and checked out at `--sha` |
| 2 | acknowledgement absent (prints our summary of the terms and the upstream licence URL, fetches nothing); `git` not on PATH; SHA not found upstream; destination exists and is not a git work tree |

Exit 2 without the acknowledgement is a hard gate: no config-file key can grant it, because a
key gets copied between repositories unread.

## `rules status`

```
ens-evidence rules status [PATH] [--rules-root DIR]
```

Prints one machine line describing the rules the next scan would use — the existing
`rules_info()` payload:

```json
{"schema": "ens-evidence/1", "mode": "local", "repo": "...", "sha": "...", "root": "...", "per_language": {"python": 412}}
```

With no rules root configured, `mode` is `registry`, `sha` is `null`, `per_language` is `null`,
and the output says the configuration is not reproducible. Exit 0 in both modes: "registry mode"
is a state to report, not an error. Exit 2 only on an unreadable configuration.

## Licence invariants binding both verbs

- Rule files never enter a published artifact, release asset, container image, cache payload or
  committed file.
- The rules root stays in `.gitignore` and in `run.py:SKIP_DIRS`.
- `run.json` records mode, repo URL, SHA and per-language counts for every run.
