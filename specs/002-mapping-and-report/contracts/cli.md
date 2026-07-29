# Contract — CLI (002 slice)

Verbs added by 002. The 001 slice (`scan`, `baseline update`) is
[here](../../001-core-pipeline/contracts/cli.md); `bundle` is spec 003. Full contract:
[DESIGN.md](../../../DESIGN.md#cli-contract).

## Verbs

```
ens-evidence report [PATH] [--run <dir>] [--format {md,pdf,auto}] [--pdf-engine <name>] [--json]
ens-evidence explain <ID> [PATH] [--run <dir>] [--json]
```

- `PATH` defaults to cwd; `--run` defaults to `out/latest`.
- `report` re-renders from the stored run — **never** re-scans, and must work with the
  engines uninstalled (SC-008).
- `--format auto` (default): always writes `report.md`; writes `report.pdf` too when the
  converter binary is present.
- `explain <ID>` accepts the finding `id` as printed in the report and the JSONL.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | report rendered (Markdown always; PDF when available in `auto`), or explanation printed |
| 2 | tool error: no stored run at the given path, unreadable run artifacts, `--format pdf` requested with the converter binary missing (message names it), unknown finding id for `explain` |

`report` never returns 1 — the gate belongs to `scan`. Rendering findings is not a
verdict, so the presence of findings is never an error condition.

## Degradation rule (PDF)

| Situation | Behaviour |
|---|---|
| `--format pdf`, converter works | writes `report.pdf`, exit 0 |
| `--format pdf`, converter missing | exit 2, message names the binary |
| `--format pdf`, converter present but unable | exit 2, message carries the converter's own reason |
| `--format auto`, converter missing | writes `report.md`, discloses on stderr **and in the document**, exit 0 |
| `--format auto`, converter present but unable | same — degrades, exit 0 |

**"Present but unable" is a real third state, not a hypothetical**: `pandoc` needs a
separate PDF engine and only reports its absence when asked to convert. Found by running
quickstart §8, not by design. `--pdf-engine` (or `ENS_EVIDENCE_PDF_ENGINE`) names the
engine; it is never auto-detected, because the tool would then pick a different engine
per machine and silently change how the PDF looks.

An HTML-rendering engine (`weasyprint`, `prince`, `wkhtmltopdf`, `pagedjs-cli`) also gets
`--css=templates/report.css`; a LaTeX engine gets nothing, since `--css` means nothing to
it. The stylesheet governs presentation only — without it the finding tables overflow the
page and clip the `Id` column, which is what a reader cross-references against
`findings.jsonl`.

Never silent: an absent PDF is disclosed in the document itself, not only on a stream a
CI log may discard.

## Streams

Unchanged from 001: machine JSON on stdout carrying `{"schema":"ens-evidence/1"}`, human
chatter on stderr. Under `--json`, `explain` emits the explanation object and errors are
JSON too.

## Outputs

Written **inside** the run directory, never elsewhere: `report.md`, and `report.pdf` when
produced. `findings.jsonl` and `run.json` are read-only to this spec.
