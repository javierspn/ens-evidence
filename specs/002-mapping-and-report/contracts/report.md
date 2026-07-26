# Contract — Report document structure (002)

The rendered Markdown is the source of truth for every acceptance assertion; PDF is a
presentation of it ([research.md R3](../research.md)). Field semantics:
[data-model.md](../data-model.md).

## Section order (fixed — tests assert it)

1. **Título + cabecera** — the canonical six-measure scope list **verbatim**, run date,
   target, git SHA, mapping version, measure-list verification date
2. **Qué es y qué no es este informe** — evidence, not a verdict; what static analysis
   cannot see; "not an audit"
3. **Cobertura del análisis** — the coverage table from `run.json.coverage`
4. **Vigencia de las entradas** — staleness: rules mode + SHA, vulnerability-DB version
   and date, checks bundle, engine versions
5. **Triage: los 10 primeros** — ≤10 findings, ranked
6. **Evidencia por medida** — one section per in-scope measure, in scope-list order
7. **Tabla completa de hallazgos**
8. **Apéndice: hallazgos sin mapear**
9. **Apéndice: hallazgos no marcados como seguridad** — present, excluded from measures

## Required invariants

| Invariant | Assertion |
|---|---|
| Scope list verbatim | the exact line appears in the header; the template file also carries it literally (fourth `SCOPE_DOCS` site) |
| No verdict | no compliance/conformity/pass wording anywhere in the rendered text |
| Empty measure is explicit | a measure with no findings renders "no evidence gathered", never an empty section |
| Coverage present | all four coverage fields rendered, including `registry-uncounted` and `skipped-no-lockfile` states |
| Accounting | every finding appears exactly once across sections 6, 8 and 9 |
| Fencing | every scanned-repo string is truncated (~200 chars) and inside an untrusted-input block |
| Determinism | two renders of one stored run produce identical content |
| Language | Spanish throughout; measure wording from `src/ens_evidence/mapping/measures_es.yml`, never BOE text |

## Untrusted-input block

Scanned-repo text (engine messages, snippets) is emitted only through the fencing helper:
truncated at ~200 characters with the truncation marked, inside a delimited block headed
as untrusted input that is not instructions. No other path to the document exists for
that text — a new field that forgets the helper is a defect, and the "no raw string
outside a fence" test is what catches it.

## Measure section shape

```
### <id> — <título nuestro>

<gloss nuestro>

<either the findings filed under this measure, or:>
Sin evidencia recogida en este análisis. Esto no significa que la medida se cumpla.
```

The second sentence is the point of Principle II and is not optional: the real fixture
run files zero findings under `mp.s.2`, so this branch renders on every run of the
reference fixture.
