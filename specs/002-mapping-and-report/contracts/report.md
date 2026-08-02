# Contract — Report document structure (002)

The rendered Markdown is the source of truth for every acceptance assertion; PDF is a
presentation of it ([research.md R3](../research.md)). Field semantics:
[data-model.md](../data-model.md).

## Section order (fixed — tests assert it)

Sections are numbered in the document. 1–4 are preamble (what was analysed and how far it
can be trusted), 5–6 are the content, 7 gathers the three data dumps as numbered annexes —
one of which used not to be called an appendix at all.

1. **Alcance** — the canonical six-measure scope list **verbatim**, run date, target, git
   SHA, mapping version, measure-list verification date, and the finding counts broken
   down rather than given as one ambiguous total
2. **Descripción** — evidence, not a verdict; what static analysis cannot see; "not an
   audit"; and the once-per-document statement that scanned-repo text is data, not
   instructions
3. **Cobertura** — the coverage table from `run.json.coverage`
4. **Vigencia** — staleness: rules mode + SHA, vulnerability-DB version and date, checks
   bundle, engine versions, and whether a baseline was used
5. **Hallazgos** — one numbered entry per finding, in our own Spanish wording
6. **Evidencia por medida** — one numbered subsection per in-scope measure that has
   evidence, in scope-list order, then one subsection gathering those that have none
7. **Anexos** — 7.1 full findings table · 7.2 unmapped · 7.3 not tagged security

## Section 5 — selection

The band is taken in **cascade**: `critical` and `high` together; if neither exists,
`medium`; if none, `low`. `info` never qualifies — it is the severity of what the engine
could not classify, and promoting it would present unknowns as what matters most. A fixed
`high` filter was wrong twice over: the canonical scale opens at `critical`, so the
corpus's worst finding (a leaked credential at 9.5) would have been the one omitted, and a
repository whose worst finding is a medium would have rendered an empty section that reads
as a pass.

Findings the engines did **not** tag as security are excluded and stay in 7.3: a
best-practice suggestion may not lead the report any more than it may count toward a
measure (FR-003).

Capped at `render.HIGHLIGHT_LIMIT`, and the report states what the cap dropped. The
cascade makes a large band reachable — 380 mediums and no highs — and truncating in
silence would read as "these are all of them".

## Section 5 — entry shape

```
### 5.<n> · <title from the matching mapping entry> — **[<SEVERITY IN SPANISH>]**[ · nuevo]

**Qué es.** <why, from the same mapping entry>

**Dónde.** `<path>`[, línea <n>][ · paquete `<p>`, versión instalada `<v>`, corregido en `<v>`]

**Medida ENS.** `<id>` — <our measure title>.

**Trazabilidad.** <engine> · huella `<id>` (regla completa en el anexo 7.1)
```

The rule id is deliberately **not** in the entry: 70 characters of `tool.namespace.rule-id`
was the one value that overflowed the page and it says nothing to an auditor. It stays in
the annex, joined by the huella — which is the `id` field, renamed in the document because
"identificador" reads as a case reference when it is a content fingerprint.

`title`/`why` come from `mapping/ens_rd311.yml` and are **per rule, not per finding**, so
they may never assert anything about the specific case — no "there is a fix available", no
"this is exploitable". Anything specific comes from data instead: the location, and the
package and versions Trivy reports. `fixed` is rendered only when the engine supplies it.

## Required invariants

| Invariant | Assertion |
|---|---|
| Scope list verbatim | the exact line appears in the header; the template file also carries it literally (fourth `SCOPE_DOCS` site) |
| No verdict | no compliance/conformity/pass wording anywhere in the rendered text |
| Empty measure is explicit | a measure with no findings is named under "sin evidencia recogida", never left silently absent |
| Section 5 is never silent | no qualifying finding renders an explicit "none found, and that is not a pass" |
| Every mapping rule carries prose | each entry in `ens_rd311.yml` has `title` and `why`, so a finding is headed by our wording rather than a rule id |
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
### 6.<n> · <id> — <título nuestro>

<gloss nuestro>

<the findings filed under this measure>
```

Measures with no findings are not given a section each — six near-identical empty ones
filled a page. They are listed together under a final subsection:

```
### 6.<n> · Medidas sin evidencia recogida

- **<id>** — <título nuestro>

Sin evidencia recogida en este análisis. Esto no significa que estas medidas se cumplan.
```

That last sentence is the point of Principle II and is not optional: the real fixture run
files zero findings under `mp.s.2`, so this branch renders on every run of the reference
fixture.

Subsection numbers are counted over the measures that actually render, not over the scope
list — numbering by scope position would emit 6.1, 6.3, 6.4 as soon as one measure is
empty.
