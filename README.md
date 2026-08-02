# ens-evidence

Herramienta CLI. Se apunta a un repositorio, ejecuta escáneres de seguridad open source,
archiva cada hallazgo bajo una medida del ENS (RD 311/2022) y genera un informe de
evidencias en español.

> **El informe es evidencia para un auditor, nunca un veredicto.** No dice que cumples.

## Alcance — medidas cubiertas

Se generan evidencias para exactamente estas seis medidas:

> `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4`

El ENS tiene ~75 medidas: esto cubre seis. Los seis códigos se verificaron contra el texto
consolidado del BOE (Anexo II, RD 311/2022) el 2026-07-25.

## Lo que no puede ver

El análisis estático no es una auditoría. Queda fuera: lógica de negocio, diseño de
autenticación y autorización, configuración en tiempo de ejecución. El informe incluye
este descargo — es lo que lo hace utilizable como evidencia.

## Tu código no sale de tu infraestructura

Todo se ejecuta dentro de tu CI. Ni el código ni el detalle de los hallazgos salen de tu
infraestructura; las salidas quedan en tu almacén de artefactos. No hay servidor, no hay
subida de datos, no hay cuenta.

## Uso

```
ens-evidence scan [PATH]        # escaneo → normalización → baseline → run almacenado
ens-evidence baseline update    # acepta los hallazgos del último run
ens-evidence report [PATH]      # renderiza el informe desde un run, sin re-escanear
ens-evidence bundle [PATH]      # bundle.md: resumen pegable desde un run almacenado
ens-evidence explain <id>       # un hallazgo: qué regla lo detectó y a qué medidas mapea
```

`bundle.md` es un único documento Markdown pensado para pegarse en un chat: fecha,
repositorio, alcance, cobertura completa, hallazgos más graves con sus medidas, recuentos y
descargo. El texto procedente del repositorio analizado viaja como dato — en bloques
delimitados, o entre comillas invertidas y desactivado cuando debe ir en una celda.

Arranque de reglas (una vez por entorno). Sin `--rules-root`, `scan` usa el registro de
Semgrep (`p/default`): funciona sin configuración, pero no es reproducible y es escaso en
algunos lenguajes. Modo fijado, el apto para CI:

```
ens-evidence rules fetch --sha <commit> --accept-rules-license
ens-evidence rules status
ens-evidence scan . --rules-root .ens-rules   # o ENS_EVIDENCE_RULES_ROOT / .ens-evidence.yml
```

Sin `--accept-rules-license` (o `ENS_EVIDENCE_ACCEPT_RULES_LICENSE=1`), `fetch` imprime los
términos y sale con código 2 sin descargar nada.

Las reglas de Semgrep las obtiene **tu** entorno, no las distribuye esta herramienta: su
licencia (Semgrep Rules License v1.0) prohíbe redistribuirlas y permite usarlas para fines
internos propios. No las incluimos en la imagen ni en el paquete, y `.ens-rules/` nunca se
publica. Tampoco en formas menos evidentes: el SARIF en bruto que guarda el almacén de runs
incorpora el catálogo **completo** de reglas, así que publica `findings.jsonl`, `run.json`,
`report.md`, `bundle.md` y `sbom.cdx.json`, nunca `*.sarif`.

Requiere los binarios de los motores (Semgrep, Trivy) en el PATH; se fijan sus versiones
en tu imagen de CI.

## Qué produce un run

Todo queda en `out/latest/`. **Todos** los hallazgos aparecen en dos sitios: `findings.jsonl`
y el anexo 7.1 del informe. Las demás secciones del informe son vistas parciales de esos
mismos hallazgos.

| Fichero | Qué es | Publicable |
|---|---|---|
| `findings.jsonl` | Todos los hallazgos, uno por línea. La fuente de verdad | sí |
| `report.md` / `report.pdf` | El informe para el auditor | sí |
| `bundle.md` | Resumen pegable en un chat | sí |
| `run.json` | Versiones de motores, SHA de reglas, fecha — la trazabilidad | sí |
| `sbom.cdx.json` | Inventario de dependencias (CycloneDX) | sí |
| `*.sarif` | Salida cruda de los motores | **no** — incorpora el catálogo de reglas |

## Cómo se lee el informe

El informe tiene dos lectores con recorridos distintos.

**Auditor — verificar el alcance y el rastro.**

1. **§1 Alcance** y **§3 Cobertura** — qué se analizó de verdad. Donde no se ejecutaron
   reglas, cero hallazgos significa *no se buscó*; la tabla lo dice lenguaje a lenguaje.
2. **§4 Vigencia** — antigüedad de la evidencia: versiones de motor, base de vulnerabilidades,
   SHA de reglas, fecha de verificación contra el BOE.
3. **§6 Evidencia por medida** — la vista que se cruza contra el Anexo II: cada medida con
   los hallazgos que la sostienen.
4. **Huella** (p. ej. `b6d047e5`) — identificador estable del hallazgo entre runs. Es lo que
   permite exigir "esto estaba en marzo y no en agosto: enséñame el cambio". Tras
   `baseline update`, la columna **Nuevo** marca las regresiones.

**Equipo — arreglar.**

1. **§5 Hallazgos** trae solo crítica y alta, agrupados: es la cola de trabajo por orden.
2. **Dónde** da `fichero:línea`; **Trazabilidad** da motor e id de regla (`DS-0002`,
   `KSV-0014`, un CVE). El *cómo se arregla* está en la documentación de esa regla — este
   informe no lo incluye.
3. Arreglar, volver a escanear, comprobar que la huella desaparece. El informe siguiente es
   la prueba del cierre.
4. No hay supresiones: un hallazgo que se decide aceptar seguirá saliendo en cada run. Su
   justificación vive fuera de este informe.

Dos avisos al leerlo:

- **Los anexos no cuentan como evidencia.** §7.2 son hallazgos sin medida asignada y §7.3
  los que el motor no marcó como seguridad. Están para que nada quede oculto, no para
  sostener una medida.
- **El informe no distingue código de producto de fixtures de prueba.** Un repositorio con
  ficheros deliberadamente vulnerables bajo `tests/` los verá contados como hallazgos altos.
  Míralo por ruta antes de priorizar.

## Documentación

- [DESIGN.md](DESIGN.md) — el porqué: arquitectura, contrato CLI, reglas del proyecto.
- [.specify/memory/constitution.md](.specify/memory/constitution.md) — reglas no negociables.
- [AGENTS.md](AGENTS.md) — para agentes que trabajen en este repositorio.
- [SKILL.md](SKILL.md) — para agentes que **usen** la herramienta.

## Licencia

Apache-2.0 — ver [LICENSE](LICENSE).

---

## English summary

CLI tool that runs open-source security scanners over a repository, files each finding
under one of six Spanish ENS measures (RD 311/2022) and renders a Spanish-language
evidence report. The report is **evidence for an auditor, never a verdict** — it does not
claim compliance.

Scope: `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4` — six of
roughly 75 ENS measures. Static analysis cannot see business logic, authn/authz design or
runtime configuration, and the report says so.

Rules are fetched by your environment, never shipped by us: the Semgrep Rules License v1.0
forbids redistribution while permitting the licensee's own internal use, so you clone
`semgrep-rules` at a pinned SHA into your own CI and pass `--rules-root` — nothing
rule-shaped ever enters our image, package or release assets.

Everything runs inside your CI: no server, no upload, no account. Engines (Semgrep, Trivy)
are subprocess calls to binaries you pin yourself. See [DESIGN.md](DESIGN.md) for the
architecture and the CLI contract.
