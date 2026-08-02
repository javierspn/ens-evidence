<a id="top"></a>
<div align="center">

# 🛡️ ens-evidence

### Evidencia de seguridad para el ENS, generada desde tu propio CI

*Se apunta a un repositorio, ejecuta escáneres open source y archiva cada hallazgo bajo una
medida del RD 311/2022. Produce el informe que un auditor puede cruzar contra el Anexo II —
y nunca dice que cumples.*

<br/>

[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](LICENSE) [![Python](https://img.shields.io/badge/python-3.12%2B-blue?style=for-the-badge)](pyproject.toml) [![Version](https://img.shields.io/badge/version-1.0.0-green?style=for-the-badge)](ROADMAP.md) [![Alcance](https://img.shields.io/badge/alcance-6%20de%20~75%20medidas-orange?style=for-the-badge)](#alcance)

<br/>

**[Qué es](#que-es)** · **[Alcance](#alcance)** · **[Uso](#uso)** · **[Salidas](#salidas)** · **[Cómo se lee](#lectura)** · **[Reglas](#reglas)** · **[Estado](#estado)**

</div>

<br/>

<details>
<summary><b>📖 Índice</b></summary>

- [Qué es — y qué no](#que-es)
- [Alcance — las seis medidas](#alcance)
- [Uso — ejecutarlo](#uso)
- [Salidas — qué deja un run](#salidas)
- [Cómo se lee el informe](#lectura)
- [Reglas y licencia](#reglas)
- [Estado](#estado)
- [Documentación](#docs)
- [English summary](#english)

</details>

---

<a id="que-es"></a>
## 🎯 Qué es — y qué no

Herramienta CLI. Se apunta a un repositorio, ejecuta escáneres de seguridad open source,
archiva cada hallazgo bajo una medida del ENS (RD 311/2022) y genera un informe de
evidencias en español.

> [!IMPORTANT]
> **El informe es evidencia para un auditor, nunca un veredicto.** No dice que cumples.

El análisis estático no es una auditoría. Queda fuera: lógica de negocio, diseño de
autenticación y autorización, configuración en tiempo de ejecución. El informe incluye
este descargo — es lo que lo hace utilizable como evidencia.

Todo se ejecuta dentro de tu CI. Ni el código ni el detalle de los hallazgos salen de tu
infraestructura; las salidas quedan en tu almacén de artefactos. No hay servidor, no hay
subida de datos, no hay cuenta.

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="alcance"></a>
## 📐 Alcance — las seis medidas

Se generan evidencias para exactamente estas seis medidas:

> `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4`

El ENS tiene ~75 medidas: esto cubre seis. Los seis códigos se verificaron contra el texto
consolidado del BOE (Anexo II, RD 311/2022) el 2026-07-25, y se releyeron literalmente el
2026-08-02 sobre la consolidación en vigor (06/11/2024).

| Medida | Título en el Anexo II |
|---|---|
| **`mp.sw.1`** | Desarrollo de aplicaciones |
| **`mp.sw.2`** | Aceptación y puesta en servicio |
| **`mp.s.2`** | Protección de servicios y aplicaciones web |
| **`op.exp.2`** | Configuración de seguridad |
| **`op.exp.3`** | Gestión de la configuración de seguridad |
| **`op.exp.4`** | Mantenimiento y actualizaciones de seguridad |

Ampliar esta lista no es una tarea de desarrollo: es una decisión de gobierno del proyecto,
y toca cuatro ficheros a la vez. Ver [ROADMAP.md](ROADMAP.md).

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="uso"></a>
## ▶️ Uso — ejecutarlo

```bash
ens-evidence scan [PATH]        # escaneo → normalización → baseline → run almacenado
ens-evidence baseline update    # acepta los hallazgos del último run
ens-evidence report [PATH]      # informe + remediation.md desde un run, sin re-escanear
ens-evidence bundle [PATH]      # bundle.md: resumen pegable desde un run almacenado
ens-evidence explain <id>       # un hallazgo: qué regla lo detectó y a qué medidas mapea
```

Arranque de reglas (una vez por entorno). Sin `--rules-root`, `scan` usa el registro de
Semgrep (`p/default`): funciona sin configuración, pero no es reproducible y es escaso en
algunos lenguajes. Modo fijado, el apto para CI:

```bash
ens-evidence rules fetch --sha <commit> --accept-rules-license
ens-evidence rules status
ens-evidence scan . --rules-root .ens-rules   # o ENS_EVIDENCE_RULES_ROOT / .ens-evidence.yml
```

Sin `--accept-rules-license` (o `ENS_EVIDENCE_ACCEPT_RULES_LICENSE=1`), `fetch` imprime los
términos y sale con código 2 sin descargar nada.

**Tú aportas:** Python 3.12+, los binarios de **Semgrep** y **Trivy** en el `PATH` con la
versión fijada en tu imagen de CI, `pandoc` y un motor PDF (`weasyprint`) si quieres
`report --format pdf`, y una copia propia de `semgrep-rules` fijada a un SHA.

`bundle.md` es un único documento Markdown pensado para pegarse en un chat: fecha,
repositorio, alcance, cobertura completa, hallazgos más graves con sus medidas, recuentos y
descargo. El texto procedente del repositorio analizado viaja como dato — en bloques
delimitados, o entre comillas invertidas y desactivado cuando debe ir en una celda.

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="salidas"></a>
## 📦 Salidas — qué deja un run

Todo queda en `out/latest/`. **Todos** los hallazgos aparecen en dos sitios: `findings.jsonl`
y el anexo 7.1 del informe. Las demás secciones del informe son vistas parciales de esos
mismos hallazgos.

| Fichero | Qué es | Publicable |
|---|---|---|
| **`findings.jsonl`** | Todos los hallazgos, uno por línea. La fuente de verdad | sí |
| **`report.md` / `report.pdf`** | El informe para el auditor | sí |
| **`remediation.md`** | La cola de trabajo: hallazgos agrupados por regla | sí |
| **`bundle.md`** | Resumen pegable en un chat | sí |
| **`run.json`** | Versiones de motores, SHA de reglas, fecha — la trazabilidad | sí |
| **`sbom.cdx.json`** | Inventario de dependencias (CycloneDX) | sí |
| **`*.sarif`** | Salida cruda de los motores | **no** — incorpora el catálogo de reglas |

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="lectura"></a>
## 📖 Cómo se lee el informe

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

**Equipo — arreglar: `remediation.md`, no el informe.**

`report` escribe los dos documentos. El informe registra lo encontrado; `remediation.md`
lo reordena como cola de trabajo — agrupado por regla, de más grave a menos, con las
ubicaciones, la versión corregida cuando el motor la da y los enlaces de la regla.

1. Se arregla una regla, se cierran todas sus ubicaciones de golpe.
2. El *cómo* concreto está en la referencia de la regla. No lo reescribimos: el catálogo lo
   mantiene al día y su licencia no permite copiarlo.
3. Arreglar, volver a escanear, comprobar que la huella desaparece. El informe siguiente es
   la prueba del cierre.
4. No hay supresiones: un hallazgo que se decide aceptar seguirá saliendo en cada run. Su
   justificación vive fuera de estos documentos.

Solo entran hallazgos marcados como seguridad por el motor: lo demás no es deuda de
seguridad. Y arreglarlo todo no es cumplir el ENS — eso lo dice una auditoría.

> [!WARNING]
> **Los anexos no cuentan como evidencia.** §7.2 son hallazgos sin medida asignada y §7.3
> los que el motor no marcó como seguridad. Están para que nada quede oculto, no para
> sostener una medida.

> [!NOTE]
> **El código de prueba va marcado, no excluido.** Un hallazgo bajo `tests/`, `fixtures/` o
> similar se cuenta igual, se etiqueta «código de prueba» y, en `remediation.md`, baja al
> final de su gravedad. Filtrarlo haría que el informe afirmara una cobertura que no tuvo;
> decidir si un fixture vulnerable a propósito es deuda no le toca a la herramienta.

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="reglas"></a>
## ⚖️ Reglas y licencia

Las reglas de Semgrep las obtiene **tu** entorno, no las distribuye esta herramienta: su
licencia (Semgrep Rules License v1.0) prohíbe redistribuirlas y permite usarlas para fines
internos propios. No las incluimos en la imagen ni en el paquete, y `.ens-rules/` nunca se
publica. Tampoco en formas menos evidentes: el SARIF en bruto que guarda el almacén de runs
incorpora el catálogo **completo** de reglas, así que publica `findings.jsonl`, `run.json`,
`report.md`, `bundle.md` y `sbom.cdx.json`, nunca `*.sarif`.

`remediation.md` lleva **direcciones, nunca texto de regla**: enlaces a la documentación del
catálogo y redacción propia. Una URL es una dirección, no la regla.

El código de esta herramienta es Apache-2.0 — ver [LICENSE](LICENSE).

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="estado"></a>
## 📊 Estado

`v1.0.0`, publicada el 2026-07-28 (wheel y sdist, ambos verificados sin fichero de reglas).
Las especificaciones 001–003 están implementadas. Lo que sostiene y lo que no:

| Hecho | Fecha | Qué significa |
|---|---|---|
| **Autoescaneo fijado** | 2026-07-29 | 74 hallazgos sobre este mismo repositorio: 61 mapeados y marcados como seguridad, **0 sin mapear**. La muestra en `samples/` está clavada a un commit y una versión de motor |
| **Títulos del Anexo II releídos** | 2026-08-02 | Los seis, literales, contra la consolidación en vigor del BOE (06/11/2024). Sin discrepancias |
| **Auditoría previa a publicar** | 2026-08-02 | 83 commits sin secretos (gitleaks sobre todo el historial); ningún fichero de reglas ni `.ens-rules/` estuvo nunca en un commit |
| **`mp.s.2` es la medida más débil** | 2026-07-25 | 4 hallazgos en el corpus de referencia. Las seis medidas no reciben evidencia por igual, y el informe no lo disimula |
| **Ecosistemas sin observar** | — | Rust, C#, Elixir y otros están marcados `UNOBSERVED` en el mapa de reglas: un patrón se promociona cuando un hallazgo real lo dispara, no antes |
| **La verificación de render lee texto, no maquetación** | 2026-07-29 | Las pruebas garantizan que cada identificador y mensaje llega al PDF; no ven una tabla simplemente fea. Leer la muestra sigue siendo cosa de una persona |

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="docs"></a>
## 📚 Documentación

| Documento | Para qué |
|---|---|
| **[ROADMAP.md](ROADMAP.md)** | Qué cubre v1, qué vendría después, y los límites permanentes |
| **[CHANGELOG.md](CHANGELOG.md)** | Qué cambió en cada versión, para quien usa la herramienta |
| **[DESIGN.md](DESIGN.md)** | El porqué: arquitectura, contrato CLI, reglas del proyecto |
| **[.specify/memory/constitution.md](.specify/memory/constitution.md)** | Reglas no negociables |
| **[the working plan](the working plan)** | El plan de trabajo abierto |
| **[AGENTS.md](AGENTS.md)** | Para agentes que trabajen **en** este repositorio |
| **[SKILL.md](SKILL.md)** | Para agentes que **usen** la herramienta |

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

<a id="english"></a>
## 🌍 English summary

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
architecture and the CLI contract, and [ROADMAP.md](ROADMAP.md) for what is and is not
planned.

<div align="right"><a href="#top">↑ volver arriba</a></div>
