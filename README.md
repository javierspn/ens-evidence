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

<!-- TODO(001-core-pipeline): comandos reales cuando el CLI exista. Contrato en DESIGN.md. -->

```
ens-evidence scan [PATH]        # escaneo → normalización → baseline → mapeo → informe
ens-evidence baseline update    # acepta los hallazgos actuales
ens-evidence bundle             # genera bundle.md
ens-evidence report             # re-renderiza sin re-escanear
ens-evidence explain <id>       # un hallazgo: qué regla lo detectó y a qué medidas mapea
```

Arranque de reglas (una vez por entorno):

```
ens-evidence rules fetch --sha <commit> --accept-rules-license
ens-evidence rules status
```

Las reglas de Semgrep las obtiene **tu** entorno, no las distribuye esta herramienta: su
licencia (Semgrep Rules License v1.0) prohíbe redistribuirlas y permite usarlas para fines
internos propios. No las incluimos en la imagen ni en el paquete, y `.ens-rules/` nunca se
publica.

Requiere los binarios de los motores (Semgrep, Trivy) en el PATH; se fijan sus versiones
en tu imagen de CI.

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
forbids redistribution while permitting the licensee's own internal use, so
`ens-evidence rules fetch --sha <commit> --accept-rules-license` puts a pinned copy in your CI
and nothing rule-shaped ever enters our image, package or release assets.

Everything runs inside your CI: no server, no upload, no account. Engines (Semgrep, Trivy)
are subprocess calls to binaries you pin yourself. See [DESIGN.md](DESIGN.md) for the
architecture and the CLI contract.
