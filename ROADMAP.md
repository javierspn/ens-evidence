# Roadmap

Qué cubre `ens-evidence` hoy, qué podría cubrir, y qué no va a cubrir nunca.

Este documento se mueve despacio y no lleva fechas: es la vista pública. Las razones de
diseño están en [DESIGN.md](DESIGN.md). El plan de trabajo abierto se lleva fuera de este
repositorio.

## Límites permanentes

No son limitaciones a resolver en una versión futura. Son la forma de la herramienta.

- **Seis medidas de ~75.** Se generan evidencias para `mp.sw.1`, `mp.sw.2`, `mp.s.2`,
  `op.exp.2`, `op.exp.3` y `op.exp.4`. El resto del Anexo II queda fuera, y ampliar el
  alcance es una decisión de gobierno del proyecto, no una tarea de desarrollo.
- **Solo análisis estático.** Lógica de negocio, diseño de autenticación y autorización y
  configuración en tiempo de ejecución no son visibles para un escáner. El informe lleva ese
  descargo escrito.
- **Evidencia, nunca veredicto.** La herramienta no dice que cumples y no lo va a decir. Un
  informe que se lea como un dictamen de conformidad es un error, no una mejora.
- **Tu código no sale de tu infraestructura.** Sin servidor, sin subida de datos, sin cuenta.
- **Las reglas no se redistribuyen.** Se descargan en tiempo de ejecución bajo la Semgrep
  Rules License v1.0; ni el paquete ni los artefactos publicados llevan su contenido.

## v1 — disponible

Publicada como `v1.0.0`. Cubre el ciclo completo sobre un repositorio:

- `scan` — motores, normalización, línea base y almacén de ejecuciones.
- `baseline update` — acepta los hallazgos de la última ejecución.
- `report` — informe de evidencias en español, en Markdown y PDF, más `remediation.md`.
- `bundle` — resumen pegable de una ejecución guardada.
- `explain` — por qué un hallazgo acabó bajo una medida concreta.
- `rules fetch` / `rules status` — copia propia de las reglas, fijada a un SHA.

Motores: Semgrep y Trivy, invocados como subprocesos. La herramienta usa el binario que
encuentre y anota su versión en la ejecución; quien fija la versión es tu CI, como hace el
flujo de trabajo de este repositorio.

## Siguiente — más motores

Dos huecos que el corpus de pruebas señala como los mayores, ambos por el mismo asiento de
subproceso que ya usan Semgrep y Trivy:

- **gitleaks** — secretos, hoy la mayor fuente de falsos negativos.
- **Checkov** — infraestructura como código.

Cada motor nuevo obliga a mapear sus reglas antes de entrar: una regla sin medida asignada
aparece como hallazgo sin clasificar, nunca como cobertura.

## En estudio

- **Ecosistemas no observados** — Rust, C#, Elixir y otros están marcados `UNOBSERVED` en el
  mapa de reglas. Un patrón se promociona cuando un hallazgo real lo dispara, no antes.
- **Cadencia de actualización de reglas** — hoy nada programa una subida del SHA de
  `semgrep-rules`; la verificación solo reacciona a una.

## Lo que no está previsto

- Un servicio alojado, un panel o una cuenta.
- Firmar o certificar el resultado de ninguna forma.
- Ampliar el alcance a las ~75 medidas del Anexo II.

---

## In English

`ens-evidence` is a CLI that points at a repository, runs open-source security scanners
(Semgrep, Trivy), files each finding under one of six Spanish ENS measures (RD 311/2022) and
renders a Spanish-language evidence report. **The report is evidence for an auditor, never a
verdict** — it does not say you comply.

v1.0.0 ships the full cycle: `scan`, `baseline update`, `report` (Markdown, PDF and
`remediation.md`), `bundle`, `explain` and `rules fetch|status`. Next up is a second pair of
engines through the same subprocess seam — gitleaks for secrets and Checkov for IaC — each
gated on its rules being mapped first.

The standing limits are not pending work: six of roughly 75 measures, static analysis only,
evidence and never a verdict, nothing leaving your infrastructure, and no redistribution of
Semgrep's rule content. The working plan is kept outside this repository.
