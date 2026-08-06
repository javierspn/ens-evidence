<a id="top"></a>

# 🗺️ Roadmap

**Qué hace `ens-evidence` hoy, qué podría hacer, y qué no va a hacer nunca.**

Vista pública, sin fechas: se mueve despacio. El porqué está en [DESIGN.md](DESIGN.md);
el plan de trabajo abierto se lleva fuera de este repositorio.

---

## 📊 De un vistazo

| | Estado | En una línea |
|---|---|---|
| **`scan` · `report` · `bundle` · `explain` · `baseline` · `rules`** | ✅ **v1.0.0** | El ciclo completo sobre un repositorio, hoy |
| **gitleaks** (secretos) | 🔜 Siguiente | Hoy la mayor fuente de falsos negativos |
| **Checkov** (infraestructura como código) | 🔜 Siguiente | Mismo asiento de subproceso que Semgrep y Trivy |
| **Rust, C#, Elixir…** | 🤔 En estudio | Marcados `UNOBSERVED` hasta que un hallazgo real los dispare |
| **Actualizar el SHA de reglas por calendario** | 🤔 En estudio | Hoy la verificación solo reacciona a una subida manual |
| **Servicio alojado, panel, cuenta** | ❌ Nunca | No es esa clase de herramienta |
| **Firmar o certificar el resultado** | ❌ Nunca | Evidencia, no dictamen |
| **Las ~75 medidas del Anexo II** | ❌ Nunca | Seis medidas es el alcance, no una fase |

---

## ✅ Disponible — v1.0.0

Seis comandos que cubren el ciclo entero:

| Comando | Qué hace |
|---|---|
| `scan` | Ejecuta los motores, normaliza los hallazgos, aplica la línea base y guarda la ejecución |
| `baseline update` | Acepta los hallazgos de la última ejecución |
| `report` | Informe de evidencias en español — Markdown y PDF — más `remediation.md` |
| `bundle` | Resumen pegable de una ejecución guardada |
| `explain` | Por qué un hallazgo acabó bajo una medida concreta |
| `rules fetch` / `rules status` | Tu propia copia de las reglas, fijada a un SHA |

**Motores:** Semgrep y Trivy, invocados como subprocesos. La herramienta usa el binario que
encuentre y anota su versión en la ejecución. Quien fija la versión es tu CI — como hace el
flujo de trabajo de este repositorio.

---

## 🔜 Siguiente — dos motores más

El corpus de pruebas señala dos huecos como los mayores, y ambos entran por el mismo sitio
que Semgrep y Trivy:

- **gitleaks** — secretos.
- **Checkov** — infraestructura como código.

**Condición de entrada:** las reglas del motor se mapean *antes* de enchufarlo. Una regla sin
medida asignada aparece como hallazgo sin clasificar; nunca como cobertura.

---

## 🤔 En estudio

- **Ecosistemas sin observar** — Rust, C#, Elixir y otros están marcados `UNOBSERVED` en el
  mapa de reglas. Un patrón se promociona cuando un hallazgo real lo dispara, no antes.
- **Cadencia de actualización de reglas** — hoy nada programa una subida del SHA de
  `semgrep-rules`; la verificación solo reacciona a una.

---

## 🚧 Límites permanentes

No son deudas pendientes. Son la forma de la herramienta.

| Límite | Por qué |
|---|---|
| **Seis medidas de ~75** | `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4`. Ampliar el alcance es una decisión de gobierno del proyecto, no una tarea de desarrollo |
| **Solo análisis estático** | Lógica de negocio, diseño de autenticación y autorización y configuración en tiempo de ejecución no son visibles para un escáner. El informe lleva ese descargo escrito |
| **Evidencia, nunca veredicto** | La herramienta no dice que cumples. Un informe que se lea como un dictamen de conformidad es un error, no una mejora |
| **Tu código no sale de tu infraestructura** | Sin servidor, sin subida de datos, sin cuenta |
| **Las reglas no se redistribuyen** | Se descargan en tiempo de ejecución bajo la Semgrep Rules License v1.0; ni el paquete ni los artefactos publicados llevan su contenido |

<div align="right"><a href="#top">↑ volver arriba</a></div>

---

## 🌍 In English

`ens-evidence` is a CLI that points at a repository, runs open-source security scanners
(Semgrep, Trivy), files each finding under one of six Spanish ENS measures (RD 311/2022) and
renders a Spanish-language evidence report. **The report is evidence for an auditor, never a
verdict** — it does not say you comply.

| | Status |
|---|---|
| `scan`, `baseline update`, `report` (Markdown + PDF + `remediation.md`), `bundle`, `explain`, `rules fetch\|status` | ✅ Shipped in v1.0.0 |
| gitleaks (secrets) and Checkov (IaC), through the same subprocess seam | 🔜 Next — each gated on its rules being mapped first |
| Rust / C# / Elixir patterns; scheduled rule-SHA bumps | 🤔 Under consideration |
| Hosted service, dashboard, account; signing or certifying results; the full ~75 Annex II measures | ❌ Never |

The standing limits are not pending work: six of roughly 75 measures, static analysis only,
evidence and never a verdict, nothing leaving your infrastructure, and no redistribution of
Semgrep's rule content. The working plan is kept outside this repository.

<div align="right"><a href="#top">↑ volver arriba</a></div>
