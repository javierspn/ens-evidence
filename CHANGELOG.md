# Changelog

Cambios visibles para quien **usa** la herramienta: comandos, salidas y lo que el informe
afirma. La reconciliación interna del proyecto vive en [the working plan](the working plan) y el rastro
completo está en `git log`.

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado: [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

### Añadido

- **`remediation.md`**, segundo documento que escribe `report` junto al informe: los
  hallazgos de seguridad agrupados por regla, de más grave a menos, con sus ubicaciones, la
  versión corregida cuando el motor la da y los enlaces de la regla. Lleva direcciones,
  nunca texto del catálogo.
- **`ROADMAP.md`** — la vista pública: qué cubre v1, qué vendría después y los límites que
  no son trabajo pendiente sino la forma de la herramienta.

### Cambiado

- **El código de prueba se marca, ya no se cuenta como código de producto.** Un hallazgo
  bajo `tests/`, `fixtures/` o similar se cuenta igual y se etiqueta; en `remediation.md`
  baja al final de su gravedad. No se filtra: eso afirmaría una cobertura que el run no tuvo.
- **Las secciones del informe van numeradas** y los hallazgos se describen con redacción
  propia, no con el texto de la regla.
- **`scan` marca su directorio de salida como ignorado**, para que un run no se escanee a sí
  mismo en el siguiente.
- **`README.md` reescrito**: mismos hechos, una sección por concepto, y una tabla de estado
  que incluye las debilidades conocidas con su fecha.

### Corregido

- **El informe ya no afirma una cobertura de reglas que el run no tuvo**, y agrupa los
  hallazgos repetidos en lugar de listarlos sueltos.
- **`remediation.md` ya no presenta el anuncio de Semgrep Pro como referencia de la regla**:
  ocupaba el primer hueco de tres en cada hallazgo de semgrep, por delante de la
  documentación de la propia regla.
- **El registro del run ya no publica rutas del sistema de ficheros** — un informe no debe
  llevar dentro el directorio personal de nadie.
- **El PDF lleva hoja de estilo**, así que las tablas de hallazgos dejan de recortar la
  columna de identificador.

### Seguridad

- **Los ficheros SARIF de prueba ya no llevan el texto de las reglas.** Guardaban la
  descripción y la ayuda completa de cada regla — contenido del catálogo, sujeto a la
  Semgrep Rules License v1.0, en un repositorio destinado a hacerse público. Conservan solo
  sus enlaces.
- **El flujo de CI pasa el contexto de GitHub a los bloques `run:` por entorno**, no por
  interpolación.

## [1.0.0] — 2026-07-28

Primera versión publicada: wheel y sdist, ambos verificados sin fichero de reglas dentro.

### Añadido

- Los seis comandos: `scan`, `baseline update`, `report`, `bundle`, `explain` y
  `rules fetch|status`.
- Evidencias para seis medidas del ENS (RD 311/2022): `mp.sw.1`, `mp.sw.2`, `mp.s.2`,
  `op.exp.2`, `op.exp.3` y `op.exp.4`, con sus títulos verificados contra el texto
  consolidado del BOE.
- Motores Semgrep y Trivy como subprocesos, con las versiones que fije tu CI.
- Modo de reglas fijado a un SHA (`rules fetch --accept-rules-license`), el apto para CI:
  reproducible y sin depender del registro público.
- Informe en Markdown y PDF, `bundle.md` pegable en un chat, línea base con huellas estables
  entre runs, y `sbom.cdx.json`.
