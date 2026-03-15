# Roadmap de Prometheus Atlas

Este documento describe la evolución planificada del proyecto.

Las fases están organizadas por incremento de capacidades.

---

# Fase 1 — Discovery inicial

Objetivo:

Crear un escáner base capaz de descubrir servicios.

Capacidades:

- resolución DNS
- detección de servicios HTTP
- CLI inicial
- salida JSON

---

# Fase 2 — Snapshots

Objetivo:

Capturar estados completos de infraestructura.

Capacidades:

- generación de snapshots
- serialización
- almacenamiento en archivos

---

# Fase 3 — Diff

Objetivo:

Comparar snapshots.

Capacidades:

- detección de activos nuevos
- detección de activos removidos
- cambios de servicios

---

# Fase 4 — Drift engine

Objetivo:

Interpretar cambios como eventos de seguridad.

Capacidades:

- scoring inicial
- clasificación de cambios

---

# Fase 5 — Policy engine

Objetivo:

Controlar hallazgos mediante reglas.

Capacidades:

- allowlists
- supresión de findings

---

# Fase 6 — Timeline

Objetivo:

Construir historial de cambios.

Capacidades:

- timeline entre snapshots
- reportes históricos

---

# Fase 7 — Asset classification

Objetivo:

Contextualizar hallazgos.

Capacidades:

- tipos de activos
- criticidad

---

# Fase 8 — Fingerprint enriquecido

Objetivo:

Mejorar la detección de servicios.

Capacidades:

- detección de tecnologías
- análisis de headers

---

# Fase 9 — Baseline adaptativo

Objetivo:

Diferenciar drift aceptado de drift riesgoso.

Capacidades:

- baseline
- excepciones temporales

---

# Fase 10 — Endurecimiento

Objetivo:

Estabilizar la plataforma.

Capacidades:

- versionado de schema
- migración de snapshots
- normalización de findings
- configuración formal
- sistema de plugins
- logging
- telemetría
- suite de tests

---

# Fase 11 — Orquestación

Objetivo:

Convertir el motor en sistema operable.

Capacidades:

- correlación
- episodios
- jobs
- scheduler
- explainability
- persistencia completa

---

# Fase 12 — Backend

Objetivo:

Separar CLI y servicio.

Capacidades:

- API REST
- workers
- backend persistente

---

# Fase 13 — Frontend

Objetivo:

Visualización operativa.

Capacidades:

- dashboards
- timeline visual
- findings
- episodios

---

# Fase 14 — Analítica avanzada

Objetivo:

Mejorar priorización.

Capacidades:

- clustering
- scoring adaptativo
- análisis Python

---

# Fase 15 — Integraciones

Objetivo:

Integración con ecosistema.

Capacidades:

- Slack
- SIEM
- ticketing

---

# Fase 16 — Multiusuario

Objetivo:

Uso organizacional.

Capacidades:

- autenticación
- permisos
- multi-tenant

---

# Fase 17 — Producto maduro

Objetivo:

Consolidación de plataforma.

Capacidades:

- estabilidad
- escalabilidad
- experiencia completa de usuario