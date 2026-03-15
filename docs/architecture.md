# Arquitectura de Prometheus Atlas

Estado actual: **Fase 11**

La arquitectura del proyecto se basa en un workspace modular de Rust que separa claramente los dominios funcionales del sistema.

---

# Principios arquitectónicos

La arquitectura sigue los siguientes principios:

- separación clara de responsabilidades
- crates independientes por dominio
- desacoplamiento entre motor y salida
- persistencia aislada
- facilidad de testeo
- evolución hacia servicio backend

---

# Vista general

Usuario

↓

CLI (apps/scanner)

↓

Motor Atlas

↓

Persistencia y reporting

---

# Organización del workspace

prometheus-atlas/

apps/

scanner (CLI principal)

crates/

atlas-config  
atlas-core  
atlas-correlation  
atlas-diff  
atlas-discovery  
atlas-dns  
atlas-drift  
atlas-episodes  
atlas-http  
atlas-jobs  
atlas-output  
atlas-plugins  
atlas-scheduler  
atlas-snapshot  
atlas-store

docs/

architecture.md  
vision.md  
roadmap.md

---

# Componentes principales

## apps/scanner

CLI principal que orquesta:

- scan
- snapshot
- diff
- drift
- timeline
- episodes
- export
- jobs

---

## atlas-config

Gestión de configuración:

- logging
- storage
- telemetry
- jobs
- profiles

---

## atlas-discovery

Motor de descubrimiento.

Integra:

- atlas-dns
- atlas-http

---

## atlas-dns

Resolución DNS y descubrimiento básico de subdominios.

---

## atlas-http

Fingerprint HTTP:

- tecnologías
- headers
- status codes
- fingerprint tecnológico

---

## atlas-snapshot

Gestión de snapshots:

- creación
- serialización
- migración

---

## atlas-diff

Comparación estructurada entre snapshots.

Detecta:

- activos nuevos
- activos removidos
- cambios de servicios

---

## atlas-drift

Motor principal del sistema.

Responsable de:

- clasificación de drift
- scoring
- severidad
- criticidad
- policy engine
- baseline
- temporary exceptions
- timeline summary

---

## atlas-correlation

Agrupa hallazgos relacionados.

---

## atlas-episodes

Construye episodios de riesgo basados en correlación.

---

## atlas-store

Persistencia SQLite:

- snapshots
- drift runs
- findings
- jobs
- telemetry

---

## atlas-jobs

Modelo de jobs programables.

---

## atlas-scheduler

Ejecuta jobs pendientes.

---

## atlas-output

Renderizado humano y JSON.

---

## atlas-plugins

Base para extensiones futuras.

---

# Flujo principal

scan → snapshot → diff → drift → timeline → correlation → episodes → store

---

# Persistencia

Actualmente SQLite guarda:

- snapshots
- drift runs
- findings
- telemetry
- jobs
- baseline

---

# Estado arquitectónico

El sistema ya posee:

- arquitectura modular sólida
- separación clara de dominios
- persistencia estable
- motor funcional completo

---

# Próxima evolución

Fase 12:

- API REST
- backend service
- workers
- separación CLI/backend

Fase 13:

- frontend
- visualización de drift

Fase 14:

- analítica avanzada
- integración Python