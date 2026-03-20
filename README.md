# Prometheus Atlas

Plataforma de **Security Drift Intelligence** para descubrir, modelar, comparar y analizar la evolución de la superficie expuesta de infraestructura.

Prometheus Atlas no se limita a responder:

**“¿Qué activos existen?”**

Su objetivo es responder:

**“¿Qué cambió, cuándo cambió, por qué importa y cómo debe priorizarse?”**

---

# Estado actual del proyecto

Versión actual: **v0.20.0**

Estado: **motor analítico funcional con operación básica y automatización local**

Arquitectura: **workspace modular en Rust**

Persistencia: **SQLite**

Pruebas: **aprobadas**

Linting: **sin warnings**

---

# Capacidades actuales

Prometheus Atlas ya implementa capacidades reales de análisis y operación:

## Descubrimiento
- resolución DNS
- enumeración básica de superficie
- fingerprint HTTP
- detección de tecnologías
- análisis de headers
- metadatos de servicios

## Estado y evolución
- generación de snapshots
- versionado de snapshots
- diff entre snapshots
- detección de drift
- timeline histórico
- correlación de hallazgos
- episodios de riesgo
- grafo de exposición

## Inteligencia de consulta
- query DSL
- filtros booleanos
- explain mode
- expansión por vecinos
- búsqueda por paths
- graph search
- saved queries

## Operación
- findings persistidos
- findings operativos
- asignación
- notas
- cambio de estado operativo
- baseline manual
- jobs
- scheduler
- reportes ejecutivos
- telemetría interna

---

# Flujo conceptual del sistema

    Discovery
       ↓
    Snapshot
       ↓
    Diff
       ↓
    Drift
       ↓
    Timeline
       ↓
    Correlation
       ↓
    Episodes
       ↓
    Graph
       ↓
    Query / Report / Operations

---

# ¿Por qué existe Prometheus Atlas?

La infraestructura moderna cambia continuamente:

- nuevos servicios desplegados
- subdominios temporales
- entornos de desarrollo expuestos
- cambios de proveedor
- drift de configuración
- endpoints que aparecen y desaparecen
- despliegues inseguros
- activos olvidados

La mayoría de herramientas tradicionales se enfocan en inventario o vulnerabilidades puntuales.

Prometheus Atlas introduce una capa distinta:

## Security Drift Intelligence

Es decir, inteligencia centrada en el **cambio de exposición**.

---

# Qué hace diferente a Atlas

## 1. El cambio es la unidad de análisis
Atlas no trata el escaneo como evento aislado. Analiza la transición entre estados.

## 2. Drift semántico
Los hallazgos no solo existen: se clasifican como:
- New
- Recurring
- Persistent
- Suppressed
- Resolved

## 3. Explainability
Los hallazgos y queries pueden explicar por qué un resultado apareció.

## 4. Memoria histórica
Atlas registra la evolución de la superficie de ataque en el tiempo.

## 5. Episodios de riesgo
Múltiples hallazgos relacionados pueden convertirse en un evento compuesto.

## 6. Modelo de grafo
La exposición se representa como relaciones entre:
- target
- subdomains
- IPs
- services
- technologies
- episodes

## 7. Operación real
Además del análisis, Atlas ya permite:
- revisar findings
- cambiar su estado operativo
- asignarlos
- documentarlos
- automatizar ejecuciones con jobs

---

# Casos de uso

- monitoreo de superficie de ataque externa
- detección de cambios de infraestructura
- análisis histórico de exposición
- validación de despliegues DevSecOps
- apoyo a red team
- auditoría de exposición
- priorización de cambios riesgosos
- construcción de evidencia de drift

---

# Arquitectura del proyecto

Prometheus Atlas está construido como un **workspace modular en Rust**.

## Apps
- apps/scanner → CLI principal

## Crates
- atlas-config
- atlas-core
- atlas-correlation
- atlas-diff
- atlas-discovery
- atlas-dns
- atlas-drift
- atlas-episodes
- atlas-graph
- atlas-http
- atlas-jobs
- atlas-output
- atlas-plugins
- atlas-query
- atlas-report
- atlas-scheduler
- atlas-snapshot
- atlas-store

---

# Ejemplos de uso

## Descubrimiento y snapshots

    cargo run -p atlas -- scan example.com
    cargo run -p atlas -- snapshot example.com
    cargo run -p atlas -- snapshot example.com --persist
    cargo run -p atlas -- snapshots example.com

## Drift y timeline

    cargo run -p atlas -- diff lab/old_snapshot.json lab/new_snapshot.json
    cargo run -p atlas -- drift lab/old_snapshot.json lab/new_snapshot.json
    cargo run -p atlas -- drift lab/old_snapshot.json lab/new_snapshot.json --policy lab/policy.json
    cargo run -p atlas -- timeline example.com
    cargo run -p atlas -- episodes example.com

## Grafo y queries

    cargo run -p atlas -- graph example.com
    cargo run -p atlas -- graph-stats example.com
    cargo run -p atlas -- query example.com 'services technology=cloudflare'
    cargo run -p atlas -- query example.com 'services technology=cloudflare EXPAND 1'
    cargo run -p atlas -- query example.com 'NEIGHBORS label=example.com DEPTH 2'
    cargo run -p atlas -- query example.com 'PATH example.com -> cloudflare'

## Saved queries

    cargo run -p atlas -- query-save risky-admin 'services (title~admin OR label~admin) AND tls_enabled=false'
    cargo run -p atlas -- query-list
    cargo run -p atlas -- query-run risky-admin example.com
    cargo run -p atlas -- query-run-all example.com
    cargo run -p atlas -- query-delete risky-admin

## Findings operativos

    cargo run -p atlas -- finding-list example.com
    cargo run -p atlas -- finding-list example.com --op-state open
    cargo run -p atlas -- finding-ack 3af898c74641e919b166da1e
    cargo run -p atlas -- finding-resolve 3af898c74641e919b166da1e
    cargo run -p atlas -- finding-accept 3af898c74641e919b166da1e
    cargo run -p atlas -- finding-assign 3af898c74641e919b166da1e claudio
    cargo run -p atlas -- finding-note 3af898c74641e919b166da1e "validado en revisión interna"
    cargo run -p atlas -- report-findings example.com

## Baseline y policy

    cargo run -p atlas -- baseline-approve admin.example.com
    cargo run -p atlas -- baseline-list
    cargo run -p atlas -- baseline-revoke admin.example.com
    cargo run -p atlas -- policy-check --policy lab/policy.json

## Jobs y scheduler

    cargo run -p atlas -- profiles
    cargo run -p atlas -- job-create example.com --profile standard --interval 3600
    cargo run -p atlas -- job-list
    cargo run -p atlas -- job-run <job_id>
    cargo run -p atlas -- job-disable <job_id>
    cargo run -p atlas -- job-enable <job_id>
    cargo run -p atlas -- job-delete <job_id>
    cargo run -p atlas -- scheduler-run
    cargo run -p atlas -- scheduler-status

## Reportes y rebuild

    cargo run -p atlas -- report example.com
    cargo run -p atlas -- report example.com --json --output report.json
    cargo run -p atlas -- rebuild example.com
    cargo run -p atlas -- rebuild example.com --persist

---

# Hoja de ruta

La siguiente evolución natural del proyecto incluye:

- API backend
- frontend visual
- dashboards
- integraciones externas
- analítica avanzada con Python
- motores de priorización más inteligentes

Ver más en:

- docs/vision.md
- docs/architecture.md
- docs/roadmap.md
- docs/product-positioning.md

---

# Filosofía del proyecto

Prometheus Atlas no busca ser solamente otro escáner.

Busca convertirse en una plataforma capaz de responder:

- qué cambió
- cuándo cambió
- por qué importa
- si ya ocurrió antes
- cómo debe priorizarse
- cómo debe operarse

Ese enfoque define su categoría:

## Security Drift Intelligence

---

# Licencia

MIT License

Ver archivo LICENSE.

---

# Contribuciones

Las contribuciones son bienvenidas.

Ver CONTRIBUTING.md.

---

# Seguridad

Para reportar vulnerabilidades, consulta SECURITY.md.

---

# Código de conducta

Ver CODE_OF_CONDUCT.md.