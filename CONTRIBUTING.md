# README.md

# Prometheus Atlas

**Inteligencia de Deriva de Seguridad para Infraestructura Cloud-Native**

Prometheus Atlas es una plataforma de ciberseguridad diseñada para detectar **deriva de seguridad (Security Drift)** en infraestructuras modernas.

En lugar de limitarse a identificar vulnerabilidades o activos expuestos, Prometheus Atlas se enfoca en entender **cómo cambia la infraestructura a lo largo del tiempo y cómo esos cambios introducen nuevos riesgos de seguridad**.

Las infraestructuras cloud modernas cambian constantemente:

- nuevos servicios
- nuevas APIs
- nuevos subdominios
- nuevos recursos cloud
- nuevos despliegues
- nuevas rutas entre servicios

Estos cambios suelen generar **degradación silenciosa de la seguridad**, algo que las herramientas tradicionales rara vez detectan o explican correctamente.

Prometheus Atlas busca resolver este problema.

---

# Concepto Central

Las herramientas tradicionales de seguridad responden preguntas como:

- ¿Qué vulnerabilidades existen?
- ¿Qué activos están expuestos?
- ¿Qué configuraciones son inseguras?

Prometheus Atlas responde una pregunta diferente:

> ¿Qué cambió en mi infraestructura y por qué ese cambio importa para la seguridad?

Este enfoque define una nueva categoría:

**Security Drift Intelligence (Inteligencia de Deriva de Seguridad)**

---

# Capacidades Principales (Visión)

Prometheus Atlas combinará múltiples capacidades en una sola plataforma:

- descubrimiento automático de activos
- modelado de infraestructura mediante grafos
- baselines dinámicos de seguridad
- detección de deriva
- priorización contextual del riesgo
- correlación con CI/CD e Infrastructure-as-Code

La plataforma transformará señales de infraestructura en **inteligencia de seguridad accionable**.

---

# Estructura del Repositorio

Este repositorio utiliza una arquitectura **monorepo basada en un workspace de Rust**.

    prometheus-atlas/
    │
    ├── apps/
    │   └── scanner/          # CLI principal (atlas)
    │
    ├── crates/
    │   ├── atlas-core
    │   ├── atlas-discovery
    │   ├── atlas-snapshot
    │   ├── atlas-diff
    │   └── atlas-output
    │
    ├── docs/
    │   ├── architecture.md
    │   ├── roadmap.md
    │   └── vision.md
    │
    ├── infra/
    ├── examples/
    └── tests/

---

# Atlas CLI (Planeado)

El primer componente del proyecto será **Prometheus Atlas Scanner**, una herramienta de línea de comandos.

Ejemplo de uso:

    atlas scan ejemplo.com
    atlas snapshot guardar
    atlas diff snapshot_viejo.json snapshot_nuevo.json

Esta herramienta permitirá:

- descubrir activos de infraestructura
- generar snapshots de infraestructura
- detectar cambios entre snapshots
- identificar posibles derivas de seguridad

---

# Stack Tecnológico

Prometheus Atlas utiliza tecnologías modernas:

| Capa                          | Tecnología                |
|-------------------------------|---------------------------|
| Motor de descubrimiento       | Rust                      |
| Análisis de deriva            | Python                    |
| Procesamiento de datos        | Rust + Python             |
| Modelado de infraestructura   | Bases de datos de grafos  |
| Almacenamiento de eventos     | ClickHouse                |
| Mensajería                    | NATS                      |
| Interfaz web                  | Next.js                   |

---

# Estado del Proyecto

Proyecto en etapa temprana de desarrollo.

El enfoque inicial es construir el **scanner MVP** con:

- descubrimiento pasivo
- snapshots de infraestructura
- detección de cambios
- exportación JSON

---

# Aviso de Seguridad

Esta herramienta está destinada únicamente para:

- investigación en ciberseguridad
- auditorías autorizadas

Solo debes escanear sistemas:

- que te pertenezcan
- o para los que tengas permiso explícito

El uso indebido puede violar leyes o políticas de seguridad.

---

# Contribuciones

Se aceptan contribuciones de:

- investigadores de seguridad
- desarrolladores Rust
- ingenieros DevSecOps

Consulta el archivo:

**CONTRIBUTING.md**

---

# Licencia

Apache License 2.0

---

# Autor

Claudio Andres Sanjines Cuellar  
Investigación y Desarrollo en Ciberseguridad

---

# Visión

Prometheus Atlas busca convertirse en la **fuente de verdad sobre cambios en infraestructura y deriva de seguridad en entornos cloud-native**.