# Prometheus Atlas

Plataforma de **Security Drift Intelligence**

Prometheus Atlas es una plataforma diseñada para **detectar, explicar y rastrear cambios en la superficie expuesta de infraestructura a lo largo del tiempo**.

En lugar de limitarse a descubrir activos, Atlas analiza **cómo evoluciona la infraestructura** y transforma esos cambios en **inteligencia de seguridad accionable**.

---

# Estado del proyecto

Fase actual: **Fase 11**

Arquitectura: **Workspace modular en Rust**

Motor de drift: **funcional**

Persistencia: **SQLite**

Suite de pruebas: **aprobada**

El sistema ya implementa el flujo completo:

Descubrimiento  
↓  
Snapshot  
↓  
Diff  
↓  
Drift  
↓  
Correlación  
↓  
Episodios  
↓  
Persistencia  
↓  
Exportación  

---

# ¿Por qué existe Prometheus Atlas?

La infraestructura moderna cambia constantemente.

Ejemplos:

- nuevos servicios desplegados
- entornos temporales
- DNS olvidados
- endpoints expuestos
- cambios de configuración
- infraestructura efímera

La mayoría de herramientas responden:

**"¿Qué activos existen?"**

Prometheus Atlas responde:

**"¿Qué cambió y por qué importa?"**

Este enfoque define una nueva categoría:

**Security Drift Intelligence**

---

# Concepto central

Atlas modela la infraestructura como **un sistema que evoluciona en el tiempo**.

En lugar de escaneos aislados, utiliza una secuencia analítica:

Snapshot  
↓  
Diff  
↓  
Drift  
↓  
Timeline  
↓  
Correlación  
↓  
Episodios  

Esto permite detectar **cambios reales en exposición de seguridad**.

---

# Capacidades principales

Descubrimiento de activos

Resolución DNS

Fingerprint HTTP

Generación de snapshots

Versionado de snapshots

Comparación entre estados de infraestructura

Detección de drift de seguridad

Motor de políticas

Gestión de baseline

Excepciones temporales

Análisis histórico

Correlación de hallazgos

Episodios de riesgo

Persistencia

Exportación

Jobs programables

Scheduler

Telemetría interna

---

# Flujo típico de uso

Escanear objetivo

cargo run -p atlas -- scan example.com

Crear snapshot

cargo run -p atlas -- snapshot example.com --persist

Comparar snapshots

cargo run -p atlas -- diff old.json new.json

Detectar drift

cargo run -p atlas -- drift old.json new.json

Ver timeline

cargo run -p atlas -- timeline example.com

Generar episodios

cargo run -p atlas -- episodes example.com

Exportar findings

cargo run -p atlas -- export example.com --format json

---

# Arquitectura

Prometheus Atlas está construido como un **workspace modular en Rust**.

Cada dominio del sistema se encuentra en un crate independiente.

apps

scanner (CLI principal)

crates

atlas-config  
atlas-core  
atlas-discovery  
atlas-dns  
atlas-http  
atlas-snapshot  
atlas-diff  
atlas-drift  
atlas-correlation  
atlas-episodes  
atlas-store  
atlas-output  
atlas-jobs  
atlas-scheduler  
atlas-plugins  

Esta arquitectura permite evolución modular hacia una **plataforma completa**.

---

# Arquitectura de alto nivel

Usuario

↓

CLI Atlas

↓

Motor de descubrimiento

↓

Snapshots

↓

Motor de diff

↓

Motor de drift

↓

Correlación

↓

Episodios

↓

Persistencia

↓

Exportación

---

# Diferenciadores

## El cambio es la unidad de análisis

Atlas no solo analiza el estado actual. Analiza **la transición entre estados**.

---

## Drift semántico

Los cambios se clasifican como:

Nuevo  
Recurrente  
Persistente  
Suprimido  
Resuelto  

---

## Explainability

Cada hallazgo incluye explicación de:

- qué cambió
- por qué se generó el score
- qué factores influyeron

---

## Memoria histórica

Atlas registra la evolución de la superficie expuesta.

Ejemplo:

Un panel de administración aparece, desaparece y vuelve a aparecer.

Ese patrón revela **riesgo operativo real**.

---

## Episodios de riesgo

Múltiples hallazgos pueden formar **eventos de riesgo complejos**.

Ejemplo:

Nuevo DNS  
+  
Nuevo servicio HTTP  
+  
Panel de login expuesto

Esto representa un evento de despliegue inseguro.

---

# Casos de uso

Monitoreo de superficie de ataque externa

Detección de cambios de infraestructura

Análisis histórico de exposición

Reconocimiento de red para red teams

Auditoría de cambios de seguridad

Verificación de despliegues DevOps

---

# Roadmap

Fase 12

API backend

Fase 13

Frontend visual

Fase 14

Analítica avanzada con Python

Fase 15

Integraciones externas

Fase 16

Multiusuario

Fase 17

Plataforma madura

---

# Filosofía del proyecto

Prometheus Atlas no intenta ser solo otro escáner.

Su objetivo es responder preguntas como:

Qué cambió  
Cuándo cambió  
Qué riesgo introduce  
Si ese cambio ya ocurrió antes  
Cómo debe priorizarse  

Este enfoque define la categoría:

**Security Drift Intelligence**

---

# Licencia

MIT License

Ver archivo LICENSE.

---

# Contribuciones

Las contribuciones son bienvenidas.

Ver:

CONTRIBUTING.md

---

# Seguridad

Para reportar vulnerabilidades consultar:

SECURITY.md