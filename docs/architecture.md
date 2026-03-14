# docs/architecture.md

# Arquitectura de Prometheus Atlas

Prometheus Atlas está diseñado como una plataforma modular.

---

# Capas Principales

## Capa de Descubrimiento

Recolecta señales desde infraestructura.

Fuentes:

- DNS
- Certificate Transparency
- metadata HTTP
- APIs cloud
- eventos CI/CD

---

## Capa de Normalización

Convierte señales crudas en activos estructurados.

Ejemplos:

- dominios
- servicios
- APIs
- endpoints
- recursos cloud

---

## Capa de Inteligencia de Grafos

Los activos se conectan en un **grafo de infraestructura vivo**.

Permite modelar:

- dependencias entre servicios
- rutas de exposición
- relaciones de confianza

---

## Capa de Detección de Deriva

Compara:

- estado esperado de la infraestructura
- estado actual

Detecta cambios relevantes.

---

## Capa de Priorización de Riesgo

Evalúa riesgo considerando:

- exposición
- entorno
- conectividad
- sensibilidad de datos

---

## Capa de Alertas

Solo genera alertas cuando la deriva tiene impacto real en seguridad.