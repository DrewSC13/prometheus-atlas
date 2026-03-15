# Visión de Prometheus Atlas

Prometheus Atlas es una plataforma orientada a modelar, analizar y explicar cambios en la superficie de exposición de sistemas externos. No es solamente un escáner de activos, ni únicamente una herramienta de gestión de superficie de ataque. Su enfoque es convertir el **cambio en exposición** en inteligencia accionable.

La tesis del proyecto es que el verdadero problema de seguridad no es solamente descubrir infraestructura, sino entender cómo cambia esa infraestructura en el tiempo y qué riesgo introducen esos cambios.

## Problema que busca resolver

Muchas herramientas actuales de seguridad:

- descubren activos
- escanean servicios
- generan reportes

Pero muy pocas pueden responder preguntas como:

- qué cambió entre dos estados de infraestructura
- cuándo ocurrió ese cambio
- si ese cambio es recurrente o persistente
- si ese cambio representa un aumento real de riesgo
- cómo explicar técnicamente ese cambio

Prometheus Atlas nace para llenar ese vacío.

## Security Drift Intelligence

El concepto central del proyecto es **Security Drift Intelligence**.

Security Drift se refiere al fenómeno en el que la superficie expuesta de un sistema cambia gradualmente debido a:

- despliegues
- configuraciones
- nuevas rutas
- nuevos servicios
- cambios en infraestructura
- modificaciones en políticas

En muchos casos estos cambios no son detectados ni correlacionados con riesgo.

Atlas transforma estos cambios en:

- hallazgos estructurados
- timeline histórico
- episodios de riesgo
- explicación técnica

## Enfoque del sistema

Atlas no trata el escaneo como evento aislado.

En cambio trabaja con el siguiente modelo:

Estado 1 → Snapshot

Estado 2 → Snapshot

Comparación → Diff

Interpretación → Drift

Persistencia → Timeline

Análisis → Episodios

Este modelo permite analizar la evolución de la exposición en lugar de solo su estado actual.

## Qué hace diferente a Atlas

Atlas introduce varias ideas que no suelen aparecer juntas en herramientas tradicionales.

### 1. El cambio es la unidad de análisis

No se analiza solamente el estado actual. Se analiza la transición entre estados.

### 2. Drift semántico

Los hallazgos se clasifican como:

- nuevo
- recurrente
- persistente
- suprimido
- resuelto

Esto permite priorización inteligente.

### 3. Explainability

Cada hallazgo tiene una explicación de:

- qué cambió
- por qué se generó el score
- qué factores influyeron

### 4. Línea temporal

Los hallazgos forman parte de un historial.

Esto permite responder:

- cuándo apareció
- cuánto duró
- cuántas veces ocurrió

### 5. Episodios

Múltiples hallazgos relacionados pueden agruparse en un episodio de riesgo.

Esto permite entender eventos complejos.

## Estado actual del proyecto

El proyecto ha alcanzado una arquitectura funcional basada en Rust.

Actualmente incluye:

- discovery modular
- snapshots versionados
- diff estructural
- motor de drift
- scoring
- policy engine
- baseline
- excepciones temporales
- correlación
- episodios
- persistencia SQLite
- jobs programables
- scheduler
- telemetría

Esto constituye el núcleo funcional del sistema.

## Evolución prevista

Las próximas etapas incluyen:

- API de servicio
- backend persistente
- interfaz web
- visualización de timeline
- correlación avanzada
- analítica basada en Python

## Objetivo final

Convertir Prometheus Atlas en una plataforma completa de:

Security Drift Intelligence

capaz de analizar la evolución de la exposición de sistemas complejos y explicar el riesgo introducido por cada cambio.