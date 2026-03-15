# Contribuir a Prometheus Atlas

Gracias por considerar contribuir al proyecto.

Prometheus Atlas es un proyecto abierto orientado a construir una plataforma de Security Drift Intelligence.

## Cómo contribuir

Puedes contribuir de varias formas:

- reportando bugs
- sugiriendo mejoras
- mejorando documentación
- enviando pull requests

## Flujo de trabajo

1. Fork del repositorio
2. Crear una rama

feature/nombre-de-la-feature

3. Implementar cambios
4. Ejecutar pruebas
5. Crear pull request

## Requisitos antes de enviar PR

El código debe pasar:

cargo fmt

cargo clippy --workspace --all-targets --all-features -- -D warnings

cargo test --workspace

## Estilo de código

- Rust idiomático
- evitar warnings
- módulos pequeños
- comentarios claros

## Tests

Cada cambio importante debe incluir:

- test unitario
- test de integración cuando sea necesario

## Issues

Los issues deben incluir:

- descripción clara
- pasos para reproducir
- comportamiento esperado
- comportamiento actual

## Filosofía del proyecto

El objetivo no es crear solo otro escáner.

El objetivo es construir un motor de:

Security Drift Intelligence.