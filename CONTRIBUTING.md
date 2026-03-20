# Contributing to Prometheus Atlas

Thank you for your interest in contributing.

Prometheus Atlas is an open project focused on building a **Security Drift Intelligence platform**.

---

## Ways to contribute

- reporting bugs
- suggesting features
- improving documentation
- submitting pull requests

---

## Workflow

1. Fork the repository
2. Create a branch

    feature/your-feature-name

3. Implement changes
4. Run checks
5. Open a Pull Request

---

## Requirements

Before submitting a PR, ensure:

    cargo fmt
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace

---

## Code Style

- idiomatic Rust
- no warnings
- small modules
- clear naming
- minimal complexity

---

## Testing

Changes should include:

- unit tests
- integration tests when needed

---

## Issues

Include:

- clear description
- reproduction steps
- expected behavior
- actual behavior

---

## Philosophy

This is not just another scanner.

This is a platform for:

**Security Drift Intelligence**