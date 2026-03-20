# Architecture — Prometheus Atlas

## Overview

Prometheus Atlas is built as a modular Rust workspace.

Each domain is isolated into its own crate.

---

## Structure

apps/
- scanner (CLI)

crates/
- atlas-core
- atlas-discovery
- atlas-dns
- atlas-http
- atlas-snapshot
- atlas-diff
- atlas-drift
- atlas-correlation
- atlas-episodes
- atlas-graph
- atlas-store
- atlas-output
- atlas-jobs
- atlas-scheduler
- atlas-query
- atlas-report
- atlas-plugins

---

## Flow

scan → snapshot → diff → drift → timeline → correlation → episodes → store

---

## Principles

- modular design
- separation of concerns
- testability
- extensibility