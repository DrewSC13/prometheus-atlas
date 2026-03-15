# Architecture Diagram — Prometheus Atlas

This document describes the high level architecture of the system.

---

# System Overview

User

↓

CLI (Atlas)

↓

Discovery Engine

↓

Snapshot System

↓

Diff Engine

↓

Drift Engine

↓

Correlation Engine

↓

Episode Builder

↓

Persistent Store

↓

Reporting / Export

---

# Layered Architecture

Layer 1 — Interface

apps/scanner

Responsibilities:

CLI interface  
command parsing  
workflow orchestration

---

Layer 2 — Discovery

atlas-discovery  
atlas-dns  
atlas-http  

Responsibilities:

DNS resolution  
service detection  
technology fingerprinting

---

Layer 3 — State Capture

atlas-snapshot

Responsibilities:

snapshot creation  
serialization  
schema versioning  
snapshot migration

---

Layer 4 — State Comparison

atlas-diff

Responsibilities:

compare snapshots  
detect changes  
produce structured diff

---

Layer 5 — Drift Intelligence

atlas-drift

Responsibilities:

risk scoring  
policy engine  
baseline logic  
temporary exceptions  
timeline classification

---

Layer 6 — Correlation

atlas-correlation

Responsibilities:

group related findings  
detect patterns

---

Layer 7 — Episodes

atlas-episodes

Responsibilities:

create risk episodes  
summarize exposure events

---

Layer 8 — Persistence

atlas-store

Responsibilities:

SQLite database

store:

snapshots  
findings  
drift runs  
jobs  
telemetry

---

Layer 9 — Orchestration

atlas-jobs  
atlas-scheduler

Responsibilities:

scheduled scans  
job execution

---

Layer 10 — Output

atlas-output

Responsibilities:

human readable output  
JSON output  
export formats

---

# Data Flow

scan target

↓

generate snapshot

↓

store snapshot

↓

diff snapshots

↓

detect drift

↓

apply policy

↓

generate findings

↓

correlate findings

↓

build episodes

↓

persist results

↓

export results

---

# Storage

Atlas uses SQLite for:

snapshots  
findings  
jobs  
telemetry  

Future evolution may include:

PostgreSQL

---

# Future Architecture

Planned improvements:

Backend API service

Worker nodes

Distributed scanning

Web frontend

Event streaming

---

# Architectural Philosophy

The architecture is modular.

Each crate represents a domain.

This allows:

independent evolution

isolated testing

clear separation of concerns