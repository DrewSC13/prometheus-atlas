# Prometheus Atlas

**Security Drift Intelligence for Cloud-Native Infrastructure**

Prometheus Atlas is a cybersecurity platform designed to detect **security drift** in modern infrastructure.  
Instead of only identifying vulnerabilities or exposed assets, Prometheus Atlas focuses on understanding **how infrastructure changes over time and how those changes introduce new security risks.**

Modern cloud environments change continuously:

- new services
- new subdomains
- new APIs
- new deployments
- new infrastructure components
- new access paths

These changes often introduce **silent security degradation** that traditional security tools fail to explain.

Prometheus Atlas aims to solve this problem.

---

# The Core Idea

Traditional security tools answer questions like:

- What vulnerabilities exist?
- What assets are exposed?
- What configurations are incorrect?

Prometheus Atlas answers a different question:

> **What changed in my infrastructure, and why does that change matter for security?**

This concept defines a new category:

**Security Drift Intelligence**

---

# Key Capabilities (Vision)

Prometheus Atlas combines several capabilities into a single platform:

- Autonomous asset discovery
- Live infrastructure graph
- Dynamic security baselines
- Drift detection
- Context-aware risk scoring
- CI/CD and Infrastructure-as-Code correlation

The platform aims to transform raw infrastructure signals into **actionable security intelligence.**

---

# Repository Structure

This repository follows a **monorepo architecture** built around a Rust workspace.


prometheus-atlas/
│
├── apps/
│ └── scanner/ # CLI tool (atlas)
│
├── crates/
│ ├── atlas-core
│ ├── atlas-discovery
│ ├── atlas-snapshot
│ ├── atlas-diff
│ └── atlas-output
│
├── docs/ # Architecture, vision, and roadmap
├── infra/ # Future infrastructure and deployment
├── examples/
└── tests/


The first component being developed is the **Prometheus Atlas Scanner**, a CLI tool designed to:

- discover assets
- generate infrastructure snapshots
- detect changes between snapshots
- surface potential security drift

---

# Atlas CLI (Planned)

The primary interface will be a command-line tool:


atlas scan example.com
atlas snapshot save
atlas diff snapshot_old.json snapshot_new.json


This tool will serve as the foundation for:

- the Prometheus Atlas platform
- the drift intelligence engine
- future SaaS capabilities

---

# Technology Stack

Core technologies used in the project include:

- **Rust** – high-performance scanning and collectors
- **Python** – data processing, correlation, drift intelligence
- **Graph databases** – infrastructure relationship modeling
- **ClickHouse** – event storage and analytics
- **NATS** – event-driven architecture
- **Next.js** – future platform interface

---

# Project Status

🚧 Early development stage.

The first milestone focuses on building the **Atlas Scanner MVP** with:

- passive discovery
- infrastructure snapshots
- drift detection
- JSON export

---

# Security

This project is developed with security research in mind.

**Only run the scanner on infrastructure you own or have explicit authorization to test.**

See `SECURITY.md` for vulnerability reporting.

---

# Contributing

Contributions, discussions, and research ideas are welcome.

See:


CONTRIBUTING.md


---

# License

Apache License 2.0

---

# Author

Andres  
Cybersecurity Research & Engineering

---

# Vision

Prometheus Atlas aims to become the **source of truth for infrastructure change and security drift in cloud-native environments.**