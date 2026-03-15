# Product Positioning — Prometheus Atlas

## Category Definition

Prometheus Atlas introduces a new category:

Security Drift Intelligence

Traditional tools fall into these categories:

Attack Surface Management (ASM)

Examples:
- Wiz
- Censys
- Palo Alto ASM
- Randori
- JupiterOne

Asset Discovery

Examples:
- Nmap
- Amass
- Subfinder

Vulnerability Management

Examples:
- Nessus
- Qualys
- OpenVAS

These tools answer:

"What exists?"

Prometheus Atlas answers a different question:

"What changed and why does it matter?"

This distinction defines a new category: **Security Drift Intelligence**.

---

# The Core Problem

Modern infrastructure changes constantly.

Examples:

- new services deployed
- temporary staging environments
- configuration drift
- DNS updates
- forgotten assets

Most tools detect assets but do not understand **the evolution of exposure**.

Security teams are flooded with alerts but lack context about change.

---

# Atlas Approach

Atlas models infrastructure as a **time evolving system**.

Instead of isolated scans, it builds:

Snapshots

↓

Diffs

↓

Drift Events

↓

Risk Findings

↓

Timeline

↓

Episodes

This allows Atlas to answer:

- When did exposure increase?
- What caused it?
- Is it recurring?
- Is it persistent?
- Should it be ignored or escalated?

---

# Differentiators

## Time-first security

Atlas focuses on **change over time**, not just state.

## Drift semantics

Changes are classified as:

New  
Recurring  
Persistent  
Suppressed  
Resolved  

## Explainability

Each finding includes reasoning.

Example:

Score explanation:

- new public endpoint
- missing security headers
- exposed admin path

## Historical memory

Atlas tracks exposure history.

Example:

Admin panel exposed:
- appeared
- disappeared
- reappeared

This pattern signals operational risk.

## Correlated risk episodes

Multiple findings can form a **risk episode**.

Example:

- new DNS entry
- new HTTP service
- exposed login panel

Together they form a deployment exposure event.

---

# Target Users

Primary users:

Security engineers  
Red teams  
AppSec teams  
SOC analysts  

Secondary users:

DevOps teams  
Platform teams  
Startup security teams  

---

# Use Cases

External attack surface monitoring

Infrastructure drift detection

Security change analysis

Historical exposure auditing

Red team reconnaissance tracking

DevOps deployment verification

---

# Long Term Vision

Atlas evolves into a platform with:

Backend service

REST API

Web UI

Drift dashboards

Episode analytics

Security timelines

AI-assisted risk prioritization

---

# Strategic Position

Atlas does not try to replace scanners.

It complements them.

Scanners detect vulnerabilities.

Atlas detects **security drift**.

Together they create a much stronger security posture.

---

# Short Positioning Statement

Prometheus Atlas is a Security Drift Intelligence platform that tracks how exposed infrastructure changes over time and transforms those changes into actionable security insights.