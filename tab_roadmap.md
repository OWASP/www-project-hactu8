---
title: Roadmap
layout:  col-sidebar
tab: true
order: 1
tags: hactu8-tag
---

## Roadmap (As Of July 2025)

This roadmap outlines the development plan for the OWASP HACTU8 reference platform. Phase 1 focuses on building a foundational system to support AI assurance testing through UI scaffolding, test agent integration, registry design, and a lightweight scanner.

---

## Project Phases

|   Phase   | Name                        | Objective |
|-----------|-----------------------------|-----------|
| **1** | Foundation and Integration  | Establish a running UI, test orchestration, extension architecture, and registry/discovery foundation |
| **2** | Platform Development        | Expand into a fully functional MVP with integrated models, test automation, and extension marketplace |
| **3** | Community Engagement        | Promote contribution, support external tools, and build adoption with documentation and collaboration models |

---

## Phase 1: Foundation and Integration

### M1: Mockup

> Scaffold the UI, engine shell, scanner, and API endpoints for initial visualization.

- [ ] Scaffold Streamlit UI Shell
- [ ] Build FastAPI Interface Skeleton
- [ ] Create Engine Module Skeleton (agents/orchestrator)
- [ ] Create Scanner CLI Skeleton

---

### M2: Requirements Documentation

> Define all core schemas, specifications, and architectural references.

- [ ] Define Initial Architecture Document
- [ ] Create Test Spec Template (JSON/YAML)
- [ ] Document OWASP Top 10 Test Concepts
- [ ] Describe Signature Format for Scanners
- [ ] Define Registry API Contract

---

### M3: Running Demo

> Deliver a working vertical slice using mock data to demonstrate test execution flow.

- [ ] Wire UI to Dummy API
- [ ] Run Simulated Prompt Injection Agent
- [ ] Display Result in Assurance Viewer
- [ ] Integrate Registry View from API

---

### M4: Extension Model

> Implement a plugin system for test extensions, aligned to the OWASP LLM Top 10.

- [ ] Define Extension Plugin Base Class
- [ ] Implement Prompt Injection Extension Stub
- [ ] Define Extension Metadata Format
- [ ] Render Extension Output in UI

---

### M5: Discovery Architecture

> Define and implement how LLMs, tools, and endpoints are discovered or registered.

- [ ] Design Discovery Interface (API + check-in)
- [ ] Create Signature Loader Logic
- [ ] Connect CLI Scanner to Registry
- [ ] Simulate Local Ollama/Foundry Detection
- [ ] Document Discovery Modes and Architecture

---

### Phase Closeout: Retrospective

> Evaluate Phase 1 and scope Phase 2 deliverables.

- [ ] Conduct Phase 1 Retrospective
- [ ] Define Milestones for Phase 2: Platform Development

