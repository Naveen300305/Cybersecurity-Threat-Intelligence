# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current State

This repository is **design-phase only** — there is no source code yet. It contains:

- `Cybersecurity-Threat-Intelligence/CyberGraph_Intelligence_Platform.md` — the complete design specification for the platform. **Read this first**; it is the source of truth for architecture, graph schema, module specs, API design, and the 6-week build plan.
- `Cybersecurity-Threat-Intelligence/Project Review -2 Presentation Template.pptx` — presentation template (binary, not readable as text).

There are no build, lint, or test commands yet. When implementation begins, follow the spec's planned structure and stack described below.

## What Is Being Built

**CyberGraph Intelligence Platform** — a Graph RAG–powered cybersecurity threat intelligence system. Public threat intel sources (NVD CVEs, MITRE ATT&CK, CAPEC, CWE, AlienVault OTX, CISA KEV, EPSS) are ingested into a **Neo4j knowledge graph**, which is exposed to an LLM through a **LangChain** pipeline combining Cypher generation (GraphCypherQAChain) with vector similarity retrieval (Neo4jVector). Ten intelligence modules (actor profiling, CVE enrichment, attack path analysis, IOC correlation, threat hunting, risk scoring, IR assistance, executive dashboard) sit on the shared graph, delivered via a FastAPI REST API and Streamlit UI.

## Planned Architecture (from the spec)

Layered flow: **Ingestion (Python connectors + Celery/Redis scheduler) → Neo4j graph + vector index → Graph RAG reasoning layer (LangChain, dual retrieval: Cypher traversal + embedding similarity) → 10 modules → FastAPI / Streamlit / CLI**.

Key design decisions to preserve when implementing:

- **Graph schema** (spec §5): node labels `ThreatActor`, `Campaign`, `Technique`, `Tactic`, `Malware`, `CVE`, `CWE`, `AffectedProduct`, `AttackPattern`, `Mitigation`, `IOC`, `Country`, `Sector`, `DataSource`; relationships like `USES`, `DEPLOYS`, `EXPLOITS`, `AFFECTS`, `HAS_WEAKNESS`, `MITIGATED_BY`, `ASSOCIATED_WITH`. The ATT&CK↔CAPEC↔CWE cross-links (`RELATED_TO`, `TARGETS_WEAKNESS`, `MAPPED_TO`) are the bridge that enables multi-hop actor→technique→CVE→product reasoning — the platform's core value.
- **Idempotent ingestion**: all Neo4j loads use `MERGE`, never `CREATE`, so feeds can be re-run safely.
- **Dual retrieval**: structured questions route to LLM-generated Cypher; fuzzy/semantic ones to the vector index; a hybrid retriever merges both before LLM synthesis. The Cypher-generation prompt must embed the full graph schema (spec §2.3).
- **ThreatPriority Score (TPS)**: composite CVE prioritization formula (CVSS + KEV flag + EPSS + actor/malware counts + recency) defined in spec §4.2 — use it rather than raw CVSS anywhere prioritization is needed.
- **TLP enforcement**: TLP:RED IOCs are never stored; TLP:AMBER never exposed in API responses by default. Incident data sent to the IR module stays in-memory only.
- **Embeddings**: local `sentence-transformers/all-MiniLM-L6-v2` by default (no API cost), stored in a Neo4j vector index on nodes with `description` fields.

## Planned Stack & Repo Layout

Python throughout: `neo4j`, `langchain` + `langchain-neo4j` + `langchain-anthropic`, `mitreattack-python`, `OTXv2`, `stix2`, `sentence-transformers`, `celery` + `redis`, `fastapi`, `streamlit`. Infrastructure runs via Docker Compose (Neo4j 5.x community with GDS + APOC plugins, Redis, api/worker/scheduler/ui services) — the intended dev startup is `docker compose up` once implemented.

Planned top-level layout (spec "Project Repository Structure"): `ingestion/` (connectors, transformers, loaders, scheduler), `graph/` (schema, indexes, Cypher query library), `rag/` (engine, prompts, retrievers, chains), `modules/` (modules 3–10, one file each), `api/` (FastAPI routers/schemas), `ui/` (Streamlit), `tests/` (pytest).

## Working in This Repo

- When implementing a module or endpoint, match the spec's REST API design (§8) and module behavior (§6) rather than redesigning; if a deviation is needed, note it in the spec document.
- All data sources are free/public — do not introduce dependencies on commercial threat intel feeds.
- The build plan (§9) defines the intended sequencing: graph schema + bulk ingestion first, then live feeds + embeddings, then the RAG engine, then modules, then UI.
