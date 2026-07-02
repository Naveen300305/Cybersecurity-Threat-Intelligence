# CyberGraph Intelligence Platform — Presentation Explanation

*Use this as speaking notes while presenting the slides. Each section maps to one slide/topic.*

---

## 1. Title Slide

**Title:** CyberGraph Intelligence Platform — Graph-Powered Threat Analysis Using RAG

**What to say:**
"Today I'll be presenting CyberGraph, a threat intelligence platform that uses Graph RAG — Retrieval-Augmented Generation combined with a graph database — to help security analysts reason about cyber threats the way they actually think: through relationships, not isolated data points."

---

## 2. Abstract

**Talking points (say each in 1–2 sentences):**

1. **Problem:** Security analysts face fragmented threat data across CVE databases, ATT&CK mappings, and IOC feeds, making multi-hop questions like "which unpatched systems are at risk from APT29?" slow and manual to answer.

2. **Solution:** CyberGraph models threat actors, CVEs, malware, and techniques as a connected Neo4j knowledge graph, using Graph RAG to traverse relationships and let an LLM synthesize analyst-grade answers.

3. **Impact:** Built entirely on free public data sources (NVD, MITRE ATT&CK, CISA KEV, OTX), it delivers 10 modular capabilities — from vulnerability prioritization to incident response — through a single natural-language interface.

**Delivery tip:** Pause briefly between each point — this slide sets up the "problem → solution → impact" narrative for the whole talk.

---

## 3. Data Collection

**Talking points:**

1. **Sources:** Ingests data from 6+ free public feeds — NVD/NIST (CVEs), MITRE ATT&CK (techniques/actors), CAPEC/CWE, AlienVault OTX (IOCs), and CISA KEV (exploited vulnerabilities).

2. **Pipeline:** A Python + Celery ETL pipeline handles bulk historical loads plus incremental refresh (daily for NVD/KEV, hourly for OTX pulses).

3. **Normalization:** Raw feeds are parsed, deduplicated, and normalized (CPE strings, STIX bundles, IOC dedup) before loading into Neo4j via idempotent MERGE operations.

**Delivery tip:** Emphasize that everything is free and public — this is a key differentiator, no commercial threat intel licenses required.

---

## 4. Data Analysis

**Talking points:**

1. **Graph Traversal:** LangChain's GraphCypherQAChain converts natural-language questions into Cypher queries, enabling multi-hop reasoning across actors, techniques, and CVEs.

2. **Hybrid Retrieval:** Combines structured graph traversal with vector similarity search (Neo4j vector index) to handle both precise and semantic/fuzzy queries.

3. **Scoring & Synthesis:** Computes composite metrics like the ThreatPriority Score (CVSS + KEV + EPSS + actor/malware exposure) and synthesizes graph evidence into LLM-generated, analyst-ready answers.

**Delivery tip:** This is a good place to give the audience a live example — "a query about APT29 automatically traverses to campaigns, tools, techniques, and the CVEs those tools exploit — all in one reasoning chain."

---

## 5. Methodology and System Design

### 5.1 Proposed Methodology

1. **Graph-centric modeling:** Represent the cybersecurity domain (threat actors, CVEs, malware, techniques) as an interconnected Neo4j knowledge graph instead of flat, siloed data tables.

2. **Retrieval-augmented reasoning:** Combine structured Cypher graph traversal with vector similarity search, letting an LLM synthesize multi-hop, relationship-aware answers rather than isolated facts.

3. **Modular, phased implementation:** Build ingestion, graph, and RAG layers first, then layer 10 independent intelligence modules on top — enabling iterative development and testing across a 6-week build plan.

### 5.2 Architecture Diagram

**What to say while showing the diagram:**
"The system is organized into 5 layers, and data flows top to bottom. At the base, six public feeds are ingested through a Python and Celery ETL pipeline. That data is normalized and loaded into a Neo4j graph — the second layer — which stores both the entity relationships and a vector index for semantic search. On top of that sits the Graph RAG reasoning layer, orchestrated by LangChain, which has four components: a Cypher query chain, a vector retriever, a graph traversal agent, and an LLM synthesis layer. This reasoning engine powers all 10 intelligence modules in the fourth layer — things like threat actor profiling, vulnerability scoring, and incident response. Finally, everything is exposed to the analyst through a REST API, a Streamlit UI, and a CLI tool."

*(Insert: CyberGraph_Architecture_Diagram.png)*

### 5.3 Flowchart — Query Processing Flow

**What to say while showing the flowchart:**
"This flowchart shows what happens to a single question. The analyst types a natural language query. The system routes it — either to the Cypher chain for structured questions, or the vector retriever for fuzzy/semantic ones. The graph traversal step walks the relevant relationships — actor to technique to CVE to product, for example. Then the LLM synthesis step turns that raw graph evidence into a readable answer, and the final response comes back with the answer, the sources used, and the actual Cypher query that was run — so analysts can verify it."

### 5.4 Selection of Algorithms, Tools, and Technologies

1. **Neo4j 5.x (Community/AuraDB Free):** Chosen as the graph database for native multi-hop traversal, Cypher querying, GDS algorithms (shortest path, centrality), and built-in vector indexing.

2. **LangChain (GraphCypherQAChain + Neo4jVector):** Orchestrates the RAG pipeline, converting natural language into Cypher queries and merging results with semantic vector search.

3. **Claude 3.5 Sonnet / GPT-4o / Ollama:** Pluggable LLM backend for synthesis — Claude is recommended for long-context reasoning, with Ollama as a fully offline, air-gapped alternative.

4. **sentence-transformers (all-MiniLM-L6-v2):** A free, local embedding model used to generate vector representations of node descriptions, avoiding API costs.

5. **Celery + Redis:** Handles scheduled and asynchronous ETL tasks — daily NVD/CISA refreshes, hourly OTX pulse ingestion — ensuring the graph stays current.

6. **FastAPI + Streamlit:** FastAPI exposes all 10 modules as REST endpoints with auto-generated docs, while Streamlit provides a rapid, no-frontend-code analyst UI with graph visualization (pyvis).

**Delivery tip:** If time is short, you can group items 4–6 together as "supporting infrastructure" and spend more time on Neo4j, LangChain, and the LLM choice, since those are the core architectural decisions.

---

## 6. References

1. MITRE Corporation. (2024). *MITRE ATT&CK®: A knowledge base of adversary tactics and techniques*. Retrieved from https://attack.mitre.org

2. National Institute of Standards and Technology (NIST). (2024). *National Vulnerability Database (NVD)*. Retrieved from https://nvd.nist.gov

3. Cybersecurity and Infrastructure Security Agency (CISA). (2024). *Known Exploited Vulnerabilities (KEV) Catalog*. Retrieved from https://www.cisa.gov/known-exploited-vulnerabilities-catalog

4. Edge, P., & LangChain Contributors. (2024). *LangChain: Building applications with LLMs through composability* [Software documentation]. Retrieved from https://python.langchain.com

5. Neo4j, Inc. (2024). *Neo4j Graph Data Science and GraphRAG documentation*. Retrieved from https://neo4j.com/docs

---

## General Presentation Tips

- **Pace:** Spend the most time on the Methodology/Architecture section — it's the technical core of the project and where questions will come from.
- **Anchor with an example:** Repeat the APT29 → technique → CVE → product example across slides; it ties the abstract, data analysis, and architecture sections together into one coherent story.
- **If asked "why Graph RAG over normal RAG":** Point back to the abstract — flat RAG retrieves isolated text chunks, but security questions are inherently relational (actor → tool → vulnerability → target), which only a graph can traverse in one step.
- **If asked about cost:** Emphasize that every data source and the embedding model are free; only the LLM synthesis step has a cost, and even that has a free/offline alternative (Ollama).
