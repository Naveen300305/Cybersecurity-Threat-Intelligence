# 🔐 CyberGraph Intelligence Platform
### A Graph RAG–Powered Cybersecurity Threat Intelligence System

> *"Threats don't exist in isolation — they live in relationships. Graph RAG is the only architecture that thinks the same way attackers do."*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Vision & Goals](#2-project-vision--goals)
3. [System Architecture Overview](#3-system-architecture-overview)
4. [Data Sources](#4-data-sources)
5. [Graph Knowledge Schema](#5-graph-knowledge-schema)
6. [Core Modules](#6-core-modules)
   - [Module 1 – Data Ingestion & ETL Pipeline](#module-1--data-ingestion--etl-pipeline)
   - [Module 2 – Graph RAG Query Engine](#module-2--graph-rag-query-engine)
   - [Module 3 – Threat Actor Intelligence](#module-3--threat-actor-intelligence)
   - [Module 4 – Vulnerability Intelligence](#module-4--vulnerability-intelligence)
   - [Module 5 – Attack Path Analyzer](#module-5--attack-path-analyzer)
   - [Module 6 – IOC Correlation Engine](#module-6--ioc-correlation-engine)
   - [Module 7 – Threat Hunting Workbench](#module-7--threat-hunting-workbench)
   - [Module 8 – Risk Scoring Engine](#module-8--risk-scoring-engine)
   - [Module 9 – Incident Response Assistant](#module-9--incident-response-assistant)
   - [Module 10 – Executive Intelligence Dashboard](#module-10--executive-intelligence-dashboard)
7. [Technology Stack](#7-technology-stack)
8. [REST API Design](#8-rest-api-design)
9. [Phased Build Plan (6 Weeks)](#9-phased-build-plan-6-weeks)
10. [Sample Queries & Use Cases](#10-sample-queries--use-cases)
11. [Security & Compliance Considerations](#11-security--compliance-considerations)
12. [Future Enhancements](#12-future-enhancements)

---

## 1. Executive Summary

**CyberGraph Intelligence Platform** is a production-grade, open-source-data–powered threat intelligence system built on **Graph RAG** (Graph Retrieval-Augmented Generation). It models the cybersecurity universe — threat actors, CVEs, malware families, attack techniques, targeted industries, and defensive mitigations — as a rich, interconnected knowledge graph in **Neo4j**, and exposes that graph to an LLM through a **LangChain-orchestrated RAG pipeline**.

Unlike traditional flat-document RAG (where chunks of text are retrieved by vector similarity), Graph RAG traverses multi-hop relationships — the exact way security analysts think. A query about APT29 can automatically traverse to their known campaigns, tools deployed, techniques used, CVEs exploited, and the software those CVEs affect — all in a single reasoning chain.

**What makes this unique:**
- 100% built on **free, public datasets** (NVD, MITRE ATT&CK, CAPEC, CWE, AlienVault OTX, CISA KEV)
- Modular architecture — each intelligence capability is a self-contained module
- Graph-native reasoning — answers multi-hop queries that flat RAG cannot
- Analyst-grade output — not just facts, but relationship context, risk scoring, and IR guidance

---

## 2. Project Vision & Goals

### Problem Statement

Security Operations Center (SOC) analysts face three compounding challenges:

| Challenge | Reality |
|---|---|
| **Data Fragmentation** | CVE databases, threat intel feeds, ATT&CK mappings, and IOC lists exist in silos with no relational context |
| **Multi-hop Blind Spots** | "Which unpatched systems are at risk from APT29?" requires joining 5+ data sources manually |
| **Alert Fatigue** | Analysts drown in individual alerts with no graph context to understand campaign-level patterns |

### Vision

A single natural-language interface where a security analyst can ask:

- *"What techniques does APT29 use that exploit unpatched Apache servers?"*
- *"Map the attack path from initial access to data exfiltration for LockBit ransomware"*
- *"Which CVEs disclosed this month have known exploits AND are targeted by nation-state actors?"*
- *"Generate an incident response playbook for a Cobalt Strike beacon detected on a Windows domain controller"*

...and receive **graph-traversed, relationship-aware, LLM-synthesized answers** — not just a list of documents.

### Core Goals

1. Ingest and normalize data from 6+ public threat intelligence sources into a unified Neo4j graph
2. Build a Graph RAG engine capable of multi-hop relationship traversal + LLM synthesis
3. Deliver 10 modular intelligence capabilities on top of the shared graph
4. Provide a REST API and analyst UI for all modules
5. Enable scheduled refresh of live threat feeds (OTX pulses, CISA KEV, NVD)

---

## 3. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CyberGraph Intelligence Platform                     │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    DATA INGESTION LAYER                              │   │
│  │  NVD/NIST  │  MITRE ATT&CK  │  CAPEC/CWE  │  AlienVault OTX  │CISA │   │
│  │      ↓            ↓               ↓               ↓             ↓   │   │
│  │               ETL Pipeline (Python + Celery)                        │   │
│  └────────────────────────────┬─────────────────────────────────────────┘   │
│                               ↓                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    GRAPH KNOWLEDGE LAYER                             │   │
│  │                                                                      │   │
│  │              Neo4j Graph Database (AuraDB Free / Self-hosted)        │   │
│  │         ┌─────────────────────────────────────────────┐             │   │
│  │         │  Nodes: Actor, CVE, Technique, Malware,     │             │   │
│  │         │         IOC, Campaign, CWE, Product,        │             │   │
│  │         │         Mitigation, Country, Sector         │             │   │
│  │         │  Relationships: USES, EXPLOITS, AFFECTS,    │             │   │
│  │         │                 ATTRIBUTED_TO, MITIGATED_BY │             │   │
│  │         └─────────────────────────────────────────────┘             │   │
│  │                     + Vector Index (Embeddings)                      │   │
│  └────────────────────────────┬─────────────────────────────────────────┘   │
│                               ↓                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    GRAPH RAG REASONING LAYER                         │   │
│  │                                                                      │   │
│  │   LangChain Orchestrator                                             │   │
│  │   ├── GraphCypherQAChain   (structured graph queries)               │   │
│  │   ├── Neo4jVector Retriever (semantic similarity on embeddings)      │   │
│  │   ├── Graph Traversal Agent (multi-hop path reasoning)              │   │
│  │   └── LLM Synthesis Layer  (Claude / GPT-4 / Ollama)               │   │
│  └────────────────────────────┬─────────────────────────────────────────┘   │
│                               ↓                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    MODULE LAYER (10 Capabilities)                    │   │
│  │                                                                      │   │
│  │  [1] ETL Pipeline    [2] RAG Engine     [3] Actor Intel             │   │
│  │  [4] Vuln Intel      [5] Attack Path    [6] IOC Correlation         │   │
│  │  [7] Threat Hunting  [8] Risk Scoring   [9] IR Assistant            │   │
│  │  [10] Exec Dashboard                                                 │   │
│  └────────────────────────────┬─────────────────────────────────────────┘   │
│                               ↓                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    DELIVERY LAYER                                    │   │
│  │      FastAPI REST API  │  Streamlit Analyst UI  │  CLI Tool         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Sources

All data sources used in this project are **free and publicly available**.

| Source | Content | Format | Refresh Cadence | API/Download |
|---|---|---|---|---|
| **NVD / NIST** | CVE details, CVSS scores, CPE (affected products), CWE mappings | JSON feeds | Daily | REST API + bulk JSON |
| **MITRE ATT&CK** | Tactics, Techniques, Sub-techniques, Groups (APTs), Software (malware/tools), Mitigations, Data Sources | STIX 2.1 / JSON | Monthly releases | GitHub + TAXII |
| **MITRE CAPEC** | Attack patterns mapped to CWEs and ATT&CK techniques | XML / JSON | Quarterly | GitHub |
| **MITRE CWE** | Weakness types, relationships between weaknesses | XML | Quarterly | GitHub |
| **AlienVault OTX** | Threat pulses, IOCs (IPs, domains, hashes, URLs), actor associations | JSON | Real-time | Free REST API |
| **CISA KEV** | Known Exploited Vulnerabilities — CVEs with confirmed in-the-wild exploitation | JSON | Real-time | Public JSON feed |
| **EPSS** (optional) | Exploit Prediction Scoring System — probability of CVE exploitation | CSV | Daily | FIRST.org |

### Data Volume Estimates

| Source | Approximate Records |
|---|---|
| NVD CVEs (all-time) | ~250,000 CVEs |
| MITRE ATT&CK Techniques | ~600 techniques + sub-techniques |
| ATT&CK Groups (APTs) | ~140+ named groups |
| ATT&CK Software | ~700+ malware/tool entries |
| CAPEC Attack Patterns | ~550 patterns |
| CWE Weaknesses | ~900 weakness types |
| AlienVault OTX Pulses | Millions (filter by recency/relevance) |
| CISA KEV | ~1,100+ CVEs (and growing) |

---

## 5. Graph Knowledge Schema

### Node Types

```
(:ThreatActor)
  - id            : String  (e.g., "G0016" from ATT&CK)
  - name          : String  (e.g., "APT29", "Cozy Bear")
  - aliases       : List    (e.g., ["Cozy Bear", "The Dukes", "IRON HEMLOCK"])
  - description   : String
  - motivation    : String  (e.g., "espionage", "financial")
  - sophistication: String  (e.g., "advanced")
  - first_seen    : Date
  - last_seen     : Date
  - embedding     : List[Float]   (vector embedding of description)

(:Campaign)
  - id            : String
  - name          : String
  - description   : String
  - first_seen    : Date
  - last_seen     : Date
  - objective     : String

(:Technique)
  - id            : String  (e.g., "T1566.001")
  - name          : String  (e.g., "Spearphishing Attachment")
  - description   : String
  - tactic_ids    : List
  - detection     : String
  - is_subtechnique: Boolean
  - embedding     : List[Float]

(:Tactic)
  - id            : String  (e.g., "TA0001")
  - name          : String  (e.g., "Initial Access")
  - description   : String
  - shortname     : String

(:Malware)
  - id            : String  (e.g., "S0002")
  - name          : String  (e.g., "Mimikatz", "Cobalt Strike")
  - type          : String  (e.g., "tool", "malware", "ransomware")
  - description   : String
  - aliases       : List
  - platforms     : List    (e.g., ["Windows", "Linux"])
  - embedding     : List[Float]

(:CVE)
  - id            : String  (e.g., "CVE-2021-44228")
  - description   : String
  - cvss_v3_score : Float
  - cvss_v3_vector: String
  - severity      : String  (Critical/High/Medium/Low)
  - published_date: Date
  - modified_date : Date
  - is_kev        : Boolean  (in CISA KEV catalog)
  - epss_score    : Float    (exploit prediction score)
  - epss_percentile: Float
  - embedding     : List[Float]

(:CWE)
  - id            : String  (e.g., "CWE-79")
  - name          : String  (e.g., "Cross-site Scripting")
  - description   : String
  - abstraction   : String  (Base/Class/Variant/Compound)

(:AffectedProduct)
  - cpe           : String  (CPE 2.3 URI, e.g., "cpe:2.3:a:apache:log4j:2.14.1:*...")
  - vendor        : String
  - product       : String
  - version       : String

(:AttackPattern)     # From CAPEC
  - id            : String  (e.g., "CAPEC-66")
  - name          : String
  - description   : String
  - likelihood    : String
  - severity      : String
  - prerequisites : String

(:Mitigation)
  - id            : String  (e.g., "M1031")
  - name          : String  (e.g., "Network Intrusion Prevention")
  - description   : String

(:IOC)
  - value         : String  (IP, domain, hash, URL)
  - type          : String  (e.g., "IPv4", "domain", "FileHash-SHA256")
  - first_seen    : DateTime
  - last_seen     : DateTime
  - confidence    : Integer
  - tlp           : String  (Traffic Light Protocol: White/Green/Amber/Red)

(:Country)
  - code          : String  (ISO 3166-1 alpha-2)
  - name          : String

(:Sector)
  - name          : String  (e.g., "Healthcare", "Finance", "Energy", "Government")

(:DataSource)        # ATT&CK detection data sources
  - id            : String
  - name          : String
  - description   : String
```

### Relationship Types

```
# Threat Actor Relationships
(:ThreatActor)-[:USES]->(:Technique)
(:ThreatActor)-[:DEPLOYS]->(:Malware)
(:ThreatActor)-[:ATTRIBUTED_TO]->(:Country)
(:ThreatActor)-[:CONDUCTED]->(:Campaign)
(:ThreatActor)-[:TARGETS]->(:Sector)
(:ThreatActor)-[:ASSOCIATED_WITH]->(:IOC)

# Campaign Relationships
(:Campaign)-[:USES]->(:Technique)
(:Campaign)-[:DEPLOYS]->(:Malware)
(:Campaign)-[:TARGETS]->(:Sector)
(:Campaign)-[:EXPLOITS]->(:CVE)

# Technique Relationships
(:Technique)-[:BELONGS_TO]->(:Tactic)
(:Technique)-[:HAS_SUBTECHNIQUE]->(:Technique)
(:Technique)-[:MITIGATED_BY]->(:Mitigation)
(:Technique)-[:DETECTED_BY]->(:DataSource)
(:Technique)-[:RELATED_TO]->(:AttackPattern)    # ATT&CK ↔ CAPEC bridge

# Malware Relationships
(:Malware)-[:EXPLOITS]->(:CVE)
(:Malware)-[:USES]->(:Technique)

# CVE Relationships
(:CVE)-[:AFFECTS]->(:AffectedProduct)
(:CVE)-[:HAS_WEAKNESS]->(:CWE)
(:CVE)-[:MAPPED_TO]->(:AttackPattern)           # via CAPEC cross-reference

# Attack Pattern (CAPEC) Relationships
(:AttackPattern)-[:TARGETS_WEAKNESS]->(:CWE)
(:AttackPattern)-[:CHILD_OF]->(:AttackPattern)

# IOC Relationships
(:IOC)-[:ASSOCIATED_WITH]->(:Campaign)
(:IOC)-[:ASSOCIATED_WITH]->(:ThreatActor)
(:IOC)-[:ASSOCIATED_WITH]->(:Malware)
```

### Graph Statistics (Expected at Full Ingestion)

| Entity | Count |
|---|---|
| Total Nodes | ~500,000+ |
| Total Relationships | ~2,000,000+ |
| ThreatActor nodes | ~140 |
| CVE nodes | ~250,000 |
| Technique nodes | ~600 |
| Malware nodes | ~700 |
| IOC nodes | ~100,000+ (OTX) |
| AffectedProduct nodes | ~500,000+ |

---

## 6. Core Modules

---

### Module 1 – Data Ingestion & ETL Pipeline

**Purpose:** Ingest, normalize, deduplicate, and load all threat intelligence data sources into Neo4j on a scheduled basis.

**Sub-components:**

#### 1.1 Source Connectors

```
ingestion/
├── connectors/
│   ├── nvd_connector.py        # NVD REST API v2 + bulk JSON feeds
│   ├── attack_connector.py     # MITRE ATT&CK via mitreattack-python library
│   ├── capec_connector.py      # CAPEC XML parser
│   ├── cwe_connector.py        # CWE XML parser
│   ├── otx_connector.py        # AlienVault OTX REST API
│   ├── cisa_kev_connector.py   # CISA KEV JSON feed
│   └── epss_connector.py       # FIRST.org EPSS daily CSV
├── transformers/
│   ├── stix_parser.py          # STIX 2.1 bundle → internal schema
│   ├── cpe_normalizer.py       # CPE string normalization
│   └── ioc_deduplicator.py     # IOC deduplication + TLP handling
├── loaders/
│   ├── neo4j_loader.py         # Batch MERGE operations to Neo4j
│   └── embedding_generator.py  # Generate + store node embeddings
└── scheduler.py                # Celery + Redis task scheduler
```

#### 1.2 Ingestion Strategy

- **Initial bulk load:** Full historical ingestion of NVD, ATT&CK, CAPEC, CWE (one-time, ~2–4 hours)
- **Incremental refresh:** NVD modified feed (daily), CISA KEV (daily), OTX pulses (hourly), EPSS (daily)
- **Idempotency:** All loads use Neo4j `MERGE` (not `CREATE`) — safe to re-run without duplicates
- **Embedding generation:** On first ingest, generate text embeddings for all nodes with `description` fields; store in Neo4j vector index

#### 1.3 Key Libraries

```python
# Core
mitreattack-python     # Official MITRE ATT&CK Python SDK
OTXv2                  # AlienVault OTX Python SDK
requests               # HTTP calls to NVD, CISA, EPSS
celery                 # Task scheduling
redis                  # Celery broker

# Neo4j
neo4j                  # Official Python driver
langchain-neo4j        # LangChain Neo4j integration

# Embeddings
sentence-transformers  # Local embedding model (free, no API cost)
                       # Alternative: OpenAI text-embedding-3-small
```

#### 1.4 Sample ETL Flow (NVD CVE)

```
NVD API Response
      ↓
  Extract CVE fields (id, description, cvss, cpe, cwe)
      ↓
  Normalize CPE strings → AffectedProduct schema
      ↓
  MERGE (:CVE) node
  MERGE (:AffectedProduct) nodes
  MERGE (:CWE) nodes
  CREATE relationships: CVE-[:AFFECTS]->Product, CVE-[:HAS_WEAKNESS]->CWE
      ↓
  Check if CVE is in CISA KEV → set is_kev=True
  Join EPSS scores → set epss_score, epss_percentile
      ↓
  Generate embedding for CVE description → store in vector index
```

---

### Module 2 – Graph RAG Query Engine

**Purpose:** The brain of the platform. Accepts natural language queries and returns graph-traversed, LLM-synthesized answers with full relationship context.

**This is what separates CyberGraph from flat-document RAG systems.**

#### 2.1 Dual Retrieval Strategy

The engine uses two complementary retrieval modes, combined automatically based on query type:

| Mode | Mechanism | Best For |
|---|---|---|
| **Graph Traversal** | Cypher query generated by LLM via GraphCypherQAChain | Structured, relationship-based queries ("What CVEs does APT29 exploit?") |
| **Vector Similarity** | Neo4j vector index + cosine similarity | Semantic/fuzzy queries ("techniques similar to phishing") |

#### 2.2 Architecture

```python
# Simplified architecture

class CyberGraphRAGEngine:
    def __init__(self):
        self.graph = Neo4jGraph(url, username, password)
        self.vector_store = Neo4jVector(embedding_model, graph=self.graph)
        
        # Chain 1: Cypher-based structured retrieval
        self.cypher_chain = GraphCypherQAChain.from_llm(
            llm=llm,
            graph=self.graph,
            cypher_prompt=CYBERSEC_CYPHER_PROMPT,  # domain-tuned prompt
            verbose=True,
            top_k=10
        )
        
        # Chain 2: Vector-based semantic retrieval
        self.vector_retriever = self.vector_store.as_retriever(
            search_kwargs={"k": 5, "fetch_k": 20}
        )
        
        # Chain 3: Hybrid merge + LLM synthesis
        self.synthesis_chain = RetrievalQA(
            llm=llm,
            retriever=HybridRetriever(self.cypher_chain, self.vector_retriever),
            prompt=SYNTHESIS_PROMPT
        )
    
    def query(self, question: str, context: dict = None) -> RAGResponse:
        # Route query to appropriate chain(s)
        # Traverse graph
        # Synthesize answer with relationship context
        # Return structured response with sources
```

#### 2.3 Custom Cypher Prompt Engineering

The LLM needs domain-specific guidance to generate correct Cypher:

```
CYBERSEC_CYPHER_PROMPT = """
You are an expert at translating cybersecurity questions into Neo4j Cypher queries.

Graph Schema:
- (:ThreatActor {id, name, aliases, motivation})
- (:CVE {id, cvss_v3_score, severity, is_kev, epss_score})
- (:Technique {id, name, description})
- (:Malware {id, name, type, platforms})
- ... [full schema]

Relationships:
- (ThreatActor)-[:USES]->(Technique)
- (ThreatActor)-[:DEPLOYS]->(Malware)
- (Malware)-[:EXPLOITS]->(CVE)
- (CVE)-[:AFFECTS]->(AffectedProduct)
...

Rules:
1. Always use MATCH with optional WHERE for filtering
2. For multi-hop queries, chain relationships explicitly
3. Use toLower() for string matching
4. Return entity properties relevant to the question
5. Limit results to 25 unless asked for more

Question: {question}
Cypher:
"""
```

#### 2.4 Multi-Hop Example

**Query:** *"What Windows software is at risk from APT29's techniques, and are those CVEs in the CISA KEV catalog?"*

**Generated Cypher:**
```cypher
MATCH (actor:ThreatActor {name: "APT29"})
-[:USES]->(technique:Technique)
<-[:USES]-(malware:Malware)
-[:EXPLOITS]->(cve:CVE)
-[:AFFECTS]->(product:AffectedProduct)
WHERE toLower(product.product) CONTAINS "windows"
  OR toLower(product.vendor) CONTAINS "microsoft"
RETURN actor.name, technique.name, malware.name, 
       cve.id, cve.cvss_v3_score, cve.is_kev, 
       product.vendor, product.product
ORDER BY cve.cvss_v3_score DESC
LIMIT 25
```

#### 2.5 Response Structure

```json
{
  "query": "What Windows software is at risk from APT29's techniques?",
  "answer": "APT29 poses significant risk to multiple Microsoft products...",
  "graph_context": {
    "traversal_depth": 4,
    "nodes_traversed": 47,
    "relationships_followed": ["USES", "EXPLOITS", "AFFECTS"]
  },
  "evidence": [
    {
      "path": "APT29 → USES → T1566.001 → DEPLOYS → Cobalt Strike → EXPLOITS → CVE-2021-40444 → AFFECTS → Microsoft MSHTML",
      "cve_in_kev": true,
      "cvss_score": 8.8
    }
  ],
  "cypher_used": "MATCH (actor:ThreatActor...",
  "sources": ["MITRE ATT&CK", "NVD", "CISA KEV"]
}
```

---

### Module 3 – Threat Actor Intelligence

**Purpose:** Generate comprehensive intelligence profiles for any threat actor in the graph — APT groups, cybercriminal organizations, hacktivists.

**Key Capabilities:**

#### 3.1 Actor Profile Generator

Produces a structured, LLM-synthesized dossier for a named threat actor including:
- Known aliases and attribution confidence
- Country of origin (if attributed)
- Primary motivations (espionage, financial, disruption)
- Targeted sectors and geographies
- Complete TTP (Tactics, Techniques, Procedures) profile mapped to MITRE ATT&CK
- Known malware/toolset arsenal
- Associated campaigns (named operations)
- Related IOCs (IPs, domains, hashes)
- Active CVEs in their exploitation repertoire

#### 3.2 Actor Comparison Engine

Compare two threat actors side-by-side:
```
Query: "Compare APT28 and APT29 — what techniques do they share vs. differ on?"

Output:
  Shared Techniques (overlap): T1566, T1059, T1055, T1078 ...
  APT28 Unique: T1190, T1203 (more exploitation-focused)
  APT29 Unique: T1550, T1563 (more living-off-the-land)
  Common Targets: Government, Defense, Think Tanks
  Differential Targets: APT28→Military; APT29→Healthcare, Research
```

**Cypher:**
```cypher
// Find shared and unique techniques between two actors
MATCH (a1:ThreatActor {name: "APT28"})-[:USES]->(t:Technique)
MATCH (a2:ThreatActor {name: "APT29"})-[:USES]->(t)
RETURN t.id, t.name AS shared_techniques

UNION

MATCH (a1:ThreatActor {name: "APT28"})-[:USES]->(t:Technique)
WHERE NOT EXISTS {
  MATCH (a2:ThreatActor {name: "APT29"})-[:USES]->(t)
}
RETURN t.id, t.name AS apt28_unique
```

#### 3.3 Actor Relationship Graph

Returns a subgraph visualization of all entities connected to a threat actor within N hops — useful for analysts exploring an unfamiliar group.

---

### Module 4 – Vulnerability Intelligence

**Purpose:** Transform raw CVE data into actionable intelligence by enriching vulnerabilities with threat actor context, exploitation evidence, and prioritization signals.

#### 4.1 CVE Enrichment Engine

For any CVE, automatically pull and synthesize:
- CVSS v3 base score + vector string breakdown (AV, AC, PR, UI, S, C, I, A)
- CWE root cause classification
- All affected products (CPE list)
- Known exploitation by specific threat actors or malware
- CISA KEV status (confirmed in-the-wild exploitation)
- EPSS score (probability of exploitation in next 30 days)
- Related ATT&CK techniques via CAPEC bridge
- Recommended mitigations

#### 4.2 Vulnerability Prioritization Scoring

Standard CVSS alone is a poor prioritization signal. CyberGraph implements a composite **ThreatPriority Score (TPS)**:

```
ThreatPriority Score (TPS) = 
    (CVSS_v3 × 0.25) +
    (KEV_Flag × 30) +           # +30 points if in CISA KEV
    (EPSS_Percentile × 20) +    # Up to +20 based on exploitation probability
    (Actor_Count × 2) +         # +2 per known threat actor exploiting it
    (Malware_Count × 3) +       # +3 per malware known to exploit it
    (Recency_Bonus × 5)         # +5 if published in last 90 days

Score range: 0–100 (normalized)
```

#### 4.3 "Threat-in-Context" Query

*"Show me all Critical CVEs in Apache products that have known exploits AND are targeted by state-sponsored actors"*

```cypher
MATCH (cve:CVE)-[:AFFECTS]->(p:AffectedProduct)
WHERE p.vendor = "apache"
  AND cve.severity = "Critical"
  AND cve.is_kev = true
WITH cve
MATCH (actor:ThreatActor {motivation: "espionage"})-[:DEPLOYS]->(:Malware)-[:EXPLOITS]->(cve)
RETURN cve.id, cve.cvss_v3_score, cve.epss_score, 
       collect(DISTINCT actor.name) AS exploiting_actors
ORDER BY cve.cvss_v3_score DESC
```

#### 4.4 Newly Published CVE Alerts

Daily scheduled task that:
1. Pulls last 24h of NVD CVEs
2. Scores each with TPS
3. Cross-references against ATT&CK-mapped techniques
4. Sends digest of Top-10 highest-priority new CVEs

---

### Module 5 – Attack Path Analyzer

**Purpose:** One of the most powerful modules. Given a starting point (threat actor, initial access technique, or compromised asset) and an end goal (data exfiltration, lateral movement, privilege escalation), compute the most likely attack paths through the graph.

#### 5.1 Full Kill Chain Mapper

Maps a complete attack campaign from initial access to objective, following ATT&CK tactic ordering:

```
Initial Access → Execution → Persistence → Privilege Escalation → 
Defense Evasion → Credential Access → Discovery → Lateral Movement → 
Collection → Command & Control → Exfiltration / Impact
```

**Query:** *"Map the full kill chain for LockBit 3.0 ransomware"*

```cypher
MATCH path = (malware:Malware {name: "LockBit 3.0"})
             -[:USES]->(technique:Technique)
             -[:BELONGS_TO]->(tactic:Tactic)
RETURN tactic.name, collect(technique.name) AS techniques
ORDER BY tactic.id
```

#### 5.2 Shortest Attack Path (Graph Shortest Path Algorithm)

Leverages Neo4j Graph Data Science (GDS) plugin to find shortest paths:

*"What is the shortest path from an unauthenticated internet position to domain admin in a Windows Active Directory environment?"*

```cypher
// Using Neo4j GDS shortest path
CALL gds.shortestPath.dijkstra.stream('attack-graph', {
  sourceNode: id(startNode),
  targetNode: id(targetNode),
  relationshipWeightProperty: 'difficulty'
})
YIELD index, sourceNode, targetNode, totalCost, nodeIds, costs, path
RETURN path
```

#### 5.3 Attack Tree Generation

Generates a structured attack tree document (in Markdown or JSON) showing all feasible attack paths to a given objective, organized by likelihood and impact.

#### 5.4 Defensive Gap Analysis

*"APT29 uses 23 techniques across 8 tactics. Which of those techniques do we currently have NO detection coverage for?"*

Given a list of deployed detection data sources (e.g., Sysmon, EDR, DNS logs, NetFlow), identify ATT&CK technique gaps:

```cypher
MATCH (actor:ThreatActor {name: "APT29"})-[:USES]->(t:Technique)
WHERE NOT EXISTS {
  MATCH (t)-[:DETECTED_BY]->(ds:DataSource)
  WHERE ds.name IN $deployed_data_sources
}
RETURN t.id, t.name AS undetected_techniques, 
       t.tactic_ids AS tactics
```

---

### Module 6 – IOC Correlation Engine

**Purpose:** Take raw IOCs (IPs, domains, file hashes, URLs) observed in the environment and automatically enrich them with full threat graph context — connecting them to actors, campaigns, malware families, and techniques.

#### 6.1 IOC Lookup & Graph Context

**Input:** A list of IOCs (from SIEM alert, incident ticket, sandbox report)

**Output:** For each IOC:
- Associated threat actor(s)
- Associated campaign(s)
- Malware family link
- Related IOCs (pivot points) within the same campaign
- ATT&CK techniques associated with the malware
- Geographic origin (if attributed)
- TLP classification and confidence score

#### 6.2 IOC Pivot Engine

Given one IOC, traverse the graph to discover related IOCs — exactly how threat hunters manually pivot through threat intel:

```cypher
// Pivot: given a domain IOC, find all related IOCs in same campaign
MATCH (seed:IOC {value: $input_ioc})
-[:ASSOCIATED_WITH]->(campaign:Campaign)
<-[:ASSOCIATED_WITH]-(related:IOC)
WHERE related.value <> $input_ioc
RETURN related.value, related.type, related.first_seen,
       campaign.name, related.confidence
ORDER BY related.confidence DESC
```

#### 6.3 IOC Feed Management

- Pulls new OTX pulses every hour via Celery beat
- Deduplicates IOCs (same hash may appear in multiple pulses)
- Maintains TLP levels — never expose TLP:RED IOCs in shared responses
- Tracks IOC age — marks IOCs >180 days old as stale (configurable threshold)

#### 6.4 Bulk IOC Screening

Accepts a file upload (CSV/JSON/STIX) of IOCs and batch-screens against the graph — ideal for post-incident analysis of firewall logs or SIEM exports.

---

### Module 7 – Threat Hunting Workbench

**Purpose:** Provide threat hunters with a hypothesis-driven query environment that combines natural language, graph traversal, and ATT&CK-mapped detection logic.

#### 7.1 Hunt Hypothesis Builder

Threat hunting starts with a hypothesis. The workbench takes a hypothesis and builds:
1. The graph query to validate it
2. The relevant ATT&CK techniques to look for
3. The detection data sources required
4. Sample SIEM/EDR queries (Sigma rules)

**Example hypothesis:** *"APT29 may have used living-off-the-land techniques on our Windows endpoints in the last 30 days"*

**Generated output:**
- Graph query: Find APT29's LOLBin techniques
- ATT&CK techniques: T1218 (Signed Binary Proxy Execution), T1059.001 (PowerShell)
- Detection sources needed: Windows Event Logs (4688, 4104), PowerShell ScriptBlock logging
- Sigma rule: Generated for each technique

#### 7.2 Hunt Package Generator

For any threat actor or campaign, generates a complete **Hunt Package**:

```markdown
# Hunt Package: APT29 Active Defense Hunt
Generated: 2024-01-15

## Threat Summary
APT29 (Cozy Bear) is a Russian SVR-affiliated APT group...

## Techniques to Hunt (23 techniques across 8 tactics)
### Initial Access
- T1566.002 – Spearphishing Link
  Detection: Email gateway logs, proxy logs
  Sigma: [generated Sigma rule]

### Persistence  
- T1053.005 – Scheduled Task
  Detection: Windows Event ID 4698
  Sigma: [generated Sigma rule]
...

## IOCs Associated with APT29 (active last 90 days)
| Type | Value | Confidence | Campaign |
|------|-------|------------|---------|
| domain | evil.example.com | 85 | Operation Bluebird |
...

## Recommended Data Sources
- Windows Security Event Log
- Sysmon (recommended config: SwiftOnSecurity)
- DNS query logs
- Proxy/web gateway logs
```

#### 7.3 ATT&CK Navigator Layer Export

Exports a JSON layer file compatible with **MITRE ATT&CK Navigator** — showing which techniques a specific actor uses, color-coded by detection coverage:
- 🟥 Red: Actor uses this, we have no detection
- 🟨 Yellow: Actor uses this, partial detection
- 🟩 Green: Actor uses this, full detection coverage

---

### Module 8 – Risk Scoring Engine

**Purpose:** Translate graph relationships into quantitative risk scores for assets, environments, and organizational sectors — enabling prioritized defensive investment.

#### 8.1 Asset Risk Scoring

Given a list of software/products in your environment (from CMDB or manual input), compute a **Asset Risk Score**:

```
Asset Risk Score for "Microsoft Exchange Server 2019" =
  Σ (CVE ThreatPriority Score for all CVEs affecting this product) +
  Actor_Targeting_Weight (# of APT groups known to target this product) +
  KEV_Count × 20 (# of KEV CVEs affecting this product)
```

#### 8.2 Sector Risk Intelligence

Computes risk profiles by industry sector:

*"Which threat actors are most active against the Healthcare sector right now, and what are their top techniques?"*

```cypher
MATCH (actor:ThreatActor)-[:TARGETS]->(sector:Sector {name: "Healthcare"})
MATCH (actor)-[:USES]->(technique:Technique)-[:BELONGS_TO]->(tactic:Tactic)
MATCH (actor)-[:DEPLOYS]->(malware:Malware)
RETURN actor.name, actor.motivation,
       collect(DISTINCT technique.name) AS techniques,
       collect(DISTINCT malware.name) AS tools
ORDER BY size(collect(DISTINCT technique.name)) DESC
```

#### 8.3 Coverage Gap Score

Scores the organization's detection coverage against its relevant threat actors:

```
Coverage Gap Score = 
  (Actor_Techniques_Not_Detected / Total_Actor_Techniques) × 100

Where:
  Actor_Techniques_Not_Detected = ATT&CK techniques used by relevant actors
                                   with no matching detection data source deployed
  Total_Actor_Techniques = all techniques used by relevant actors
```

A Coverage Gap Score of 0% = full coverage. 100% = no detection coverage at all.

#### 8.4 Trend Analysis

Tracks changes in the threat landscape over time:
- New CVEs in CISA KEV this week vs. last week
- New threat actors active against your sector
- Technique popularity trends (which ATT&CK techniques are appearing more in recent campaigns)

---

### Module 9 – Incident Response Assistant

**Purpose:** During an active incident, provide the IR team with graph-powered context — accelerating triage, scoping, and containment decision-making.

#### 9.1 Incident Context Enrichment

**Input:** Any combination of:
- IOCs from the incident (IPs, domains, hashes)
- Observed techniques (from EDR or analyst notes)
- Affected software/systems

**Output:**
- Most likely threat actor(s) responsible (similarity scoring against known actor TTPs)
- Likely campaign attribution
- Predicted next moves (based on actor's known kill chain)
- Affected systems scope (via AffectedProduct graph traversal)
- Recommended containment actions

#### 9.2 IR Playbook Generator

Generates a structured, graph-grounded IR playbook for a specific scenario:

**Scenario:** *"Cobalt Strike beacon detected on Windows Server 2019 domain controller. What do I do?"*

**Generated Playbook:**
```markdown
# IR Playbook: Cobalt Strike on Windows Domain Controller
Severity: CRITICAL | Generated by CyberGraph Intelligence Platform

## Threat Context
Cobalt Strike is used by 47 documented threat actors including:
- APT29 (Russian SVR), APT41 (Chinese MSS), LockBit (ransomware),
  FIN7 (financial), Lazarus Group (DPRK)...

## Techniques Likely Active (via graph)
Based on Cobalt Strike's documented ATT&CK mapping:
- T1059.001 – PowerShell execution
- T1055 – Process injection
- T1134 – Access Token Manipulation
- T1021.002 – SMB/Windows Admin Shares (lateral movement risk)
- T1003.001 – LSASS Memory dump (credential theft risk)

## Immediate Containment (0–30 minutes)
1. Isolate the DC from the network (do NOT power off — preserve memory artifacts)
2. Block all SMB (445) egress from the DC at the firewall
3. Reset KRBTGT password TWICE (mitigates Kerberos Golden Ticket risk)
4. Revoke and rotate all service account credentials
5. Block known Cobalt Strike C2 IOCs at DNS/proxy: [list from graph]

## CVEs to Check on This System
[Auto-pulled: CVEs affecting Windows Server 2019, is_kev=true, 
 known to be exploited by Cobalt Strike operators]

## Recommended Forensic Artifacts
- Windows Security Event Log (ID: 4624, 4688, 4776)
- PowerShell ScriptBlock Log
- Sysmon Event ID 1, 3, 10
- LSASS memory dump for credential analysis
- Prefetch files for execution history

## Eradication
1. Rebuild domain controller from clean backup
2. Conduct full AD health check (BloodHound recommended)
3. Review all privileged access granted in last 30 days
```

#### 9.3 Actor Attribution Confidence Scorer

Given observed TTPs from an incident, scores likelihood of attribution to known threat actors:

```python
# Similarity between observed technique set and known actor technique sets
AttributionScore(actor) = 
    |observed_techniques ∩ actor_techniques| / |observed_techniques|
    × confidence_weight(actor)
```

Outputs a ranked list: APT29 (72% match), APT41 (45% match), FIN7 (38% match)...

---

### Module 10 – Executive Intelligence Dashboard

**Purpose:** Translate complex graph intelligence into concise, business-readable summaries for CISOs and executive audiences.

#### 10.1 Threat Landscape Summary

Weekly auto-generated executive brief:
- New critical CVEs affecting our technology stack
- Threat actor activity targeting our sector (this week vs. last week)
- Top 5 highest-priority vulnerabilities requiring attention
- Detection coverage health score trend

#### 10.2 CISO Dashboard Metrics

Real-time metrics served via API to the Streamlit UI:

| Metric | Description |
|---|---|
| **Active Threat Actors** | # of APT groups targeting your sector |
| **KEV Exposure Count** | # of CISA KEV CVEs in your product inventory |
| **Detection Coverage %** | % of relevant ATT&CK techniques with active detection |
| **TPS Top-10** | Highest-priority unpatched CVEs by ThreatPriority Score |
| **New Campaigns (7d)** | New campaigns added to the graph in last 7 days |
| **IOC Freshness** | % of IOCs updated in last 30 days |

#### 10.3 Report Export

Generates PDF/Markdown executive reports:
- **Monthly Threat Landscape Report** — sector-specific threat overview
- **Vulnerability Prioritization Report** — Top-20 CVEs to patch this sprint
- **Actor Spotlight** — Deep dive on a specific emerging threat group

---

## 7. Technology Stack

### Core Infrastructure

| Component | Technology | Justification |
|---|---|---|
| **Graph Database** | Neo4j 5.x (Community Edition / AuraDB Free) | Native graph traversal, GDS plugin, vector index, Cypher |
| **RAG Orchestration** | LangChain 0.3+ | GraphCypherQAChain, Neo4jVector, agent framework |
| **LLM Backend** | Claude 3.5 Sonnet / GPT-4o / Ollama (Mistral) | Pluggable; Claude recommended for long-context synthesis |
| **Embedding Model** | `sentence-transformers/all-MiniLM-L6-v2` (free, local) | No API cost; good quality for security text |
| **Task Queue** | Celery + Redis | Scheduled ETL jobs, async feed ingestion |
| **API Layer** | FastAPI | Async, auto-generated OpenAPI docs |
| **UI** | Streamlit | Rapid analyst UI; no frontend expertise needed |

### Python Libraries

```toml
[dependencies]
# Graph
neo4j = "^5.0"
langchain-neo4j = "^0.1"
langchain = "^0.3"
langchain-anthropic = "^0.2"   # or langchain-openai

# Data Ingestion
mitreattack-python = "^3.0"   # Official MITRE ATT&CK SDK
OTXv2 = "^1.5"               # AlienVault OTX
requests = "^2.31"
httpx = "^0.27"               # Async HTTP
lxml = "^5.0"                 # CAPEC/CWE XML parsing
stix2 = "^3.0"               # STIX bundle parsing

# Embeddings
sentence-transformers = "^2.7"

# Task Queue
celery = "^5.3"
redis = "^5.0"

# API
fastapi = "^0.111"
uvicorn = "^0.29"
pydantic = "^2.0"

# UI
streamlit = "^1.35"
streamlit-agraph = "^0.0.45"  # Graph visualization in Streamlit
pyvis = "^0.3"               # Interactive graph rendering

# Data Processing
pandas = "^2.2"
python-dotenv = "^1.0"
```

### Infrastructure (Docker Compose)

```yaml
services:
  neo4j:
    image: neo4j:5.20-community
    ports: ["7474:7474", "7687:7687"]
    environment:
      NEO4J_PLUGINS: '["graph-data-science", "apoc"]'
    volumes: ["neo4j_data:/data"]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  api:
    build: ./api
    ports: ["8000:8000"]
    depends_on: [neo4j, redis]

  worker:
    build: ./worker
    command: celery -A tasks worker --loglevel=info
    depends_on: [neo4j, redis]

  scheduler:
    build: ./worker
    command: celery -A tasks beat --loglevel=info
    depends_on: [redis]

  ui:
    build: ./ui
    ports: ["8501:8501"]
    depends_on: [api]
```

---

## 8. REST API Design

All modules expose endpoints via FastAPI. Base URL: `http://localhost:8000/api/v1`

### Core Endpoints

```
# Graph RAG Query Engine
POST   /query                        Query the graph in natural language
GET    /query/history                Recent query history

# Threat Actor Intelligence  
GET    /actors                       List all threat actors
GET    /actors/{name}                Full actor profile
GET    /actors/{name}/ttps           Actor's full TTP mapping
GET    /actors/{name}/campaigns      Actor's campaigns
POST   /actors/compare               Compare two actors side-by-side
GET    /actors/{name}/hunt-package   Download hunt package

# Vulnerability Intelligence
GET    /cves/{cve_id}                CVE enrichment with threat context
GET    /cves/top-priority            Top CVEs by ThreatPriority Score
GET    /cves/kev                     CISA KEV CVEs with actor context
POST   /cves/bulk-score              Score a list of CVEs

# Attack Path Analysis
POST   /attack-paths/map             Map attack paths given actor/technique
GET    /attack-paths/kill-chain/{actor}  Full kill chain for actor
POST   /attack-paths/gap-analysis    Detection gap analysis

# IOC Correlation
POST   /iocs/lookup                  Enrich one or many IOCs from graph
POST   /iocs/pivot/{ioc_value}       Pivot from IOC to related IOCs
POST   /iocs/bulk-screen             Batch IOC screening (file upload)

# Threat Hunting
POST   /hunting/hypothesis           Build hunt from hypothesis
GET    /hunting/packages/{actor}     Hunt package for actor
GET    /hunting/navigator/{actor}    ATT&CK Navigator layer (JSON)

# Risk Scoring
POST   /risk/asset-score             Score assets given product list
GET    /risk/sector/{sector_name}    Sector risk profile
GET    /risk/coverage-gap            Detection coverage gap report

# Incident Response
POST   /ir/enrich                    Enrich incident with graph context
POST   /ir/playbook                  Generate IR playbook
POST   /ir/attribute                 Actor attribution scoring

# Dashboard
GET    /dashboard/summary            Executive summary metrics
GET    /dashboard/landscape          Weekly threat landscape brief
```

### Sample API Call

```bash
# Natural language query
curl -X POST http://localhost:8000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What attack techniques does APT29 use that affect unpatched Windows servers?",
    "include_cypher": true,
    "max_hops": 4
  }'
```

---

## 9. Phased Build Plan (6 Weeks)

### Week 1 — Foundation: Graph Schema & Bulk Ingestion

**Goal:** A populated Neo4j graph with core MITRE and NVD data.

| Day | Task |
|---|---|
| 1 | Project setup: repo structure, Docker Compose, Neo4j + Redis up |
| 2 | Define and document full graph schema; create Neo4j constraints and indexes |
| 3 | MITRE ATT&CK ingestion (Techniques, Tactics, Groups, Software, Mitigations) |
| 4 | NVD CVE ingestion (last 2 years — ~40k CVEs to start, expand later) |
| 5 | CPE → AffectedProduct parsing and relationship creation |
| 6–7 | CWE + CAPEC ingestion; validate cross-links ATT&CK ↔ CAPEC ↔ CWE |

**Week 1 Deliverable:** Neo4j browser shows populated graph with ~50k+ nodes, verifiable Cypher queries return correct results.

---

### Week 2 — Intelligence Feeds & Embeddings

**Goal:** Live feeds running + vector search operational.

| Day | Task |
|---|---|
| 8 | AlienVault OTX connector — fetch recent pulses, parse IOCs, load graph |
| 9 | CISA KEV connector — mark CVE nodes with `is_kev=true` flag |
| 10 | EPSS connector — add `epss_score` and `epss_percentile` to CVE nodes |
| 11 | Celery scheduler — set up daily/hourly feed refresh jobs |
| 12 | Embedding generation — run batch embedding for all Technique, CVE, Malware, Actor nodes |
| 13 | Neo4j Vector Index creation and test semantic similarity queries |
| 14 | Integration tests — validate full data pipeline end to end |

**Week 2 Deliverable:** Automated feed updates running; vector similarity queries returning semantically relevant results.

---

### Week 3 — Graph RAG Engine & Core Modules (1–5)

**Goal:** Natural language queries working across the first five intelligence modules.

| Day | Task |
|---|---|
| 15 | LangChain GraphCypherQAChain setup + custom cybersecurity Cypher prompt |
| 16 | Hybrid retriever (vector + graph) architecture; test multi-hop queries |
| 17 | Module 3: Threat Actor profile API + actor comparison |
| 18 | Module 4: CVE enrichment + ThreatPriority Score computation |
| 19 | Module 5: Attack path mapper + kill chain generator |
| 20 | Module 6: IOC correlation + pivot engine |
| 21 | FastAPI skeleton — route all modules through API endpoints |

**Week 3 Deliverable:** CLI and API can answer natural language threat intel questions with graph-traversed responses.

---

### Week 4 — Advanced Modules (6–10)

**Goal:** Hunting, risk scoring, IR, and dashboard modules complete.

| Day | Task |
|---|---|
| 22 | Module 7: Hunt hypothesis builder + hunt package generator |
| 23 | ATT&CK Navigator layer export (JSON) |
| 24 | Module 8: Asset risk scoring + sector risk profiles |
| 25 | Module 8: Coverage gap analysis (requires user to input their data sources) |
| 26 | Module 9: IR enrichment + actor attribution confidence scorer |
| 27 | Module 9: IR playbook generator with graph-grounded context |
| 28 | Module 10: Executive dashboard metrics API |

**Week 4 Deliverable:** All 10 modules have working API endpoints; functional CLI tool for all major queries.

---

### Week 5 — Streamlit UI

**Goal:** A usable analyst interface with graph visualization.

| Day | Task |
|---|---|
| 29 | Streamlit app skeleton — sidebar navigation, page routing |
| 30 | Query page — natural language input, response display with sources |
| 31 | Threat Actor page — profile viewer, TTP grid, ATT&CK heatmap |
| 32 | CVE Intelligence page — search, enrich, prioritization list |
| 33 | IOC Lookup page — single IOC enrichment + pivot visualization (pyvis graph) |
| 34 | Executive Dashboard page — metrics, charts, weekly brief |
| 35 | Hunt Package page — actor selection → downloadable Markdown package |

**Week 5 Deliverable:** Functional Streamlit UI covering all major analyst workflows.

---

### Week 6 — Hardening, Testing & Documentation

**Goal:** Production-ready quality, documented, and demo-able.

| Day | Task |
|---|---|
| 36 | Performance optimization — Neo4j query profiling, add missing indexes |
| 37 | LLM prompt refinement — improve Cypher generation accuracy across edge cases |
| 38 | Unit + integration tests for all API endpoints (pytest) |
| 39 | README.md — setup guide, architecture overview, example queries |
| 40 | Architecture diagrams (draw.io / Mermaid) |
| 41 | Demo script — 10 showcase queries covering all modules |
| 42 | Final Docker Compose polish — one-command startup for the full platform |

**Week 6 Deliverable:** A polished, documented, demo-ready platform deployable with `docker compose up`.

---

## 10. Sample Queries & Use Cases

The following real-world analyst scenarios demonstrate the platform's multi-hop reasoning power:

---

### Query 1 — Classic Multi-hop Threat Intel
```
"What attack techniques does APT29 use that exploit unpatched Windows servers, 
and are any of those CVEs in the CISA Known Exploited Vulnerabilities catalog?"

Graph path: APT29 → USES → Technique → (malware deploys) → EXPLOITS → CVE 
            → AFFECTS → Windows product + is_kev=true filter
Hops: 5
Unique value over flat RAG: Connects actor → technique → CVE → product in one query
```

---

### Query 2 — Vulnerability Prioritization
```
"We're running Apache Log4j 2.14.1 in production. Which threat actors are 
actively exploiting it, what techniques do they use after initial access, 
and what's our risk?"

Graph path: AffectedProduct (Log4j 2.14.1) → CVE-2021-44228 
            ← EXPLOITS ← Malware ← DEPLOYS ← ThreatActor
            + ThreatActor → USES → Technique (post-exploitation)
```

---

### Query 3 — Ransomware Intelligence
```
"What is the complete attack chain for LockBit 3.0 ransomware, 
what CVEs does it exploit, and which Windows versions are at risk?"

Graph path: Malware (LockBit 3.0) → USES → [all Techniques ordered by Tactic]
            + Malware → EXPLOITS → CVE → AFFECTS → Product
```

---

### Query 4 — Sector Threat Profiling
```
"Which nation-state actors are currently targeting the Energy sector 
and what are their most dangerous techniques?"

Graph path: ThreatActor {motivation: espionage} → TARGETS → Sector {name: Energy}
            + Actor → USES → Technique → BELONGS_TO → Tactic
```

---

### Query 5 — Incident Attribution
```
"We observed these techniques: T1566.001, T1059.001, T1055, T1003.001, T1071.001.
Which threat actor is most likely responsible?"

Logic: Technique set intersection against all known actor TTP sets
       Attribution confidence ranked by overlap percentage
```

---

### Query 6 — Defensive Planning
```
"We have Sysmon, Windows Security Event Log, and Zeek network logs deployed.
Which APT29 techniques do we have NO visibility into?"

Graph path: APT29 → USES → Technique 
            WHERE NOT Technique → DETECTED_BY → DataSource in [Sysmon, WinSec, Zeek]
```

---

### Query 7 — IOC Investigation
```
"This IP 192.168.x.x appeared in our firewall logs. Is it associated with 
any known campaigns? What actor operates it? What other IOCs are related?"

Graph path: IOC {value: "..."} → ASSOCIATED_WITH → Campaign → ASSOCIATED_WITH → [related IOCs]
            + Campaign ← CONDUCTED ← ThreatActor
```

---

### Query 8 — Emerging Threat Brief
```
"What new CVEs were added to CISA KEV this week, are any targeted by 
active threat actors, and do we have any products in our stack affected?"

Logic: CVE {is_kev: true, published_date > NOW()-7d}
       + CVE ← EXPLOITS ← Malware ← DEPLOYS ← ThreatActor
       + CVE → AFFECTS → AffectedProduct WHERE product IN $our_inventory
```

---

## 11. Security & Compliance Considerations

### Data Classification

All data ingested by this platform is from **public sources** only — NVD, MITRE, CISA, AlienVault OTX public pulses. No sensitive internal data is stored unless the user explicitly provides asset inventory for risk scoring (stored locally only).

| Data Type | Classification | Storage |
|---|---|---|
| MITRE ATT&CK data | Public | Neo4j graph |
| NVD CVE data | Public | Neo4j graph |
| AlienVault OTX IOCs | Public (TLP:WHITE/GREEN) | Neo4j graph |
| User asset inventory | Internal/Confidential | Local only, not persisted |
| Incident context provided to IR module | Restricted | In-memory only, never stored |

### TLP (Traffic Light Protocol) Enforcement

- **TLP:WHITE** — Can be shared freely; stored in graph and queryable
- **TLP:GREEN** — Stored in graph; shared only within the organization
- **TLP:AMBER** — Stored in graph; not exposed in API responses by default
- **TLP:RED** — Never stored; used only for in-session enrichment

### LLM Data Handling

- All LLM API calls are made server-side through the FastAPI layer
- No raw incident data or internal asset information is sent to the LLM without explicit user confirmation
- For fully air-gapped deployments: swap Claude/GPT-4 for Ollama (Mistral, Llama 3) — 100% on-premises

### GDPR Relevance

This platform processes no personal data by default. All data is technical threat intelligence. If the platform is extended to include user activity logs or analyst notes, standard data retention and access control policies apply per organizational requirements.

---

## 12. Future Enhancements

### Near-term (Post-MVP)

- **STIX/TAXII Feed Integration** — Connect to commercial ISAC feeds (FS-ISAC, H-ISAC, etc.) for sector-specific intelligence
- **Sigma Rule Generator** — Auto-generate Sigma detection rules from ATT&CK technique + DataSource graph data
- **Shodan Integration** — Enrich AffectedProduct nodes with real-world exposure data (how many internet-exposed instances exist)
- **VirusTotal Enrichment** — Real-time hash/domain/IP enrichment for IOC module (free tier: 4 req/min)
- **Graph Temporal Analysis** — Track how threat actor TTPs evolve over time using Neo4j temporal properties

### Medium-term

- **Multi-tenant Support** — Allow multiple organization profiles, each with their own asset inventory and coverage data
- **SOAR Integration** — Webhook output to Splunk SOAR, Palo Alto XSOAR, or Shuffle for automated playbook execution
- **OpenCTI Sync** — Bidirectional sync with OpenCTI for organizations already using it as their CTI platform
- **Threat Modeling Module** — Take a system architecture diagram as input; auto-identify relevant threats, actors, and techniques using ATT&CK for ICS / ATT&CK for Cloud
- **Graph Anomaly Detection** — Use Neo4j GDS algorithms (community detection, centrality) to identify unusual relationships in the threat graph

### Long-term Vision

- **Private Threat Graph Overlay** — Let organizations add their own classified threat intel on top of the public graph, with strict access controls
- **Automated Threat Sharing** — Export enriched intelligence back to OTX/MISP in STIX 2.1 format
- **LLM Fine-tuning** — Fine-tune a smaller open-source model specifically on cybersecurity graph reasoning tasks

---

## Project Repository Structure

```
cybergraph-intel/
├── README.md
├── docker-compose.yml
├── .env.example
│
├── ingestion/                  # Module 1: ETL Pipeline
│   ├── connectors/
│   ├── transformers/
│   ├── loaders/
│   └── scheduler.py
│
├── graph/                      # Graph schema & utilities
│   ├── schema.py               # Node/relationship definitions
│   ├── indexes.cypher          # Index & constraint creation
│   └── queries/                # Reusable Cypher query library
│
├── rag/                        # Module 2: Graph RAG Engine
│   ├── engine.py
│   ├── prompts.py
│   ├── retrievers.py
│   └── chains.py
│
├── modules/                    # Modules 3–10
│   ├── actor_intel.py
│   ├── vuln_intel.py
│   ├── attack_path.py
│   ├── ioc_correlation.py
│   ├── threat_hunting.py
│   ├── risk_scoring.py
│   ├── ir_assistant.py
│   └── dashboard.py
│
├── api/                        # FastAPI REST API
│   ├── main.py
│   ├── routers/
│   └── schemas/
│
├── ui/                         # Streamlit UI
│   ├── app.py
│   └── pages/
│
├── tests/
│   ├── test_ingestion.py
│   ├── test_rag.py
│   └── test_modules.py
│
└── docs/
    ├── architecture.md
    ├── graph_schema.md
    └── api_reference.md
```

---

*Built with Neo4j · LangChain · Python · MITRE ATT&CK · NVD/NIST · AlienVault OTX · CISA KEV*

*All data sources are free and publicly available. No commercial threat intel licenses required.*
