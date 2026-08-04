# Project Overview — CyberGraph Intelligence Platform

This document explains what the project is, how the pieces fit
together, and what every file in the repo is for. If [SETUP.md](SETUP.md)
is "how do I run it," this is "how does it work."

---

## 1. What this project is

CyberGraph is a **Graph RAG** (Retrieval-Augmented Generation over a
graph database) system for cybersecurity threat intelligence. Instead of
storing threat data as flat rows in a table, it models it as a **graph**:
threat actors, the techniques they use, the malware they deploy, the
CVEs that malware exploits, and the products those CVEs affect — all
connected by explicit relationships. An LLM can then translate a
plain-English question into a graph query, walk those relationships, and
turn the raw results into a readable answer.

The full vision (10 modules, CAPEC/CWE, OTX IOC feeds, EPSS/KEV scoring,
Celery-scheduled ingestion, embeddings + vector search) is documented in
[CyberGraph_Intelligence_Platform.md](CyberGraph_Intelligence_Platform.md) —
that file is the original design spec and source of truth for anything
not yet built. This repo currently implements a **working slice** of
that spec: enough to load real data and get real, verifiable answers
end-to-end. [CLAUDE.md](CLAUDE.md) tracks the gap between spec and
implementation for whoever (human or AI) picks this up next.

## 2. How a question flows through the system

```
Browser (React UI, :5173)
   │  POST /api/v1/query { question }
   ▼
FastAPI (api/main.py, :8000)
   │  engine.query(question)
   ▼
GraphRAGEngine (rag/engine.py)
   │  1. LLM turns the question into Cypher (rag/prompts.py supplies the schema)
   │  2. Cypher runs against Neo4j, returns rows
   │  3. LLM turns those rows into a readable answer
   ▼
Neo4j graph (populated by ingestion/run_ingest.py)
```

The graph itself is filled in ahead of time by the ingestion pipeline,
which pulls from MITRE ATT&CK and NVD and writes nodes/relationships
using `MERGE` (idempotent — safe to re-run without creating duplicates).

## 3. Repository layout

```
├── graph/            graph schema + Neo4j constraints/indexes
├── ingestion/         ATT&CK + NVD connectors, Neo4j loaders, CLI
├── rag/               the Graph RAG query engine (LangChain)
├── api/               FastAPI app exposing it all over HTTP
├── ui/                React frontend
├── tests/             unit tests (parsing/scoring logic, no live services)
├── docker-compose.yml / Dockerfile   infra to run Neo4j + API in containers
└── requirements.txt / .env.example   Python deps + config template
```

Below is a file-by-file walkthrough.

---

## 4. `graph/` — the schema

Defines what's allowed to exist in the graph. This is the contract every
other layer relies on: ingestion writes to it, the RAG engine's prompt
describes it to the LLM so it doesn't hallucinate labels that don't
exist.

- **`schema.py`** — `SCHEMA_TEXT`, a plain-text description of node
  labels/properties and relationship types, embedded directly into the
  Cypher-generation prompt (see `rag/prompts.py`). Also has
  `apply_constraints(driver)`, which reads and runs `indexes.cypher`
  against Neo4j — called once at the start of ingestion.
- **`indexes.cypher`** — raw Cypher: uniqueness constraints (e.g. one
  node per `CVE.id`), a couple of lookup indexes (`CVE.severity`,
  `CVE.is_kev`), and a full-text index over entity descriptions for
  future semantic search. Every statement uses `IF NOT EXISTS`, so
  running it twice is a no-op.

The MVP schema is a **subset** of the full spec (spec §5): it covers
`ThreatActor`, `Technique`, `Tactic`, `Malware`, `Mitigation`, `CVE`, and
`AffectedProduct`. `CWE`, `AttackPattern` (CAPEC), `IOC`, `Campaign`,
`Country`, `Sector`, and `DataSource` are designed in the spec but not
yet ingested.

---

## 5. `ingestion/` — getting real data into the graph

### `connectors/attack.py`

Downloads the official MITRE ATT&CK Enterprise STIX bundle (a big JSON
file of "objects" and "relationships") from MITRE's public GitHub repo,
and parses it into plain Python dicts:

- `fetch_attack_bundle()` — HTTP GET of the bundle.
- `parse_attack_bundle(bundle)` — walks every STIX object. Threat actors
  are STIX `intrusion-set` objects, techniques are `attack-pattern`,
  tactics are `x-mitre-tactic`, malware/tools are `malware`/`tool`,
  mitigations are `course-of-action`. STIX `relationship` objects become
  our graph relationships (e.g. an actor `uses` a technique →
  `ThreatActor-[:USES]->Technique`). Revoked/deprecated objects are
  skipped. Returns one dict of lists, keyed by node/relationship type,
  ready for the loader.

### `connectors/nvd.py`

Pulls recently-published CVEs from the NVD REST API (v2.0):

- `fetch_recent_cves(lookback_days, max_results, api_key)` — paginates
  through NVD's `/cves/2.0` endpoint, bounded by both a time window and
  a result cap (the full CVE corpus is ~250k; the MVP only needs a
  demo-sized slice). Paces requests to respect NVD's rate limit (5
  req/30s without a key, 50 with one).
- Helper functions `_severity_from_score`, `_extract_cvss_v3`,
  `_extract_cpes` do the actual parsing of NVD's JSON shape into our
  schema's fields (CVSS v3 score/vector, severity bucket, affected CPEs).
  These are the functions covered by `tests/test_ingestion.py`.

### `loaders/neo4j_loader.py`

The only place that writes to Neo4j. Every function is a single
`UNWIND $rows AS row ... MERGE ...` Cypher statement — batch-loading a
whole list of dicts in one round trip, and using `MERGE` (never
`CREATE`) so re-running ingestion updates existing nodes instead of
duplicating them. `load_attack_data()` loads all ATT&CK node/relationship
types; `load_cves()` loads CVEs and their `AffectedProduct` links;
`mark_kev()` is a stub for flagging CISA KEV CVEs (connector not yet
built — see gaps below).

### `run_ingest.py`

The CLI entry point (`python -m ingestion.run_ingest`). Loads `.env`,
opens a Neo4j driver, applies constraints, then runs the ATT&CK and/or
NVD pipelines (`--skip-attack` / `--skip-nvd` flags let you run just
one). This is the only ingestion script that exists today — the spec's
Celery/Redis scheduler for automatic daily/hourly refreshes is designed
but not implemented.

---

## 6. `rag/` — the Graph RAG query engine

This is spec Module 2, cut down to its core: Cypher-generation retrieval
only (no vector/hybrid retrieval yet).

### `prompts.py`

Two LangChain `PromptTemplate`s:

- `CYPHER_GENERATION_PROMPT` — instructs the LLM to write **one** Cypher
  query, gives it `graph.schema.SCHEMA_TEXT` verbatim so it can't invent
  labels/relationships, and tells it to prefer fuzzy `CONTAINS` matching
  on names (analysts type "APT29", not the STIX ID `G0016`).
- `QA_PROMPT` — takes the question plus the raw graph query results and
  asks the LLM to synthesize a precise, cited answer (or say plainly
  that there were no results, instead of guessing).

### `engine.py`

- `build_graph()` — creates a `Neo4jGraph` (LangChain's Neo4j wrapper)
  from `.env` connection settings.
- `build_chain()` — wires an Anthropic chat model (model name
  configurable via `ANTHROPIC_MODEL`, defaults to `claude-sonnet-5`)
  into LangChain's `GraphCypherQAChain`, using the two prompts above.
- `GraphRAGEngine` — a thin class the API layer imports. Building the
  chain does real setup work (LLM client, graph connection), so it's
  built **once** per process and reused across requests
  (`api/main.py`'s `_get_engine()` lazily constructs and caches it).
  `.query(question)` returns both the synthesized answer and the actual
  Cypher query that was run, so an analyst can double-check it — this
  pairing is what the UI's Query page displays.

---

## 7. `api/` — the HTTP layer

A slice of the spec's full REST API (§8), which describes ~30 endpoints
across 10 modules. This MVP implements the query engine plus read-only
actor/CVE lookups; everything else (attack paths, IOC correlation,
hunting, risk scoring, IR assistant, dashboard) is designed but not
built.

- **`main.py`** — the FastAPI app.
  - `lifespan()` opens one shared Neo4j driver for the process's
    lifetime and closes it on shutdown.
  - CORS middleware is enabled (origin configurable via `CORS_ORIGINS`)
    so the React dev server, or a UI served from a different origin in
    Docker, can call the API directly.
  - `GET /health` — trivial liveness check, polled by the UI's sidebar
    status dot.
  - `POST /api/v1/query` — the Graph RAG endpoint. Builds the RAG engine
    on first use (deferred import — it needs `ANTHROPIC_API_KEY`, so
    importing it eagerly would break the API for anyone who hasn't set
    that yet). LLM/graph errors surface as a `502` with the underlying
    message.
  - `GET /api/v1/actors` — list actors (paginated via `limit`).
  - `GET /api/v1/actors/{name}` — fuzzy-matches on name or alias, and
    pulls the actor's techniques and malware in the same query via
    `OPTIONAL MATCH` + `collect()`. 404s if nothing matches.
  - `GET /api/v1/cves/{cve_id}` — exact-ID CVE lookup. 404s if not found.
- **`schemas.py`** — Pydantic request/response models
  (`QueryRequest`/`QueryResponse`, `ActorSummary`/`ActorProfile`,
  `CVESummary`). These double as FastAPI's auto-generated OpenAPI docs
  schema (visible at `/docs`) and as the shape the UI's TypeScript types
  in `ui/src/api.ts` mirror by hand.

---

## 8. `ui/` — the React frontend

A Vite + React 19 + TypeScript app, styled with Tailwind v4, that gives
the API a real interface instead of raw `curl`/Swagger.

- **`vite.config.ts`** — enables the React and Tailwind Vite plugins,
  and configures a **dev proxy**: any request to `/api/*` or `/health`
  from the browser is forwarded to the FastAPI backend
  (`http://localhost:8000` locally, or `http://api:8000` inside Docker
  Compose via the `VITE_API_PROXY_TARGET` env var). This is what lets
  the frontend just call `fetch('/api/v1/actors')` without worrying
  about CORS or hardcoded hosts.
- **`index.html`** — page shell; pulls in Google Fonts (JetBrains Mono
  for code/data, Inter for UI text).
- **`src/index.css`** — Tailwind import plus a small `@theme` block
  defining the app's color tokens (`--color-bg`, `--color-accent`, etc.)
  that Tailwind turns into utility classes like `bg-panel` or
  `text-accent`. Also has the subtle grid background and custom
  scrollbar styling.
- **`src/main.tsx`** — React entry point; wraps the app in
  `BrowserRouter` for client-side routing.
- **`src/App.tsx`** — route table: `/query`, `/actors`, `/actors/:name`,
  `/cves`, all rendered inside the shared `Layout`.
- **`src/api.ts`** — the one place that talks to the backend. Typed
  wrappers (`api.query`, `api.listActors`, `api.getActor`, `api.getCve`,
  `api.health`) around `fetch`, plus an `ApiError` class so pages can
  distinguish "backend returned a 404/500 with a message" from "the
  request itself failed."
- **`src/components/Layout.tsx`** — the persistent sidebar (logo, nav
  links, health indicator) and content area every page renders inside.
  `HealthIndicator` polls `GET /health` every 15s and shows a green/red
  dot accordingly.
- **`src/components/Badge.tsx`** — two small presentational pieces
  reused across pages: `SeverityBadge` (colors CVE severity
  Critical/High/Medium/Low/Unknown) and `Tag` (used for aliases,
  techniques, malware names).
- **`src/pages/QueryPage.tsx`** — the Graph RAG console: a textarea,
  example-question shortcuts, and — once a query resolves — the answer
  plus the exact Cypher query that produced it.
- **`src/pages/ActorsPage.tsx`** — fetches all actors once, then
  filters client-side as you type (search matches name or alias).
  Each card links to...
- **`src/pages/ActorDetailPage.tsx`** — one actor's full profile:
  description, aliases, and its techniques/malware as tag lists (data
  comes from the same `GET /api/v1/actors/{name}` call that does the
  `OPTIONAL MATCH` + `collect()` on the backend).
- **`src/pages/CvesPage.tsx`** — CVE ID search box → severity badge,
  CVSS score, KEV flag (if set), and description.

---

## 9. `tests/`

- **`test_ingestion.py`** — unit tests for the pure-logic pieces of
  ingestion: STIX bundle parsing (`parse_attack_bundle`, including that
  revoked objects are skipped) and NVD field extraction (severity
  bucketing, CVSS extraction, CPE filtering). Deliberately has **no**
  dependency on a live Neo4j instance or network access — it feeds in
  small hand-built fixture dicts and asserts on the parsed output. Run
  with `pytest`.

---

## 10. Infra & config files

- **`docker-compose.yml`** — three services: `neo4j` (Community 5.20
  with the APOC plugin, healthcheck via `cypher-shell`), `api` (builds
  from the root `Dockerfile`, waits for Neo4j to be healthy), and `ui`
  (builds from `ui/Dockerfile`, points its Vite proxy at the `api`
  service by container name).
- **`Dockerfile`** (root) — Python 3.11-slim image for the API service:
  installs `requirements.txt`, copies the repo, runs `uvicorn`.
- **`ui/Dockerfile`** — Node 20-alpine image for the UI service: installs
  npm deps, runs the Vite dev server with `--host` so it's reachable
  from outside the container.
- **`requirements.txt`** — Python dependencies: `neo4j` +
  `langchain`/`langchain-neo4j`/`langchain-anthropic` for the graph and
  RAG layers, `mitreattack-python`-adjacent `requests` for ingestion,
  `fastapi`/`uvicorn`/`pydantic` for the API, `pytest` for tests.
- **`.env.example`** — template for the one config file every layer
  reads (`ingestion/run_ingest.py`, `rag/engine.py`, `api/main.py` all
  load it via `python-dotenv`): Neo4j connection details, the Anthropic
  API key, optional NVD API key, and ingestion size limits.
- **`.gitignore`** — keeps virtual envs, `node_modules`, `__pycache__`,
  `.env`, Neo4j's data volume, and build output out of version control.

---

## 11. Docs

- **`README.md`** — the quick-start: what's implemented, setup, run
  commands. Start here for the short version.
- **`SETUP.md`** — the long version: a friend-cloning-this-repo,
  step-by-step guide from zero to a working UI, with a troubleshooting
  table.
- **`PROJECT_OVERVIEW.md`** — this file.
- **`CLAUDE.md`** — guidance for AI coding assistants working in this
  repo: current state, key design decisions to preserve, and pointers
  into the spec.
- **`CyberGraph_Intelligence_Platform.md`** — the original design
  spec: full architecture, complete graph schema (all 13 node types),
  all 10 planned modules, the full REST API design, and the 6-week
  build plan. This is the "north star" — anything in this repo that
  looks incomplete relative to that document is a known, intentional
  gap for the MVP, not a bug.
- **`explanation.md`** — speaking notes for presenting the project
  (maps to the slide deck), not implementation documentation.

---

## 12. What's implemented vs. what's designed-only

| Area | Status |
|---|---|
| Graph schema (7 of 13 node types) | ✅ Implemented |
| MITRE ATT&CK ingestion | ✅ Implemented |
| NVD CVE ingestion | ✅ Implemented (bounded pull, not full historical corpus) |
| CISA KEV / EPSS enrichment | ⬜ Designed only (`mark_kev` loader exists, no connector calls it yet) |
| CAPEC / CWE ingestion | ⬜ Designed only |
| AlienVault OTX (IOCs) | ⬜ Designed only |
| Vector/hybrid retrieval, embeddings | ⬜ Designed only |
| Celery/Redis scheduled refresh | ⬜ Designed only |
| Graph RAG query engine (Cypher generation) | ✅ Implemented |
| REST API — query, actors, CVEs | ✅ Implemented |
| REST API — modules 3–10 (attack paths, IOC correlation, hunting, risk scoring, IR, dashboard) | ⬜ Designed only |
| Web UI | ✅ Implemented (React, not the spec's originally-planned Streamlit) |

If you're picking this up to extend it, `CyberGraph_Intelligence_Platform.md`
section 9 ("Phased Build Plan") is the intended order of operations for
everything still unbuilt.
