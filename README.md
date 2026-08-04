# CyberGraph Intelligence Platform — MVP

Graph RAG–powered cybersecurity threat intel: MITRE ATT&CK + NVD CVEs
loaded into Neo4j, queried in natural language through a FastAPI
endpoint backed by a LangChain `GraphCypherQAChain`.

Full design spec: [CyberGraph_Intelligence_Platform.md](CyberGraph_Intelligence_Platform.md).
This MVP implements a slice of it — see "What's in the MVP" below.

New here? **[SETUP.md](SETUP.md)** walks through cloning this repo and
getting a fully working instance running end-to-end. **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)**
explains the architecture and what every file does.

## What's in the MVP

- **Graph schema**: `ThreatActor`, `Technique`, `Tactic`, `Malware`,
  `Mitigation`, `CVE`, `AffectedProduct` + core relationships ([graph/schema.py](graph/schema.py)).
- **Ingestion**: MITRE ATT&CK Enterprise (actors, techniques, tactics,
  malware, mitigations) and recent NVD CVEs ([ingestion/](ingestion/)).
- **Graph RAG query engine**: natural-language question → LLM-generated
  Cypher → graph traversal → LLM-synthesized answer ([rag/engine.py](rag/engine.py)).
- **API**: `POST /api/v1/query`, `GET /api/v1/actors`, `GET /api/v1/actors/{name}`,
  `GET /api/v1/cves/{cve_id}` ([api/main.py](api/main.py)).
- **UI**: a React + Tailwind app ([ui/](ui/)) with a Graph RAG query
  console, a threat actor browser (search → profile with techniques/malware),
  and CVE lookup (severity, CVSS, KEV flag).

**Not yet built** (see spec + [CLAUDE.md](CLAUDE.md) for the full plan):
CAPEC/CWE ingestion, OTX IOCs, CISA KEV/EPSS enrichment, vector/hybrid
retrieval, embeddings, Celery scheduling, modules 3–10. (The spec called
for Streamlit; this MVP ships a React UI instead.)

## Setup

```bash
cp .env.example .env
# edit .env: set NEO4J_PASSWORD and ANTHROPIC_API_KEY

docker compose up -d neo4j
pip install -r requirements.txt
```

## Ingest data

```bash
python -m ingestion.run_ingest              # ATT&CK + last 90 days of NVD CVEs
python -m ingestion.run_ingest --skip-nvd    # ATT&CK only (fast, no rate limits)
```

Adjust `NVD_CVE_LOOKBACK_DAYS` / `NVD_CVE_MAX_RESULTS` in `.env` to widen
or shrink the CVE pull. Get a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
to raise the rate limit from 5 to 50 requests/30s.

## Run the API

```bash
uvicorn api.main:app --reload
```

```bash
curl -X POST http://localhost:8000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What techniques does APT29 use?"}'

curl http://localhost:8000/api/v1/actors/APT29
```

Interactive docs at http://localhost:8000/docs.

## Run the UI

```bash
cd ui
npm install
npm run dev
```

Open http://localhost:5173. In dev, Vite proxies `/api/*` and `/health`
to the FastAPI server at `http://localhost:8000` (see `ui/vite.config.ts`),
so no CORS setup is needed for local development.

Or run everything (Neo4j + API + UI) together:

```bash
docker compose up
```

## Tests

```bash
pytest
```

Tests cover ingestion parsing/scoring logic only — no live Neo4j or LLM
calls required.
