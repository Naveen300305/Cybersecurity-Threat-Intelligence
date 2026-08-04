# Setup Guide — From Clone to Running App

This walks through everything needed to go from `git clone` to a working
CyberGraph instance: a populated graph, a live API, and the web UI open
in your browser. Follow it top to bottom the first time.

---

## 1. Prerequisites

Install these before you start:

| Tool | Version | Check with | Get it |
|---|---|---|---|
| Git | any recent | `git --version` | https://git-scm.com/downloads |
| Docker Desktop | any recent | `docker --version` | https://www.docker.com/products/docker-desktop/ |
| Python | 3.11+ | `python --version` | https://www.python.org/downloads/ |
| Node.js | 20+ | `node --version` | https://nodejs.org/ |

You will also need:

- An **Anthropic API key** (for the LLM that generates Cypher and writes
  answers) — get one at https://console.anthropic.com/settings/keys.
  This is the one required external dependency; everything else is free.
- *(Optional)* An **NVD API key** — https://nvd.nist.gov/developers/request-an-api-key.
  Without it, CVE ingestion is rate-limited to 5 requests/30s (still fine
  for the small MVP pull, just slower). With it, 50 requests/30s.

---

## 2. Clone the repo

```bash
git clone https://github.com/Naveen300305/Cybersecurity-Threat-Intelligence.git
cd Cybersecurity-Threat-Intelligence
```

---

## 3. Configure environment variables

Copy the example env file and fill in your keys:

```bash
cp .env.example .env
```

Open `.env` and set:

```ini
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=changeme-please      # must match docker-compose.yml's NEO4J_AUTH
ANTHROPIC_API_KEY=sk-ant-...        # required — the query engine won't work without it
NVD_API_KEY=                        # optional, see above
NVD_CVE_LOOKBACK_DAYS=90
NVD_CVE_MAX_RESULTS=500
```

`NEO4J_PASSWORD` must match the password baked into `docker-compose.yml`
(`neo4j/changeme-please` by default). If you change one, change the other.

---

## 4. Start Neo4j

```bash
docker compose up -d neo4j
```

Wait ~30 seconds for it to become healthy, then check:

```bash
docker compose ps
```

`neo4j` should show `healthy`. You can also open the Neo4j Browser at
http://localhost:7474 and log in with `neo4j` / `changeme-please` to
confirm it's reachable (the graph will be empty until you ingest data
in the next step).

---

## 5. Set up Python and ingest data

Create a virtual environment and install dependencies:

```bash
python -m venv .venv

# Windows (PowerShell / Git Bash):
source .venv/Scripts/activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

Load MITRE ATT&CK + recent NVD CVEs into the graph:

```bash
python -m ingestion.run_ingest
```

This takes a few minutes (mostly the NVD portion, which is rate-limited).
If you just want to try things out fast, skip NVD on the first run:

```bash
python -m ingestion.run_ingest --skip-nvd
```

You should see log lines like:

```
Applying constraints/indexes...
Fetching MITRE ATT&CK Enterprise bundle...
Parsed 148 actors, 649 techniques, 758 malware/tools, 44 mitigations.
ATT&CK data loaded.
Ingestion complete.
```

**Sanity check** in the Neo4j Browser (http://localhost:7474):

```cypher
MATCH (a:ThreatActor) RETURN count(a);
MATCH (a:ThreatActor {name: "APT29"})-[:USES]->(t:Technique) RETURN t.id, t.name LIMIT 10;
```

---

## 6. Run the API

With the same virtual environment active:

```bash
uvicorn api.main:app --reload
```

Verify it's up:

```bash
curl http://localhost:8000/health
# {"status":"ok"}

curl http://localhost:8000/api/v1/actors/APT29
```

Interactive API docs: http://localhost:8000/docs.

Leave this running in its own terminal.

---

## 7. Run the UI

In a **new terminal** (leave the API running in the other one):

```bash
cd ui
npm install
npm run dev
```

Open **http://localhost:5173**. You should see the CyberGraph sidebar
with **Query**, **Threat Actors**, and **CVE Lookup**. The green dot next
to "API online" in the bottom-left confirms the UI can reach the backend.

### Try it out

- **Threat Actors** → search "APT29" → click through to see its
  techniques and malware.
- **CVE Lookup** → paste a CVE ID from your ingested data (find one via
  the Neo4j Browser query `MATCH (c:CVE) RETURN c.id LIMIT 5`) → see its
  severity, CVSS score, and description.
- **Query** → ask *"What techniques does APT29 use?"* → the answer comes
  back with the exact Cypher query that was generated, so you can verify
  it yourself in the Neo4j Browser.

---

## 8. Stopping / restarting

```bash
# Stop the UI / API: Ctrl+C in their terminals

# Stop Neo4j (keeps data):
docker compose stop neo4j

# Stop and remove containers (keeps data volume):
docker compose down

# Wipe all graph data and start fresh:
docker compose down -v
```

Re-running `python -m ingestion.run_ingest` any time is safe — all writes
use `MERGE`, not `CREATE`, so re-ingesting never creates duplicates.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose up` fails to bind ports 7474/7687/8000/5173 | Something else is using them. Stop it, or change the left-hand port in `docker-compose.yml` / `ui/vite.config.ts`. |
| API `/health` works but `/api/v1/actors` returns 500 | Neo4j isn't reachable or is still starting. Run `docker compose ps` and wait for `healthy`; check `NEO4J_PASSWORD` matches in `.env` and `docker-compose.yml`. |
| `python -m ingestion.run_ingest` raises a `KeyError: 'NEO4J_PASSWORD'` | You didn't create `.env`, or you're running the command from a shell where it wasn't loaded — re-check step 3, and make sure you're in the repo root. |
| NVD ingestion is very slow or gets `403`/`429` | You're hitting the unauthenticated rate limit (5 req/30s). Add an `NVD_API_KEY` in `.env`, or lower `NVD_CVE_MAX_RESULTS`. |
| UI shows "API unreachable" | The FastAPI server (step 6) isn't running, or isn't on port 8000. Check the terminal running `uvicorn`. |
| `/api/v1/query` returns a 502 error | Usually a bad/missing `ANTHROPIC_API_KEY`, or the Anthropic account has no credit. Check the error detail in the response body. |
| `npm install` in `ui/` fails on Windows | Make sure Node 20+ is installed and you're running it from inside the `ui/` folder, not the repo root. |

---

## What you should end up with

- Neo4j running in Docker, populated with MITRE ATT&CK + a slice of NVD CVEs.
- FastAPI backend on **http://localhost:8000** (docs at `/docs`).
- React UI on **http://localhost:5173** that can search actors, look up
  CVEs, and answer natural-language questions against the graph.

For what's implemented vs. what's still on the roadmap, see the
"What's in the MVP" section of [README.md](README.md). For a tour of
every file and how the pieces fit together, see
[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).
