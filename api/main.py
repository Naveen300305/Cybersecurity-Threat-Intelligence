"""FastAPI MVP - a slice of the full REST API design (spec section 8).

Implements the query engine plus read-only actor/CVE lookups. The
remaining modules (attack paths, IOC correlation, hunting, risk scoring,
IR assistant, dashboard) are planned but not yet built - see CLAUDE.md.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase

from api.schemas import ActorProfile, CVESummary, QueryRequest, QueryResponse

load_dotenv()

_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    _state["driver"] = GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USERNAME", "neo4j"), os.environ["NEO4J_PASSWORD"]),
    )
    yield
    _state["driver"].close()


app = FastAPI(title="CyberGraph Intelligence Platform (MVP)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    # Dev UI (Vite) origins - the React app also proxies /api in dev, but CORS
    # is needed when the UI is served separately (e.g. its own Docker service).
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_engine():
    if "engine" not in _state:
        from rag.engine import GraphRAGEngine  # deferred: needs ANTHROPIC_API_KEY

        _state["engine"] = GraphRAGEngine()
    return _state["engine"]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/query", response_model=QueryResponse)
def query(request: QueryRequest):
    try:
        engine = _get_engine()
        return engine.query(request.question)
    except Exception as exc:  # LLM/graph errors surface as a clean 502 to the analyst
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/v1/actors", response_model=list[ActorProfile])
def list_actors(limit: int = 50):
    with _state["driver"].session() as session:
        rows = session.run(
            "MATCH (a:ThreatActor) RETURN a.id AS id, a.name AS name, "
            "a.aliases AS aliases, a.description AS description LIMIT $limit",
            limit=limit,
        )
        return [
            ActorProfile(
                id=r["id"], name=r["name"], aliases=r["aliases"] or [],
                description=r["description"] or "",
            )
            for r in rows
        ]


@app.get("/api/v1/actors/{name}", response_model=ActorProfile)
def get_actor(name: str):
    with _state["driver"].session() as session:
        result = session.run(
            """
            MATCH (a:ThreatActor)
            WHERE toLower(a.name) CONTAINS toLower($name)
               OR any(alias IN a.aliases WHERE toLower(alias) CONTAINS toLower($name))
            OPTIONAL MATCH (a)-[:USES]->(t:Technique)
            OPTIONAL MATCH (a)-[:DEPLOYS]->(m:Malware)
            RETURN a.id AS id, a.name AS name, a.aliases AS aliases,
                   a.description AS description,
                   collect(DISTINCT t.id) AS techniques,
                   collect(DISTINCT m.name) AS malware
            LIMIT 1
            """,
            name=name,
        ).single()

    if result is None:
        raise HTTPException(status_code=404, detail=f"No threat actor matching '{name}'")

    return ActorProfile(
        id=result["id"], name=result["name"], aliases=result["aliases"] or [],
        description=result["description"] or "",
        techniques=[t for t in result["techniques"] if t],
        malware=[m for m in result["malware"] if m],
    )


@app.get("/api/v1/cves/{cve_id}", response_model=CVESummary)
def get_cve(cve_id: str):
    with _state["driver"].session() as session:
        result = session.run(
            "MATCH (c:CVE {id: $cve_id}) RETURN c.id AS id, c.description AS description, "
            "c.cvss_v3_score AS cvss_v3_score, c.severity AS severity, "
            "coalesce(c.is_kev, false) AS is_kev",
            cve_id=cve_id,
        ).single()

    if result is None:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")

    return CVESummary(**result)
