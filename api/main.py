"""FastAPI MVP - a slice of the full REST API design (spec section 8).

Implements the query engine plus read-only actor/CVE lookups. The
remaining modules (attack paths, IOC correlation, hunting, risk scoring,
IR assistant, dashboard) are planned but not yet built - see CLAUDE.md.

Module 11 (Asset Monitoring & Alerting) routes are included here.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase

from api.schemas import ActorProfile, CVESummary, QueryRequest, QueryResponse

# Module 11 imports
from monitoring.enricher import generate_mitigation_checklist, generate_narrative
from monitoring.matcher import run_matching
from monitoring.notifier import IMMEDIATE_TIERS
from monitoring.schemas import (
    AlertListResponse,
    AssetAlert,
    MitigationRequest,
    MitigationResponse,
    MonitoredAsset,
    MonitoredAssetCreate,
)

load_dotenv()

_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    import logging
    log = logging.getLogger(__name__)
    _state["driver"] = GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USERNAME", "neo4j"), os.environ["NEO4J_PASSWORD"]),
    )
    # Apply constraints — non-fatal if Neo4j isn't ready yet
    try:
        from graph.schema import apply_constraints
        apply_constraints(_state["driver"])
        log.info("Graph constraints applied successfully.")
    except Exception as exc:
        log.warning(
            "Could not apply graph constraints on startup (Neo4j may not be ready): %s. "
            "Run manually once Neo4j is available.", exc
        )
    yield
    _state["driver"].close()


app = FastAPI(title="CyberGraph Intelligence Platform (MVP)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_engine():
    if "engine" not in _state:
        from rag.engine import GraphRAGEngine  # deferred: needs GOOGLE_API_KEY

        _state["engine"] = GraphRAGEngine()
    return _state["engine"]


# ===========================================================================
# Core routes (unchanged)
# ===========================================================================

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/query", response_model=QueryResponse)
def query(request: QueryRequest):
    try:
        engine = _get_engine()
        return engine.query(request.question)
    except Exception as exc:
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


# ===========================================================================
# Module 11: Asset Monitoring & Alerting routes
# ===========================================================================

# ---------------------------------------------------------------------------
# Monitored Assets CRUD
# ---------------------------------------------------------------------------

@app.get("/api/v1/assets", response_model=list[MonitoredAsset])
def list_assets():
    """Return all registered MonitoredAsset nodes."""
    with _state["driver"].session() as session:
        rows = session.run(
            """
            MATCH (a:MonitoredAsset)
            RETURN a.id AS id, a.name AS name, a.vendor AS vendor,
                   a.product AS product, a.version_range AS version_range,
                   a.owner AS owner, a.version_min AS version_min,
                   a.version_max AS version_max, a.created_at AS created_at
            ORDER BY a.name
            """
        ).data()
        return [
            MonitoredAsset(
                id=r["id"],
                name=r["name"],
                vendor=r["vendor"],
                product=r["product"],
                version_range=r["version_range"],
                owner=r.get("owner", ""),
                version_min=r.get("version_min"),
                version_max=r.get("version_max"),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]


@app.post("/api/v1/assets", response_model=MonitoredAsset, status_code=201)
def create_asset(payload: MonitoredAssetCreate, background_tasks: BackgroundTasks):
    """Register a new MonitoredAsset and link it to matching AffectedProduct nodes."""
    asset_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    with _state["driver"].session() as session:
        # Create the MonitoredAsset node
        session.run(
            """
            CREATE (a:MonitoredAsset {
                id: $id, name: $name, vendor: $vendor, product: $product,
                version_range: $version_range, owner: $owner,
                version_min: $version_min, version_max: $version_max,
                created_at: $created_at
            })
            """,
            id=asset_id,
            name=payload.name,
            vendor=payload.vendor,
            product=payload.product,
            version_range=payload.version_range,
            owner=payload.owner,
            version_min=payload.version_min,
            version_max=payload.version_max,
            created_at=now,
        )

        # Link to matching AffectedProduct nodes (case-insensitive vendor + product match)
        session.run(
            """
            MATCH (a:MonitoredAsset {id: $asset_id})
            MATCH (ap:AffectedProduct)
            WHERE toLower(ap.vendor) CONTAINS toLower($vendor)
              AND toLower(ap.product) CONTAINS toLower($product)
            MERGE (a)-[:MATCHES]->(ap)
            """,
            asset_id=asset_id,
            vendor=payload.vendor,
            product=payload.product,
        )

    # Kick off immediate matching in background
    background_tasks.add_task(_run_matching_bg, asset_id)

    return MonitoredAsset(
        id=asset_id,
        name=payload.name,
        vendor=payload.vendor,
        product=payload.product,
        version_range=payload.version_range,
        owner=payload.owner,
        version_min=payload.version_min,
        version_max=payload.version_max,
        created_at=datetime.fromisoformat(now),
    )


@app.delete("/api/v1/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: str):
    """Remove a MonitoredAsset and all its associated alerts."""
    with _state["driver"].session() as session:
        result = session.run(
            """
            MATCH (a:MonitoredAsset {id: $asset_id})
            OPTIONAL MATCH (a)-[:HAS_ALERT]->(al:AssetAlert)
            DETACH DELETE a, al
            RETURN count(a) AS deleted
            """,
            asset_id=asset_id,
        ).single()
        if not result or result["deleted"] == 0:
            raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.get("/api/v1/alerts", response_model=AlertListResponse)
def list_alerts(
    asset_id: str | None = Query(default=None),
    tier: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
):
    """Return asset alerts, optionally filtered by asset or tier."""
    filters = "WHERE 1=1"
    params: dict = {"limit": limit}
    if asset_id:
        filters += " AND al.asset_id = $asset_id"
        params["asset_id"] = asset_id
    if tier:
        filters += " AND al.alert_tier = $tier"
        params["tier"] = tier.upper()

    with _state["driver"].session() as session:
        rows = session.run(
            f"""
            MATCH (a:MonitoredAsset)-[:HAS_ALERT]->(al:AssetAlert)
            {filters}
            RETURN al.alert_id AS alert_id, al.asset_id AS asset_id,
                   a.name AS asset_name, al.cve_id AS cve_id,
                   al.cvss_v3_score AS cvss_v3_score, al.severity AS severity,
                   al.is_kev AS is_kev, al.epss_score AS epss_score,
                   al.threat_priority_score AS threat_priority_score,
                   al.alert_tier AS alert_tier,
                   al.first_seen AS first_seen, al.notified_at AS notified_at,
                   al.exploiting_malware AS exploiting_malware,
                   al.deploying_actors AS deploying_actors,
                   al.targeted_sectors AS targeted_sectors,
                   al.narrative AS narrative,
                   al.mitigation_checklist AS mitigation_checklist
            ORDER BY al.threat_priority_score DESC
            LIMIT $limit
            """,
            **params,
        ).data()

    alerts = [
        AssetAlert(
            alert_id=r["alert_id"],
            asset_id=r["asset_id"],
            asset_name=r["asset_name"],
            cve_id=r["cve_id"],
            cvss_v3_score=r.get("cvss_v3_score"),
            severity=r.get("severity"),
            is_kev=bool(r.get("is_kev")),
            epss_score=r.get("epss_score"),
            threat_priority_score=float(r.get("threat_priority_score") or 0),
            alert_tier=r.get("alert_tier", "LOW"),
            first_seen=datetime.fromisoformat(r["first_seen"]) if r.get("first_seen") else datetime.now(timezone.utc),
            notified_at=datetime.fromisoformat(r["notified_at"]) if r.get("notified_at") else None,
            exploiting_malware=list(r.get("exploiting_malware") or []),
            deploying_actors=list(r.get("deploying_actors") or []),
            targeted_sectors=list(r.get("targeted_sectors") or []),
            narrative=r.get("narrative") or "",
            mitigation_checklist=r.get("mitigation_checklist") or "",
        )
        for r in rows
    ]
    return AlertListResponse(alerts=alerts, total=len(alerts))


@app.get("/api/v1/alerts/{alert_id}", response_model=AssetAlert)
def get_alert(alert_id: str, background_tasks: BackgroundTasks):
    """Get a single alert; triggers narrative generation if not yet populated."""
    with _state["driver"].session() as session:
        r = session.run(
            """
            MATCH (a:MonitoredAsset)-[:HAS_ALERT]->(al:AssetAlert {alert_id: $alert_id})
            RETURN al.alert_id AS alert_id, al.asset_id AS asset_id,
                   a.name AS asset_name, a.version_range AS version_range,
                   al.cve_id AS cve_id,
                   al.cvss_v3_score AS cvss_v3_score, al.severity AS severity,
                   al.is_kev AS is_kev, al.epss_score AS epss_score,
                   al.threat_priority_score AS threat_priority_score,
                   al.alert_tier AS alert_tier,
                   al.first_seen AS first_seen, al.notified_at AS notified_at,
                   al.exploiting_malware AS exploiting_malware,
                   al.deploying_actors AS deploying_actors,
                   al.targeted_sectors AS targeted_sectors,
                   al.narrative AS narrative,
                   al.mitigation_checklist AS mitigation_checklist
            """,
            alert_id=alert_id,
        ).single()

    if r is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    narrative = r.get("narrative") or ""
    # Lazily generate narrative in background if empty
    if not narrative:
        background_tasks.add_task(
            _generate_narrative_bg,
            alert_id,
            r["asset_name"],
            r.get("version_range", ""),
            r["cve_id"],
        )

    return AssetAlert(
        alert_id=r["alert_id"],
        asset_id=r["asset_id"],
        asset_name=r["asset_name"],
        cve_id=r["cve_id"],
        cvss_v3_score=r.get("cvss_v3_score"),
        severity=r.get("severity"),
        is_kev=bool(r.get("is_kev")),
        epss_score=r.get("epss_score"),
        threat_priority_score=float(r.get("threat_priority_score") or 0),
        alert_tier=r.get("alert_tier", "LOW"),
        first_seen=datetime.fromisoformat(r["first_seen"]) if r.get("first_seen") else datetime.now(timezone.utc),
        notified_at=datetime.fromisoformat(r["notified_at"]) if r.get("notified_at") else None,
        exploiting_malware=list(r.get("exploiting_malware") or []),
        deploying_actors=list(r.get("deploying_actors") or []),
        targeted_sectors=list(r.get("targeted_sectors") or []),
        narrative=narrative,
        mitigation_checklist=r.get("mitigation_checklist") or "",
    )


@app.post("/api/v1/alerts/{alert_id}/mitigate", response_model=MitigationResponse)
def get_mitigation(alert_id: str):
    """Generate (or return cached) mitigation checklist for a specific alert."""
    with _state["driver"].session() as session:
        r = session.run(
            """
            MATCH (a:MonitoredAsset)-[:HAS_ALERT]->(al:AssetAlert {alert_id: $alert_id})
            RETURN al.cve_id AS cve_id, a.name AS asset_name,
                   a.version_range AS version_range,
                   al.mitigation_checklist AS mitigation_checklist
            """,
            alert_id=alert_id,
        ).single()

    if r is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    checklist = r.get("mitigation_checklist") or ""
    if not checklist:
        checklist = generate_mitigation_checklist(
            cve_id=r["cve_id"],
            asset_name=r["asset_name"],
            asset_version_range=r.get("version_range", ""),
        )
        # Persist to graph
        with _state["driver"].session() as session:
            session.run(
                "MATCH (al:AssetAlert {alert_id: $aid}) SET al.mitigation_checklist = $checklist",
                aid=alert_id,
                checklist=checklist,
            )

    return MitigationResponse(alert_id=alert_id, cve_id=r["cve_id"], checklist=checklist)


@app.post("/api/v1/assets/scan", status_code=202)
def trigger_scan(background_tasks: BackgroundTasks):
    """Manually trigger an asset → CVE matching scan for all assets."""
    background_tasks.add_task(_run_matching_bg, None)
    return {"message": "Scan triggered", "status": "running"}


# ===========================================================================
# Background helpers
# ===========================================================================

def _run_matching_bg(asset_id: str | None) -> None:
    """Background task: run CVE matching and enrich critical alerts."""
    try:
        alerts = run_matching(_state["driver"], asset_id)
        # Eagerly generate narratives for CRITICAL/HIGH alerts
        for alert in alerts:
            if alert["alert_tier"] in ("CRITICAL", "HIGH"):
                narrative = generate_narrative(
                    cve_id=alert["cve_id"],
                    asset_name=alert["asset_name"],
                    asset_version_range="",
                )
                with _state["driver"].session() as s:
                    s.run(
                        "MATCH (al:AssetAlert {alert_id: $aid}) SET al.narrative = $narrative",
                        aid=alert["alert_id"],
                        narrative=narrative,
                    )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("Background matching failed: %s", exc)


def _generate_narrative_bg(
    alert_id: str, asset_name: str, version_range: str, cve_id: str
) -> None:
    """Background task: generate and persist narrative for a specific alert."""
    try:
        narrative = generate_narrative(cve_id, asset_name, version_range)
        with _state["driver"].session() as s:
            s.run(
                "MATCH (al:AssetAlert {alert_id: $aid}) SET al.narrative = $narrative",
                aid=alert_id,
                narrative=narrative,
            )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("Narrative generation failed: %s", exc)
