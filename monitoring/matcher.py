"""Asset → CVE matcher with ThreatPriority scoring (Module 11, step 2 & 3).

For each MonitoredAsset stored in Neo4j, this module:
1. Queries the graph for CVEs linked to matching AffectedProduct nodes.
2. Enriches each match with actor/malware graph context.
3. Computes a ThreatPriority score.
4. Decides alert tier (CRITICAL / HIGH / MEDIUM / LOW).
5. Persists new matches as (:AssetAlert) nodes and returns them.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any

from neo4j import Driver

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------

def _threat_priority_score(
    cvss: float | None,
    is_kev: bool,
    epss: float | None,
    actor_count: int,
    malware_count: int,
    days_since_published: int,
) -> float:
    """Return a 0–100 composite ThreatPriority score.

    Weights (sum = 100):
      CVSS normalised (0–10 → 0–35)         35 pts
      KEV actively-exploited flag            25 pts
      EPSS (0–1 → 0–20)                     20 pts
      Actor/malware graph coverage (0–10)    10 pts
      Recency (< 30 days = 10, < 90 = 5)    10 pts
    """
    score = 0.0
    # CVSS
    if cvss is not None:
        score += min(cvss, 10.0) / 10.0 * 35
    # KEV
    if is_kev:
        score += 25
    # EPSS
    if epss is not None:
        score += min(epss, 1.0) * 20
    # Graph coverage
    coverage = min((actor_count + malware_count), 10)
    score += coverage
    # Recency
    if days_since_published <= 30:
        score += 10
    elif days_since_published <= 90:
        score += 5
    return round(score, 2)


def _alert_tier(score: float, is_kev: bool) -> str:
    """Map composite score to alert tier."""
    if is_kev or score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Graph queries
# ---------------------------------------------------------------------------

_MATCH_QUERY = """
MATCH (a:MonitoredAsset {id: $asset_id})
MATCH (a)-[:MATCHES]->(ap:AffectedProduct)<-[:AFFECTS]-(c:CVE)
WHERE NOT EXISTS {
    MATCH (a)-[:HAS_ALERT]->(al:AssetAlert {cve_id: c.id})
    WHERE al.first_seen IS NOT NULL
}
WITH c, ap,
     coalesce(c.cvss_v3_score, 0.0)   AS cvss,
     coalesce(c.is_kev, false)         AS is_kev,
     coalesce(c.epss_score, 0.0)       AS epss,
     coalesce(c.published_date, '')    AS published_date,
     c.severity                        AS severity
OPTIONAL MATCH (m:Malware)-[:EXPLOITS]->(c)
OPTIONAL MATCH (ta:ThreatActor)-[:DEPLOYS]->(m2:Malware)-[:EXPLOITS]->(c)
RETURN c.id                          AS cve_id,
       c.description                 AS description,
       cvss, is_kev, epss, severity, published_date,
       collect(DISTINCT m.name)      AS exploiting_malware,
       collect(DISTINCT ta.name)     AS deploying_actors
LIMIT 50
"""

_ACTOR_SECTORS_QUERY = """
UNWIND $actors AS actor_name
MATCH (ta:ThreatActor)
WHERE toLower(ta.name) = toLower(actor_name)
RETURN collect(DISTINCT ta.motivation) AS sectors
LIMIT 1
"""

_UPSERT_ALERT_QUERY = """
MATCH (a:MonitoredAsset {id: $asset_id})
MERGE (al:AssetAlert {alert_id: $alert_id})
ON CREATE SET
    al.asset_id              = $asset_id,
    al.cve_id                = $cve_id,
    al.cvss_v3_score         = $cvss,
    al.severity              = $severity,
    al.is_kev                = $is_kev,
    al.epss_score            = $epss,
    al.threat_priority_score = $tps,
    al.alert_tier            = $tier,
    al.first_seen            = $now,
    al.notified_at           = null,
    al.exploiting_malware    = $malware,
    al.deploying_actors      = $actors,
    al.targeted_sectors      = $sectors,
    al.narrative             = ''
MERGE (a)-[:HAS_ALERT]->(al)
RETURN al.alert_id AS alert_id
"""


def _stable_alert_id(asset_id: str, cve_id: str) -> str:
    """Deterministic alert ID so MERGE is idempotent."""
    return hashlib.sha256(f"{asset_id}:{cve_id}".encode()).hexdigest()[:16]


def _days_since(date_str: str) -> int:
    """Parse ISO date string and return days elapsed (fallback = 999)."""
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return 999


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_matching(driver: Driver, asset_id: str | None = None) -> list[dict[str, Any]]:
    """Run CVE matching for one or all MonitoredAssets.

    Returns list of newly created alert dicts.
    """
    new_alerts: list[dict[str, Any]] = []

    with driver.session() as session:
        if asset_id:
            assets = session.run(
                "MATCH (a:MonitoredAsset {id: $id}) RETURN a.id AS id, a.name AS name",
                id=asset_id,
            ).data()
        else:
            assets = session.run(
                "MATCH (a:MonitoredAsset) RETURN a.id AS id, a.name AS name"
            ).data()

        for asset in assets:
            aid = asset["id"]
            aname = asset["name"]
            log.info("Matching CVEs for asset %s (%s)", aname, aid)

            rows = session.run(_MATCH_QUERY, asset_id=aid).data()
            for row in rows:
                cve_id = row["cve_id"]
                cvss = float(row.get("cvss") or 0.0)
                is_kev = bool(row.get("is_kev"))
                epss = float(row.get("epss") or 0.0)
                severity = row.get("severity")
                pub_date = row.get("published_date", "")
                malware = [m for m in (row.get("exploiting_malware") or []) if m]
                actors = [a for a in (row.get("deploying_actors") or []) if a]

                days = _days_since(pub_date)
                tps = _threat_priority_score(
                    cvss, is_kev, epss, len(actors), len(malware), days
                )
                tier = _alert_tier(tps, is_kev)

                # Sector enrichment
                sectors: list[str] = []
                if actors:
                    sector_data = session.run(
                        _ACTOR_SECTORS_QUERY, actors=actors
                    ).single()
                    if sector_data:
                        sectors = [s for s in (sector_data["sectors"] or []) if s]

                alert_id = _stable_alert_id(aid, cve_id)
                session.run(
                    _UPSERT_ALERT_QUERY,
                    asset_id=aid,
                    alert_id=alert_id,
                    cve_id=cve_id,
                    cvss=cvss,
                    severity=severity,
                    is_kev=is_kev,
                    epss=epss,
                    tps=tps,
                    tier=tier,
                    now=datetime.now(timezone.utc).isoformat(),
                    malware=malware,
                    actors=actors,
                    sectors=sectors,
                )

                new_alerts.append({
                    "alert_id": alert_id,
                    "asset_id": aid,
                    "asset_name": aname,
                    "cve_id": cve_id,
                    "cvss_v3_score": cvss,
                    "severity": severity,
                    "is_kev": is_kev,
                    "epss_score": epss,
                    "threat_priority_score": tps,
                    "alert_tier": tier,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "notified_at": None,
                    "exploiting_malware": malware,
                    "deploying_actors": actors,
                    "targeted_sectors": sectors,
                    "narrative": "",
                    "mitigation_checklist": "",
                })

    log.info("Matching complete — %d new alerts created", len(new_alerts))
    return new_alerts
