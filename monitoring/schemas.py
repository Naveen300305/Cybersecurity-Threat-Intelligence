"""Pydantic schemas for Module 11: Asset Monitoring & Alerting."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# MonitoredAsset
# ---------------------------------------------------------------------------

class MonitoredAssetCreate(BaseModel):
    name: str = Field(..., description="Human-readable label, e.g. 'Production Apache'")
    vendor: str
    product: str
    version_range: str = Field(
        ...,
        description="e.g. 'Apache 2.4.x below 2.4.58' — free-text, also stored as semver bounds",
    )
    owner: str = Field(default="", description="Team / owner identifier")
    version_min: Optional[str] = None  # inclusive lower bound (semver string)
    version_max: Optional[str] = None  # exclusive upper bound (semver string)


class MonitoredAsset(MonitoredAssetCreate):
    id: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Alert / Match
# ---------------------------------------------------------------------------

class AlertSeverity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssetAlert(BaseModel):
    alert_id: str
    asset_id: str
    asset_name: str
    cve_id: str
    cvss_v3_score: Optional[float]
    severity: Optional[str]
    is_kev: bool
    epss_score: Optional[float]
    threat_priority_score: float = Field(
        description="Composite score: CVSS + KEV + EPSS + actor/malware coverage + recency"
    )
    alert_tier: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    first_seen: datetime
    notified_at: Optional[datetime]
    # Enrichment from graph traversal
    exploiting_malware: list[str] = []
    deploying_actors: list[str] = []
    targeted_sectors: list[str] = []
    narrative: str = Field(
        default="", description="RAG-synthesized explanation of the threat chain"
    )
    mitigation_checklist: str = Field(
        default="", description="RAG-generated mitigation steps (populated on demand)"
    )


class AlertListResponse(BaseModel):
    alerts: list[AssetAlert]
    total: int


class MitigationRequest(BaseModel):
    alert_id: str
    asset_id: str
    cve_id: str


class MitigationResponse(BaseModel):
    alert_id: str
    cve_id: str
    checklist: str
