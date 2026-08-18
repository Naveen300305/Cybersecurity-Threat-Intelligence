"""RAG-powered enrichment for asset alerts (Module 11, steps 4 & 6).

Two functions:
  - generate_narrative()       → explain the threat chain using graph + LLM
  - generate_mitigation_checklist()  → action plan for a specific CVE+asset
"""

from __future__ import annotations

import logging
import os

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_neo4j import Neo4jGraph

log = logging.getLogger(__name__)


def _build_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model=os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
        temperature=0.1,
    )


def _build_graph() -> Neo4jGraph:
    return Neo4jGraph(
        url=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        username=os.environ.get("NEO4J_USERNAME", "neo4j"),
        password=os.environ["NEO4J_PASSWORD"],
    )


# ---------------------------------------------------------------------------
# Graph context retrieval
# ---------------------------------------------------------------------------

_CHAIN_QUERY = """
MATCH (c:CVE {id: $cve_id})
OPTIONAL MATCH (m:Malware)-[:EXPLOITS]->(c)
OPTIONAL MATCH (ta:ThreatActor)-[:DEPLOYS]->(m2:Malware)-[:EXPLOITS]->(c)
OPTIONAL MATCH (ta2:ThreatActor)-[:USES]->(tech:Technique)<-[:USES]-(m3:Malware)-[:EXPLOITS]->(c)
OPTIONAL MATCH (tech2:Technique)-[:MITIGATED_BY]->(mit:Mitigation)
WHERE (m3)-[:USES]->(tech2)
RETURN
    c.id             AS cve_id,
    c.description    AS cve_description,
    c.cvss_v3_score  AS cvss,
    c.is_kev         AS is_kev,
    collect(DISTINCT m.name)   AS malware,
    collect(DISTINCT ta.name)  AS actors,
    collect(DISTINCT tech.name) AS techniques,
    collect(DISTINCT {mitigation: mit.name, description: mit.description}) AS mitigations
LIMIT 1
"""


def _get_graph_context(cve_id: str) -> dict:
    """Return raw graph context for a CVE as a dict."""
    graph = _build_graph()
    results = graph.query(_CHAIN_QUERY, params={"cve_id": cve_id})
    if not results:
        return {}
    return results[0]


# ---------------------------------------------------------------------------
# Narrative synthesis
# ---------------------------------------------------------------------------

_NARRATIVE_TEMPLATE = """You are a senior threat intelligence analyst.
Using the graph data below, write a concise (3–5 sentence) threat narrative 
that explains WHY this CVE is a real risk to the affected asset.
Lead with the threat actors and malware involved, then describe the attack 
chain, and close with the potential impact.
Do NOT use generic phrases. Cite specific names from the data.

CVE: {cve_id}
Asset affected: {asset_name} ({asset_version_range})

Graph context:
- Description: {cve_description}
- CVSS: {cvss}  |  CISA KEV: {is_kev}
- Exploiting malware: {malware}
- Deploying threat actors: {actors}
- ATT&CK techniques: {techniques}

Narrative:"""


def generate_narrative(
    cve_id: str,
    asset_name: str,
    asset_version_range: str,
) -> str:
    """Return a RAG-synthesized threat chain narrative for the alert."""
    try:
        ctx = _get_graph_context(cve_id)
        if not ctx:
            return (
                f"{cve_id} affects {asset_name}. No additional graph context available yet."
            )

        prompt = _NARRATIVE_TEMPLATE.format(
            cve_id=cve_id,
            asset_name=asset_name,
            asset_version_range=asset_version_range,
            cve_description=ctx.get("cve_description", "N/A"),
            cvss=ctx.get("cvss", "N/A"),
            is_kev=ctx.get("is_kev", False),
            malware=", ".join(ctx.get("malware", [])) or "none recorded",
            actors=", ".join(ctx.get("actors", [])) or "none recorded",
            techniques=", ".join(ctx.get("techniques", [])) or "none recorded",
        )

        llm = _build_llm()
        response = llm.invoke(prompt)
        return response.content.strip()

    except Exception as exc:
        log.warning("Narrative generation failed for %s: %s", cve_id, exc)
        return f"Narrative unavailable ({exc})"


# ---------------------------------------------------------------------------
# Mitigation checklist
# ---------------------------------------------------------------------------

_MITIGATION_TEMPLATE = """You are a cybersecurity incident response expert.
Generate a numbered, actionable mitigation checklist for the following situation.
Use specific steps that a SOC analyst can execute today.
Reference ATT&CK mitigations and CISA guidance where applicable.
Keep it under 10 steps.

CVE: {cve_id}
Affected asset: {asset_name} running {asset_version_range}
CVSS score: {cvss}
Threat actors known to exploit this: {actors}
Malware used: {malware}
Relevant ATT&CK mitigations from graph:
{mitigation_text}

Mitigation Checklist:"""


def generate_mitigation_checklist(
    cve_id: str,
    asset_name: str,
    asset_version_range: str,
) -> str:
    """Return a RAG-generated mitigation checklist pulling Mitigation nodes from the graph."""
    try:
        ctx = _get_graph_context(cve_id)
        mitigations = ctx.get("mitigations", []) if ctx else []
        mit_text = "\n".join(
            f"- {m.get('mitigation', '')}: {(m.get('description') or '')[:120]}"
            for m in mitigations
            if m.get("mitigation")
        ) or "No specific mitigations in graph — apply vendor patch immediately."

        prompt = _MITIGATION_TEMPLATE.format(
            cve_id=cve_id,
            asset_name=asset_name,
            asset_version_range=asset_version_range,
            cvss=ctx.get("cvss", "N/A") if ctx else "N/A",
            actors=", ".join(ctx.get("actors", [])) if ctx else "unknown",
            malware=", ".join(ctx.get("malware", [])) if ctx else "unknown",
            mitigation_text=mit_text,
        )

        llm = _build_llm()
        response = llm.invoke(prompt)
        return response.content.strip()

    except Exception as exc:
        log.warning("Mitigation generation failed for %s: %s", cve_id, exc)
        return f"Checklist unavailable ({exc})"
