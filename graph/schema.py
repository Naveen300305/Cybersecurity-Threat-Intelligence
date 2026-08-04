"""Graph schema for the CyberGraph MVP.

Full schema (spec section 5) is larger; this MVP covers the subset
populated by the current ingestion connectors: MITRE ATT&CK
(ThreatActor, Technique, Tactic, Malware, Mitigation) and NVD
(CVE, AffectedProduct).
"""

from pathlib import Path

INDEXES_CYPHER_PATH = Path(__file__).with_name("indexes.cypher")

# Embedded in the Graph RAG Cypher-generation prompt (rag/prompts.py) so the
# LLM knows exactly which labels, properties, and relationships it may use.
SCHEMA_TEXT = """
Node labels and key properties:
  (:ThreatActor {id, name, aliases, description, motivation, sophistication})
  (:Technique {id, name, description, is_subtechnique})
  (:Tactic {id, name, description, shortname})
  (:Malware {id, name, type, description, aliases, platforms})
  (:Mitigation {id, name, description})
  (:CVE {id, description, cvss_v3_score, severity, published_date, is_kev, epss_score})
  (:AffectedProduct {cpe, vendor, product, version})

Relationships:
  (:ThreatActor)-[:USES]->(:Technique)
  (:ThreatActor)-[:DEPLOYS]->(:Malware)
  (:Malware)-[:USES]->(:Technique)
  (:Technique)-[:BELONGS_TO]->(:Tactic)
  (:Technique)-[:HAS_SUBTECHNIQUE]->(:Technique)
  (:Technique)-[:MITIGATED_BY]->(:Mitigation)
  (:CVE)-[:AFFECTS]->(:AffectedProduct)
"""


def apply_constraints(driver) -> None:
    """Run graph/indexes.cypher against Neo4j. Idempotent - safe to re-run."""
    statements = [
        s.strip()
        for s in INDEXES_CYPHER_PATH.read_text(encoding="utf-8").split(";")
        if s.strip() and not s.strip().startswith("//")
    ]
    with driver.session() as session:
        for statement in statements:
            session.run(statement)
