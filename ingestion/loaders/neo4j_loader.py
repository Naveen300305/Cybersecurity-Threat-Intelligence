"""Idempotent Neo4j loaders. Every write uses MERGE (never CREATE) so
feeds can be re-run safely, per the ingestion strategy in the spec.
"""

from __future__ import annotations


def _run(driver, query: str, **params) -> None:
    with driver.session() as session:
        session.run(query, **params)


def load_attack_data(driver, parsed: dict) -> None:
    _run(driver, """
        UNWIND $rows AS row
        MERGE (a:ThreatActor {id: row.id})
        SET a.name = row.name, a.aliases = row.aliases, a.description = row.description
    """, rows=parsed["actors"])

    _run(driver, """
        UNWIND $rows AS row
        MERGE (t:Technique {id: row.id})
        SET t.name = row.name, t.description = row.description,
            t.is_subtechnique = row.is_subtechnique
    """, rows=parsed["techniques"])

    _run(driver, """
        UNWIND $rows AS row
        MERGE (t:Tactic {id: row.id})
        SET t.name = row.name, t.description = row.description, t.shortname = row.shortname
    """, rows=parsed["tactics"])

    _run(driver, """
        UNWIND $rows AS row
        MERGE (m:Malware {id: row.id})
        SET m.name = row.name, m.type = row.type, m.description = row.description,
            m.aliases = row.aliases, m.platforms = row.platforms
    """, rows=parsed["malware"])

    _run(driver, """
        UNWIND $rows AS row
        MERGE (m:Mitigation {id: row.id})
        SET m.name = row.name, m.description = row.description
    """, rows=parsed["mitigations"])

    _run(driver, """
        UNWIND $rows AS row
        MATCH (a:ThreatActor {id: row.actor_id})
        MATCH (t:Technique {id: row.technique_id})
        MERGE (a)-[:USES]->(t)
    """, rows=parsed["uses"])

    _run(driver, """
        UNWIND $rows AS row
        MATCH (a:ThreatActor {id: row.actor_id})
        MATCH (m:Malware {id: row.malware_id})
        MERGE (a)-[:DEPLOYS]->(m)
    """, rows=parsed["deploys"])

    _run(driver, """
        UNWIND $rows AS row
        MATCH (m:Malware {id: row.malware_id})
        MATCH (t:Technique {id: row.technique_id})
        MERGE (m)-[:USES]->(t)
    """, rows=parsed["malware_uses"])

    _run(driver, """
        UNWIND $rows AS row
        MATCH (t:Technique {id: row.technique_id})
        MATCH (tac:Tactic {shortname: row.tactic_shortname})
        MERGE (t)-[:BELONGS_TO]->(tac)
    """, rows=parsed["belongs_to"])

    _run(driver, """
        UNWIND $rows AS row
        MATCH (sub:Technique {id: row.sub_id})
        MATCH (parent:Technique {id: row.parent_id})
        MERGE (parent)-[:HAS_SUBTECHNIQUE]->(sub)
    """, rows=parsed["subtechnique_of"])

    _run(driver, """
        UNWIND $rows AS row
        MATCH (t:Technique {id: row.technique_id})
        MATCH (m:Mitigation {id: row.mitigation_id})
        MERGE (t)-[:MITIGATED_BY]->(m)
    """, rows=parsed["mitigated_by"])


def load_cves(driver, cves: list[dict]) -> None:
    _run(driver, """
        UNWIND $rows AS row
        MERGE (c:CVE {id: row.id})
        SET c.description = row.description,
            c.cvss_v3_score = row.cvss_v3_score,
            c.cvss_v3_vector = row.cvss_v3_vector,
            c.severity = row.severity,
            c.published_date = row.published_date,
            c.modified_date = row.modified_date
        WITH c, row
        UNWIND row.cpes AS cpe
        MERGE (p:AffectedProduct {cpe: cpe})
        MERGE (c)-[:AFFECTS]->(p)
    """, rows=cves)


def mark_kev(driver, cve_ids: list[str]) -> None:
    """Flag CVEs present in the CISA KEV catalog (spec 1.2/6.4.2)."""
    _run(driver, """
        UNWIND $ids AS cve_id
        MATCH (c:CVE {id: cve_id})
        SET c.is_kev = true
    """, ids=cve_ids)
