// MVP graph schema: constraints & indexes.
// Safe to re-run - IF NOT EXISTS makes all statements idempotent.

CREATE CONSTRAINT threat_actor_id IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT malware_id IF NOT EXISTS FOR (m:Malware) REQUIRE m.id IS UNIQUE;
CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT product_cpe IF NOT EXISTS FOR (p:AffectedProduct) REQUIRE p.cpe IS UNIQUE;

CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity);
CREATE INDEX cve_is_kev IF NOT EXISTS FOR (c:CVE) ON (c.is_kev);
CREATE FULLTEXT INDEX entity_description IF NOT EXISTS
FOR (n:ThreatActor|Technique|Malware|CVE) ON EACH [n.description];
