// MVP graph schema: constraints & indexes.
// Safe to re-run - IF NOT EXISTS makes all statements idempotent.

CREATE CONSTRAINT threat_actor_id IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT malware_id IF NOT EXISTS FOR (m:Malware) REQUIRE m.id IS UNIQUE;
CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT product_cpe IF NOT EXISTS FOR (p:AffectedProduct) REQUIRE p.cpe IS UNIQUE;

// Module 11: Asset Monitoring & Alerting
CREATE CONSTRAINT monitored_asset_id IF NOT EXISTS FOR (a:MonitoredAsset) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT asset_alert_id IF NOT EXISTS FOR (al:AssetAlert) REQUIRE al.alert_id IS UNIQUE;

CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity);
CREATE INDEX cve_is_kev IF NOT EXISTS FOR (c:CVE) ON (c.is_kev);
CREATE INDEX alert_tier IF NOT EXISTS FOR (al:AssetAlert) ON (al.alert_tier);
CREATE INDEX alert_asset IF NOT EXISTS FOR (al:AssetAlert) ON (al.asset_id);
CREATE INDEX monitored_vendor_product IF NOT EXISTS FOR (a:MonitoredAsset) ON (a.vendor, a.product);
CREATE FULLTEXT INDEX entity_description IF NOT EXISTS
FOR (n:ThreatActor|Technique|Malware|CVE) ON EACH [n.description];
