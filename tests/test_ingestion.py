from ingestion.connectors.attack import parse_attack_bundle
from ingestion.connectors.nvd import _extract_cpes, _extract_cvss_v3, _severity_from_score


def _external_ref(external_id):
    return {"external_references": [{"source_name": "mitre-attack", "external_id": external_id}]}


def test_parse_attack_bundle_extracts_nodes_and_relationships():
    bundle = {
        "objects": [
            {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT29",
             "aliases": ["Cozy Bear"], "description": "...", **_external_ref("G0016")},
            {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Spearphishing",
             "description": "...", "kill_chain_phases": [
                 {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
             ], **_external_ref("T1566")},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Initial Access",
             "description": "...", "x_mitre_shortname": "initial-access", **_external_ref("TA0001")},
            {"type": "relationship", "id": "relationship--1", "relationship_type": "uses",
             "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
        ]
    }

    parsed = parse_attack_bundle(bundle)

    assert parsed["actors"] == [
        {"id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"], "description": "..."}
    ]
    assert parsed["techniques"][0]["id"] == "T1566"
    assert parsed["tactics"][0]["id"] == "TA0001"
    assert parsed["uses"] == [{"actor_id": "G0016", "technique_id": "T1566"}]
    assert parsed["belongs_to"] == [{"technique_id": "T1566", "tactic_shortname": "initial-access"}]


def test_parse_attack_bundle_skips_revoked_objects():
    bundle = {"objects": [{"type": "intrusion-set", "id": "intrusion-set--1", "name": "Old",
                            "revoked": True, **_external_ref("G9999")}]}
    assert parse_attack_bundle(bundle)["actors"] == []


def test_severity_from_score():
    assert _severity_from_score(9.8) == "Critical"
    assert _severity_from_score(7.5) == "High"
    assert _severity_from_score(4.0) == "Medium"
    assert _severity_from_score(0.1) == "Low"
    assert _severity_from_score(None) == "Unknown"


def test_extract_cvss_v3_prefers_v31():
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/..."}}]}
    score, vector = _extract_cvss_v3(metrics)
    assert score == 9.8
    assert vector == "CVSS:3.1/..."


def test_extract_cvss_v3_missing_returns_none():
    assert _extract_cvss_v3({}) == (None, None)


def test_extract_cpes_filters_non_vulnerable():
    configurations = [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*"},
    ]}]}]
    assert _extract_cpes(configurations) == ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"]
