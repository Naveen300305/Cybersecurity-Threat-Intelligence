"""MITRE ATT&CK (Enterprise) connector.

Downloads the official STIX bundle and extracts the subset of objects
needed for the MVP graph: threat actors (intrusion-set), techniques
(attack-pattern), tactics (x-mitre-tactic), malware/tools, mitigations
(course-of-action), and the relationships between them.
"""

from __future__ import annotations

import requests

ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _external_id(obj: dict, source: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source:
            return ref.get("external_id")
    return None


def fetch_attack_bundle(url: str = ENTERPRISE_ATTACK_URL, timeout: int = 60) -> dict:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()


def parse_attack_bundle(bundle: dict) -> dict:
    """Parse a STIX bundle into flat lists of node/relationship dicts."""
    objects = bundle.get("objects", [])
    by_stix_id = {obj["id"]: obj for obj in objects}

    actors, techniques, tactics, malware, mitigations = [], [], [], [], []
    uses, deploys, malware_uses, belongs_to, subtechnique_of, mitigated_by = (
        [], [], [], [], [], []
    )

    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        obj_type = obj.get("type")

        if obj_type == "intrusion-set":
            actor_id = _external_id(obj)
            if not actor_id:
                continue
            actors.append({
                "id": actor_id,
                "name": obj.get("name"),
                "aliases": obj.get("aliases", []),
                "description": obj.get("description", ""),
            })

        elif obj_type == "attack-pattern":
            tech_id = _external_id(obj)
            if not tech_id:
                continue
            techniques.append({
                "id": tech_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            })
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    belongs_to.append({
                        "technique_id": tech_id,
                        "tactic_shortname": phase.get("phase_name"),
                    })

        elif obj_type == "x-mitre-tactic":
            tactic_id = _external_id(obj)
            if not tactic_id:
                continue
            tactics.append({
                "id": tactic_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "shortname": obj.get("x_mitre_shortname"),
            })

        elif obj_type in ("malware", "tool"):
            mal_id = _external_id(obj)
            if not mal_id:
                continue
            malware.append({
                "id": mal_id,
                "name": obj.get("name"),
                "type": obj_type,
                "description": obj.get("description", ""),
                "aliases": obj.get("x_mitre_aliases", []),
                "platforms": obj.get("x_mitre_platforms", []),
            })

        elif obj_type == "course-of-action":
            mit_id = _external_id(obj)
            if not mit_id:
                continue
            mitigations.append({
                "id": mit_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
            })

        elif obj_type == "relationship":
            src, tgt = by_stix_id.get(obj["source_ref"]), by_stix_id.get(obj["target_ref"])
            if not src or not tgt:
                continue
            rel_type = obj.get("relationship_type")

            if rel_type == "uses" and src["type"] == "intrusion-set" and tgt["type"] == "attack-pattern":
                uses.append({"actor_id": _external_id(src), "technique_id": _external_id(tgt)})
            elif rel_type == "uses" and src["type"] == "intrusion-set" and tgt["type"] in ("malware", "tool"):
                deploys.append({"actor_id": _external_id(src), "malware_id": _external_id(tgt)})
            elif rel_type == "uses" and src["type"] in ("malware", "tool") and tgt["type"] == "attack-pattern":
                malware_uses.append({"malware_id": _external_id(src), "technique_id": _external_id(tgt)})
            elif rel_type == "mitigates" and src["type"] == "course-of-action" and tgt["type"] == "attack-pattern":
                mitigated_by.append({"technique_id": _external_id(tgt), "mitigation_id": _external_id(src)})
            elif rel_type == "subtechnique-of":
                subtechnique_of.append({
                    "sub_id": _external_id(src),
                    "parent_id": _external_id(tgt),
                })

    return {
        "actors": actors,
        "techniques": techniques,
        "tactics": tactics,
        "malware": malware,
        "mitigations": mitigations,
        "uses": uses,
        "deploys": deploys,
        "malware_uses": malware_uses,
        "belongs_to": belongs_to,
        "subtechnique_of": subtechnique_of,
        "mitigated_by": mitigated_by,
    }
