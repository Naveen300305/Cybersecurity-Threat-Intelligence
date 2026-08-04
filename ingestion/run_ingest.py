"""MVP ingestion CLI.

Usage:
    python -m ingestion.run_ingest              # ATT&CK + recent NVD CVEs
    python -m ingestion.run_ingest --skip-nvd    # ATT&CK only (fast)
    python -m ingestion.run_ingest --skip-attack # NVD only
"""

from __future__ import annotations

import argparse
import os

from dotenv import load_dotenv
from neo4j import GraphDatabase

from graph.schema import apply_constraints
from ingestion.connectors.attack import fetch_attack_bundle, parse_attack_bundle
from ingestion.connectors.nvd import fetch_recent_cves
from ingestion.loaders.neo4j_loader import load_attack_data, load_cves


def get_driver():
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USERNAME", "neo4j")
    password = os.environ["NEO4J_PASSWORD"]
    return GraphDatabase.driver(uri, auth=(user, password))


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Ingest ATT&CK + NVD data into Neo4j")
    parser.add_argument("--skip-attack", action="store_true")
    parser.add_argument("--skip-nvd", action="store_true")
    args = parser.parse_args()

    driver = get_driver()
    try:
        print("Applying constraints/indexes...")
        apply_constraints(driver)

        if not args.skip_attack:
            print("Fetching MITRE ATT&CK Enterprise bundle...")
            bundle = fetch_attack_bundle()
            parsed = parse_attack_bundle(bundle)
            print(
                f"Parsed {len(parsed['actors'])} actors, "
                f"{len(parsed['techniques'])} techniques, "
                f"{len(parsed['malware'])} malware/tools, "
                f"{len(parsed['mitigations'])} mitigations."
            )
            load_attack_data(driver, parsed)
            print("ATT&CK data loaded.")

        if not args.skip_nvd:
            lookback_days = int(os.environ.get("NVD_CVE_LOOKBACK_DAYS", 90))
            max_results = int(os.environ.get("NVD_CVE_MAX_RESULTS", 500))
            print(f"Fetching last {lookback_days} days of NVD CVEs (max {max_results})...")
            cves = fetch_recent_cves(
                lookback_days=lookback_days,
                max_results=max_results,
                api_key=os.environ.get("NVD_API_KEY") or None,
            )
            print(f"Fetched {len(cves)} CVEs.")
            load_cves(driver, cves)
            print("CVE data loaded.")

        print("Ingestion complete.")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
