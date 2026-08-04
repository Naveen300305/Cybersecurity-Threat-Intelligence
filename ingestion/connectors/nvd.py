"""NVD CVE connector (NVD API 2.0).

MVP scope: pull recently published CVEs (bounded by lookback window and a
max result count so a laptop demo finishes in seconds, not hours) rather
than the full historical ~250k CVE corpus described in the spec.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _extract_cvss_v3(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            cvss = entries[0]["cvssData"]
            return cvss.get("baseScore"), cvss.get("vectorString")
    return None, None


def _extract_cpes(configurations: list) -> list[str]:
    cpes = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    cpes.append(match["criteria"])
    return cpes


def fetch_recent_cves(
    lookback_days: int = 90,
    max_results: int = 500,
    api_key: str | None = None,
    page_size: int = PAGE_SIZE,
) -> list[dict]:
    """Fetch recently published CVEs, newest first, capped at max_results."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    headers = {"apiKey": api_key} if api_key else {}
    # No API key -> NVD enforces 5 req/30s; pace requests accordingly.
    delay = 0.6 if api_key else 6.0

    cves, start_index = [], 0
    while len(cves) < max_results:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(page_size, max_results - len(cves)),
            "startIndex": start_index,
        }
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()

        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for entry in vulnerabilities:
            cve = entry["cve"]
            score, vector = _extract_cvss_v3(cve.get("metrics", {}))
            descriptions = cve.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
            cves.append({
                "id": cve["id"],
                "description": description,
                "cvss_v3_score": score,
                "cvss_v3_vector": vector,
                "severity": _severity_from_score(score),
                "published_date": cve.get("published"),
                "modified_date": cve.get("lastModified"),
                "cpes": _extract_cpes(cve.get("configurations", [])),
            })

        start_index += len(vulnerabilities)
        total = payload.get("totalResults", 0)
        if start_index >= total:
            break
        time.sleep(delay)

    return cves[:max_results]
