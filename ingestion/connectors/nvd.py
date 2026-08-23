"""NVD CVE connector (NVD API 2.0).

Two fetch modes:
  fetch_recent_cves()  — CVEs published in the last N days (bulk ingestion)
  fetch_cve_by_id()    — a single CVE by explicit ID (targeted / demo ingestion)

MVP scope: pull recently published CVEs (bounded by lookback window and a
max result count so a laptop demo finishes in seconds, not hours) rather
than the full historical ~250k CVE corpus described in the spec.

NVD API v2.0 constraints:
  - Date range per request MUST be ≤ 120 days (hard server limit → 404 otherwise).
  - Dates MUST be formatted as ISO 8601 with UTC offset, e.g. 2025-08-23T14:24:53.000+00:00.
  - Without an API key: max 5 requests per 30 s (enforced by 6 s delay between pages).
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


def _build_headers(api_key: str | None) -> dict:
    return {"apiKey": api_key} if api_key else {}


def _parse_vulnerability_entry(entry: dict) -> dict:
    """Normalise a single NVD vulnerability entry into our internal schema."""
    cve = entry["cve"]
    score, vector = _extract_cvss_v3(cve.get("metrics", {}))
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
    return {
        "id": cve["id"],
        "description": description,
        "cvss_v3_score": score,
        "cvss_v3_vector": vector,
        "severity": _severity_from_score(score),
        "published_date": cve.get("published"),
        "modified_date": cve.get("lastModified"),
        "cpes": _extract_cpes(cve.get("configurations", [])),
    }


def fetch_cve_by_id(cve_id: str, api_key: str | None = None) -> dict | None:
    """Fetch a single CVE by its exact ID from the NVD API.

    Returns the normalised CVE dict, or None if NVD doesn't know the ID.
    Raises requests.HTTPError on non-404 API failures.
    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=_build_headers(api_key),
        timeout=30,
    )
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    return _parse_vulnerability_entry(vulnerabilities[0])


# NVD API v2.0 hard limit: date window per request must not exceed 120 days.
_NVD_MAX_WINDOW_DAYS = 120


def _fmt_nvd_date(dt: datetime) -> str:
    """Format a datetime as NVD API v2.0 ISO-8601 string with UTC offset."""
    # NVD requires explicit UTC offset: 2025-08-23T14:24:53.000+00:00
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _fetch_cves_in_window(
    window_start: datetime,
    window_end: datetime,
    max_results: int,
    headers: dict,
    delay: float,
    page_size: int,
) -> list[dict]:
    """Fetch CVEs within a single ≤120-day window, handling NVD pagination."""
    cves, start_index = [], 0
    while len(cves) < max_results:
        params = {
            "pubStartDate": _fmt_nvd_date(window_start),
            "pubEndDate": _fmt_nvd_date(window_end),
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
            cves.append(_parse_vulnerability_entry(entry))

        start_index += len(vulnerabilities)
        total = payload.get("totalResults", 0)
        if start_index >= total:
            break
        time.sleep(delay)

    return cves


def fetch_recent_cves(
    lookback_days: int = 90,
    max_results: int = 2000,
    api_key: str | None = None,
    page_size: int = PAGE_SIZE,
) -> list[dict]:
    """Fetch recently published CVEs (newest first), capped at max_results.

    Automatically chunks the date range into ≤120-day windows to comply with
    the NVD API v2.0 hard limit (larger ranges return 404).
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    headers = _build_headers(api_key)
    # No API key -> NVD enforces 5 req/30s; pace requests accordingly.
    delay = 0.6 if api_key else 6.0

    # Build non-overlapping chunks of at most _NVD_MAX_WINDOW_DAYS each.
    chunks: list[tuple[datetime, datetime]] = []
    chunk_start = start
    while chunk_start < end:
        chunk_end = min(chunk_start + timedelta(days=_NVD_MAX_WINDOW_DAYS), end)
        chunks.append((chunk_start, chunk_end))
        chunk_start = chunk_end

    cves: list[dict] = []
    for chunk_start, chunk_end in chunks:
        if len(cves) >= max_results:
            break
        remaining = max_results - len(cves)
        print(
            f"  NVD: fetching {_fmt_nvd_date(chunk_start)} → {_fmt_nvd_date(chunk_end)}"
            f" (up to {remaining} CVEs)"
        )
        chunk_cves = _fetch_cves_in_window(
            chunk_start, chunk_end, remaining, headers, delay, page_size
        )
        cves.extend(chunk_cves)
        if len(chunks) > 1:
            time.sleep(delay)  # polite gap between chunk requests

    return cves[:max_results]
