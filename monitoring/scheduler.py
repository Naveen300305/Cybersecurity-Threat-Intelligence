"""Scheduled monitoring job (Module 11, step 2).

Runs as a standalone process OR can be called from a cron/Celery beat task.
Orchestrates: ingest → match → score → notify.

Usage:
    python -m monitoring.scheduler                  # run once immediately
    python -m monitoring.scheduler --daemon         # loop every SCAN_INTERVAL_HOURS
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from datetime import datetime, timezone

from dotenv import load_dotenv
from neo4j import GraphDatabase

from monitoring.matcher import run_matching
from monitoring.notifier import DIGEST_TIERS, IMMEDIATE_TIERS, dispatch_digest, dispatch_immediate

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
log = logging.getLogger("monitoring.scheduler")


def _get_driver():
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(
            os.environ.get("NEO4J_USERNAME", "neo4j"),
            os.environ["NEO4J_PASSWORD"],
        ),
    )


def run_once() -> None:
    """Execute one full scan cycle."""
    log.info("=== Asset monitoring scan started at %s ===", datetime.now(timezone.utc).isoformat())

    driver = _get_driver()
    try:
        alerts = run_matching(driver)
    finally:
        driver.close()

    if not alerts:
        log.info("No new alerts this cycle.")
        return

    immediate = [a for a in alerts if a["alert_tier"] in IMMEDIATE_TIERS]
    digest = [a for a in alerts if a["alert_tier"] in DIGEST_TIERS]

    log.info(
        "New alerts: %d immediate (CRITICAL/HIGH), %d digest (MEDIUM/LOW)",
        len(immediate), len(digest),
    )

    for alert in immediate:
        dispatch_immediate(alert)

    dispatch_digest(digest)

    log.info("=== Scan complete ===")


def run_daemon(interval_hours: float) -> None:
    """Run continuously, sleeping `interval_hours` between cycles."""
    log.info("Starting monitoring daemon (interval=%.1fh)", interval_hours)
    while True:
        try:
            run_once()
        except Exception as exc:
            log.exception("Scan cycle failed: %s", exc)
        log.info("Next scan in %.1f hours", interval_hours)
        time.sleep(interval_hours * 3600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGraph asset monitoring scheduler")
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously (default: single scan then exit)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("SCAN_INTERVAL_HOURS", "24")),
        help="Hours between scans when --daemon is set (default: 24)",
    )
    args = parser.parse_args()

    if args.daemon:
        run_daemon(args.interval)
    else:
        run_once()
