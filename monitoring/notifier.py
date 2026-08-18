"""Alert notification delivery (Module 11, step 5).

Delivery strategy mirrors real SOC tooling:
  - CRITICAL / HIGH  → immediate push (email | Slack | webhook)
  - MEDIUM / LOW     → batched daily/weekly digest
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import requests  # type: ignore[import-untyped]

log = logging.getLogger(__name__)

IMMEDIATE_TIERS = {"CRITICAL", "HIGH"}
DIGEST_TIERS = {"MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# Channel helpers
# ---------------------------------------------------------------------------

def _send_slack(webhook_url: str, alert: dict[str, Any]) -> None:
    """POST a Slack Block Kit message for one alert."""
    tier = alert.get("alert_tier", "?")
    cve = alert.get("cve_id", "?")
    asset = alert.get("asset_name", "?")
    score = alert.get("threat_priority_score", 0)
    narrative = alert.get("narrative", "No narrative yet.") or "No narrative yet."
    kev_flag = " 🔥 CISA KEV" if alert.get("is_kev") else ""

    color = "#ef4444" if tier == "CRITICAL" else "#f97316"
    blocks = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"[{tier}] {cve} affects {asset}{kev_flag}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*ThreatPriority:* {score:.1f}/100"},
                            {"type": "mrkdwn", "text": f"*CVSS:* {alert.get('cvss_v3_score', 'N/A')}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Threat chain:*\n{narrative[:600]}"},
                    },
                ],
            }
        ]
    }
    resp = requests.post(webhook_url, json=blocks, timeout=10)
    resp.raise_for_status()


def _send_email(alert: dict[str, Any]) -> None:
    """Send a plain-text email alert via SMTP env vars."""
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    email_to = os.environ.get("ALERT_EMAIL_TO", "")

    if not (smtp_host and smtp_user and email_to):
        log.debug("Email not configured, skipping email delivery")
        return

    tier = alert.get("alert_tier", "?")
    cve = alert.get("cve_id", "?")
    asset = alert.get("asset_name", "?")
    narrative = alert.get("narrative", "") or "(narrative pending)"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CyberGraph {tier}] {cve} affects {asset}"
    msg["From"] = smtp_user
    msg["To"] = email_to

    text = (
        f"ALERT — {tier}\n"
        f"CVE: {cve}\nAsset: {asset}\n"
        f"ThreatPriority: {alert.get('threat_priority_score', 0):.1f}/100\n"
        f"CVSS: {alert.get('cvss_v3_score', 'N/A')}\n"
        f"CISA KEV: {alert.get('is_kev', False)}\n\n"
        f"Threat chain:\n{narrative}\n"
    )
    msg.attach(MIMEText(text, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_user, [email_to], msg.as_string())
    except Exception as exc:
        log.warning("Email delivery failed: %s", exc)


def _send_webhook(url: str, alert: dict[str, Any]) -> None:
    """POST alert payload as JSON to a generic webhook URL."""
    try:
        requests.post(url, json=alert, timeout=10).raise_for_status()
    except Exception as exc:
        log.warning("Webhook delivery failed: %s", exc)


# ---------------------------------------------------------------------------
# Public dispatch
# ---------------------------------------------------------------------------

def dispatch_immediate(alert: dict[str, Any]) -> None:
    """Send a single CRITICAL/HIGH alert via all configured channels."""
    slack_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    webhook_url = os.environ.get("ALERT_WEBHOOK_URL", "")

    if slack_url:
        try:
            _send_slack(slack_url, alert)
            log.info("Slack alert sent for %s", alert.get("cve_id"))
        except Exception as exc:
            log.warning("Slack send failed: %s", exc)

    if webhook_url:
        _send_webhook(webhook_url, alert)

    _send_email(alert)


def build_digest(alerts: list[dict[str, Any]]) -> str:
    """Build a plain-text digest of MEDIUM/LOW alerts."""
    lines = ["CyberGraph Daily Digest — Asset Alert Summary", "=" * 52, ""]
    for al in alerts:
        lines.append(
            f"[{al.get('alert_tier')}] {al.get('cve_id')} → {al.get('asset_name')}  "
            f"(TPS={al.get('threat_priority_score', 0):.0f}  "
            f"CVSS={al.get('cvss_v3_score', 'N/A')})"
        )
    lines.append("")
    lines.append("Log in to CyberGraph to view full details and mitigations.")
    return "\n".join(lines)


def dispatch_digest(alerts: list[dict[str, Any]]) -> None:
    """Send batched MEDIUM/LOW digest."""
    if not alerts:
        return
    digest = build_digest(alerts)
    log.info("Digest ready (%d alerts):\n%s", len(alerts), digest)

    slack_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if slack_url:
        try:
            payload = {"text": f"```{digest}```"}
            requests.post(slack_url, json=payload, timeout=10).raise_for_status()
        except Exception as exc:
            log.warning("Digest Slack send failed: %s", exc)
