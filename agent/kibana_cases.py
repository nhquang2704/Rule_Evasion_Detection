"""Kibana Cases integration for readable AI investigation reports."""

import logging
import os
from typing import Optional

import requests

logger = logging.getLogger("agent.kibana_cases")

KIBANA_URL = os.environ.get("KIBANA_URL", "").rstrip("/")
KIBANA_USER = os.environ.get("KIBANA_USER", "")
KIBANA_PASSWORD = os.environ.get("KIBANA_PASSWORD", "")
KIBANA_SPACE_ID = os.environ.get("KIBANA_SPACE_ID", "default")
KIBANA_CASE_OWNER = os.environ.get("KIBANA_CASE_OWNER", "securitySolution")
KIBANA_CASES_ENABLED = os.environ.get("KIBANA_CASES_ENABLED", "0") == "1"

MAX_COMMENT_LEN = 30000


def create_case_for_investigation(inv) -> tuple[Optional[str], Optional[str]]:
    """Create a Kibana Case containing the full Markdown report."""
    if not KIBANA_CASES_ENABLED or not KIBANA_URL or not inv.report:
        return None, None

    host = inv.trigger_alert.get("host", {}).get("name", "unknown")
    source_event_id = inv.trigger_alert.get("source_event_id", "unknown")
    payload = {
        "title": f"[RED] {inv.report.title_vi}"[:160],
        "description": inv.report.summary_vi[:30000],
        "owner": KIBANA_CASE_OWNER,
        "severity": _case_severity(inv),
        "tags": [
            "red",
            "ai-agent",
            f"host:{host}",
            f"source_event_id:{source_event_id}",
            f"inv:{inv.investigation_id}",
        ],
        "connector": {
            "id": "none",
            "name": "none",
            "type": ".none",
            "fields": None,
        },
        "settings": {
            "syncAlerts": True,
            "extractObservables": True,
        },
    }

    response = requests.post(
        f"{_base_api()}/cases",
        auth=_auth(),
        headers=_headers(),
        json=payload,
        timeout=15,
    )
    response.raise_for_status()
    case_id = response.json()["id"]

    markdown = inv.report.full_markdown_vi or inv.report.summary_vi
    for offset in range(0, len(markdown), MAX_COMMENT_LEN):
        comment_response = requests.post(
            f"{_base_api()}/cases/{case_id}/comments",
            auth=_auth(),
            headers=_headers(),
            json={
                "type": "user",
                "owner": KIBANA_CASE_OWNER,
                "comment": markdown[offset:offset + MAX_COMMENT_LEN],
            },
            timeout=15,
        )
        comment_response.raise_for_status()

    case_url = _case_url(case_id)
    logger.info("Created Kibana case: %s", case_url)
    return case_id, case_url


def compact_report_for_dashboard(inv, report_url: Optional[str]) -> str:
    """Return a short report preview suitable for Kibana tables."""
    if not inv.report:
        return ""

    severity = inv.triage.severity if inv.triage else "UNKNOWN"
    confidence = inv.triage.confidence if inv.triage else None
    host = inv.trigger_alert.get("host", {}).get("name", "unknown")

    lines = [
        f"## {inv.report.title_vi}",
        "",
        f"- Host: {host}",
        f"- Severity: {severity}",
    ]
    if confidence is not None:
        lines.append(f"- Confidence: {confidence:.2f}")
    lines.extend([
        "",
        inv.report.summary_vi,
    ])

    actions = inv.report.recommended_actions_vi[:3]
    if actions:
        lines.extend(["", "### Hành động ưu tiên"])
        lines.extend(f"- {action}" for action in actions)

    if report_url:
        lines.extend(["", f"Full report: {report_url}"])

    return "\n".join(lines)


def _base_api() -> str:
    if KIBANA_SPACE_ID and KIBANA_SPACE_ID != "default":
        return f"{KIBANA_URL}/s/{KIBANA_SPACE_ID}/api"
    return f"{KIBANA_URL}/api"


def _auth():
    return (KIBANA_USER, KIBANA_PASSWORD) if KIBANA_PASSWORD else None


def _headers() -> dict:
    return {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }


def _case_severity(inv) -> str:
    severity = inv.triage.severity.lower() if inv.triage else "low"
    if severity == "false_positive":
        return "low"
    if severity not in {"low", "medium", "high", "critical"}:
        return "low"
    return severity


def _case_url(case_id: str) -> str:
    app_path = f"/app/security/cases/{case_id}"
    if KIBANA_SPACE_ID and KIBANA_SPACE_ID != "default":
        return f"{KIBANA_URL}/s/{KIBANA_SPACE_ID}{app_path}"
    return f"{KIBANA_URL}{app_path}"
