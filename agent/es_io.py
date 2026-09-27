"""Elasticsearch I/O — đọc red-alerts, ghi ai-investigations-*, manage state.

Pure requests-based — không cần elasticsearch-py.
"""

import os
import json
import logging
import copy
from typing import Optional
from datetime import datetime, timezone

import requests

from agent.schemas import Investigation

logger = logging.getLogger("agent.es_io")

ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
ES_AUTH = (ES_USER, ES_PASSWORD) if ES_PASSWORD else None
ES_RED_INDEX = os.environ.get("ES_RED_INDEX", "red-alerts")
ES_AI_INDEX = os.environ.get("ES_AI_INDEX", "ai-investigations")
ES_VERIFY = os.environ.get("ES_VERIFY_SSL", "true").lower() != "false"
if not ES_VERIFY:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".agent_daemon_state.json",
)


# ── ES index mapping (flat structure, Kibana-friendly) ──
AI_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "investigation_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "trigger_alert": {"type": "object", "enabled": True},
            "workflow_plan": {
                "properties": {
                    "workflow_type": {"type": "keyword"},
                    "priority": {"type": "integer"},
                    "reasoning": {"type": "text"},
                    "agents_to_run": {"type": "keyword"},
                },
            },
            "triage": {
                "properties": {
                    "severity": {"type": "keyword"},
                    "is_false_positive": {"type": "boolean"},
                    "confidence": {"type": "float"},
                    "reasoning": {"type": "text"},
                    "mitre_technique": {"type": "keyword"},
                    "quick_findings": {"type": "text"},
                    "needs_deeper_investigation": {"type": "boolean"},
                },
            },
            "hunt": {
                "properties": {
                    "related_events_count": {"type": "integer"},
                    "iocs_found": {"type": "keyword"},
                    "network_indicators": {"type": "text"},
                    "suspicious_score": {"type": "float"},
                    "hunt_summary_vi": {"type": "text"},
                    "timeline_vi": {"type": "text"},
                },
            },
            "red_analyst": {
                "properties": {
                    "evasion_technique": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "evasion_reasoning_vi": {"type": "text"},
                    "discriminative_tokens": {"type": "keyword"},
                    "sigma_rule_comparison_vi": {"type": "text"},
                },
            },
            "mitre": {
                "properties": {
                    "primary_tactic": {"type": "keyword"},
                    "primary_technique": {"type": "keyword"},
                    "sub_techniques": {"type": "keyword"},
                    "severity_baseline": {"type": "keyword"},
                    "ttp_chain_vi": {"type": "text"},
                },
            },
            "response": {
                "properties": {
                    "sigma_patch_yaml": {"type": "text"},
                    "sigma_patch_explanation_vi": {"type": "text"},
                    "notification_sent": {"type": "boolean"},
                    "notification_target": {"type": "keyword"},
                    "requires_human_approval": {"type": "boolean"},
                    "summary_vi": {"type": "text"},
                    # containment_actions kept as nested object array
                },
            },
            "report": {
                "properties": {
                    "title_vi": {"type": "text"},
                    "summary_vi": {"type": "text"},
                    "full_markdown_vi": {"type": "text"},
                    "recommended_actions_vi": {"type": "text"},
                    "full_report_url": {"type": "keyword"},
                    "kibana_case_id": {"type": "keyword"},
                    "kibana_case_url": {"type": "keyword"},
                },
            },
            "agent_metadata": {
                "properties": {
                    "agent_name": {"type": "keyword"},
                    "duration_ms": {"type": "float"},
                    "steps": {"type": "integer"},
                    "tokens_prompt": {"type": "long"},
                    "tokens_completion": {"type": "long"},
                    "tokens_cached": {"type": "long"},
                    "error": {"type": "keyword"},
                },
            },
            "total_duration_ms": {"type": "float"},
            "total_tokens": {"type": "long"},
            "estimated_cost_usd": {"type": "float"},
        },
    },
}


# ── Index management ────────────────────────────────────────────────
def ensure_ai_index() -> bool:
    """Tạo ai-investigations index với mapping nếu chưa có."""
    r = requests.head(f"{ES_HOST}/{ES_AI_INDEX}", auth=ES_AUTH, timeout=5, verify=ES_VERIFY)
    if r.status_code == 200:
        logger.debug("Index %s đã tồn tại", ES_AI_INDEX)
        return True
    if r.status_code == 404:
        logger.info("Tạo index %s với mapping...", ES_AI_INDEX)
        r2 = requests.put(
            f"{ES_HOST}/{ES_AI_INDEX}",
            auth=ES_AUTH,
            json=AI_INDEX_MAPPING,
            timeout=10,
            verify=ES_VERIFY,
        )
        if r2.ok:
            logger.info("✓ Index %s created", ES_AI_INDEX)
            return True
        raise RuntimeError(f"Tạo index thất bại: {r2.status_code} {r2.text}")
    raise RuntimeError(f"ES check failed: {r.status_code} {r.text}")


# ── Investigation write ─────────────────────────────────────────────
def write_investigation(inv: Investigation) -> dict:
    """Index Investigation vào ai-investigations.

    Document ID = investigation_id (idempotent — chạy lại không tạo dup).
    """
    doc = inv.model_dump(mode="json", exclude_none=False)
    _sanitize_forensic_raw_fields(doc)
    r = requests.put(
        f"{ES_HOST}/{ES_AI_INDEX}/_doc/{inv.investigation_id}",
        auth=ES_AUTH,
        json=doc,
        timeout=15,
        verify=ES_VERIFY,
    )
    if not r.ok:
        raise RuntimeError(f"Index failed ({r.status_code}): {r.text}")
    return r.json()

def _sanitize_forensic_raw_fields(doc: dict) -> None:
    """Prevent dynamic ES mappings from rejecting arbitrary forensic raw fields."""
    forensic = doc.get("forensic")
    if not isinstance(forensic, dict):
        return

    artifacts = forensic.get("suspicious_artifacts")
    if not isinstance(artifacts, list):
        return

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        raw = artifact.get("raw")
        if not isinstance(raw, dict) or not raw:
            continue
        artifact["raw_json"] = json.dumps(raw, ensure_ascii=False, sort_keys=True)
        artifact["raw"] = {}

# ── Alert read ──────────────────────────────────────────────────────
def _ensure_path(obj: dict, path: str) -> dict:
    cur = obj
    for part in path.split("."):
        child = cur.get(part)
        if not isinstance(child, dict):
            child = {}
            cur[part] = child
        cur = child
    return cur


def _set_path(obj: dict, path: str, value) -> None:
    parts = path.split(".")
    cur = _ensure_path(obj, ".".join(parts[:-1])) if len(parts) > 1 else obj
    cur[parts[-1]] = value


def normalize_alert_source(src: dict) -> dict:
    """Normalize red-alerts documents from detect_live.py and mock injectors.

    detect_live.py writes dotted _source keys such as ``red.detection_score`` and
    ``host.name``. The multi-agent prompts/schemas expect nested objects such as
    ``red.stage1_score`` and ``host.name``. Elasticsearch can query dotted field
    paths, but _source keeps the original dotted keys, so normalize here.
    """
    alert = copy.deepcopy(src)

    dotted_to_nested = {
        "host.name": "host.name",
        "winlog.event_id": "winlog.event_id",
        "winlog.computer_name": "winlog.computer_name",
        "red.detection_score": "red.detection_score",
        "red.attribution_method": "red.attribution_method",
        "red.evaded_rules_meta": "red.evaded_rules_meta",
        "red.command_line": "red.command_line",
        # Stage 2 live fields
        "red.confidence": "red.confidence",
        "red.needs_agent": "red.needs_agent",
        "red.evasion_technique": "red.evasion_technique",
        "red.decode_chain": "red.decode_chain",
        "red.report": "red.report",
        "red.stage2_mode": "red.stage2_mode",
        "red.cosine_top": "red.cosine_top",
    }
    for dotted_key, nested_path in dotted_to_nested.items():
        if dotted_key in alert:
            _set_path(alert, nested_path, alert[dotted_key])

    red = alert.setdefault("red", {})
    if "stage1_score" not in red and "detection_score" in red:
        red["stage1_score"] = red["detection_score"]

    # Normalize evaded_rules_meta entries into shape used by AI agent
    normalized_evaded = []
    for item in red.get("evaded_rules_meta", []) or []:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id") or item.get("rule")
        score = item.get("cosine_score", item.get("score"))
        normalized = dict(item)
        if rule_id is not None:
            normalized.setdefault("rule_id", rule_id)
            normalized.setdefault("rule", rule_id)
        if score is not None:
            normalized.setdefault("cosine_score", score)
            normalized.setdefault("score", score)
        # Normalize field names (no sigma_ prefix in evaded_rules_meta)
        normalized.setdefault("sigma_title", item.get("title", ""))
        normalized.setdefault("sigma_level", item.get("level", ""))
        normalized.setdefault("sigma_filename", item.get("filename", ""))
        normalized_evaded.append(normalized)
    if normalized_evaded:
        red["evaded_rules_meta"] = normalized_evaded

    if "top_rule" not in red and normalized_evaded:
        red["top_rule"] = normalized_evaded[0].get("rule_id")

    if "source_event_id" not in alert and alert.get("_es_id"):
        alert["source_event_id"] = alert["_es_id"]

    return alert


def poll_new_alerts(
    since_timestamp: Optional[str] = None,
    until_timestamp: Optional[str] = None,
    limit: int = 50,
    score_threshold: float = 0.0,
    query_string: Optional[str] = None,
) -> list[dict]:
    """Lấy alerts mới từ red-alerts.

    - since_timestamp: ISO 8601/date math, lấy alerts có @timestamp > giá trị này
    - until_timestamp: ISO 8601/date math, lấy alerts có @timestamp <= giá trị này
    - score_threshold: lấy alerts có red.stage1_score hoặc red.detection_score >= ngưỡng
    """
    filters: list[dict] = []
    timestamp_range = {}
    if since_timestamp:
        timestamp_range["gt"] = since_timestamp
    if until_timestamp:
        timestamp_range["lte"] = until_timestamp
    if timestamp_range:
        filters.append({"range": {"@timestamp": timestamp_range}})
    if score_threshold > 0:
        filters.append({
            "bool": {
                "should": [
                    {"range": {"red.stage1_score": {"gte": score_threshold}}},
                    {"range": {"red.detection_score": {"gte": score_threshold}}},
                ],
                "minimum_should_match": 1,
            }
        })
    must: list[dict] = []
    if query_string:
        must.append({"query_string": {"query": query_string}})

    query = {
        "query": {"bool": {"filter": filters, "must": must}} if filters or must else {"match_all": {}},
        "size": limit,
        "sort": [{"@timestamp": "asc"}],
    }

    r = requests.post(
        f"{ES_HOST}/{ES_RED_INDEX}/_search",
        auth=ES_AUTH,
        json=query,
        timeout=15,
        verify=ES_VERIFY,
    )
    if not r.ok:
        raise RuntimeError(f"Poll failed ({r.status_code}): {r.text}")

    hits = r.json().get("hits", {}).get("hits", [])
    out: list[dict] = []
    for h in hits:
        src = h["_source"]
        src["_es_id"] = h["_id"]
        out.append(normalize_alert_source(src))
    return out


def get_alert_by_id(es_id: str) -> Optional[dict]:
    """Lấy 1 alert theo ES document ID."""
    r = requests.get(
        f"{ES_HOST}/{ES_RED_INDEX}/_doc/{es_id}",
        auth=ES_AUTH,
        timeout=10,
        verify=ES_VERIFY,
    )
    if r.status_code == 404:
        return None
    if not r.ok:
        raise RuntimeError(f"Get failed: {r.text}")
    src = r.json().get("_source", {})
    src["_es_id"] = es_id
    return normalize_alert_source(src)


# ── State management ────────────────────────────────────────────────
def load_state() -> dict:
    """Load daemon state — last processed timestamp + counters."""
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {
        "last_processed_timestamp": None,
        "processed_count": 0,
        "error_count": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


def save_state(state: dict) -> None:
    """Atomic write — viết temp file rồi rename."""
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


def reset_state() -> None:
    """Xóa state file (sẽ process lại tất cả alerts)."""
    if os.path.isfile(STATE_FILE):
        os.remove(STATE_FILE)
        logger.info("State file removed")


# ── Health check ────────────────────────────────────────────────────
def check_es_connection() -> bool:
    """Verify ES reachable + credentials đúng."""
    try:
        r = requests.get(f"{ES_HOST}/_cluster/health", auth=ES_AUTH, timeout=5, verify=ES_VERIFY)
        if r.ok:
            health = r.json()
            logger.info("✓ ES connection OK: cluster=%s status=%s",
                        health.get("cluster_name"), health.get("status"))
            return True
        logger.error("ES health check failed: %d %s", r.status_code, r.text)
        return False
    except Exception as e:
        logger.error("ES unreachable: %s", e)
        return False
