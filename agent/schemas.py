"""Pydantic models — typed outputs cho mỗi agent + investigation aggregate."""

from typing import Literal, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "FALSE_POSITIVE"]
WorkflowType = Literal["quick_triage", "full_investigation", "skip_fp"]


class AlertInput(BaseModel):
    """RED alert đầu vào (từ red-alerts index)."""
    model_config = {"extra": "allow"}  # cho phép field bổ sung

    host: dict
    user: Optional[dict] = None
    process: dict
    red: dict
    source_event_id: Optional[str] = None


class WorkflowPlan(BaseModel):
    """Output của Supervisor — quyết định gọi agent nào."""
    workflow_type: WorkflowType
    agents_to_run: list[str]
    reasoning: str
    priority: int = Field(default=3, ge=1, le=5)


class TriageOutput(BaseModel):
    """Output của Triage Agent."""
    severity: Severity
    is_false_positive: bool
    confidence: float = Field(ge=0, le=1)
    reasoning: str
    quick_findings: list[str] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    needs_deeper_investigation: bool = False


class HuntOutput(BaseModel):
    """Output của Hunt Agent — correlate signals & timeline."""
    related_events_count: int
    timeline_vi: list[str] = Field(default_factory=list)
    iocs_found: list[str] = Field(default_factory=list)
    network_indicators: list[str] = Field(default_factory=list)
    hunt_summary_vi: str
    suspicious_score: float = Field(ge=0, le=1)


class RedAnalystOutput(BaseModel):
    """Output của RED Analyst Agent — giải thích vì sao evasion."""
    evasion_reasoning_vi: str
    discriminative_tokens: list[str] = Field(default_factory=list)
    sigma_rule_comparison_vi: str
    evasion_technique: str  # "shorthand_flag" | "encoding" | "case_manipulation" | "obfuscation" | "unknown"
    confidence: float = Field(ge=0, le=1)


class MitreOutput(BaseModel):
    """Output của MITRE Agent — map technique & TTP chain."""
    primary_tactic: str
    primary_technique: str
    sub_techniques: list[str] = Field(default_factory=list)
    ttp_chain_vi: list[str] = Field(default_factory=list)
    severity_baseline: str  # "low" | "medium" | "high" | "critical"


_KIND_ALLOWED = {"process", "file", "registry", "network",
                 "alert_correlation", "sigma_rules", "threat_intel", "wmi"}
_KIND_ALIASES = {
    "sigma_rule": "sigma_rules", "sigma": "sigma_rules", "rule": "sigma_rules",
    "privilege": "process", "privilege_escalation": "process",
    "process_tree": "process", "command": "process", "execution": "process",
    "cron": "process", "crontab": "process", "service": "process",
    "persistence": "file", "dropper": "file", "script": "file",
    "data_pattern": "network", "exfil": "network", "exfiltration": "network",
    "c2": "network", "connection": "network",
    "ioc": "threat_intel", "intel": "threat_intel",
    "correlation": "alert_correlation",
}


class ForensicEvidence(BaseModel):
    """1 mảnh bằng chứng từ host.

    `kind` chỉ để PHÂN LOẠI/hiển thị — không điều khiển logic downstream. Vì vậy
    coerce_kind nắn nhãn lệch của LLM về 1 trong 8 giá trị hợp lệ, và nhãn lạ →
    fallback "process" thay vì raise → KHÔNG bao giờ vứt bằng chứng (description_vi
    + raw mới là phần giá trị, không được mất).

    Hợp lệ cho cả Windows lẫn Linux:
    - process       : tiến trình / cây cha-con / privilege escalation
    - file          : file dropper / script / archive trên đĩa
    - registry      : Windows Run keys (Linux dùng "process"/"file" cho cron/service)
    - network       : kết nối C2 / exfil / data pattern
    - alert_correlation : tương quan nhiều alert
    - sigma_rules   : rule Sigma liên quan
    - threat_intel  : IOC / reputation
    - wmi           : WMI subscription (Windows)
    """
    kind: Literal["process", "file", "registry", "network", "alert_correlation", "sigma_rules", "threat_intel", "wmi"]
    description_vi: str
    raw: dict = Field(default_factory=dict)
    severity_contribution: Literal["high", "medium", "low", "exonerating"] = "medium"

    @field_validator("kind", mode="before")
    @classmethod
    def coerce_kind(cls, v):
        s = str(v).strip().lower()
        if s in _KIND_ALLOWED:
            return s
        return _KIND_ALIASES.get(s, "process")


class ForensicOutput(BaseModel):
    """Output của Forensic Agent — bằng chứng host-level từ Velociraptor.

    ⭐ Khác Triage: Triage đoán từ log; Forensic xác minh từ chính máy bị cảnh báo.
    """
    evidence_grade: Literal["high", "medium", "low", "missing"]
    process_tree_summary_vi: str

    @field_validator("evidence_grade", mode="before")
    @classmethod
    def coerce_evidence_grade(cls, v: str) -> str:
        if v not in {"high", "medium", "low", "missing"}:
            return "missing"
        return v
    suspicious_artifacts: list[ForensicEvidence] = Field(default_factory=list)
    persistence_found: bool = False
    c2_confirmed: bool = False
    iocs_observed: list[str] = Field(default_factory=list)
    timeline_vi: list[str] = Field(default_factory=list)
    forensic_verdict_vi: str  # "confirmed_malicious" | "likely_benign" | "inconclusive"
    confidence: float = Field(ge=0, le=1)


KNOWN_ACTION_TYPES = {
    "isolate_host", "kill_process", "block_ip", "block_domain",
    "disable_user", "reset_credentials", "create_case", "send_alert",
    "scan_host", "collect_forensics",
    "remove_persistence", "update_detection_rules", "quarantine_file",
    "kill_service", "delete_registry_key", "delete_scheduled_task",
    "delete_wmi_subscription", "rotate_secret", "restore_backup",
    "patch_vulnerability", "deploy_yara_rule",
}


class ResponseAction(BaseModel):
    """1 hành động containment/response — có thể cần human approval.

    action_type là free-form string: LLM hay sinh tên action chưa có trong enum.
    KNOWN_ACTION_TYPES dùng để downstream dispatch — unknown vẫn được giữ làm
    advisory cho analyst chứ không drop.
    """
    action_type: str
    target: str
    priority: int = Field(ge=1, le=5)
    needs_approval: bool = True
    rationale_vi: str
    executed: bool = False
    executed_at: Optional[str] = None


class ResponseOutput(BaseModel):
    """Output của Response Agent — Sigma patch + containment + notification.

    ⭐ NOVELTY của project: auto-generate Sigma rule fix từ evasion sample.
    """
    sigma_patch_yaml: str  # Patched rule (full hoặc diff)
    sigma_patch_explanation_vi: str
    containment_actions: list[ResponseAction] = Field(default_factory=list)
    notification_sent: bool = False
    notification_target: Optional[str] = None
    requires_human_approval: bool = True
    summary_vi: str


class ReportOutput(BaseModel):
    """Output của Report Agent — báo cáo tiếng Việt cho SOC."""
    title_vi: str
    summary_vi: str
    full_markdown_vi: str
    recommended_actions_vi: list[str] = Field(default_factory=list)
    full_report_url: Optional[str] = None
    kibana_case_id: Optional[str] = None
    kibana_case_url: Optional[str] = None


class AgentMetadata(BaseModel):
    """Metadata mỗi lần invoke agent."""
    agent_name: str
    duration_ms: float
    steps: int
    tokens_prompt: int = 0
    tokens_completion: int = 0
    tokens_cached: int = 0
    error: Optional[str] = None


class Investigation(BaseModel):
    """Final output — tổng hợp toàn workflow, ghi vào ai-investigations-*."""
    investigation_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    trigger_alert: dict
    workflow_plan: Optional[WorkflowPlan] = None
    triage: Optional[TriageOutput] = None
    forensic: Optional[ForensicOutput] = None
    hunt: Optional[HuntOutput] = None
    red_analyst: Optional[RedAnalystOutput] = None
    mitre: Optional[MitreOutput] = None
    response: Optional[ResponseOutput] = None
    report: Optional[ReportOutput] = None
    agent_metadata: list[AgentMetadata] = Field(default_factory=list)
    total_duration_ms: float = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0
