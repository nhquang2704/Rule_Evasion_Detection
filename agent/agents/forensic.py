"""Forensic Agent — thu thập bằng chứng host-level qua Velociraptor.

Chạy SAU Triage, TRƯỚC parallel block (Hunt/RED Analyst/MITRE).
Cung cấp bằng chứng cứng (process tree thật, file thật, network thật)
để Response Agent có cơ sở sinh Sigma patch chính xác — không bịa.
"""

import json
import logging
from typing import Optional

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import ForensicOutput, ForensicEvidence, TriageOutput

logger = logging.getLogger("agent.forensic")

FORENSIC_TOOLS = ["vr_process_tree_deep", "vr_file_artifacts", "vr_network_connections"]


async def run_forensic(
    llm: LLMClient,
    alert: dict,
    triage: TriageOutput,
    verbose: bool = True,
) -> tuple[ForensicOutput, dict]:
    """Use Velociraptor tools to collect host-level evidence."""
    system_prompt = load_prompt("forensic")

    # Tìm client_id (Velociraptor) trong alert — fallback dùng host.name nếu không có
    host_block = alert.get("host", {}) or {}
    client_id = host_block.get("client_id") or host_block.get("name", "unknown")
    pid = alert.get("process", {}).get("pid", 0)

    user_input = (
        "Thu thập bằng chứng host-level từ Velociraptor cho alert sau.\n"
        f"Velociraptor client_id: `{client_id}`, target PID: `{pid}`.\n"
        "Gọi 3 tool song song nếu được — Velociraptor query có thể chậm.\n\n"
        "**ALERT**:\n"
        f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```\n\n"
        "**TRIAGE FINDINGS (cần xác minh)**:\n"
        f"- Severity tạm: {triage.severity}\n"
        f"- Reasoning Triage: {triage.reasoning}\n"
        f"- Quick findings: {triage.quick_findings}\n"
    )

    result = await react_loop(
        llm=llm,
        agent_name="forensic",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=FORENSIC_TOOLS,
        max_iter=5,
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("Forensic failed: %s — đánh dấu missing evidence", result["error"])
        return ForensicOutput(
            evidence_grade="missing",
            process_tree_summary_vi=f"Forensic Agent lỗi: {result['error']}",
            forensic_verdict_vi="inconclusive",
            confidence=0.0,
        ), result

    # Parse suspicious_artifacts (list of dict → list of ForensicEvidence)
    artifacts_raw = result.get("suspicious_artifacts", [])
    artifacts: list[ForensicEvidence] = []
    for a in artifacts_raw:
        try:
            artifacts.append(ForensicEvidence(**a))
        except Exception as e:
            logger.warning("Bỏ qua evidence không hợp lệ: %s — %s", a, e)

    return ForensicOutput(
        evidence_grade=result.get("evidence_grade", "missing"),
        process_tree_summary_vi=result.get("process_tree_summary_vi", ""),
        suspicious_artifacts=artifacts,
        persistence_found=result.get("persistence_found", False),
        c2_confirmed=result.get("c2_confirmed", False),
        iocs_observed=result.get("iocs_observed", []),
        timeline_vi=result.get("timeline_vi", []),
        forensic_verdict_vi=result.get("forensic_verdict_vi", "inconclusive"),
        confidence=float(result.get("confidence", 0.5)),
    ), result
