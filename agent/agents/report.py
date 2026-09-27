"""Report Agent — sinh báo cáo tiếng Việt cho SOC analyst.

Không dùng tools — chỉ format dữ liệu từ alert + tất cả agent outputs thành markdown.
"""

import json
import logging
from typing import Optional

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import (
    TriageOutput, ReportOutput, ForensicOutput,
    HuntOutput, RedAnalystOutput, MitreOutput, ResponseOutput,
)

logger = logging.getLogger("agent.report")


async def run_report(
    llm: LLMClient,
    alert: dict,
    triage: TriageOutput,
    hunt: Optional[HuntOutput] = None,
    red_analyst: Optional[RedAnalystOutput] = None,
    mitre: Optional[MitreOutput] = None,
    response: Optional[ResponseOutput] = None,
    forensic: Optional[ForensicOutput] = None,
    verbose: bool = True,
) -> tuple[ReportOutput, dict]:
    """Generate Vietnamese SOC report dùng tất cả agent outputs."""
    system_prompt = load_prompt("report")

    sections = ["**ALERT**:", f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```"]
    sections += ["\n**TRIAGE**:", f"```json\n{triage.model_dump_json(indent=2)}\n```"]
    if forensic:
        sections += ["\n**FORENSIC EVIDENCE (host-level từ Velociraptor — đưa vào timeline báo cáo)**:",
                     f"```json\n{forensic.model_dump_json(indent=2)}\n```"]
    if hunt:
        sections += ["\n**HUNT**:", f"```json\n{hunt.model_dump_json(indent=2)}\n```"]
    if red_analyst:
        sections += ["\n**RED ANALYST**:", f"```json\n{red_analyst.model_dump_json(indent=2)}\n```"]
    if mitre:
        sections += ["\n**MITRE**:", f"```json\n{mitre.model_dump_json(indent=2)}\n```"]
    if response:
        sections += ["\n**RESPONSE (Sigma patch + containment)**:",
                     f"```json\n{response.model_dump_json(indent=2)}\n```"]

    user_input = "Viết báo cáo SOC tiếng Việt dựa trên tất cả kết quả sau:\n\n" + "\n".join(sections)

    result = await react_loop(
        llm=llm,
        agent_name="report",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=[],
        max_iter=3,
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("Report failed: %s", result["error"])
        return ReportOutput(
            title_vi="Báo cáo lỗi tự động",
            summary_vi=f"Không sinh được báo cáo: {result['error']}",
            full_markdown_vi="(Report Agent gặp lỗi)",
        ), result

    return ReportOutput(
        title_vi=result.get("title_vi", "Untitled"),
        summary_vi=result.get("summary_vi", ""),
        full_markdown_vi=result.get("full_markdown_vi", ""),
        recommended_actions_vi=result.get("recommended_actions_vi", []),
    ), result
