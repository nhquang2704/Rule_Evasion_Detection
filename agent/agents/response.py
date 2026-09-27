"""Response Agent — Sigma patch generation + containment + notification.

⭐ NOVELTY chính của project: agent tự sinh Sigma rule patch từ evasion sample.
"""

import json
import logging
from typing import Optional

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import (
    TriageOutput, HuntOutput, RedAnalystOutput, MitreOutput,
    ForensicOutput, ResponseOutput, ResponseAction,
)

logger = logging.getLogger("agent.response")

RESPONSE_TOOLS = ["get_sigma_rule_text", "suggest_containment", "send_telegram"]


async def run_response(
    llm: LLMClient,
    alert: dict,
    triage: TriageOutput,
    hunt: Optional[HuntOutput] = None,
    red_analyst: Optional[RedAnalystOutput] = None,
    mitre: Optional[MitreOutput] = None,
    forensic: Optional[ForensicOutput] = None,
    verbose: bool = True,
) -> tuple[ResponseOutput, dict]:
    system_prompt = load_prompt("response")

    sections = [
        "**ALERT**:",
        f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```",
        "\n**TRIAGE**:",
        f"```json\n{triage.model_dump_json(indent=2)}\n```",
    ]
    if forensic:
        sections += [
            "\n**FORENSIC EVIDENCE (BẰNG CHỨNG CỨNG từ Velociraptor — ưu tiên dùng để ground Sigma patch, KHÔNG BỊA)**:",
            f"```json\n{forensic.model_dump_json(indent=2)}\n```",
        ]
    if red_analyst:
        sections += [
            "\n**RED ANALYST (dùng evasion_technique để tạo patch phù hợp)**:",
            f"```json\n{red_analyst.model_dump_json(indent=2)}\n```",
        ]
    if hunt:
        sections += [
            "\n**HUNT (lấy IOCs để block, network indicators để chặn)**:",
            f"```json\n{hunt.model_dump_json(indent=2)}\n```",
        ]
    if mitre:
        sections += [
            "\n**MITRE**:",
            f"```json\n{mitre.model_dump_json(indent=2)}\n```",
        ]

    user_input = "Sinh Sigma patch + containment actions + notification cho alert sau:\n\n" + "\n".join(sections)

    result = await react_loop(
        llm=llm,
        agent_name="response",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=RESPONSE_TOOLS,
        max_iter=6,
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("Response failed: %s", result["error"])
        return ResponseOutput(
            sigma_patch_yaml="",
            sigma_patch_explanation_vi=f"Lỗi: {result['error']}",
            summary_vi="Response Agent gặp lỗi, cần manual review",
        ), result

    # Parse containment_actions (list of dict → list of ResponseAction)
    actions_raw = result.get("containment_actions", [])
    actions: list[ResponseAction] = []
    for a in actions_raw:
        try:
            actions.append(ResponseAction(**a))
        except Exception as e:
            logger.warning("Bỏ qua action không hợp lệ: %s — %s", a, e)

    return ResponseOutput(
        sigma_patch_yaml=result.get("sigma_patch_yaml", ""),
        sigma_patch_explanation_vi=result.get("sigma_patch_explanation_vi", ""),
        containment_actions=actions,
        notification_sent=result.get("notification_sent", False),
        notification_target=result.get("notification_target"),
        requires_human_approval=result.get("requires_human_approval", True),
        summary_vi=result.get("summary_vi", ""),
    ), result
