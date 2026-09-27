"""Hunt Agent — correlate signals, build timeline, find IOCs."""

import json
import logging

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import HuntOutput, TriageOutput

logger = logging.getLogger("agent.hunt")

HUNT_TOOLS = ["query_es_history", "get_process_tree",
              "get_network_connections", "search_threat_intel"]


async def run_hunt(
    llm: LLMClient,
    alert: dict,
    triage: TriageOutput,
    verbose: bool = True,
) -> tuple[HuntOutput, dict]:
    system_prompt = load_prompt("hunt")
    user_input = (
        "Hunt deeper context cho alert sau:\n\n"
        "**ALERT**:\n"
        f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```\n\n"
        "**TRIAGE FINDINGS**:\n"
        f"- Severity: {triage.severity}\n"
        f"- Reasoning: {triage.reasoning}\n"
        f"- Quick findings: {triage.quick_findings}\n"
    )

    result = await react_loop(
        llm=llm,
        agent_name="hunt",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=HUNT_TOOLS,
        max_iter=5,
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("Hunt failed: %s", result["error"])
        return HuntOutput(
            related_events_count=0,
            hunt_summary_vi=f"Hunt lỗi: {result['error']}",
            suspicious_score=0.5,
        ), result

    return HuntOutput(
        related_events_count=result.get("related_events_count", 0),
        timeline_vi=result.get("timeline_vi", []),
        iocs_found=result.get("iocs_found", []),
        network_indicators=result.get("network_indicators", []),
        hunt_summary_vi=result.get("hunt_summary_vi", ""),
        suspicious_score=float(result.get("suspicious_score", 0.5)),
    ), result
