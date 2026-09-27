"""Triage Agent — phân loại severity + FP, dùng tools để gather context."""

import json
import logging

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import TriageOutput

logger = logging.getLogger("agent.triage")

# Triage được dùng 3 tools
TRIAGE_TOOLS = ["query_es_history", "get_process_tree", "lookup_mitre"]


async def run_triage(llm: LLMClient, alert: dict, verbose: bool = True) -> tuple[TriageOutput, dict]:
    """Use tools to triage. Returns: (TriageOutput, raw_dict)."""
    system_prompt = load_prompt("triage")
    user_input = (
        "Triage RED alert sau. Dùng tools để gather context trước khi conclude.\n\n"
        f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```"
    )

    result = await react_loop(
        llm=llm,
        agent_name="triage",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=TRIAGE_TOOLS,
        max_iter=6,
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("Triage failed: %s — return MEDIUM placeholder", result["error"])
        triage = TriageOutput(
            severity="MEDIUM",
            is_false_positive=False,
            confidence=0.3,
            reasoning=f"Triage failed: {result['error']}",
            quick_findings=[],
        )
    else:
        triage = TriageOutput(
            severity=result.get("severity", "MEDIUM"),
            is_false_positive=result.get("is_false_positive", False),
            confidence=float(result.get("confidence", 0.5)),
            reasoning=result.get("reasoning", ""),
            quick_findings=result.get("quick_findings", []),
            mitre_technique=result.get("mitre_technique"),
            needs_deeper_investigation=result.get("needs_deeper_investigation", False),
        )

    return triage, result
