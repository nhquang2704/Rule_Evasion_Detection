"""MITRE Agent — map alert sang MITRE ATT&CK framework."""

import json
import logging

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import MitreOutput

logger = logging.getLogger("agent.mitre")

MITRE_TOOLS = ["lookup_mitre"]


async def run_mitre(
    llm: LLMClient,
    alert: dict,
    verbose: bool = True,
) -> tuple[MitreOutput, dict]:
    system_prompt = load_prompt("mitre")
    user_input = (
        "Map alert sau sang MITRE ATT&CK:\n\n"
        f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```"
    )

    result = await react_loop(
        llm=llm,
        agent_name="mitre",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=MITRE_TOOLS,
        max_iter=5,  # tăng từ 3 → 5 cho phép finalize sau tool calls
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("MITRE failed: %s", result["error"])
        return MitreOutput(
            primary_tactic="Unknown",
            primary_technique="Unknown",
            severity_baseline="medium",
        ), result

    return MitreOutput(
        primary_tactic=result.get("primary_tactic", "Unknown"),
        primary_technique=result.get("primary_technique", "Unknown"),
        sub_techniques=result.get("sub_techniques", []),
        ttp_chain_vi=result.get("ttp_chain_vi", []),
        severity_baseline=result.get("severity_baseline", "medium"),
    ), result
