"""Supervisor Agent — quyết định workflow type & agents nào sẽ chạy."""

import json
import logging

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import WorkflowPlan, AlertInput

logger = logging.getLogger("agent.supervisor")


async def run_supervisor(llm: LLMClient, alert: dict, verbose: bool = True) -> tuple[WorkflowPlan, dict]:
    """Decide investigation workflow. Không có tools — chỉ phân tích alert.

    Returns: (WorkflowPlan, raw_dict_với_meta)
    """
    system_prompt = load_prompt("supervisor")
    user_input = (
        "Phân tích alert sau và quyết định workflow:\n\n"
        f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```"
    )

    result = await react_loop(
        llm=llm,
        agent_name="supervisor",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=[],  # Supervisor không cần tools
        max_iter=3,  # Quyết định nhanh
        verbose=verbose,
    )

    if "error" in result:
        # Fallback safe default: full investigation, priority 3
        logger.warning("Supervisor failed (%s) → fallback full_investigation", result["error"])
        plan = WorkflowPlan(
            workflow_type="full_investigation",
            agents_to_run=["triage", "report"],
            reasoning="Supervisor fallback do error",
            priority=3,
        )
    else:
        plan = WorkflowPlan(
            workflow_type=result.get("workflow_type", "quick_triage"),
            agents_to_run=result.get("agents_to_run", ["triage", "report"]),
            reasoning=result.get("reasoning", ""),
            priority=result.get("priority", 3),
        )

    return plan, result
