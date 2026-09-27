"""RED Analyst Agent — giải thích kỹ thuật rule evasion (UNIQUE agent của project)."""

import json
import logging

from agent.llm import LLMClient
from agent._loop import react_loop, load_prompt
from agent.schemas import RedAnalystOutput

logger = logging.getLogger("agent.red_analyst")

RED_TOOLS = ["get_sigma_rule_text", "get_evasion_tokens"]


async def run_red_analyst(
    llm: LLMClient,
    alert: dict,
    verbose: bool = True,
) -> tuple[RedAnalystOutput, dict]:
    system_prompt = load_prompt("red_analyst")

    red = alert.get("red", {}) or {}
    is_behavioral = red.get("needs_agent") is True or red.get("confidence") == "unknown"

    if is_behavioral:
        # Stage 2 không attribution được → chuyển sang behavioral analysis
        user_input = (
            "**BEHAVIORAL ATTRIBUTION MODE** — `red.confidence=unknown`, `red.needs_agent=true`.\n\n"
            "Stage 2 Sigma engine đã chạy nhưng KHÔNG fire rule nào và cosine dưới ngưỡng.\n"
            "Evasion phức tạp: attacker có thể dùng Linux /proc substitution, API trực tiếp, "
            "stdlib thay shell, hoặc kỹ thuật chưa có Sigma rule.\n\n"
            "Phân tích alert sau bằng behavioral evidence "
            "(process tree, file artifacts, network từ Forensic output sẽ có sau):\n\n"
            f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```\n\n"
            "Dùng tools để tìm Sigma rules gần nhất với hành vi quan sát được. "
            "Nếu không tìm được rule khớp, hãy suy luận kỹ thuật evasion từ behavioral pattern "
            "và đặt evasion_technique='unknown' với reasoning chi tiết."
        )
    else:
        user_input = (
            "Phân tích kỹ thuật rule evasion cho alert sau:\n\n"
            f"```json\n{json.dumps(alert, ensure_ascii=False, indent=2)}\n```\n\n"
            "Dùng tools để lấy Sigma rule gốc và phân tích token evasion."
        )

    result = await react_loop(
        llm=llm,
        agent_name="red_analyst",
        system_prompt=system_prompt,
        user_input=user_input,
        tool_names=RED_TOOLS,
        max_iter=4,
        verbose=verbose,
    )

    if "error" in result:
        logger.warning("RED Analyst failed: %s", result["error"])
        return RedAnalystOutput(
            evasion_reasoning_vi=f"Phân tích lỗi: {result['error']}",
            sigma_rule_comparison_vi="",
            evasion_technique="unknown",
            confidence=0.0,
        ), result

    return RedAnalystOutput(
        evasion_reasoning_vi=result.get("evasion_reasoning_vi", ""),
        discriminative_tokens=result.get("discriminative_tokens", []),
        sigma_rule_comparison_vi=result.get("sigma_rule_comparison_vi", ""),
        evasion_technique=result.get("evasion_technique", "unknown"),
        confidence=float(result.get("confidence", 0.5)),
    ), result
