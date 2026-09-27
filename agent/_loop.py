"""Shared ReAct loop — gọi LLM, thực thi tools, parse <final> tag.

Mỗi agent gọi `react_loop()` với system prompt, user input, và tool subset của nó.
"""

import os
import json
import time
import asyncio
import logging
from typing import Any, Optional

from agent.llm import LLMClient
from agent.tools import TOOL_FNS, TOOLS_SCHEMA, get_tools_schema

logger = logging.getLogger("agent.loop")


def load_prompt(name: str) -> str:
    """Load system prompt từ agent/prompts/<name>.md."""
    path = os.path.join(os.path.dirname(__file__), "prompts", f"{name}.md")
    with open(path, encoding="utf-8") as f:
        return f.read()


def _parse_final(content: str) -> Optional[dict]:
    if "<final>" in content and "</final>" in content:
        start = content.index("<final>") + len("<final>")
        end = content.index("</final>")
        try:
            return json.loads(content[start:end].strip())
        except json.JSONDecodeError as e:
            logger.warning("Cannot parse <final> JSON: %s", e)
    return None


async def _execute_tools(tool_calls, agent_name: str, verbose: bool) -> list[dict]:
    """Execute tool calls (sync tools, có thể chạy concurrent via to_thread)."""
    results: list[dict] = []
    for tc in tool_calls:
        fn_name = tc.function.name
        fn_args = json.loads(tc.function.arguments)
        if verbose:
            logger.info("[%s]   → %s(%s)", agent_name, fn_name, list(fn_args.keys()))
        try:
            fn = TOOL_FNS[fn_name]
            # Tools hiện tại đều sync → chạy trong thread để không block event loop
            result = await asyncio.to_thread(fn, **fn_args)
        except KeyError:
            result = {"error": f"unknown tool: {fn_name}"}
        except Exception as e:
            result = {"error": str(e)}
        if verbose:
            preview = json.dumps(result, ensure_ascii=False)[:150]
            logger.info("[%s]     ← %s", agent_name, preview)
        results.append({
            "role": "tool",
            "tool_call_id": tc.id,
            "content": json.dumps(result, ensure_ascii=False),
        })
    return results


async def react_loop(
    llm: LLMClient,
    agent_name: str,
    system_prompt: str,
    user_input: str,
    tool_names: list[str],
    max_iter: int = 6,
    verbose: bool = True,
) -> dict:
    """Generic ReAct loop. Return parsed <final> JSON hoặc {"error": ...}."""
    # AGENT_MAX_ITERATIONS env var = absolute ceiling cho tất cả agents.
    # Nếu env set và lớn hơn caller default → dùng env (cho phép bump global).
    env_max = os.environ.get("AGENT_MAX_ITERATIONS")
    if env_max:
        try:
            max_iter = max(max_iter, int(env_max))
        except ValueError:
            pass
    tools_schema = get_tools_schema(tool_names) if tool_names else None

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_input},
    ]

    t0 = time.time()
    steps = 0
    # Local token accounting — parallel-safe (không dùng llm.checkpoint)
    local_prompt = 0
    local_completion = 0
    local_cached = 0

    for step in range(max_iter):
        steps = step + 1
        if verbose:
            logger.info("[%s] Step %d", agent_name, steps)

        resp = await llm.chat(messages, tools=tools_schema)
        # Track tokens for THIS agent only (resp.usage thuộc về call này)
        if resp.usage:
            local_prompt += resp.usage.prompt_tokens
            local_completion += resp.usage.completion_tokens
            details = getattr(resp.usage, "prompt_tokens_details", None)
            if details:
                local_cached += getattr(details, "cached_tokens", 0) or 0
        msg = resp.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))

        if msg.tool_calls:
            tool_results = await _execute_tools(msg.tool_calls, agent_name, verbose)
            messages.extend(tool_results)
            continue

        # No tool calls → check for <final>
        content = msg.content or ""
        final = _parse_final(content)
        if final is not None:
            duration_ms = (time.time() - t0) * 1000
            final["_meta"] = {
                "agent_name": agent_name,
                "steps": steps,
                "duration_ms": round(duration_ms, 1),
                "tokens_prompt": local_prompt,
                "tokens_completion": local_completion,
                "tokens_cached": local_cached,
            }
            return final

        # No final tag yet → nudge
        if verbose:
            logger.info("[%s] No <final> yet — nudging", agent_name)
        messages.append({
            "role": "user",
            "content": "Đủ thông tin chưa? Hãy đưa final answer trong <final>{...}</final>.",
        })

    duration_ms = (time.time() - t0) * 1000
    return {
        "error": "max_iterations_reached",
        "_meta": {
            "agent_name": agent_name,
            "steps": steps,
            "duration_ms": round(duration_ms, 1),
            "tokens_prompt": local_prompt,
            "tokens_completion": local_completion,
            "tokens_cached": local_cached,
        },
    }
