"""Async LLM client — wraps DeepSeek/OpenAI/Anthropic via OpenAI-compatible API.

Mặc định dùng DeepSeek. Switch sang OpenAI/Claude bằng cách đổi env vars.
"""

import os
import logging
from typing import Any, Optional

from openai import AsyncOpenAI

logger = logging.getLogger("agent.llm")


class LLMClient:
    """Async LLM client với token accounting."""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.model = model or os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
        api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        base_url = base_url or os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")

        if not api_key:
            raise ValueError("DEEPSEEK_API_KEY chưa set — kiểm tra .env")

        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cached_tokens = 0
        self.call_count = 0

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict]] = None,
        temperature: Optional[float] = None,
        **kwargs,
    ):
        if temperature is None:
            temperature = float(os.environ.get("AGENT_TEMPERATURE", "0.2"))

        params: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            **kwargs,
        }
        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"

        resp = await self.client.chat.completions.create(**params)
        self.call_count += 1
        if resp.usage:
            self.total_prompt_tokens += resp.usage.prompt_tokens
            self.total_completion_tokens += resp.usage.completion_tokens
            # DeepSeek-specific: cached tokens
            details = getattr(resp.usage, "prompt_tokens_details", None)
            if details:
                cached = getattr(details, "cached_tokens", 0) or 0
                self.total_cached_tokens += cached
        return resp

    def usage_summary(self) -> dict:
        return {
            "model": self.model,
            "calls": self.call_count,
            "prompt_tokens": self.total_prompt_tokens,
            "completion_tokens": self.total_completion_tokens,
            "cached_tokens": self.total_cached_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "cache_hit_rate": (
                self.total_cached_tokens / self.total_prompt_tokens
                if self.total_prompt_tokens else 0
            ),
        }

    def checkpoint(self) -> dict:
        """Snapshot token counters để tính delta cho 1 agent."""
        return {
            "prompt_tokens": self.total_prompt_tokens,
            "completion_tokens": self.total_completion_tokens,
            "cached_tokens": self.total_cached_tokens,
            "calls": self.call_count,
        }

    def delta_since(self, ckpt: dict) -> dict:
        """Tokens consumed kể từ checkpoint."""
        return {
            "prompt_tokens": self.total_prompt_tokens - ckpt["prompt_tokens"],
            "completion_tokens": self.total_completion_tokens - ckpt["completion_tokens"],
            "cached_tokens": self.total_cached_tokens - ckpt["cached_tokens"],
            "calls": self.call_count - ckpt["calls"],
        }
