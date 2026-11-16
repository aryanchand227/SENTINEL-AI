"""
SENTINEL AI — Unified LLM Client Abstraction.

Provides structured generation with Cloud LLM (OpenAI / Anthropic / Gemini compatible)
with deterministic fallback for offline testing and synthetic benchmark execution.
"""

from __future__ import annotations

import json
import logging
from typing import TypeVar

import httpx
from pydantic import BaseModel

from backend.app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMClient:
    """Client for invoking LLM with structured outputs and fallback support."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def is_configured(self) -> bool:
        return bool(self._settings.llm_api_key)

    async def generate_structured(
        self,
        prompt: str,
        response_model: type[T],
        system_prompt: str = "",
    ) -> T | None:
        """
        Request structured JSON from LLM conforming to response_model.
        Returns None if not configured or call fails.
        """
        if not self.is_configured:
            return None

        # Build OpenAI/Gemini compatible payload
        base_url = self._settings.llm_base_url or "https://api.openai.com/v1"
        endpoint = f"{base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._settings.llm_api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._settings.llm_model or "gpt-4o-mini",
            "messages": messages,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=self._settings.llm_timeout_seconds) as client:
                resp = await client.post(endpoint, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return response_model.model_validate(parsed)
        except Exception as e:
            logger.warning("LLM call failed, falling back to deterministic parser: %s", e)
            return None
