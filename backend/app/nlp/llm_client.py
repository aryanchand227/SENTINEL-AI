"""
SENTINEL AI — Unified LLM Client Abstraction & Provider Factory.

Supports Groq Cloud LLM (via langchain-groq), generic cloud endpoints,
and deterministic fallbacks for offline testing and synthetic benchmark execution.
Enforces request timeouts, retries, rate-limit defense, and zero secret leakage.
"""

from __future__ import annotations

import json
import logging
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from backend.app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def mask_key(key: str | None) -> str:
    """Safely mask an API key for logs (e.g. gsk_abc...xyz)."""
    if not key or len(key) < 8:
        return "[NOT SET]"
    return f"{key[:4]}...{key[-4:]}"


class LLMClient:
    """Client for invoking LLM with structured outputs, text generation, and fallback support."""

    def __init__(
        self,
        settings: Settings | None = None,
        chat_model: Any | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._chat_model = chat_model

    @property
    def provider(self) -> str:
        return self._settings.llm_provider.lower()

    @property
    def is_configured(self) -> bool:
        """Check whether the active provider has valid credentials."""
        if self.provider == "groq":
            return self._settings.is_groq_configured()
        if self.provider == "cloud":
            return bool(self._settings.llm_api_key)
        return False

    def get_chat_model(self) -> Any | None:
        """Resolve or construct the LangChain chat model based on provider settings."""
        if self._chat_model is not None:
            return self._chat_model

        if self.provider == "groq":
            key = self._settings.effective_groq_api_key
            if not key or key == "your_actual_groq_api_key":
                return None
            try:
                from langchain_groq import ChatGroq

                return ChatGroq(
                    model_name=self._settings.effective_groq_model,
                    groq_api_key=key,
                    temperature=0.0,
                    max_retries=self._settings.llm_max_retries,
                    request_timeout=float(self._settings.llm_timeout_seconds),
                )
            except Exception as exc:
                logger.warning("Failed to initialize ChatGroq client: %s", exc)
                return None

        return None

    async def generate_structured(
        self,
        prompt: str,
        response_model: type[T],
        system_prompt: str = "",
    ) -> T | None:
        """
        Request structured JSON from LLM conforming to response_model.
        Returns None if not configured or call fails (triggering deterministic fallback).
        """
        if not self.is_configured and self._chat_model is None:
            return None

        # 1. Groq Provider via langchain-groq
        if self.provider == "groq" or self._chat_model is not None:
            model = self.get_chat_model()
            if model is None:
                return None

            try:
                structured_model = model.with_structured_output(response_model)
                from langchain_core.messages import HumanMessage, SystemMessage

                messages: list[Any] = []
                if system_prompt:
                    messages.append(SystemMessage(content=system_prompt))
                messages.append(HumanMessage(content=prompt))

                res = await structured_model.ainvoke(messages)
                if isinstance(res, response_model):
                    return res
                if isinstance(res, dict):
                    return response_model.model_validate(res)
                logger.warning("Groq structured output returned unexpected type: %s", type(res))
                return None
            except ValidationError as ve:
                logger.warning("Model output failed schema validation: %s", ve)
                return None
            except Exception as exc:
                err_str = str(exc).lower()
                if "rate_limit" in err_str or "429" in err_str:
                    logger.warning(
                        "Groq rate limit exceeded (HTTP 429). Falling back to deterministic logic."
                    )
                elif "auth" in err_str or "401" in err_str or "invalid_api_key" in err_str:
                    logger.warning(
                        "Groq authentication failure. Check GROQ_API_KEY. Falling back."
                    )
                elif "timeout" in err_str:
                    logger.warning("Groq request timed out. Falling back to deterministic logic.")
                else:
                    logger.warning("Groq call failed, falling back: %s", exc)
                return None

        # 2. Generic Cloud Provider via HTTP POST (OpenAI / Gemini compatible)
        base_url = self._settings.llm_base_url or "https://api.openai.com/v1"
        endpoint = f"{base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._settings.llm_api_key}",
            "Content-Type": "application/json",
        }

        http_messages = []
        if system_prompt:
            http_messages.append({"role": "system", "content": system_prompt})
        http_messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._settings.llm_model or "gpt-4o-mini",
            "messages": http_messages,
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
            logger.warning("Generic cloud LLM call failed, falling back: %s", e)
            return None

    async def generate_text(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> str | None:
        """
        Request text completion from LLM.
        Returns None if not configured or call fails (triggering deterministic fallback).
        """
        if not self.is_configured and self._chat_model is None:
            return None

        if self.provider == "groq" or self._chat_model is not None:
            model = self.get_chat_model()
            if model is None:
                return None

            try:
                from langchain_core.messages import HumanMessage, SystemMessage

                messages: list[Any] = []
                if system_prompt:
                    messages.append(SystemMessage(content=system_prompt))
                messages.append(HumanMessage(content=prompt))

                res = await model.ainvoke(messages)
                content = getattr(res, "content", "")
                return str(content) if content else None
            except Exception as exc:
                logger.warning("Groq text generation failed, falling back: %s", exc)
                return None

        return None
