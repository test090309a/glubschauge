"""Async Ollama-Client für glubschauge."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

log = logging.getLogger(__name__)

Category = Literal[
    "dns", "connectivity", "security", "performance",
    "discovery", "unknown",
]


class Evaluation(BaseModel):
    severity: int = Field(ge=0, le=10)
    category: Category
    explanation: str


@dataclass(slots=True)
class LlmResult:
    model: str
    evaluation: Evaluation
    raw_response: str
    duration_ms: int


class OllamaClient:
    """Dünner async Wrapper um /api/generate."""

    def __init__(self, base_url: str = "http://localhost:11434", timeout_s: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout_s)

    async def close(self) -> None:
        await self._client.aclose()

    async def evaluate(
        self,
        model: str,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 120,         # ← war 200
        keep_alive: str = "24h",       # ← neu
    ) -> LlmResult:
        payload: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": keep_alive,   # ← neu
            "options": {
                "temperature": 0.1,
                "num_predict": max_tokens,
                "num_ctx": 2048,        # ← neu: begrenzt Kontextfenster
            },
        }        
        if system:
            payload["system"] = system

        t0 = time.monotonic()
        r = await self._client.post(f"{self.base_url}/api/generate", json=payload)
        r.raise_for_status()
        data = r.json()
        duration_ms = int((time.monotonic() - t0) * 1000)

        raw = data.get("response", "")
        try:
            parsed = json.loads(raw)
            evaluation = Evaluation.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError) as e:
            log.warning("LLM-Antwort ungültig: %s / raw=%r", e, raw[:200])
            evaluation = Evaluation(
                severity=0,
                category="unknown",
                explanation="LLM-Antwort konnte nicht interpretiert werden.",
            )

        return LlmResult(
            model=model,
            evaluation=evaluation,
            raw_response=raw,
            duration_ms=duration_ms,
        )