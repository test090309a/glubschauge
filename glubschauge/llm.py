"""Async Ollama-Client für glubschauge.

Zwei Endpunkte:
  * /api/generate      → Chat-Modell (Legacy-Pfad + Erklärung)
  * /v1/systemone      → Decision-Modell Tev1 (Severity/Category/Flags)
"""
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


@dataclass(slots=True)
class DecisionResult:
    model: str
    answers: dict
    raw_response: str
    duration_ms: int


class OllamaClient:
    """Dünner async Wrapper um /api/generate und /v1/systemone."""

    def __init__(self, base_url: str = "http://localhost:11434",
                 timeout_s: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout_s)

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Chat-Pfad (Legacy + Erklärung)
    # ------------------------------------------------------------------

    async def evaluate(
        self,
        model: str,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 120,
        keep_alive: str = "24h",
    ) -> LlmResult:
        payload: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": keep_alive,
            "options": {
                "temperature": 0.1,
                "num_predict": max_tokens,
                "num_ctx": 2048,
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

    async def explain(
        self,
        prompt: str,
        system: str,
        model: str = "llama3.2:3b",
        max_tokens: int = 120,
        keep_alive: str = "24h",
    ) -> tuple[str, int]:
        """Freitext-Erklärung. Rückgabe: (text, duration_ms)."""
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "keep_alive": keep_alive,
            "options": {
                "temperature": 0.3,
                "num_predict": max_tokens,
                "num_ctx": 1024,
            },
        }
        t0 = time.monotonic()
        try:
            r = await self._client.post(
                f"{self.base_url}/api/generate", json=payload
            )
            r.raise_for_status()
            data = r.json()
            dt_ms = int((time.monotonic() - t0) * 1000)
            text = (data.get("response") or "").strip()
            return text, dt_ms
        except Exception as e:
            log.warning("explain() fehlgeschlagen: %s", e)
            dt_ms = int((time.monotonic() - t0) * 1000)
            return "", dt_ms

    # ------------------------------------------------------------------
    # Decision-Pfad (Tev1)
    # ------------------------------------------------------------------

    async def decide(
        self,
        state: str,
        questions: dict,
        model: str = "tev1:4b",
        keep_alive: str = "24h",
    ) -> DecisionResult:
        """Ruft /v1/systemone auf. Rückgabe enthält die 'answers'."""
        payload = {
            "model": model,
            "state": state,
            "questions": questions,
            "keep_alive": keep_alive,
        }
        t0 = time.monotonic()
        r = await self._client.post(
            f"{self.base_url}/v1/systemone", json=payload,
            timeout=120.0,
        )
        r.raise_for_status()
        data = r.json()
        dt_ms = int((time.monotonic() - t0) * 1000)

        answers = data.get("answers") or data.get("responses") or {}
        return DecisionResult(
            model=model,
            answers=answers,
            raw_response=json.dumps(data, ensure_ascii=False),
            duration_ms=dt_ms,
        )