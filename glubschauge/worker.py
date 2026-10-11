"""Konsumiert die Event-Queue und lässt jedes Event vom LLM bewerten."""
from __future__ import annotations

import asyncio
import logging

from .broker import SYSTEM_PROMPT, build_prompt, model_for
from .events import Event, EventStore
from .llm import OllamaClient

log = logging.getLogger(__name__)


class LlmWorker:
    """Ein einzelner Worker. Verarbeitet Events sequenziell (später skalierbar)."""

    def __init__(
        self,
        queue: asyncio.Queue,
        store: EventStore,
        client: OllamaClient,
        stage: str = "filter",
        ui_event_queue: asyncio.Queue | None = None,
    ) -> None:
        self.queue  = queue
        self.store  = store
        self.client = client
        self.stage  = stage
        self.model  = model_for(stage)
        self.processed = 0
        self.ui_event_queue = ui_event_queue

    async def run(self) -> None:
        log.info("LLM-Worker startet (stage=%s, model=%s)", self.stage, self.model)
        while True:
            item = await self.queue.get()
            if item is None:                # Poison Pill = Shutdown
                log.info("LLM-Worker beendet sich.")
                return
            event_id, ev = item
            try:
                await self._handle(event_id, ev)
            except Exception:
                log.exception("LLM-Worker Fehler bei Event %s", event_id)
            finally:
                self.queue.task_done()

    async def _handle(self, event_id: int, ev: Event) -> None:
        prompt = build_prompt(ev)
        result = await self.client.evaluate(
            model=self.model,
            prompt=prompt,
            system=SYSTEM_PROMPT,
            max_tokens=200,
        )
        self.store.write_evaluation(
            event_id=event_id,
            model=result.model,
            severity=result.evaluation.severity,
            category=result.evaluation.category,
            explanation=result.evaluation.explanation,
            raw=result.raw_response,
            duration_ms=result.duration_ms,
        )
        self.processed += 1
        log.info(
            "LLM [%s] Event %d → sev=%d %s | %s",
            result.model, event_id, result.evaluation.severity,
            result.evaluation.category, result.evaluation.explanation,
        )
        if self.ui_event_queue is not None:
            try:
                self.ui_event_queue.put_nowait((event_id, ev, result.evaluation.severity))
            except asyncio.QueueFull:
                pass