"""Konsumiert die Event-Queue und bewertet jedes Event.

Zwei Modi (gesteuert über config.toml [llm] decision_mode):

* decision_mode = true  (Standard)
    Tev1 (/v1/systemone) liefert category + Flags (is_scan, is_beaconing,
    is_external_destination). Der Regel-Hint bestimmt die Basis-Severity,
    wird aber durch die Flags angepasst (siehe broker.final_severity).
    Ein Chat-Modell schreibt die Erklärung.

* decision_mode = false  (Legacy)
    Alter Pfad: llama3.2:3b bewertet selbst, mit Auto-Eskalation und
    Trust-the-Rule für Regel-Hints >= 7.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from .broker import (
    EXPLANATION_SYSTEM,
    SYSTEM_PROMPT,
    build_decision,
    build_explanation_prompt,
    build_prompt,
    final_severity,
    model_for,
)
from .config import LlmConfig
from .events import Event, EventStore
from .llm import OllamaClient

log = logging.getLogger(__name__)


class LlmWorker:
    def __init__(
        self,
        queue: asyncio.Queue,
        store: EventStore,
        client: OllamaClient,
        stage: str = "filter",
        ui_event_queue: asyncio.Queue | None = None,
        llm_config: LlmConfig | None = None,
        local_subnets: list[str] | None = None,
    ) -> None:
        self.queue  = queue
        self.store  = store
        self.client = client
        self.stage  = stage
        self.model  = model_for(stage)   # Fallback-Modell für Legacy
        self.processed = 0
        self.ui_event_queue = ui_event_queue

        # Decision-Pfad
        self.cfg = llm_config or LlmConfig()
        self.local_subnets = local_subnets or []
        self._questions = None    # lazy: build_decision() baut sie einmal

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        mode = "decision" if self.cfg.decision_mode else "legacy"
        log.info(
            "LLM-Worker startet (mode=%s, decision=%s, explain=%s)",
            mode, self.cfg.decision_model, self.cfg.explanation_model,
        )
        if self.cfg.decision_mode and self.cfg.warmup_on_start:
            await self._warmup()
        while True:
            item = await self.queue.get()
            if item is None:                      # Poison Pill = Shutdown
                log.info("LLM-Worker beendet sich.")
                return
            event_id, ev = item
            try:
                if self.cfg.decision_mode:
                    await self._handle_decision(event_id, ev)
                else:
                    await self._handle_legacy(event_id, ev)
            except Exception:
                log.exception("LLM-Worker Fehler bei Event %s", event_id)
            finally:
                self.queue.task_done()

    async def _warmup(self) -> None:
        """Lädt das Entscheider-Modell vorab in den VRAM (~20 s beim ersten Mal)."""
        try:
            t0 = time.monotonic()
            await self.client.decide(
                state="detector=warmup\ntitle=warmup",
                questions={"ping": {
                    "type": "noul",
                    "instructions": "Is this a warmup call?",
                }},
                model=self.cfg.decision_model,
            )
            dt = time.monotonic() - t0
            log.info("Warmup %s abgeschlossen (%.1fs)", self.cfg.decision_model, dt)
        except Exception as e:
            log.warning("Warmup fehlgeschlagen: %s", e)

    # ------------------------------------------------------------------
    # Decision-Pfad (Tev1 + Erklärer)
    # ------------------------------------------------------------------

    async def _handle_decision(self, event_id: int, ev: Event) -> None:
        state, questions = build_decision(ev, self.local_subnets, self._questions)
        # Fragen sind konstant — beim ersten Call cachen
        if self._questions is None:
            self._questions = questions

        decision = await self.client.decide(
            state=state,
            questions=questions,
            model=self.cfg.decision_model,
        )

        severity = final_severity(
            ev.severity_hint,
            decision.answers,
            scan_threshold=self.cfg.scan_threshold,
            beaconing_threshold=self.cfg.beaconing_threshold,
            internal_threshold=self.cfg.internal_threshold,
            external_threshold=self.cfg.external_threshold,
            internal_beaconing_cap=self.cfg.internal_beaconing_cap,
        )
        category = ((decision.answers.get("category") or {}).get("choice")
                    or "unknown")

        # Erklärung generieren
        expl_prompt = build_explanation_prompt(ev, severity, category)
        explanation, expl_ms = await self.client.explain(
            prompt=expl_prompt,
            system=EXPLANATION_SYSTEM,
            model=self.cfg.explanation_model,
        )

        self.store.write_evaluation(
            event_id=event_id,
            model=f"{self.cfg.decision_model}+{self.cfg.explanation_model}",
            severity=severity,
            category=category,
            explanation=explanation or "(keine Erklärung erzeugt)",
            raw=decision.raw_response,
            duration_ms=decision.duration_ms + expl_ms,
        )
        self.processed += 1

        # Kompaktes Log mit allen Signalwerten
        def _p(k):
            v = (decision.answers.get(k) or {}).get("noul")
            return f"{v:.2f}" if isinstance(v, (int, float)) else "—"

        log.info(
            "LLM [decision] Event %d → sev=%d (hint=%d scan=%s beacon=%s ext=%s) "
            "%s | %.0f+%.0f ms | %s",
            event_id, severity, ev.severity_hint,
            _p("is_scan"), _p("is_beaconing"), _p("is_external_destination"),
            category,
            decision.duration_ms, expl_ms,
            (explanation[:80] + "…") if len(explanation) > 80 else explanation,
        )

        self._publish_to_ui(event_id, ev, severity)

    # ------------------------------------------------------------------
    # Legacy-Pfad (unverändert)
    # ------------------------------------------------------------------

    ESCALATE_HINT   = 7
    TRUST_RULE_HINT = 7

    def _choose_model(self, ev: Event) -> str:
        if ev.severity_hint >= self.ESCALATE_HINT:
            return model_for("analyze")
        return self.model

    def _final_severity_legacy(self, ev: Event, llm_severity: int) -> int:
        if ev.severity_hint >= self.TRUST_RULE_HINT:
            return max(ev.severity_hint, llm_severity)
        return llm_severity

    async def _handle_legacy(self, event_id: int, ev: Event) -> None:
        prompt = build_prompt(ev)
        chosen_model = self._choose_model(ev)

        if chosen_model != self.model:
            log.info(
                "Auto-Eskalation Event %d (hint=%d) → %s",
                event_id, ev.severity_hint, chosen_model,
            )

        result = await self.client.evaluate(
            model=chosen_model,
            prompt=prompt,
            system=SYSTEM_PROMPT,
            max_tokens=200,
        )

        llm_severity   = result.evaluation.severity
        final_sev      = self._final_severity_legacy(ev, llm_severity)

        if final_sev != llm_severity:
            log.info(
                "Trust-the-Rule Event %d: LLM=%d → final=%d (Regel-Hint=%d)",
                event_id, llm_severity, final_sev, ev.severity_hint,
            )

        self.store.write_evaluation(
            event_id=event_id,
            model=result.model,
            severity=final_sev,
            category=result.evaluation.category,
            explanation=result.evaluation.explanation,
            raw=result.raw_response,
            duration_ms=result.duration_ms,
        )
        self.processed += 1
        log.info(
            "LLM [legacy] Event %d → sev=%d (llm=%d, hint=%d) %s | %s",
            event_id, final_sev, llm_severity, ev.severity_hint,
            result.evaluation.category, result.evaluation.explanation,
        )
        self._publish_to_ui(event_id, ev, final_sev)

    # ------------------------------------------------------------------
    # UI-Update
    # ------------------------------------------------------------------

    def _publish_to_ui(self, event_id: int, ev: Event, severity: int) -> None:
        if self.ui_event_queue is None:
            return
        try:
            self.ui_event_queue.put_nowait((event_id, ev, severity))
        except asyncio.QueueFull:
            pass