"""Textual-TUI für glubschauge."""
from __future__ import annotations

import asyncio
import json as _json
import logging
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static
from textual.widgets.data_table import RowKey

from .broker import SYSTEM_PROMPT, build_prompt, model_for

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

FILTER_LEVELS = [0, 2, 3, 5, 7, 8]   # Zyklus für `s`


# ---------------------------------------------------------------------------
# Statuszeile
# ---------------------------------------------------------------------------

class StatusBar(Static):
    processed  = reactive(0)
    events     = reactive(0)
    llm_done   = reactive(0)
    pps        = reactive(0.0)
    sev_filter = reactive(0)

    def render(self) -> str:
        filt = (
            f"[yellow]Filter≥{self.sev_filter}[/]"
            if self.sev_filter > 0
            else "[dim]Filter off[/]"
        )
        return (
            f"Engine: {self.processed:>7} pkts   "
            f"Events: {self.events:>4}   "
            f"LLM: {self.llm_done:>4}   "
            f"({self.pps:>6.1f} pkts/s)   "
            f"{filt}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_addr(addr: str) -> str:
    if ":" not in addr:
        return addr
    parts = addr.split(":")
    if len(parts) > 4:
        return f"{parts[0]}:{parts[1]}:…:{parts[-1]}"
    return addr


def _sev_color(sev: int) -> str:
    if sev >= 8: return "bold red"
    if sev >= 6: return "red"
    if sev >= 4: return "yellow"
    if sev >= 2: return "green"
    return "dim white"


# ---------------------------------------------------------------------------
# Paket-Tabelle
# ---------------------------------------------------------------------------

class PacketTable(DataTable):
    MAX_ROWS = 500

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_column("Zeit",   width=14)
        self.add_column("Proto",  width=8)
        self.add_column("Quelle", width=28)
        self.add_column("Ziel",   width=28)
        self.add_column("Info")

    def push(self, pkt) -> None:
        time_str = pkt.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3]
        src = f"{_short_addr(pkt.src)}:{pkt.src_port}" if pkt.src_port else _short_addr(pkt.src)
        dst = f"{_short_addr(pkt.dst)}:{pkt.dst_port}" if pkt.dst_port else _short_addr(pkt.dst)
        info = pkt.summary().split(None, 3)[-1] if pkt.frame_number else ""
        self.add_row(time_str, pkt.protocol, src, dst, info or "")
        if self.row_count > self.MAX_ROWS:
            self.remove_row(next(iter(self.rows)))


# ---------------------------------------------------------------------------
# Event-Tabelle mit Filter
# ---------------------------------------------------------------------------

class EventFeed(DataTable):
    """Ein Event = eine Zeile. Severity wird beim LLM-Ergebnis aktualisiert.
    Mit integriertem Severity-Filter (nur Anzeige, DB bleibt unberührt)."""

    class RowActivated(Message):
        def __init__(self, event_id: int) -> None:
            self.event_id = event_id
            super().__init__()

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._row_keys:   dict[int, RowKey] = {}
        self._events:     dict[int, object] = {}
        self._llm_sev:    dict[int, int]    = {}
        self._min_sev:    int = 0
        self._current_event_id: int | None = None
        self._col_sev_key = None

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_column("Zeit",     width=10)
        self._col_sev_key = self.add_column("Sev", width=5)
        self.add_column("Detektor", width=16)
        self.add_column("Titel")

    @property
    def min_sev(self) -> int:
        return self._min_sev

    # -- Event eintreffen ---------------------------------------------

    def add_event(self, event_id: int, ev) -> None:
        self._events[event_id] = ev
        if self._effective_sev(event_id, ev) >= self._min_sev:
            self._insert_row(event_id, ev)

    def update_event_severity(self, event_id: int, severity: int) -> None:
        self._llm_sev[event_id] = severity
        ev = self._events.get(event_id)
        if ev is None:
            return

        visible   = event_id in self._row_keys
        should_show = severity >= self._min_sev

        if should_show and not visible:
            self._insert_row(event_id, ev)
        elif should_show and visible:
            self._update_sev_cell(event_id, severity)
        elif not should_show and visible:
            self._remove_row(event_id)

    # -- Filter --------------------------------------------------------

    def set_filter(self, min_sev: int) -> None:
        if min_sev == self._min_sev:
            return
        self._min_sev = min_sev
        self._rebuild()

    def _rebuild(self) -> None:
        # Alle Zeilen weg, dann gefilterte neu einfügen
        self.clear()                              # rows only, columns bleiben
        self._row_keys.clear()
        for eid, ev in self._events.items():
            if self._effective_sev(eid, ev) >= self._min_sev:
                self._insert_row(eid, ev)

        # Cursor wiederherstellen
        if self._current_event_id in self._row_keys and self.row_count > 0:
            self.move_cursor(row=0)
            for idx, eid in enumerate(self._row_keys.keys()):
                if eid == self._current_event_id:
                    self.move_cursor(row=idx)
                    break

    # -- Interne Helfer -------------------------------------------------

    def _effective_sev(self, event_id: int, ev) -> int:
        return self._llm_sev.get(event_id, ev.severity_hint)

    def _insert_row(self, event_id: int, ev) -> None:
        time_str = ev.timestamp.astimezone().strftime("%H:%M:%S")
        sev      = self._effective_sev(event_id, ev)
        color    = _sev_color(sev)
        row_key = self.add_row(
            time_str,
            f"[{color}]{sev}[/]",
            ev.detector,
            ev.title,
        )
        self._row_keys[event_id] = row_key

        # Erste sichtbare Zeile bekommt Fokus, damit `d`/`w`/`r` sofort greifen
        if self._current_event_id is None:
            self._current_event_id = event_id
            self.move_cursor(row=self.row_count - 1)
            try:
                self.focus()
            except Exception:
                pass

    def _remove_row(self, event_id: int) -> None:
        rk = self._row_keys.pop(event_id, None)
        if rk is not None:
            try:
                self.remove_row(rk)
            except Exception:
                pass

    def _update_sev_cell(self, event_id: int, severity: int) -> None:
        rk = self._row_keys.get(event_id)
        if rk is None or self._col_sev_key is None:
            return
        color = _sev_color(severity)
        try:
            self.update_cell(
                rk, self._col_sev_key,
                f"[{color}]{severity}[/]",
                update_width=True,
            )
        except Exception as e:
            log.warning("update_cell fehlgeschlagen: %s", e)

    # -- Tracking -------------------------------------------------------

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        for eid, rk in self._row_keys.items():
            if rk == event.row_key:
                self._current_event_id = eid
                return

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        for eid, rk in self._row_keys.items():
            if rk == event.row_key:
                self._current_event_id = eid
                self.post_message(self.RowActivated(eid))
                return

    # -- Zugriff --------------------------------------------------------

    def selected_event_id(self) -> int | None:
        return self._current_event_id

    def get_event(self, event_id: int):
        return self._events.get(event_id)

    def clear_all(self) -> None:
        self.clear()
        self._row_keys.clear()
        self._events.clear()
        self._llm_sev.clear()
        self._current_event_id = None


# ---------------------------------------------------------------------------
# Detail-Panel
# ---------------------------------------------------------------------------

class DetailPanel(Static):
    def on_mount(self) -> None:
        self.update("[dim]Event auswählen und [b]d[/b] drücken für Details.[/]")

    def show(self, data: dict | None) -> None:
        if data is None:
            self.update("[dim]Kein Event selektiert.[/]")
            return
        try:
            details_pretty = _json.dumps(
                _json.loads(data["details"]), indent=2, ensure_ascii=False
            )
        except Exception:
            details_pretty = str(data.get("details") or "{}")

        sev_hint = data["severity_hint"]
        sev_llm  = data["llm_severity"]
        sev      = sev_llm if sev_llm is not None else sev_hint
        color    = _sev_color(sev)

        llm_line = (
            f"[bold]LLM:[/] [{color}]{sev}[/] "
            f"[cyan]{data['llm_category'] or '–'}[/]  "
            f"[dim]({data['llm_model'] or '–'}, {data['llm_duration_ms'] or 0} ms)[/]"
        )
        explanation = data["llm_explanation"] or "[dim]noch keine Antwort[/]"

        self.update(
            f"[bold]#{data['id']}[/]  {data['ts']}  [dim]{data['detector']}[/]\n"
            f"[bold]{data['title']}[/]\n"
            f"src={data['src'] or '–'}   dst={data['dst'] or '–'}\n"
            f"{llm_line}\n"
            f"{explanation}\n"
            f"[dim]Details:[/] {details_pretty}"
        )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

class GlubschaugeApp(App):
    CSS = """
    Screen { layout: vertical; }
    StatusBar {
        height: 1;
        background: $boost;
        color: $text;
        padding: 0 1;
    }
    #main { height: 1fr; }
    #packets { width: 3fr; }
    #events  { width: 2fr; }
    DataTable { height: 1fr; }
    #details {
        height: 9;
        border: round $primary;
        padding: 0 1;
        overflow-y: auto;
    }
    """
    TITLE     = "glubschauge"
    SUB_TITLE = "Netzwerk-Monitor mit lokaler KI"

    BINDINGS = [
        ("q",       "quit",              "Beenden"),
        ("c",       "clear_tables",      "Leeren"),
        ("d",       "show_details",      "Details"),
        ("escape",  "hide_details",      "Detail schließen"),
        ("w",       "open_wireshark",    "Wireshark"),
        ("s",       "cycle_filter",      "Filter"),
        ("r",       "reanalyse",         "Re-Analyse"),
        ("R",       "reanalyse_deep",    "Tiefenanalyse"),
    ]

    def __init__(self, engine, worker, capture, ringbuffer=None) -> None:
        super().__init__()
        self.engine     = engine
        self.worker     = worker
        self.capture    = capture
        self.ringbuffer = ringbuffer
        self._packet_times: deque[float] = deque(maxlen=200)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatusBar()
        with Horizontal(id="main"):
            yield PacketTable(id="packets")
            yield EventFeed(id="events")
        yield DetailPanel(id="details")
        yield Footer()

    # ---- Lifecycle ----------------------------------------------------

    def on_mount(self) -> None:
        self.run_worker(self._engine_task(),  name="engine")
        self.run_worker(self._worker_task(),  name="llm-worker")
        self.run_worker(self._packet_pump(),  name="packet-pump")
        self.run_worker(self._event_pump(),   name="event-pump")
        self.run_worker(self._stats_ticker(), name="stats-ticker")
        if self.ringbuffer is not None:
            self.ringbuffer.start()

    async def on_unmount(self) -> None:
        self.capture.stop()
        if self.ringbuffer is not None:
            self.ringbuffer.stop()

    # ---- Background-Tasks --------------------------------------------

    async def _engine_task(self) -> None:
        await self.engine.run()

    async def _worker_task(self) -> None:
        await self.worker.run()

    async def _packet_pump(self) -> None:
        table = self.query_one("#packets", PacketTable)
        while True:
            pkt = await self.engine.packet_queue.get()
            self._packet_times.append(datetime.now(timezone.utc).timestamp())
            table.push(pkt)

    async def _event_pump(self) -> None:
        table = self.query_one("#events", EventFeed)
        while True:
            event_id, ev, severity = await self.engine.ui_event_queue.get()
            if severity is None:
                table.add_event(event_id, ev)
            else:
                table.update_event_severity(event_id, severity)

    async def _stats_ticker(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            now = datetime.now(timezone.utc).timestamp()
            recent = [t for t in self._packet_times if now - t < 1.0]
            bar = self.query_one(StatusBar)
            bar.processed  = self.engine._processed
            bar.events     = self.engine.store.count()
            bar.llm_done   = self.worker.processed
            bar.pps        = float(len(recent))
            bar.sev_filter = self.query_one("#events", EventFeed).min_sev

    # ---- Actions -------------------------------------------------------

    def action_clear_tables(self) -> None:
        self.query_one("#packets", PacketTable).clear()
        self.query_one("#events",  EventFeed).clear_all()
        self.query_one("#details", DetailPanel).show(None)

    def action_show_details(self) -> None:
        feed = self.query_one("#events", EventFeed)
        eid = feed.selected_event_id()
        if eid is None:
            self.notify("Kein Event selektiert – erst eins anklicken",
                        severity="warning")
            return
        data = self.engine.store.get_event_full(eid)
        if data is None:
            self.notify(f"Event #{eid} nicht in DB", severity="warning")
            return
        self.query_one("#details", DetailPanel).show(data)

    def action_hide_details(self) -> None:
        self.query_one("#details", DetailPanel).show(None)

    def action_open_wireshark(self) -> None:
        feed = self.query_one("#events", EventFeed)
        eid  = feed.selected_event_id()
        if eid is None:
            self.notify("Kein Event selektiert", severity="warning")
            return
        ev = feed.get_event(eid)
        if ev is None:
            self.notify("Event-Objekt nicht gefunden", severity="error")
            return
        self._open_wireshark_for(ev)

    def action_cycle_filter(self) -> None:
        feed = self.query_one("#events", EventFeed)
        try:
            idx = FILTER_LEVELS.index(feed.min_sev)
            new = FILTER_LEVELS[(idx + 1) % len(FILTER_LEVELS)]
        except ValueError:
            new = 0
        feed.set_filter(new)
        self.notify(f"Severity-Filter: ≥ {new}" if new > 0 else "Severity-Filter: aus",
                    timeout=1)

    def action_reanalyse(self) -> None:
        self._trigger_reanalyse(stage="analyze")

    def action_reanalyse_deep(self) -> None:
        self._trigger_reanalyse(stage="forensic")

    # ---- Wireshark ----------------------------------------------------

    def _open_wireshark_for(self, ev) -> None:
        if self.ringbuffer is None:
            self.notify("Ringpuffer nicht aktiv", severity="warning")
            return

        snapshot = self.ringbuffer.snapshot_for(
            event_time=ev.timestamp,
            before_s=5, after_s=2,
            out_path=str(Path("snapshot_last.pcapng").resolve()),
        )
        if snapshot is None:
            self.notify("Keine Aufnahme im Ring vorhanden", severity="warning")
            return

        wireshark_exe = Path(self.ringbuffer.tshark_path).parent / "Wireshark.exe"
        if not wireshark_exe.exists():
            self.notify(f"Wireshark.exe nicht gefunden: {wireshark_exe}",
                        severity="error")
            return

        creationflags = 0x00000008 | 0x00000200
        subprocess.Popen(
            [str(wireshark_exe), str(snapshot)],
            creationflags=creationflags,
            close_fds=True,
        )
        self.notify(f"Wireshark: {snapshot.name}", timeout=3)

    # ---- Re-Analyse ---------------------------------------------------

    def _trigger_reanalyse(self, stage: str) -> None:
        feed = self.query_one("#events", EventFeed)
        eid = feed.selected_event_id()
        if eid is None:
            self.notify("Kein Event selektiert – erst eins anklicken",
                        severity="warning")
            return
        ev = feed.get_event(eid)
        if ev is None:
            self.notify("Event-Objekt nicht gefunden", severity="error")
            return
        model = model_for(stage)
        self.notify(f"Re-Analyse # {eid} läuft ({model})…", timeout=2)
        # exclusive in der Gruppe 'reanalyse' → verhindert VRAM-Thrashing
        self.run_worker(
            self._reanalyse(eid, ev, model),
            name=f"reanalyse-{eid}",
            group="reanalyse",
            exclusive=True,
        )

    async def _reanalyse(self, event_id: int, ev, model: str) -> None:
        try:
            prompt = build_prompt(ev)
            result = await self.worker.client.evaluate(
                model=model,
                prompt=prompt,
                system=SYSTEM_PROMPT,
                max_tokens=200,
            )
        except Exception as e:
            log.exception("Re-Analyse fehlgeschlagen")
            self.notify(f"Re-Analyse Fehler: {e}", severity="error", timeout=5)
            return

        # In DB überschreiben
        self.engine.store.write_evaluation(
            event_id=event_id,
            model=result.model,
            severity=result.evaluation.severity,
            category=result.evaluation.category,
            explanation=result.evaluation.explanation,
            raw=result.raw_response,
            duration_ms=result.duration_ms,
        )

        # TUI-Update über dieselbe Queue → existierende Row wird aktualisiert
        try:
            self.engine.ui_event_queue.put_nowait(
                (event_id, ev, result.evaluation.severity)
            )
        except asyncio.QueueFull:
            pass

        # Detail-Panel live nachziehen, falls dieses Event gerade angezeigt wird
        try:
            feed = self.query_one("#events", EventFeed)
            if feed.selected_event_id() == event_id:
                data = self.engine.store.get_event_full(event_id)
                self.query_one("#details", DetailPanel).show(data)
        except Exception:
            pass

        self.notify(
            f"#{event_id}: sev={result.evaluation.severity} "
            f"({result.duration_ms} ms, {result.model})",
            timeout=4,
        )