"""Ringpuffer: zweiter tshark schreibt rotierende pcapng-Dateien."""
from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger(__name__)


class RingBuffer:
    """Schreibt kontinuierlich rotierende pcapng-Files in einen Ordner.
    Bei Bedarf kann für ein Event ein Snapshot extrahiert werden."""

    def __init__(
        self,
        tshark_path: str | Path,
        interface: str,
        bpf_filter: str = "",
        ring_dir: str | Path = "ring",
        file_interval_s: int = 10,
        num_files: int = 12,
    ) -> None:
        self.tshark_path    = str(tshark_path)
        self.interface      = interface
        self.bpf_filter     = bpf_filter
        self.ring_dir       = Path(ring_dir).resolve()
        self.ring_dir.mkdir(parents=True, exist_ok=True)
        self.file_interval_s = file_interval_s
        self.num_files       = num_files
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        if self._proc is not None:
            return
        pattern = str(self.ring_dir / "ring.pcapng")
        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-q",
            "-b", f"duration:{self.file_interval_s}",
            "-b", f"files:{self.num_files}",
            "-w", pattern,
        ]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        log.info("RingBuffer startet: %s", " ".join(cmd))
        creationflags = 0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        finally:
            self._proc = None

    # -----------------------------------------------------------------

    def _ring_files(self) -> list[Path]:
        """Chronologisch sortierte Ring-Files."""
        files = sorted(self.ring_dir.glob("*.pcapng"), key=lambda p: p.stat().st_mtime)
        return files

    def snapshot_for(
        self,
        event_time: datetime,
        before_s: int = 5,
        after_s: int = 2,
        out_path: str | Path = "snapshot.pcapng",
    ) -> Path | None:
        """Extrahiert ein Zeitfenster um `event_time` in eine neue pcapng."""
        files = self._ring_files()
        if not files:
            log.warning("RingBuffer: keine pcapng-Files in %s", self.ring_dir)
            return None

        event_ts = event_time.timestamp()

        # Kandidaten: alle Files, deren mtime >= (event_ts - 2*interval)
        candidates = [
            f for f in files
            if f.stat().st_mtime >= event_ts - 2 * self.file_interval_s
        ]
        if not candidates:
            candidates = [files[-1]]     # Fallback: jüngstes File

        # Numerischer Filter (frame.time_epoch) – robust gegen Zeitzonen
        t_start = event_ts - before_s
        t_end   = event_ts + after_s
        display_filter = (
            f"frame.time_epoch >= {t_start:.6f} and "
            f"frame.time_epoch <= {t_end:.6f}"
        )

        out_path = Path(out_path).resolve()
        out_path.unlink(missing_ok=True)

        # Alle Kandidaten mergen – Events können am Rand zwischen zwei Files liegen
        tmp_parts: list[Path] = []
        for i, f in enumerate(candidates):
            part = out_path.with_suffix(f".part{i}.pcapng")
            cmd = [
                self.tshark_path,
                "-r", str(f),
                "-Y", display_filter,
                "-w", str(part),
            ]
            try:
                subprocess.run(
                    cmd, check=True, timeout=20,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                log.warning("Snapshot-Teil %s fehlgeschlagen: %s", f.name, e)
                continue
            if part.exists() and part.stat().st_size > 0:
                tmp_parts.append(part)
            else:
                part.unlink(missing_ok=True)

        if not tmp_parts:
            log.warning("Snapshot: keine Pakete im Zeitfenster gefunden")
            return None

        # Erste Datei als Ziel, weitere Teile per mergecap zusammenfügen
        if len(tmp_parts) == 1:
            tmp_parts[0].rename(out_path)
        else:
            mergecap = Path(self.tshark_path).parent / "mergecap.exe"
            if mergecap.exists():
                try:
                    subprocess.run(
                        [str(mergecap), "-w", str(out_path), *[str(p) for p in tmp_parts]],
                        check=True, timeout=20,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    )
                    for p in tmp_parts:
                        p.unlink(missing_ok=True)
                except Exception as e:
                    log.warning("mergecap fehlgeschlagen: %s – nutze ersten Teil", e)
                    tmp_parts[0].rename(out_path)
                    for p in tmp_parts[1:]:
                        p.unlink(missing_ok=True)
            else:
                # Fallback: nur erster Teil
                tmp_parts[0].rename(out_path)
                for p in tmp_parts[1:]:
                    p.unlink(missing_ok=True)

        return out_path if out_path.exists() and out_path.stat().st_size > 0 else None