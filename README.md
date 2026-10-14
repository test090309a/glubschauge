# 👁️ glubschauge

> **Heimnetzwerk-Monitor mit lokaler KI, TUI und Web-Dashboard**

**glubschauge** überwacht passiv den Datenverkehr im lokalen Netzwerk in Echtzeit. Es kombiniert eine leichtgewichtige, regelbasierte Paket- und Anomalie-Erkennung mit **lokalen Sprachmodellen (via Ollama)**, um erkannte Vorfälle ohne Cloud-Abhängigkeit präzise zu bewerten und verständlich zu erklären.

Das System bietet sowohl eine blitzschnelle **Terminal-Benutzeroberfläche (TUI)** als auch ein modernes **Web-Dashboard** mit interaktiver Netzwerktopologie und Inventarverwaltung.

---

## ✨ Features

- **Live-Paketanalyse:** Liest Pakete direkt aus `tshark` (Wireshark) mit konfigurierbarem BPF-Filter.
- **Regelbasierte Detektoren (Vorfilterung):**
  - `NewHostDetector`: Erkennt neue physische Geräte im LAN und pflegt Online-/Idle-Stati.
  - `ServiceDiscoveryDetector`: Erkennt passiv lauschende Dienste und offene Ports anhand von Server-Antworten (SYN+ACK, UDP).
  - `SynFanOutDetector` & `SynFanOutMultiDetector`: Identifiziert Port-Scans und laterale Netzwerk-Scans.
  - `BeaconingDetector`: Erkennt regelmäßige Kommunikationsmuster (z. B. C2-Server-Verbindungen).
  - `DnsFailureDetector`: Schlägt Alarm bei auffälligen DNS-Fehler-Bursts.
  - `HighVolumeFlowDetector`: Überwacht ungewöhnlich hohe Datenübertragungsraten.
  - `ArpSpoofDetector`: Schützt vor ARP-Poisoning und Man-in-the-Middle-Angriffen.
- **Lokale KI-Bewertung (Hybrid-Pipeline via Ollama):**
  - **Entscheider-Modell (`tev1:4b`):** Ermittelt über `/v1/systemone` strukturierte Wahrscheinlichkeiten (z. B. Scan, externes C2).
  - **Erklärer-Modell (`llama3.2:3b`):** Generiert kurze, präzise deutsche Erklärungen zu Vorfällen.
  - **Auto-Eskalation:** Manuelle Tiefenanalyse mit größeren Modellen (`llama3.1:8b`, `qwen2.5-coder:14b`).
- **Rotierender PCAP-Ringpuffer:** Schreibt im Hintergrund rotierende Capture-Dateien. Per Tastendruck öffnet sich der Vorfall direkt als Snapshot in **Wireshark**.
- **Modernes Dash-Web-Dashboard:**
  - **Übersicht:** KPIs, Schweregrad-Verteilung, Event-Feed und Zeitverlauf.
  - **Hosts & Topologie:** Interaktiver Cytoscape-Graph mit Online-Status (Grün/Gelb/Grau) und Klick-Drawer für offene Ports, Dienste und Details.
  - **Events & Reports:** Volltextsuche, Severity-Filter und Markdown-Export.

---

## 🏗️ Architektur

code Code

[ Netzwerk-Interface ]
                         │
                         ▼
                ┌─────────────────┐
                │  tshark (ek)    │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │   RuleEngine    │◄─── [ Detectors ]
                └────────┬────────┘
    ┌────────────────────┼────────────────────┐
    ▼                    ▼                    ▼

┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ EventStore │ │ LLM-Worker │ │ RingBuffer │
│ (SQLite) │ │ (Ollama) │ │ (pcapng) │
└───────┬──────┘ └───────┬──────┘ └──────┬───────┘
│ │ │
├────────────────────┴───────────────────┤
▼ ▼
┌──────────────────┐ ┌──────────────────┐
│ Terminal-TUI │ │ Web-Dashboard │
│ (Textual) │ │ (Dash / Plotly) │
└──────────────────┘ └──────────────────┘
code Code

---

## 📋 Voraussetzungen

1. **Python 3.11+**
2. **Wireshark / tshark:** Muss installiert sein (z. B. `C:\Program Files\Wireshark\tshark.exe` oder `M:\Wireshark\tshark.exe`).
3. **Npcap:** Für Live-Captures unter Windows.
4. **Ollama:** Lokal installiert und laufend (`http://localhost:11434`).
   ```bash
   ollama pull llama3.2:3b
   ollama pull tev1:4b

🚀 Installation & Start
1. Repository klonen & Abhängigkeiten installieren
code Bash

git clone https://github.com/dein-user/glubschauge.git
cd glubschauge

# Virtuelle Umgebung erstellen
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate # Linux/macOS

# Pakete installieren
pip install -r requirements.txt

(Falls keine requirements.txt vorhanden ist: pip install textual dash dash-bootstrap-components dash-cytoscape dash-bootstrap-templates plotly pandas httpx pydantic)
2. Konfiguration anpassen (config.toml)

Passe Pfade, Netzwerkkarte und Subnetze an:
code Toml

[capture]
tshark_path = "M:\\Wireshark\\tshark.exe"
interface   = "8"                           # Interface-ID oder Name
bpf_filter  = "not port 22 and not port 21027"

[network]
local_subnets = ["192.168.0.0/24"]
trusted_hosts = [
  "00:cb:7a:50:16:c4",                      # Eigene bekannte MAC-Adressen
]

[llm]
decision_mode     = true
decision_model    = "tev1:4b"
explanation_model = "llama3.2:3b"

    Tipp: Führe tshark -D im Terminal aus, um die Nummer deines Netzwerk-Interfaces herauszufinden.

3. Anwendung starten

Terminal-TUI:
code Bash

python run.py

Web-Dashboard (parallel startbar):
code Bash

python dashboard/app.py

Öffne anschließend http://127.0.0.1:8050 im Browser.
⌨️ Tastenbelegung in der TUI
Taste	Aktion	Beschreibung
d	Details	Zeigt vollständige Details und LLM-Erklärung zum markierten Event
Esc	Schließen	Schließt das Detail-Panel
w	Wireshark	Öffnet den pcap-Snapshot des Events direkt in Wireshark
h	Hosts / Pakete	Schaltet das linke Panel zwischen Live-Paketen und Host-Inventar um
s	Filter	Schaltet den minimalen Severity-Filter zyklisch durch (0, 2, 3, 5, 7, 8)
r	Re-Analyse	Wiederholt die LLM-Bewertung mit Standardmodell (llama3.1:8b)
R	Tiefenanalyse	Führt forensische Re-Analyse durch (qwen2.5-coder:14b)
e	Export	Schreibt gefilterte Events als Markdown-Report in /reports
c	Leeren	Leert die Tabellenansicht (Datenbank bleibt erhalten)
q	Beenden	Beendet glubschauge und stoppt Hintergrund-Captures
📁 Projektstruktur
code Text

glubschauge/
├── config.toml             # Konfigurationsdatei
├── run.py                  # Haupteinstiegspunkt (TUI)
├── glubschauge/            # Kern-Paket
│   ├── broker.py           # LLM-Prompting, Decision-Logik & Severity-Regeln
│   ├── capture.py          # tshark-Subprozess & Packet-Parsing
│   ├── config.py           # Typed Config Loader
│   ├── detectors.py        # Regelbasierte Detektoren & passive Porterkennung
│   ├── engine.py           # RuleEngine & Event-Routing
│   ├── events.py           # SQLite-EventStore (Hosts, Ports, Events)
│   ├── exporter.py         # Markdown-Report-Generator
│   ├── llm.py              # Async Ollama-Client (/v1/systemone & /api/generate)
│   ├── models.py           # Datenmodelle (Packet, Event)
│   ├── oui.py              # MAC-OUI Vendor-Erkennung
│   ├── ringbuffer.py       # Pcap-Ringpuffer & Snapshot-Extraktion
│   ├── tui.py              # Textual-TUI-Oberfläche
│   └── worker.py           # Async Worker für LLM-Verarbeitung
├── dashboard/              # Dash-Web-Dashboard
│   ├── app.py              # Dash-Einstiegspunkt
│   ├── data.py             # Datenbank-Abfragen & Topologie-Berechnung
│   ├── components/         # Tabellen, Cards & UI-Elemente
│   └── pages/              # Overview, Hosts, Events, Reports
└── reports/                # Generierte Markdown-Reports

🔒 Datenschutz & Sicherheit

    100 % Lokal: Es werden keinerlei Telemetriedaten oder Netzwerk-Payloads an externe Server gesendet. Alle Auswertungen laufen auf deiner eigenen Hardware via Ollama.

    Passiv: glubschauge agiert primär als passiver Sniffer und sendet standardmäßig keine störenden Netzwerk-Scans durch dein LAN.

📄 Lizenz

MIT License — Siehe LICENSE für Details.