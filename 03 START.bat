@echo off
setlocal EnableDelayedExpansion

:: ====================================================================
::  glubschauge - Startscript
::  Aufruf:
::    start.bat              startet TUI + Dashboard [+ Browser]
::    start.bat tui          nur Netzwerk-Monitor (TUI)
::    start.bat dash         nur Dashboard [+ Browser]
::    start.bat check        nur Voraussetzungen pruefen, nichts starten
::    start.bat nobrowser    TUI + Dashboard, aber ohne Browser
:: ====================================================================

set "MODE=%~1"
if "%MODE%"=="" set "MODE=beide"

set "OPEN_BROWSER=1"
if /I "%MODE%"=="nobrowser" (
    set "MODE=beide"
    set "OPEN_BROWSER=0"
)

:: Projekt-Wurzelverzeichnis ermitteln
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "PYTHON=python"
if exist "%ROOT%\.venv\Scripts\python.exe" (
    set "PYTHON=%ROOT%\.venv\Scripts\python.exe"
)

set "DASH_PORT=8050"
set "OLLAMA_PORT=11434"
set "FAILED=0"

echo.
echo ================================================================
echo   glubschauge - Netzwerk-Monitor mit lokaler KI
echo   Modus: %MODE%
echo ================================================================
echo.

:: --------------------------------------------------------------------
:: 1. Python pruefen
:: --------------------------------------------------------------------
echo [1/5] Pruefe Python-Installation...
"%PYTHON%" --version >nul 2>nul
if errorlevel 1 (
    echo   [FEHLER] Python nicht gefunden: %PYTHON%
    echo            Bitte Python 3.11+ installieren oder .venv anlegen.
    set "FAILED=1"
    goto :end
)
for /f "tokens=2" %%v in ('"%PYTHON%" --version 2^>^&1') do set "PYVER=%%v"
echo   OK - Python %PYVER%
echo        Pfad: %PYTHON%

:: --------------------------------------------------------------------
:: 2. Projekt-Dateien pruefen
:: --------------------------------------------------------------------
echo [2/5] Pruefe Projekt-Dateien...
if not exist "%ROOT%\config.toml" (
    echo   [FEHLER] %ROOT%\config.toml fehlt.
    set "FAILED=1"
    goto :end
)
if not exist "%ROOT%\run.py" (
    echo   [FEHLER] %ROOT%\run.py fehlt.
    set "FAILED=1"
    goto :end
)
if not exist "%ROOT%\dashboard\app.py" (
    echo   [WARNUNG] dashboard\app.py fehlt - Dashboard wird uebersprungen.
    set "MODE=tui"
)
echo   OK

:: --------------------------------------------------------------------
:: 3. Python-Pakete pruefen
:: --------------------------------------------------------------------
echo [3/5] Pruefe Python-Pakete...
"%PYTHON%" -c "import dash, dash_bootstrap_components, dash_cytoscape, pandas, plotly" >nul 2>nul
if errorlevel 1 (
    echo   [WARNUNG] Nicht alle Dashboard-Pakete installiert.
    echo             Installiere mit:
    echo               "%PYTHON%" -m pip install dash dash-bootstrap-components dash-cytoscape dash-bootstrap-templates pandas
    echo.
    choice /C JN /M "Trotzdem fortfahren"
    if errorlevel 2 (
        set "FAILED=1"
        goto :end
    )
)
echo   OK

:: --------------------------------------------------------------------
:: 4. Ollama pruefen
:: --------------------------------------------------------------------
echo [4/5] Pruefe Ollama [Port %OLLAMA_PORT%]...

set "OLLAMA_OK=0"

where ollama >nul 2>nul
if errorlevel 1 (
    echo   [WARNUNG] ollama CLI nicht im PATH.
    echo             Die LLM-Bewertung wird nicht funktionieren.
    goto :ollama_done
)

ollama list >nul 2>nul
if errorlevel 1 (
    echo   [WARNUNG] Ollama installiert, aber Dienst antwortet nicht.
    echo             Bitte Ollama starten - Tray-Icon - und erneut versuchen.
    goto :ollama_done
)

set "MODELS_FOUND=0"
for /f "tokens=1" %%m in ('ollama list 2^>nul') do (
    if "%%m"=="llama3.2:3b"        set "MODELS_FOUND=1"
    if "%%m"=="llama3.1:8b"        set "MODELS_FOUND=1"
    if "%%m"=="qwen2.5-coder:14b"  set "MODELS_FOUND=1"
)
if "%MODELS_FOUND%"=="0" (
    echo   [WARNUNG] Ollama laeuft, aber keines der erwarteten Modelle gefunden.
    echo             Empfohlen:
    echo               ollama pull llama3.2:3b
    echo               ollama pull llama3.1:8b
    echo.
)

set "OLLAMA_OK=1"
echo   OK - Ollama laeuft auf Port %OLLAMA_PORT%

:ollama_done

:: --------------------------------------------------------------------
:: 5. Port 8050 pruefen
:: --------------------------------------------------------------------
echo [5/5] Pruefe Port %DASH_PORT%...
netstat -ano | findstr ":%DASH_PORT% " | findstr "LISTENING" >nul
if not errorlevel 1 (
    echo   [WARNUNG] Port %DASH_PORT% ist bereits belegt.
    echo             Moeglicherweise laeuft das Dashboard schon.
    choice /C JN /M "Trotzdem starten"
    if errorlevel 2 (
        set "FAILED=1"
        goto :end
    )
)
echo   OK
echo.

:: --------------------------------------------------------------------
:: Check-Modus
:: --------------------------------------------------------------------
if /I "%MODE%"=="check" (
    echo ================================================================
    echo   Alle Pruefungen abgeschlossen. Kein Start angefordert.
    echo ================================================================
    echo.
    pause
    goto :end
)

:: --------------------------------------------------------------------
:: Prozesse starten
:: --------------------------------------------------------------------
if /I "%MODE%"=="tui"   goto :start_tui
if /I "%MODE%"=="dash"  goto :start_dash
if /I "%MODE%"=="beide" goto :start_beide

echo [FEHLER] Unbekannter Modus: %MODE%
echo         Erlaubt: tui, dash, beide, check, nobrowser
set "FAILED=1"
goto :end

:start_tui
echo [START] Netzwerk-Monitor - TUI...
start "glubschauge TUI" /d "%ROOT%" cmd /k ""%PYTHON%" run.py"
goto :started

:start_dash
echo [START] Dashboard...
start "glubschauge Dashboard" /d "%ROOT%\dashboard" cmd /k ""%PYTHON%" app.py"
goto :started

:start_beide
echo [START] Netzwerk-Monitor - TUI...
start "glubschauge TUI" /d "%ROOT%" cmd /k ""%PYTHON%" run.py"

echo [INFO]  Warte 3 Sekunden - tshark-Initialisierung...
timeout /t 3 /nobreak >nul

echo [START] Dashboard...
start "glubschauge Dashboard" /d "%ROOT%\dashboard" cmd /k ""%PYTHON%" app.py"

goto :started

:: --------------------------------------------------------------------
:: Erfolgsmeldung
:: --------------------------------------------------------------------
:started
echo.
echo ================================================================
echo   Gestartet.
echo ================================================================
if /I "%MODE%"=="beide" (
    echo   - TUI-Fenster:   "glubschauge TUI"
    echo   - Dashboard:     http://127.0.0.1:%DASH_PORT%
    echo.
    echo   Beenden:   stop.bat   - oder Fenster schliessen
) else if /I "%MODE%"=="tui" (
    echo   - TUI-Fenster:   "glubschauge TUI"
    echo   Beenden:   stop.bat tui
) else if /I "%MODE%"=="dash" (
    echo   - Dashboard:     http://127.0.0.1:%DASH_PORT%
    echo   Beenden:   stop.bat dash
)
echo.

:: --------------------------------------------------------------------
:: Browser oeffnen
:: --------------------------------------------------------------------
if "%OPEN_BROWSER%"=="0" goto :skip_browser
if /I "%MODE%"=="tui" goto :skip_browser

echo [INFO]  Warte 6 Sekunden auf Dashboard...
timeout /t 6 /nobreak >nul

echo [INFO]  Oeffne Browser: http://127.0.0.1:%DASH_PORT%
start "" "http://127.0.0.1:%DASH_PORT%"

:skip_browser
echo.
timeout /t 3 /nobreak >nul
exit /b 0

:: --------------------------------------------------------------------
:: Fehlerbehandlung
:: --------------------------------------------------------------------
:end
if "%FAILED%"=="1" (
    echo.
    echo Abgebrochen.
    pause
    exit /b 1
)
exit /b 0