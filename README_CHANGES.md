# What changed (4 features + quarantine page update)

| # | Feature | New files | Edited files |
|---|---------|-----------|--------------|
| 1 | BadUSB / HID guard | `scanners/hid_guard.py` | `app.py`, `desktop.py`, `config.py`, `templates/index.html`, `static/app.js` |
| 2 | Offline signature verification | `scanners/signature_verifier.py`, `certificates/` | `scanners/level3_pe.py`, `scanners/risk_engine.py`, `config.py` |
| 3 | Tray + background + auto-popup | `utils/tray.py`, `utils/ui_bridge.py` | `desktop.py`, `app.py`, `config.py`, `templates/index.html`, `static/app.js`, `requirements.txt`, `.spec` |
| 4 | Protected quarantine release | `utils/credential_prompt.py` | `scanners/quarantine.py`, `app.py`, `static/app.js` |

Tests: `python -m unittest discover tests` (35 tests; pure-logic parts only, no Windows needed).

## Must be tested on Windows (written here, never executed on Windows)
1. Plug in a USB drive -> window restores, maximizes, shows scan progress (from tray AND from taskbar-minimized).
2. Settings -> tick background mode -> minimize: taskbar button disappears, tray icon appears; single click restores. Tray -> Exit really quits.
3. Quarantine -> Restore: Windows Security prompt appears; wrong password denies; correct password / PIN restores.
4. Drop a company .crt/.pem into `certificates/` (or `%LOCALAPPDATA%\USBThreatAnalyzer\certificates\` in the EXE) and scan a file signed by it. Also scan a Microsoft-signed .exe copied to the USB (should be trusted via the Windows store).
5. BadUSB: use a real Rubber Ducky / Pico-based HID injector, or a keyboard emulator, and confirm the alert + lockdown.

## Known limits
- HID: user-mode software cannot drop one keyboard's keys selectively. Response = brief global hardware-key lockdown + device disable (needs Administrator). Keys typed before detection get through.
- Signatures: no revocation or timestamp checks (offline by design); catalog-signed Windows files appear unsigned; first signature only.
- Quarantine: sandbox hand-off is not gated (it doesn't release the file). Gate also covers export.
- The installed EXE keeps certificates in `%LOCALAPPDATA%\USBThreatAnalyzer\certificates`, not next to the EXE.


---

# Update: Quarantine page, 75+ auto-quarantine, Python 3.10+

| Change | Where |
|---|---|
| Sidebar **Quarantine** page: in-app file browser (USB first) + drag & drop to quarantine by hand | `templates/index.html`, `static/app.js`, `static/style.css`, `app.py` (`/api/fs/*`, `/api/quarantine/add`, `manual_quarantine`), `desktop.py` |
| Auto-quarantine at risk score **>= 75** (was 60), one shared rule for USB scans and dropped files | `config.AUTO_QUARANTINE_THRESHOLD`, `app.auto_quarantine_if_needed` |
| PDF report: *Quarantine Actions* section, per-file "QUARANTINED automatically / manually" marker, count rows, list of 75+ files that could not be moved | `report_generator.py` |
| `quarantine.source` column (`auto` / `manual`), added to old databases automatically | `database.py`, `scanners/quarantine.py` |
| Python **3.10+** on every version: guard with a clear message, relaxed `requirements*.txt` (unused `lief`, `yara-python`, `capstone` removed), build script accepts any 3.10+ | `config.py`, `requirements*.txt`, `build_exe.bat`, docs |

Safety rules: a file inside the Windows folder or already in quarantine is refused; manual quarantine from a drop asks for
confirmation first; the file API needs a custom header so other web pages cannot call it.

Tests: `python -m unittest discover tests` (58 tests; includes a check that every file parses as Python 3.10).

## Must be tested on Windows (written here, never executed on Windows)
6. Quarantine page -> drag a file from File Explorer and from the USB drive into the window: the Yes/No box appears, Yes moves the file, No leaves it.
7. Dashboard -> drag the same file: it is scanned (not quarantined) unless it scores 75+.
8. Insert a USB with a file that scores 75+: it is moved automatically, shows "Auto (75+)" in Quarantine, and the generated PDF lists it under *Quarantine Actions*.
9. `build_exe.bat` on Python 3.10, 3.11, 3.12 and 3.13 if you have them (the batch logic and pywebview/PyInstaller wheels were not run here).
