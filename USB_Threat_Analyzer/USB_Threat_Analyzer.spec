# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the standalone Windows build.
# Build with build_exe.bat (or: pyinstaller --noconfirm --clean USB_Threat_Analyzer.spec)
# Output: dist\USBThreatAnalyzer.exe  (single file, no console window)

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

datas = [("templates", "templates"), ("static", "static"), ("assets", "assets")]   # assets/app.ico is used by the tray icon at runtime
binaries = []
hiddenimports = []

# Third-party packages that load DLLs / data files / submodules dynamically and
# therefore need to be collected explicitly.
for pkg in ("webview", "clr_loader", "pythonnet"):
    d, b, h = collect_all(pkg)          # pywebview + its .NET/WebView2 bridge
    datas += d; binaries += b; hiddenimports += h

datas += collect_data_files("magic")    # python-magic-bin: libmagic DLLs + magic.mgc database
datas += collect_data_files("reportlab")
hiddenimports += collect_submodules("reportlab.pdfbase")
hiddenimports += ["magic", "pefile", "psutil", "pystray._win32", "PIL.Image", "cryptography"]

a = Analysis(
    ["desktop.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PIL.ImageTk"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="USBThreatAnalyzer",
    icon="assets/app.ico",   # icon shown on the EXE, taskbar and shortcuts
    console=False,      # windowed app: no black console window
    upx=False,          # UPX-packed EXEs are far more likely to be flagged by antivirus
    runtime_tmpdir=None,
    disable_windowed_traceback=False,
)
