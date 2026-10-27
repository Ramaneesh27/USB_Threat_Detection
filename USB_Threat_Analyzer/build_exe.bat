@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo ================================================================
echo   USB Threat Analyzer - Windows 10/11 Builder
echo ================================================================
echo.

echo [1/7] Looking for 64-bit Python 3.10 or newer...
set "PY_CMD="
where py >nul 2>nul
if not errorlevel 1 (
    for %%V in (3.12 3.11 3.13 3.10) do (
        if not defined PY_CMD (
            py -%%V -c "import struct; raise SystemExit(0 if struct.calcsize('P')*8==64 else 1)" >nul 2>nul
            if not errorlevel 1 set "PY_CMD=py -%%V"
        )
    )
)
if not defined PY_CMD (
    where python >nul 2>nul
    if not errorlevel 1 (
        python -c "import struct,sys; raise SystemExit(0 if sys.version_info>=(3,10) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
        if not errorlevel 1 set "PY_CMD=python"
    )
)

if not defined PY_CMD (
    echo No 64-bit Python 3.10 or newer was found.
    echo.
    echo Please install 64-bit Python 3.10 or newer from:
    echo https://www.python.org/downloads/windows/
    echo.
    echo During installation, enable: Add python.exe to PATH
    exit /b 1
)

%PY_CMD% --version

if not exist ".build_venv\Scripts\python.exe" (
    echo.
echo [2/7] Creating clean build environment...
    %PY_CMD% -m venv .build_venv
    if errorlevel 1 (
        echo ERROR: Could not create .build_venv.
        exit /b 1
    )
)

call ".build_venv\Scripts\activate.bat"
if errorlevel 1 (
    echo ERROR: Could not activate build environment.
    exit /b 1
)

echo.
echo [3/7] Installing build dependencies...
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 exit /b 1
python -m pip install --upgrade --force-reinstall -r requirements-desktop.txt
if errorlevel 1 exit /b 1

echo.
echo [4/7] Cleaning old PyInstaller output and Python caches...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
for /d /r %%D in (__pycache__) do if exist "%%D" rmdir /s /q "%%D"

echo.
echo [5/7] Building USBThreatAnalyzer.exe...
python -m PyInstaller --noconfirm --clean USB_Threat_Analyzer.spec
if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller build failed.
    exit /b 1
)

if not exist "dist\USBThreatAnalyzer.exe" (
    echo ERROR: dist\USBThreatAnalyzer.exe was not created.
    exit /b 1
)

echo.
echo [6/7] Running packaged self-test...
start /wait "USB Threat Analyzer Self-Test" "dist\USBThreatAnalyzer.exe" --selftest
if errorlevel 1 (
    echo.
    echo WARNING: Packaged self-test failed.
    echo Check: %%LOCALAPPDATA%%\USBThreatAnalyzer\history\selftest.log
    exit /b 1
)

echo.
echo [7/7] Checking for Inno Setup...
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if exist "%ISCC%" (
    echo Building Windows installer...
    "%ISCC%" installer\USBThreatAnalyzer.iss
    if errorlevel 1 (
        echo ERROR: Inno Setup failed.
        exit /b 1
    )
) else (
    echo Inno Setup is not installed.
    echo EXE build is complete; installer was skipped.
    echo Install Inno Setup 6 and run this BAT again to create the installer.
)

echo.
echo ================================================================
echo BUILD COMPLETE
echo EXE:       %CD%\dist\USBThreatAnalyzer.exe
if exist "installer\USBThreatAnalyzer_Setup.exe" echo INSTALLER: %CD%\installer\USBThreatAnalyzer_Setup.exe
echo ================================================================
echo.
exit /b 0
