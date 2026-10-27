# Windows 10/11 Build Instructions

## Requirements

- Windows 10 or Windows 11, 64-bit
- CPython 3.10 or newer (3.10, 3.11, 3.12, 3.13 ...), 64-bit
- Internet connection for the first build
- Optional: Inno Setup 6 for the installer

Do **not** use the old project `venv` for packaging.

## Build

Open PowerShell in this folder and run:

```powershell
.\build_exe.bat
```

The script creates `.build_venv` automatically and installs the desktop dependencies (newest versions that support your Python).

Successful output:

```text
dist\USBThreatAnalyzer.exe
```

If Inno Setup 6 is installed, it also creates:

```text
installer\USBThreatAnalyzer_Setup.exe
```

## If Python is missing

Install any **64-bit** Python 3.10-or-newer Windows installer from python.org and enable **Add python.exe to PATH**. Then open a new PowerShell window and run the build again.

## Run the EXE

```powershell
.\dist\USBThreatAnalyzer.exe
```

The installer, when created, can be started with:

```powershell
.\installer\USBThreatAnalyzer_Setup.exe
```

The `./` (or `.` prefix in PowerShell) is required when running an executable from the current directory.
