"""
LEVEL 3 - Executable static analysis (EXE, DLL, BAT, CMD, MSI, SCR, INF,
PS1, VBS).

True PE-format files (EXE/DLL/SCR/MSI) are parsed structurally with
`pefile` for headers, sections, imports/exports, resources, and digital
signature presence. Script-style "executables" (BAT/CMD/PS1/VBS/INF)
are routed to a text/command analyzer since they have no PE structure.

Findings are always phrased as behavior indicators, never a malware
verdict - see the wording rules enforced in the `reasons` text below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PEFILE_AVAILABLE = False

from scanners import signature_verifier
from utils.entropy import classify_entropy, shannon_entropy
from utils.logger import get_logger

logger = get_logger(__name__)

PE_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".sys"}
SCRIPT_EXECUTABLE_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".inf"}

# Categorized suspicious Windows API imports (behavior indicators only).
_API_CATEGORIES = {
    "registry_api": {
        "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
    },
    "network_api": {
        "socket", "connect", "send", "recv", "WSAStartup", "InternetOpenA",
        "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA",
        "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
    },
    "crypto_api": {
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptGenKey", "BCryptEncrypt", "BCryptDecrypt", "CryptProtectData",
    },
    "process_api": {
        "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "WriteProcessMemory",
        "VirtualAllocEx", "OpenProcess", "SetWindowsHookExA", "SetWindowsHookExW",
        "ShellExecuteA", "ShellExecuteW",
    },
    "file_encryption_api": {
        "CryptEncrypt", "MoveFileExA", "MoveFileExW", "DeleteFileA", "DeleteFileW",
    },
}

_SCRIPT_DANGEROUS_PATTERNS = {
    "Invoke-Expression", "IEX", "DownloadString", "DownloadFile", "-EncodedCommand",
    "Hidden", "Bypass", "WScript.Shell", "Shell.Application", "FileSystemObject",
    "cmd.exe /c", "powershell -", "reg add", "reg delete", "schtasks", "certutil -decode",
}


@dataclass
class PEAnalysisResult:
    path: str
    file_type: str = "PE"
    dos_header: dict = field(default_factory=dict)
    nt_header: dict = field(default_factory=dict)
    machine: str = ""
    compiler_timestamp: str = ""
    sections: list[dict] = field(default_factory=list)
    overall_entropy_label: str = ""
    is_signed: bool = False          # True only for a VALID signature that chains to a trusted store
    signature: dict = field(default_factory=dict)   # full verification verdict (see signature_verifier)
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    suspicious_api_categories: dict[str, list[str]] = field(default_factory=dict)
    is_packed: bool = False
    reasons: list[str] = field(default_factory=list)
    parse_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path, "file_type": self.file_type, "dos_header": self.dos_header,
            "nt_header": self.nt_header, "machine": self.machine,
            "compiler_timestamp": self.compiler_timestamp, "sections": self.sections,
            "overall_entropy_label": self.overall_entropy_label, "is_signed": self.is_signed,
            "signature": self.signature,
            "imports": self.imports, "exports": self.exports, "resources": self.resources,
            "suspicious_api_categories": self.suspicious_api_categories,
            "is_packed": self.is_packed, "reasons": self.reasons, "parse_error": self.parse_error,
        }


def _has_authenticode_signature(pe: "pefile.PE") -> bool:
    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        return directory.VirtualAddress != 0 and directory.Size != 0
    except (AttributeError, IndexError, KeyError):
        return False


def _apply_signature_verdict(result: "PEAnalysisResult", pe: "pefile.PE", path: Path) -> None:
    """Offline Authenticode check against the Windows root store + the certificates/ whitelist."""
    sig = signature_verifier.verify_pe_file(path)
    result.signature = sig.to_dict()

    if sig.status == signature_verifier.UNAVAILABLE:
        # `cryptography` missing: fall back to the old presence-only check.
        result.is_signed = _has_authenticode_signature(pe)
        if not result.is_signed:
            result.reasons.append("Binary has no Authenticode digital signature (Unsigned Binary).")
        return

    result.is_signed = sig.is_trusted
    if sig.status == signature_verifier.UNSIGNED:
        result.reasons.append("Binary has no Authenticode digital signature (Unsigned Binary).")
    elif sig.status == signature_verifier.UNTRUSTED_ROOT:
        result.reasons.append(
            f"Signed by '{sig.signer_subject}', but the issuer is not in the Windows trusted-root "
            f"store or the certificates/ whitelist (signature could not be trusted).")
    elif sig.status in (signature_verifier.INVALID_SIGNATURE, signature_verifier.DIGEST_MISMATCH):
        result.reasons.append(f"Digital signature FAILED verification: {sig.message}")
    elif sig.status == signature_verifier.ERROR:
        result.reasons.append(f"Digital signature could not be verified: {sig.message}")


def analyze_pe(path: str | Path) -> PEAnalysisResult:
    """Parse a PE-format file (EXE/DLL/SCR/MSI-as-PE) and extract structural facts."""
    path = Path(path)
    result = PEAnalysisResult(path=str(path))

    if not _PEFILE_AVAILABLE:
        result.parse_error = "pefile library not available in this environment"
        return result

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        result.parse_error = f"Not a valid PE file or corrupt header: {exc}"
        return result
    except (OSError, PermissionError) as exc:
        result.parse_error = f"Could not read file: {exc}"
        return result

    try:
        result.dos_header = {
            "e_magic": hex(pe.DOS_HEADER.e_magic),
            "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
        }
        result.nt_header = {
            "signature": hex(pe.NT_HEADERS.Signature),
            "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        }
        result.machine = hex(pe.FILE_HEADER.Machine)

        import datetime
        try:
            result.compiler_timestamp = datetime.datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp
            ).isoformat() + "Z"
        except (OSError, OverflowError, ValueError):
            result.compiler_timestamp = "unavailable"

        max_entropy = 0.0
        for section in pe.sections:
            raw = section.get_data()
            ent = shannon_entropy(raw) if raw else 0.0
            max_entropy = max(max_entropy, ent)
            result.sections.append({
                "name": section.Name.decode(errors="ignore").strip("\x00"),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(ent, 3),
            })
        result.overall_entropy_label = classify_entropy(max_entropy)
        if result.overall_entropy_label in ("Packed", "Encrypted Indicator"):
            result.is_packed = True
            result.reasons.append(
                f"Highest section entropy corresponds to '{result.overall_entropy_label}' - "
                f"consistent with a packed executable (behavior indicator only)."
            )

        _apply_signature_verdict(result, pe, path)

        found_apis: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
                names = []
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        names.append(name)
                        found_apis.add(name)
                result.imports[dll_name] = names

        for category, api_set in _API_CATEGORIES.items():
            hits = sorted(found_apis & api_set)
            if hits:
                result.suspicious_api_categories[category] = hits

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            result.exports = [
                exp.name.decode(errors="ignore") for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
                if exp.name
            ]

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                res_id = res.id if res.id is not None else (res.name.__str__() if res.name else "unknown")
                result.resources.append({"type_id": str(res_id)})

        if "registry_api" in result.suspicious_api_categories:
            result.reasons.append(
                f"Suspicious APIs - Registry: {', '.join(result.suspicious_api_categories['registry_api'])}."
            )
        if "network_api" in result.suspicious_api_categories:
            result.reasons.append(
                f"Suspicious APIs - Networking: {', '.join(result.suspicious_api_categories['network_api'])}."
            )
        if "crypto_api" in result.suspicious_api_categories:
            result.reasons.append(
                f"Suspicious APIs - Cryptography: {', '.join(result.suspicious_api_categories['crypto_api'])}."
            )
        if "process_api" in result.suspicious_api_categories:
            result.reasons.append(
                f"Suspicious APIs - Process creation: {', '.join(result.suspicious_api_categories['process_api'])}."
            )

    finally:
        pe.close()

    return result


@dataclass
class ScriptExecutableResult:
    path: str
    file_type: str
    dangerous_commands: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path, "file_type": self.file_type,
            "dangerous_commands": self.dangerous_commands, "reasons": self.reasons,
        }


def analyze_script_executable(path: str | Path) -> ScriptExecutableResult:
    """
    Analyze non-PE 'executable' formats (BAT/CMD/PS1/VBS/INF) by scanning
    for known dangerous command patterns (download-and-execute chains,
    obfuscated encoded commands, persistence-related registry/task edits).
    """
    path = Path(path)
    result = ScriptExecutableResult(path=str(path), file_type=path.suffix.lower())
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError) as exc:
        logger.warning("Could not read script-executable %s: %s", path, exc)
        return result

    for pattern in _SCRIPT_DANGEROUS_PATTERNS:
        if pattern.lower() in content.lower():
            result.dangerous_commands.append(pattern)

    if result.dangerous_commands:
        result.reasons.append(
            f"Dangerous command pattern(s) detected: {', '.join(sorted(set(result.dangerous_commands)))}."
        )
    return result


def analyze_executable(path: str | Path):
    """Dispatch to PE analysis or script-executable analysis based on extension."""
    path = Path(path)
    ext = path.suffix.lower()
    if ext in PE_EXTENSIONS:
        return analyze_pe(path)
    if ext in SCRIPT_EXECUTABLE_EXTENSIONS:
        return analyze_script_executable(path)
    raise ValueError(f"Unsupported executable extension for Level 3 analysis: {ext}")
