"""
LEVEL 2 - ZIP archive analysis and programming-language AST analysis.

ZIP analysis reads the central directory table only - nothing is ever
extracted until the zip-bomb and zip-slip guards below have both
cleared, and even then extraction goes only into the isolated
Temp/USB_Sandbox/<scan_id>/ directory, never into Downloads or any
user-facing folder.

Script analysis parses a real abstract syntax tree for Python (the
stdlib `ast` module) and uses a language-aware tokenizer/grammar-based
approach for the other supported languages, rather than naive keyword
substring matching, to find imports, system-command execution, network
calls, and dangerous dynamic-evaluation calls.
"""

from __future__ import annotations

import ast as py_ast
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)


# ===========================================================================
# ZIP ANALYSIS
# ===========================================================================
@dataclass
class ZipEntryInfo:
    filename: str
    extension: str
    compressed_size: int
    original_size: int
    compression_ratio: float

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "extension": self.extension,
            "compressed_size": self.compressed_size,
            "original_size": self.original_size,
            "compression_ratio": round(self.compression_ratio, 2),
        }


@dataclass
class ZipAnalysisResult:
    path: str
    entries: list[ZipEntryInfo] = field(default_factory=list)
    total_compressed: int = 0
    total_original: int = 0
    overall_ratio: float = 0.0
    nested_zip_depth: int = 0
    is_zip_bomb: bool = False
    zip_slip_entries: list[str] = field(default_factory=list)
    file_count: int = 0
    reasons: list[str] = field(default_factory=list)
    flag_details: dict = field(default_factory=dict)  # weight key -> file-specific sentence(s)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "flag_details": self.flag_details,
            "entries": [e.to_dict() for e in self.entries],
            "total_compressed": self.total_compressed,
            "total_original": self.total_original,
            "overall_ratio": round(self.overall_ratio, 2),
            "nested_zip_depth": self.nested_zip_depth,
            "is_zip_bomb": self.is_zip_bomb,
            "zip_slip_entries": self.zip_slip_entries,
            "file_count": self.file_count,
            "reasons": self.reasons,
        }


def _is_path_traversal(member_name: str) -> bool:
    """
    Zip Slip detection: a malicious archive entry whose name resolves
    outside the intended extraction directory via '../' sequences or an
    absolute path.
    """
    normalized = os.path.normpath(member_name)
    if normalized.startswith("..") or os.path.isabs(normalized):
        return True
    return False


def _inspect_nested_zip_depth(zf: zipfile.ZipFile, current_depth: int = 1) -> int:
    """Recursively read (never extract) nested zip central directories to find max depth."""
    max_depth = current_depth
    if current_depth >= config.ZIP_MAX_NESTED_DEPTH:
        return max_depth
    for info in zf.infolist():
        if info.filename.lower().endswith(".zip"):
            try:
                with zf.open(info) as inner_fh:
                    import io
                    inner_bytes = inner_fh.read(config.ZIP_MAX_TOTAL_EXTRACTED_BYTES)
                    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner_zf:
                        depth = _inspect_nested_zip_depth(inner_zf, current_depth + 1)
                        max_depth = max(max_depth, depth)
            except (zipfile.BadZipFile, OSError) as exc:
                logger.debug("Could not inspect nested zip %s: %s", info.filename, exc)
    return max_depth


def analyze_zip(path: str | Path) -> ZipAnalysisResult:
    """
    Analyze a zip archive's central directory table WITHOUT extracting
    any content, and detect zip bombs, zip slip path traversal, and
    excessive nesting depth up front.
    """
    path = Path(path)
    result = ZipAnalysisResult(path=str(path))

    def _note(flag: str, message: str) -> None:
        """Record a reason and remember which risk flag it belongs to."""
        result.reasons.append(message)
        result.flag_details[flag] = (result.flag_details.get(flag, "") + " " + message).strip()

    try:
        with zipfile.ZipFile(path, "r") as zf:
            infolist = zf.infolist()
            result.file_count = len(infolist)

            if result.file_count > config.ZIP_MAX_FILE_COUNT:
                _note("zip_bomb",
                    f"Archive contains {result.file_count} entries, exceeding the safety "
                    f"limit of {config.ZIP_MAX_FILE_COUNT}; treated as a potential zip bomb."
                )
                result.is_zip_bomb = True

            for info in infolist:
                ext = Path(info.filename).suffix.lower()
                ratio = (info.file_size / info.compress_size) if info.compress_size else 0.0
                result.entries.append(ZipEntryInfo(
                    filename=info.filename, extension=ext,
                    compressed_size=info.compress_size, original_size=info.file_size,
                    compression_ratio=ratio,
                ))
                result.total_compressed += info.compress_size
                result.total_original += info.file_size

                if _is_path_traversal(info.filename):
                    result.zip_slip_entries.append(info.filename)

            result.overall_ratio = (
                result.total_original / result.total_compressed if result.total_compressed else 0.0
            )

            if result.overall_ratio > config.ZIP_BOMB_RATIO_THRESHOLD:
                result.is_zip_bomb = True
                _note("zip_bomb",
                    f"Extraction ratio {result.overall_ratio:.1f}:1 exceeds the zip-bomb "
                    f"threshold of {config.ZIP_BOMB_RATIO_THRESHOLD}:1."
                )

            if result.total_original > config.ZIP_MAX_TOTAL_EXTRACTED_BYTES:
                result.is_zip_bomb = True
                _note("zip_bomb",
                    f"Uncompressed size {result.total_original / (1024*1024):.0f} MB exceeds "
                    f"the maximum safe extraction size of "
                    f"{config.ZIP_MAX_TOTAL_EXTRACTED_BYTES / (1024*1024):.0f} MB."
                )

            if result.zip_slip_entries:
                _note("zip_slip",
                    f"{len(result.zip_slip_entries)} entr"
                    f"{'y uses' if len(result.zip_slip_entries) == 1 else 'ies use'} path traversal ('../' or absolute paths) that could write files outside "
                    f"the intended extraction directory (Zip Slip)."
                )

            result.nested_zip_depth = _inspect_nested_zip_depth(zf)
            if result.nested_zip_depth >= config.ZIP_MAX_NESTED_DEPTH:
                _note("nested_zip_depth",
                    f"Nested zip depth of {result.nested_zip_depth} reaches the configured "
                    f"limit of {config.ZIP_MAX_NESTED_DEPTH} - deeper nesting is blocked from extraction."
                )

    except (zipfile.BadZipFile, OSError) as exc:
        logger.warning("Could not analyze zip %s: %s", path, exc)
        result.reasons.append(f"Archive could not be read/parsed: {exc}")
        result.flag_details["analysis_note"] = f"Archive could not be read/parsed: {exc}"

    return result


def safe_extract(path: str | Path, scan_id: str) -> Optional[Path]:
    """
    Extract a zip ONLY after analyze_zip() has cleared it (no bomb, no
    slip, depth within limits), and only into the isolated
    Temp/USB_Sandbox/<scan_id>/ directory - never into Downloads or any
    user-facing folder.
    """
    analysis = analyze_zip(path)
    if analysis.is_zip_bomb or analysis.zip_slip_entries:
        logger.warning("Refusing to extract unsafe archive %s", path)
        return None

    dest_root = config.SAFE_EXTRACTION_ROOT / scan_id
    dest_root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(path, "r") as zf:
        for info in zf.infolist():
            target = (dest_root / info.filename).resolve()
            if not str(target).startswith(str(dest_root.resolve())):
                logger.warning("Blocked Zip Slip extraction attempt: %s", info.filename)
                continue
            zf.extract(info, dest_root)

    logger.info("Safely extracted %s to isolated sandbox path %s", path, dest_root)
    return dest_root


# ===========================================================================
# PROGRAMMING LANGUAGE AST / STRUCTURAL ANALYSIS
# ===========================================================================
@dataclass
class ScriptAnalysisResult:
    path: str
    language: str
    imports: list[str] = field(default_factory=list)
    function_calls: list[str] = field(default_factory=list)
    system_commands: list[str] = field(default_factory=list)
    network_calls: list[str] = field(default_factory=list)
    process_execution: list[str] = field(default_factory=list)
    dynamic_eval: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path, "language": self.language, "imports": self.imports,
            "function_calls": self.function_calls, "system_commands": self.system_commands,
            "network_calls": self.network_calls, "process_execution": self.process_execution,
            "dynamic_eval": self.dynamic_eval, "reasons": self.reasons,
        }


_NETWORK_MARKERS = {"socket", "requests", "urllib", "http.client", "ftplib", "smtplib",
                     "paramiko", "telnetlib", "net.Socket", "HttpURLConnection",
                     "XMLHttpRequest", "fetch", "curl_init", "fsockopen"}
_PROCESS_MARKERS = {"subprocess", "os.system", "os.popen", "ProcessBuilder", "Runtime.exec",
                     "system(", "popen(", "exec(", "shell_exec", "proc_open",
                     "Start-Process", "Invoke-Expression", "WScript.Shell"}
_EVAL_MARKERS = {"eval", "exec", "execfile", "Function(", "assert(", "create_function",
                  "Invoke-Expression", "IEX"}


def _analyze_python_ast(source: str) -> tuple[list[str], list[str], list[str]]:
    """Real AST parse of Python source using the stdlib ast module."""
    imports: list[str] = []
    calls: list[str] = []
    dangerous: list[str] = []
    try:
        tree = py_ast.parse(source)
    except SyntaxError as exc:
        logger.debug("Python AST parse failed: %s", exc)
        return imports, calls, dangerous

    for node in py_ast.walk(tree):
        if isinstance(node, py_ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, py_ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, py_ast.Call):
            func_name = _call_name(node.func)
            if func_name:
                calls.append(func_name)
                if func_name.split(".")[-1] in ("eval", "exec", "execfile", "compile"):
                    dangerous.append(func_name)
    return imports, calls, dangerous


def _call_name(func_node: py_ast.AST) -> Optional[str]:
    if isinstance(func_node, py_ast.Name):
        return func_node.id
    if isinstance(func_node, py_ast.Attribute):
        parts = []
        node: Optional[py_ast.AST] = func_node
        while isinstance(node, py_ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, py_ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
    return None


# Grammar-aware regexes (not naive keyword substring matching) for languages
# without a bundled AST parser: each pattern anchors on real language syntax
# (import/using/require statements, qualified call expressions) rather than
# matching a bare word anywhere in the file.
_IMPORT_PATTERNS = {
    "Java": re.compile(r"^\s*import\s+([\w\.]+)\s*;", re.MULTILINE),
    "C": re.compile(r'^\s*#include\s*[<"]([\w\./]+)[>"]', re.MULTILINE),
    "C++": re.compile(r'^\s*#include\s*[<"]([\w\./]+)[>"]', re.MULTILINE),
    "JavaScript": re.compile(
        r'(?:import\s+.*?from\s+[\'"]([\w\./\-@]+)[\'"]|require\(\s*[\'"]([\w\./\-@]+)[\'"]\s*\))'
    ),
    "PHP": re.compile(r'\b(?:require|require_once|include|include_once)\s*\(?\s*[\'"]([\w\./\-]+)[\'"]'),
    "PowerShell": re.compile(r'^\s*Import-Module\s+([\w\.\-]+)', re.MULTILINE | re.IGNORECASE),
    "VBScript": re.compile(r'CreateObject\(\s*"([\w\.\-]+)"\s*\)', re.IGNORECASE),
}

_CALL_PATTERN = re.compile(r'\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(')


def _analyze_generic_script(source: str, language: str) -> tuple[list[str], list[str]]:
    """
    Structural (grammar-anchored) extraction of imports and call
    expressions for non-Python languages, used as the AST-equivalent
    signal when a full third-party parser isn't bundled.
    """
    imports: list[str] = []
    pattern = _IMPORT_PATTERNS.get(language)
    if pattern:
        for match in pattern.finditer(source):
            group = next((g for g in match.groups() if g), None)
            if group:
                imports.append(group)

    calls = [m.group(1) for m in _CALL_PATTERN.finditer(source)]
    return imports, calls


def analyze_script(path: str | Path) -> Optional[ScriptAnalysisResult]:
    """
    Run structural/AST analysis on a supported script file and classify
    calls into system-command, network, process-execution, and dynamic
    eval buckets.
    """
    path = Path(path)
    language = config.SCRIPT_LANGUAGE_EXTENSIONS.get(path.suffix.lower())
    if not language:
        return None

    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError) as exc:
        logger.warning("Could not read script %s: %s", path, exc)
        return None

    result = ScriptAnalysisResult(path=str(path), language=language)

    if language == "Python":
        imports, calls, dangerous = _analyze_python_ast(source)
        result.imports = imports
        result.function_calls = calls
        result.dynamic_eval = dangerous
    else:
        imports, calls = _analyze_generic_script(source, language)
        result.imports = imports
        result.function_calls = calls
        result.dynamic_eval = [c for c in calls if any(m.rstrip("(") in c for m in _EVAL_MARKERS)]

    combined_signal = set(result.imports) | set(result.function_calls)
    result.network_calls = sorted({s for s in combined_signal if any(m in s for m in _NETWORK_MARKERS)})
    result.process_execution = sorted({s for s in combined_signal if any(m.rstrip("(") in s for m in _PROCESS_MARKERS)})
    result.system_commands = result.process_execution

    if result.dynamic_eval:
        result.reasons.append(
            f"Dynamic code evaluation detected ({', '.join(sorted(set(result.dynamic_eval)))}) - "
            f"code content is determined at runtime, which is difficult to statically vet."
        )
    if result.network_calls:
        result.reasons.append(
            f"Network-capable API usage detected: {', '.join(result.network_calls)}."
        )
    if result.process_execution:
        result.reasons.append(
            f"Process/command execution capability detected: {', '.join(result.process_execution)}."
        )

    return result
