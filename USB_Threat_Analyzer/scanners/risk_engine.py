"""
Intelligent Risk Engine.

Combines findings from Level 1 (file), Level 2 (zip/script), and
Level 3 (PE/script-executable) analyzers into a single 0-100 risk
score with a human-readable explanation for every point awarded.
Score is always additive-and-capped, never a bare guess - every
contributing flag is traceable back to config.RISK_WEIGHTS.

Every point awarded also produces a structured *explanation* (see
FLAG_CATALOG and RiskAssessment.explanations) telling the user what
kind of check fired (signature match / heuristic / behavior indicator),
what was actually found in this file, and why it matters. The UI renders
these directly, so a flagged file is never just a number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import config
from utils.logger import get_logger

logger = get_logger(__name__)


# Kinds of check that can raise a flag. Shown as a badge next to each reason.
SIGNATURE = "Signature match"        # content signature / known-pattern list matched
HEURISTIC = "Heuristic"              # statistical or structural rule of thumb
BEHAVIOR = "Behavior indicator"      # code that is capable of risky behavior
INFO = "Note"                        # no points; explains a limitation of the analysis

# weight key -> (short title, check kind, why it matters - generic, file-independent)
FLAG_CATALOG: dict[str, tuple[str, str, str]] = {
    "double_extension": (
        "Disguised double extension", HEURISTIC,
        "The name ends in two extensions (e.g. .pdf.exe), so it looks like a harmless "
        "document but Windows runs it as a program."),
    "hidden_system_file": (
        "Hidden / System attribute set", HEURISTIC,
        "Hidden and System files do not appear in normal Explorer views, so they are often "
        "used to conceal dropped files on removable media. Some legitimate OS files use them too."),
    "mime_mismatch": (
        "File type does not match its extension", SIGNATURE,
        "The file's internal content signature (magic bytes) identifies a different format "
        "than the extension claims."),
    "disguised_executable": (
        "Program code hidden behind a non-program extension", SIGNATURE,
        "The content signature identifies executable code, but the extension suggests a "
        "document, image or media file - a classic renamed-executable trick."),
    "zip_bomb": (
        "Possible zip bomb", HEURISTIC,
        "The archive expands to far more data (or far more entries) than its size suggests, "
        "which can exhaust disk or memory when opened."),
    "zip_slip": (
        "Zip Slip path traversal", HEURISTIC,
        "Some entries use '../' or absolute paths, so extracting the archive could write files "
        "outside the chosen folder."),
    "high_entropy": (
        "High-entropy (random-looking) content", HEURISTIC,
        "The data looks packed, compressed or encrypted. This is normal for many legitimate "
        "files (photos, archives, video) and is a statistical indicator only."),
    "appended_payload": (
        "Data appended after the end-of-file marker", HEURISTIC,
        "Extra bytes follow the format's real end marker. The file still opens normally but "
        "can carry a hidden second payload."),
    "abnormal_size": (
        "Unusually large for its file type", HEURISTIC,
        "The file is far larger than is typical for this type, which can indicate embedded "
        "or bundled content."),
    "registry_api": (
        "Uses registry-modifying functions", BEHAVIOR,
        "Imports Windows functions that read or change the registry - a common way for "
        "programs to make themselves start automatically."),
    "network_api": (
        "Uses network functions", BEHAVIOR,
        "Contains functions that can open network connections or download files."),
    "process_api": (
        "Can start or manipulate other processes", BEHAVIOR,
        "Contains functions that launch programs or interact with other running processes "
        "(including memory-writing calls used by injection techniques)."),
    "crypto_api": (
        "Uses cryptography functions", BEHAVIOR,
        "Contains encryption APIs. Ransomware relies on these, but so do many legitimate programs."),
    "unsigned_exe": (
        "No digital signature", HEURISTIC,
        "The binary carries no Authenticode signature, so its publisher cannot be verified. "
        "Common for small or in-house tools as well as malware."),
    "invalid_signature": (
        "Digital signature failed verification", SIGNATURE,
        "The file claims to be signed, but the signature does not verify or the file was changed "
        "after signing - a strong sign of tampering or a forged signature."),
    "packed_exe": (
        "Packed / obfuscated executable", HEURISTIC,
        "At least one section has entropy consistent with packing or encryption, which hides "
        "the real code from static inspection."),
    "dangerous_script_call": (
        "Risky script behavior", BEHAVIOR,
        "The script contains constructs that run code determined at runtime or match "
        "known dangerous command patterns, so its real actions are hard to vet statically."),
    "nested_zip_depth": (
        "Deeply nested archives", HEURISTIC,
        "Archives inside archives at or beyond the safe limit are a common way to slip content "
        "past scanners and to build zip bombs."),
}


@dataclass
class RiskAssessment:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
    contributing_flags: dict[str, int] = field(default_factory=dict)
    # One dict per reason: flag, title, category, points, why, detail, evidence[]
    explanations: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score, "level": self.level,
            "reasons": self.reasons, "contributing_flags": self.contributing_flags,
            "explanations": self.explanations,
        }


def _note(detail: str) -> dict:
    """A zero-point explanation entry used to tell the user about an analysis limitation."""
    return {"flag": "analysis_note", "title": "Analysis limitation", "category": INFO,
            "points": 0, "why": "The result below may be incomplete for this file.",
            "detail": detail, "evidence": []}


def _level_for_score(score: int) -> str:
    for low, high, label in config.RISK_LEVELS:
        if low <= score <= high:
            return label
    return "Critical" if score > 100 else "Low"


def score_level1(finding_flags: dict, flag_details: dict | None = None) -> RiskAssessment:
    """
    Score a Level 1 FileFinding.flags dict against the weight table.
    `flag_details` maps flag name -> the scanner's file-specific sentence.
    """
    evidence: dict[str, list[str]] = {}
    hidden = finding_flags.get("hidden_system_file")
    if isinstance(hidden, list) and hidden:
        evidence["hidden_system_file"] = [f"Attributes set: {', '.join(hidden)}"]
    if finding_flags.get("high_entropy"):
        evidence["high_entropy"] = [
            f"Shannon entropy {finding_flags.get('entropy_value', 0):.2f} / 8.0 "
            f"({finding_flags.get('entropy_label', 'high')})"]
    appended = finding_flags.get("appended_payload")
    if isinstance(appended, int) and not isinstance(appended, bool):
        evidence["appended_payload"] = [f"{appended} trailing bytes after the end marker"]
    return _score_flags(finding_flags, {
        "double_extension": "double_extension",
        "hidden_system_file": "hidden_system_file",
        "mime_mismatch": "mime_mismatch",
        "disguised_executable": "disguised_executable",
        "high_entropy": "high_entropy",
        "appended_payload": "appended_payload",
        "abnormal_size": "abnormal_size",
    }, details=flag_details, evidence=evidence)


def score_zip(zip_flags: dict) -> RiskAssessment:
    mapping = {}
    if zip_flags.get("is_zip_bomb"):
        mapping["is_zip_bomb"] = "zip_bomb"
    if zip_flags.get("zip_slip_entries"):
        mapping["zip_slip_entries"] = "zip_slip"
    if zip_flags.get("nested_zip_depth", 0) >= config.ZIP_MAX_NESTED_DEPTH:
        mapping["nested_zip_depth"] = "nested_zip_depth"

    evidence: dict[str, list[str]] = {}
    slip = zip_flags.get("zip_slip_entries") or []
    if slip:
        shown = slip[:5]
        evidence["zip_slip"] = [f"Entry: {name}" for name in shown]
        if len(slip) > len(shown):
            evidence["zip_slip"].append(f"...and {len(slip) - len(shown)} more")
    if zip_flags.get("is_zip_bomb"):
        evidence["zip_bomb"] = [
            f"{zip_flags.get('file_count', 0)} entries, "
            f"expansion ratio {zip_flags.get('overall_ratio', 0)}:1"]
    if zip_flags.get("nested_zip_depth"):
        evidence["nested_zip_depth"] = [f"Nesting depth: {zip_flags['nested_zip_depth']}"]

    details = zip_flags.get("flag_details") or {}
    assessment = _score_flags(zip_flags, mapping, details=details, evidence=evidence)
    if details.get("analysis_note"):
        assessment.explanations.append(_note(details["analysis_note"]))
    return assessment


def score_script(script_flags: dict) -> RiskAssessment:
    mapping = {}
    if script_flags.get("network_calls"):
        mapping["network_calls"] = "network_api"
    if script_flags.get("process_execution"):
        mapping["process_execution"] = "process_api"
    if script_flags.get("dynamic_eval"):
        mapping["dynamic_eval"] = "dangerous_script_call"
    evidence = {
        "network_api": [f"Found: {n}" for n in script_flags.get("network_calls", [])[:8]],
        "process_api": [f"Found: {n}" for n in script_flags.get("process_execution", [])[:8]],
        "dangerous_script_call": [
            f"Found: {n}" for n in sorted(set(script_flags.get("dynamic_eval", [])))[:8]],
    }
    details = {
        "dangerous_script_call": (
            "Dynamic code evaluation detected - the code that runs is decided at runtime."),
        "network_api": f"{script_flags.get('language', 'Script')} code uses network-capable APIs.",
        "process_api": (
            f"{script_flags.get('language', 'Script')} code can execute commands or programs."),
    }
    return _score_flags(script_flags, mapping, details=details, evidence=evidence)


def score_script_executable(data: dict) -> RiskAssessment:
    """Score a BAT/CMD/PS1/VBS/INF analysis (Level 3 script-style executables)."""
    patterns = sorted(set(data.get("dangerous_commands") or []))
    ext = data.get("file_type", "script")
    return _score_flags(
        {"dynamic_eval": bool(patterns)}, {"dynamic_eval": "dangerous_script_call"},
        details={"dangerous_script_call": (
            f"{ext} file contains known dangerous command pattern(s) such as "
            f"download-and-run, encoded commands or persistence edits.")},
        evidence={"dangerous_script_call": [f"Matched pattern: {p}" for p in patterns[:10]]},
        categories={"dangerous_script_call": SIGNATURE},
    )


def score_pe(pe_flags: dict) -> RiskAssessment:
    mapping = {}
    sig = pe_flags.get("signature") or {}
    sig_status = sig.get("status", "")
    if sig_status in ("invalid_signature", "digest_mismatch"):
        mapping["bad_signature"] = "invalid_signature"
    elif not pe_flags.get("is_signed", True):
        mapping["is_signed"] = "unsigned_exe"
    if pe_flags.get("is_packed"):
        mapping["is_packed"] = "packed_exe"
    categories = pe_flags.get("suspicious_api_categories", {})
    for cat_key in ("registry_api", "network_api", "crypto_api", "process_api"):
        if categories.get(cat_key):
            mapping[cat_key] = cat_key

    evidence: dict[str, list[str]] = {
        k: [f"Imports: {', '.join(categories[k][:10])}"] for k in mapping if k in categories}
    if "bad_signature" in mapping:
        evidence["invalid_signature"] = [sig.get("message", "Signature failed verification")]
    elif not pe_flags.get("is_signed", True):
        evidence["unsigned_exe"] = [sig.get("message") or
                                    "No Authenticode signature entry in the PE security directory"]
    if pe_flags.get("is_packed"):
        top = sorted((sec for sec in pe_flags.get("sections", []) if sec.get("entropy", 0) >= 6.5),
                     key=lambda x: x.get("entropy", 0), reverse=True)[:3]
        evidence["packed_exe"] = [
            f"Section '{sec.get('name', '?')}' entropy {sec.get('entropy', 0)} / 8.0" for sec in top]

    assessment = _score_flags({**pe_flags, **{k: True for k in mapping}}, mapping, evidence=evidence)
    if pe_flags.get("parse_error"):
        assessment.explanations.append(_note(pe_flags["parse_error"]))
    return assessment


def _score_flags(flags: dict, key_to_weight: dict[str, str], *,
                 details: dict | None = None, evidence: dict | None = None,
                 categories: dict | None = None) -> RiskAssessment:
    """
    Additive scoring. For every flag that fires, also record a structured
    explanation: catalog title/kind/why-it-matters plus the file-specific
    `details` sentence and `evidence` lines supplied by the caller.
    """
    details = details or {}
    evidence = evidence or {}
    categories = categories or {}
    score = 0
    reasons: list[str] = []
    contributing: dict[str, int] = {}
    explanations: list[dict] = []
    for flag_key, weight_key in key_to_weight.items():
        if flags.get(flag_key):
            weight = config.RISK_WEIGHTS.get(weight_key, 0)
            score += weight
            contributing[weight_key] = weight
            title, kind, why = FLAG_CATALOG.get(
                weight_key, (weight_key.replace("_", " ").title(), HEURISTIC, ""))
            reasons.append(f"{title} (+{weight})")
            explanations.append({
                "flag": weight_key, "title": title,
                "category": categories.get(weight_key, kind), "points": weight,
                "why": why, "detail": details.get(weight_key, ""),
                "evidence": list(evidence.get(weight_key, [])),
            })
    score = min(score, 100)
    return RiskAssessment(score=score, level=_level_for_score(score), reasons=reasons,
                           contributing_flags=contributing, explanations=explanations)


def combine_assessments(*assessments: RiskAssessment) -> RiskAssessment:
    """Merge multiple partial assessments (e.g. Level1 + Level3) into one final score."""
    total = 0
    reasons: list[str] = []
    contributing: dict[str, int] = {}
    explanations: list[dict] = []
    for a in assessments:
        total += a.score if not contributing else sum(a.contributing_flags.values())
        for k, v in a.contributing_flags.items():
            contributing[k] = v
        reasons.extend(a.reasons)
        explanations.extend(a.explanations)
    total = min(sum(contributing.values()), 100)
    return RiskAssessment(score=total, level=_level_for_score(total), reasons=reasons,
                           contributing_flags=contributing, explanations=explanations)


def explain(assessment: RiskAssessment) -> str:
    """Produce the standard 'Risk 87 / Reason: ...' style explanation block."""
    lines = [f"Risk {assessment.score} ({assessment.level})", "Reason:"]
    lines.extend(f"- {r}" for r in assessment.reasons) if assessment.reasons else lines.append("- No risk indicators detected")
    return "\n".join(lines)
