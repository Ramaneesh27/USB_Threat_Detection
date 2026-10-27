"""
Professional forensic PDF report generator using ReportLab.

Pulls a completed scan's full record set out of SQLite (USB info, every
file scanned with its risk score/reasons, sandbox results, registry and
network activity, and the quarantine list) and lays it out as a
structured, readable forensic report with an overall verdict section.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import config
import database
from utils.logger import get_logger

logger = get_logger(__name__)

_styles = getSampleStyleSheet()
_TITLE = ParagraphStyle("ReportTitle", parent=_styles["Title"], textColor=colors.HexColor("#0B1F3A"))
_H2 = ParagraphStyle("H2", parent=_styles["Heading2"], textColor=colors.HexColor("#12335B"), spaceBefore=14)
_BODY = ParagraphStyle("Body", parent=_styles["BodyText"], leading=14)
_SMALL = ParagraphStyle("Small", parent=_styles["BodyText"], fontSize=8, leading=10)

_QUARANTINE_NOTE = ParagraphStyle("QuarantineNote", parent=_BODY, textColor=colors.HexColor("#9B1C31"))

_RISK_COLORS = {
    "Low": colors.HexColor("#2ecc71"), "Medium": colors.HexColor("#f1c40f"),
    "High": colors.HexColor("#e67e22"), "Critical": colors.HexColor("#e74c3c"),
}


def _esc(value) -> str:
    """Paragraph() parses its text as markup; file names/paths from a USB must be escaped."""
    return escape(str(value if value is not None else ""))


def _path_key(path) -> str:
    return os.path.normcase(str(path or ""))


def _quarantine_summary(files: list[dict], quarantine_items: list[dict]) -> dict:
    """Counts + lookups shared by every part of the report that talks about quarantine."""
    threshold = config.AUTO_QUARANTINE_THRESHOLD
    auto = [q for q in quarantine_items if q.get("source") != "manual"]
    manual = [q for q in quarantine_items if q.get("source") == "manual"]
    by_path = {_path_key(q["original_path"]): q for q in quarantine_items}
    # Required by the rule (score >= threshold) but not moved: say so instead of staying silent.
    not_quarantined = [f for f in files
                       if (f.get("risk_score") or 0) >= threshold
                       and _path_key(f.get("absolute_path")) not in by_path]
    return {"threshold": threshold, "auto": auto, "manual": manual, "by_path": by_path,
            "not_quarantined": not_quarantined}


def _quarantine_marker(q: dict | None, threshold: int) -> str:
    if not q:
        return ""
    how = "manually by the user" if q.get("source") == "manual" else f"automatically (risk score {threshold}+)"
    state = q.get("status", "quarantined")
    suffix = "" if state == "quarantined" else f" - since {state}"
    return f"<b>QUARANTINED {how}{suffix}</b>"


# ---------------------------------------------------------------------------
# Sandbox BEFORE / AFTER state comparison (works for manual AND automatic runs;
# both are persisted to sandbox_runs and rendered here).
# ---------------------------------------------------------------------------
_EXEC_EXT = (".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
             ".js", ".jse", ".wsf", ".hta", ".msi", ".lnk", ".jar", ".sys")
_SANDBOX_STAGING_HINTS = ("\\sandbox\\", "\\temp\\", "\\appdata\\", "\\downloads\\",
                          "\\desktop\\", "\\programdata\\", "\\users\\public\\")
_NA = "Not collected by this sandbox type"


def _name_set(values) -> set[str]:
    return {str(v) for v in (values or [])}


def _proc_label(p) -> str:
    if isinstance(p, dict):
        name = p.get("Name") or p.get("name") or "?"
        exe = p.get("ExecutablePath") or p.get("exe") or ""
        pid = p.get("ProcessId") or p.get("pid") or ""
        return f"{name} (PID {pid}){' - ' + str(exe) if exe else ''}"
    return str(p)


def _proc_path(p) -> str:
    return str((p.get("ExecutablePath") or p.get("exe") or "") if isinstance(p, dict) else p)


def _port_label(c: dict) -> str:
    if not isinstance(c, dict):
        return str(c)
    local = c.get("local") or c.get("laddr") or ""
    remote = c.get("remote") or c.get("raddr") or ""
    proto = c.get("protocol") or "TCP"
    status = c.get("status") or ""
    return f"{proto} {local}" + (f" -> {remote}" if remote else "") + (f" [{status}]" if status else "")


def _registry_changes(before: dict, after: dict) -> dict:
    b, a = before.get("registry_run_keys") or {}, after.get("registry_run_keys") or {}
    return {
        "added": [(k, a[k]) for k in sorted(a.keys() - b.keys())],
        "modified": [(k, b[k], a[k]) for k in sorted(a.keys() & b.keys()) if a[k] != b[k]],
        "removed": [(k, b[k]) for k in sorted(b.keys() - a.keys())],
    }


def _sandbox_state_summary(run: dict) -> dict:
    """Derive the 7 requested answers from the persisted BEFORE/AFTER snapshots."""
    before, after = run.get("before_snapshot") or {}, run.get("after_snapshot") or {}
    diff = run.get("diff") or {}
    has_snapshots = bool(before) and bool(after)

    reg = _registry_changes(before, after)
    startup_new = list(diff.get("startup_persistence_new") or
                       sorted(_name_set(after.get("startup_entries")) - _name_set(before.get("startup_entries"))))
    startup_removed = sorted(_name_set(before.get("startup_entries")) - _name_set(after.get("startup_entries")))

    new_files = list(diff.get("new_files") or [])
    new_folders = list(diff.get("new_folders") or [])

    before_pids = {(p.get("ProcessId") or p.get("pid"), p.get("Name") or p.get("name"))
                   for p in (before.get("processes") or []) if isinstance(p, dict)}
    new_procs = [p for p in (after.get("processes") or []) if isinstance(p, dict)
                 and ((p.get("ProcessId") or p.get("pid")), (p.get("Name") or p.get("name"))) not in before_pids]
    exe_run = []
    for p in new_procs:
        path = _proc_path(p).lower()
        name = str(p.get("Name") or p.get("name") or "").lower()
        if path.endswith(_EXEC_EXT) or name.endswith(_EXEC_EXT):
            exe_run.append(_proc_label(p))
    if not new_procs and diff.get("new_processes"):
        exe_run = [_proc_label(p) for p in diff["new_processes"]]
    dropped_exes = [f for f in new_files if str(f).lower().endswith(_EXEC_EXT)]

    new_ports = list(diff.get("new_open_ports") or [])
    closed_ports = list(diff.get("closed_ports") or [])
    new_conns = [_port_label(c) for c in (diff.get("new_network_connections") or [])]
    protocols = sorted({(c.get("protocol") or "TCP") for c in (diff.get("new_network_connections") or [])
                        if isinstance(c, dict)} | {p.split(":", 1)[0] for p in new_ports if ":" in str(p)})

    enc_changes = list(diff.get("encrypted_or_locked_changes") or [])
    enc_files = [c for c in enc_changes if c.get("category") == "encrypted_files" and c.get("state") == "added"]
    enc_dirs = [c for c in enc_changes if c.get("category") == "encrypted_folders" and c.get("state") == "added"]
    locked = [c for c in enc_changes if c.get("category") == "locked_files" and c.get("state") == "added"]

    return {
        "has_snapshots": has_snapshots, "before": before, "after": after, "reg": reg,
        "startup_new": startup_new, "startup_removed": startup_removed,
        "new_files": new_files, "new_folders": new_folders,
        "exe_run": exe_run, "dropped_exes": dropped_exes,
        "new_ports": new_ports, "closed_ports": closed_ports, "new_conns": new_conns, "protocols": protocols,
        "enc_files": enc_files, "enc_dirs": enc_dirs, "locked": locked,
        "failures": list(diff.get("collection_failures") or []),
        "folders_tracked": "folders" in before, "enc_tracked": "encrypted_files" in before,
        "ports_tracked": "open_ports" in before,
    }


def _yes_no(flag: bool, tracked: bool = True) -> str:
    if not tracked:
        return _NA
    return "<b>YES</b>" if flag else "No"


def _lines(items, limit: int = 40) -> str:
    items = list(items)
    out = [_esc(i) for i in items[:limit]]
    if len(items) > limit:
        out.append(f"... and {len(items) - limit} more")
    return "<br/>".join(out) if out else "-"


def _state_table(rows: list[list]) -> Table:
    data = [[Paragraph(f"<b>{_esc(r[0])}</b>", _SMALL), Paragraph(r[1], _SMALL), Paragraph(r[2], _SMALL)]
            for r in rows]
    data.insert(0, [Paragraph("<b>Check</b>", _SMALL), Paragraph("<b>Before sandbox test</b>", _SMALL),
                    Paragraph("<b>After sandbox test</b>", _SMALL)])
    t = Table(data, colWidths=[3.6 * cm, 6.0 * cm, 7.4 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12335B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7FB")]),
    ]))
    return t


def _sandbox_state_story(run: dict, mode_label: str) -> list:
    s = _sandbox_state_summary(run)
    before, after, reg = s["before"], s["after"], s["reg"]
    story = [Paragraph(f"Before vs After Sandbox Test ({_esc(mode_label)})", _styles["Heading4"])]
    if not s["has_snapshots"]:
        story.append(Paragraph("BEFORE/AFTER snapshots were not captured for this run (the sandbox did not "
                               "complete). Nothing is inferred.", _QUARANTINE_NOTE))
        return story
    story.append(Paragraph(f"Before snapshot taken: {_esc(before.get('taken_at', '-'))} | "
                           f"After snapshot taken: {_esc(after.get('taken_at', '-'))}", _SMALL))
    story.append(Spacer(1, 4))

    reg_before = before.get("registry_run_keys") or {}
    reg_after = after.get("registry_run_keys") or {}
    reg_changed = bool(reg["added"] or reg["modified"] or reg["removed"])
    reg_detail = []
    reg_detail += [f"ADDED: {k} = {v}" for k, v in reg["added"]]
    reg_detail += [f"MODIFIED: {k}: '{o}' -> '{n}'" for k, o, n in reg["modified"]]
    reg_detail += [f"REMOVED: {k} (was '{v}')" for k, v in reg["removed"]]

    startup_changed = bool(s["startup_new"] or s["startup_removed"])
    startup_detail = [f"ADDED: {x}" for x in s["startup_new"]] + [f"REMOVED: {x}" for x in s["startup_removed"]]

    exe_changed = bool(s["exe_run"] or s["dropped_exes"])
    exe_detail = [f"RUN: {x}" for x in s["exe_run"]] + [f"DROPPED (not seen running): {x}" for x in s["dropped_exes"]
                                                         if not any(str(x).lower() in e.lower() for e in s["exe_run"])]

    port_changed = bool(s["new_ports"] or s["new_conns"])
    port_detail = [f"NEW LISTENING PORT: {p}" for p in s["new_ports"]] + \
                  [f"NEW CONNECTION: {c}" for c in s["new_conns"]]
    if s["protocols"]:
        port_detail.append("Protocols involved: " + ", ".join(s["protocols"]))

    enc_changed = bool(s["enc_files"] or s["enc_dirs"])
    enc_detail = [f"ENCRYPTED FILE: {c['path']}" for c in s["enc_files"]] + \
                 [f"ENCRYPTED FOLDER: {c['path']}" for c in s["enc_dirs"]]
    if s["locked"]:
        enc_detail += [f"LOCKED/IN USE: {c['path']}" for c in s["locked"][:20]]

    nb = lambda k: len(before.get(k) or [])
    na = lambda k: len(after.get(k) or [])
    rows = [
        ["Registry key modified?",
         f"{len(reg_before)} Run-key value(s) recorded<br/>" + _lines([f"{k} = {v}" for k, v in sorted(reg_before.items())], 15),
         f"{_yes_no(reg_changed)} - {len(reg_after)} value(s) now<br/>" + (_lines(reg_detail) if reg_changed else "No change")],
        ["Startup shell / folder modified?",
         f"{nb('startup_entries')} startup item(s)<br/>" + _lines(before.get("startup_entries") or [], 15),
         f"{_yes_no(startup_changed)} - {na('startup_entries')} item(s) now<br/>" + (_lines(startup_detail) if startup_changed else "No change")],
        ["New file created?",
         f"{nb('files')} file(s) in monitored locations",
         f"{_yes_no(bool(s['new_files']))} - {na('files')} file(s) now<br/>" + (_lines(s["new_files"]) if s["new_files"] else "No new files")],
        ["Folder created?",
         f"{nb('folders')} folder(s)" if s["folders_tracked"] else _NA,
         f"{_yes_no(bool(s['new_folders']), s['folders_tracked'])}" +
         (f" - {na('folders')} folder(s) now<br/>" + _lines(s["new_folders"]) if s["new_folders"] else "")],
        ["Executable run?",
         f"{nb('processes')} process(es) running",
         f"{_yes_no(exe_changed)} - {na('processes')} process(es) now<br/>" + (_lines(exe_detail) if exe_changed else "No new executable processes")],
        ["New ports / protocols opened?",
         f"{len(before.get('open_ports') or [])} listening port(s), {nb('network_connections')} connection(s)"
         if s["ports_tracked"] else f"{nb('network_connections')} connection(s)",
         f"{_yes_no(port_changed)}<br/>" + (_lines(port_detail) if port_changed else "No new ports or connections")
         + (f"<br/>Closed: {_lines(s['closed_ports'], 15)}" if s["closed_ports"] else "")],
        ["Data encrypted?",
         f"{len(before.get('encrypted_files') or [])} encrypted file(s), {len(before.get('encrypted_folders') or [])} folder(s)"
         if s["enc_tracked"] else _NA,
         f"{_yes_no(enc_changed, s['enc_tracked'])}" + ("<br/>" + _lines(enc_detail) if enc_detail else "")],
    ]
    story.append(_state_table(rows))
    if s["failures"]:
        story.append(Spacer(1, 3))
        story.append(Paragraph("Items that could not be collected (not inferred): " +
                               _esc("; ".join(s["failures"][:10])), _QUARANTINE_NOTE))
    story.append(Paragraph("Scope: registry = Run keys; startup = Startup folders; files/folders = Desktop, "
                           "Downloads, Temp, Startup, C:\\Sandbox, ProgramData (VM sandboxes). "
                           "'Encrypted' = Windows EFS attribute. Windows Sandbox mode compares the host staging "
                           "folder and process table only.", _SMALL))
    story.append(Spacer(1, 8))
    return story


def _overall_verdict(scan: dict, files: list[dict]) -> str:
    highest = scan.get("highest_risk", 0)
    if highest >= 80:
        level = "CRITICAL"
        text = ("One or more files on this device show a Critical risk profile with multiple "
                "strong indicators (disguised executables, dangerous API usage, or confirmed "
                "runtime persistence/network behavior). Do not open unquarantined files from "
                "this device on a production machine.")
    elif highest >= 60:
        level = "HIGH"
        text = ("This device contains files with High risk indicators. Review the flagged files "
                "and sandbox results below before using this device further.")
    elif highest >= 30:
        level = "MEDIUM"
        text = ("This device contains files with Medium risk indicators. No confirmed malicious "
                "behavior was observed, but the flagged items warrant a manual review.")
    else:
        level = "LOW"
        text = "No significant risk indicators were found across the files scanned on this device."
    return f"Overall Verdict: {level}\n\n{text}"


def generate_report(scan_id: str) -> str:
    """Build the full forensic PDF for a completed scan and return its file path."""
    scan = database.get_scan(scan_id)
    if not scan:
        raise ValueError(f"No scan found with id {scan_id}")

    files = database.list_files_for_scan(scan_id)
    quarantine_items = database.list_quarantine_for_scan(scan_id)
    qsum = _quarantine_summary(files, quarantine_items)
    sandbox_runs = database.list_sandbox_runs_for_scan(scan_id)

    report_path = config.REPORTS_DIR / f"{scan_id}_forensic_report.pdf"
    doc = SimpleDocTemplate(
        str(report_path), pagesize=A4,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
    )
    story = []

    # --- Title & USB info ---------------------------------------------------
    story.append(Paragraph("USB Threat Analyzer", _TITLE))
    story.append(Paragraph("Digital Forensic Report", _styles["Heading3"]))
    story.append(Spacer(1, 10))

    usb_table_data = [
        ["Scan ID", scan_id],
        ["USB Name / Label", scan.get("usb_name") or "Unknown"],
        ["Drive Letter", scan.get("drive_letter") or "-"],
        ["Capacity", f"{scan.get('capacity_bytes', 0) / (1024**3):.2f} GB"],
        ["File System", scan.get("file_system") or "-"],
        ["Scan Started", scan.get("started_at") or "-"],
        ["Scan Finished", scan.get("finished_at") or "-"],
        ["Files Scanned", str(scan.get("files_scanned", 0))],
        ["Suspicious Files", str(scan.get("suspicious_files", 0))],
        ["Highest Risk Score", str(scan.get("highest_risk", 0))],
        ["Auto-quarantine Rule", f"Risk score {qsum['threshold']} or higher"],
        ["Files Quarantined", f"{len(qsum['auto'])} automatically, {len(qsum['manual'])} manually"],
        ["Sandbox Used", scan.get("sandbox_used") or "None"],
    ]
    t = Table(usb_table_data, colWidths=[5 * cm, 10.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1FB")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # --- Overall verdict ------------------------------------------------------
    story.append(Paragraph("Overall Verdict", _H2))
    story.append(Paragraph(_overall_verdict(scan, files).replace("\n\n", "<br/><br/>"), _BODY))
    if qsum["auto"]:
        n = len(qsum["auto"])
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<b>Automatic quarantine:</b> {n} file{'s' if n != 1 else ''} scored {qsum['threshold']} or "
            f"higher and {'were' if n != 1 else 'was'} automatically moved to quarantine "
            f"(listed under Quarantine Actions below).", _QUARANTINE_NOTE))
    if qsum["not_quarantined"]:
        n = len(qsum["not_quarantined"])
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<b>Action required:</b> {n} file{'s' if n != 1 else ''} scored {qsum['threshold']} or higher "
            f"but could not be quarantined automatically (see Quarantine Actions below).", _QUARANTINE_NOTE))

    # --- All files & risk scores -----------------------------------------
    story.append(Paragraph("Scanned Files & Risk Scores", _H2))
    file_rows = [["File", "Ext", "Level", "Size", "Risk", "Reasons"]]
    for f in files:
        reasons = _esc("; ".join(f.get("reasons", [])[:4]) or "None")
        marker = _quarantine_marker(qsum["by_path"].get(_path_key(f.get("absolute_path"))), qsum["threshold"])
        if marker:
            reasons = f"{marker}<br/>{reasons}"
        file_rows.append([
            Paragraph(_esc(f.get("file_name", "")), _SMALL),
            f.get("extension", ""),
            str(f.get("level", "")),
            f"{(f.get('size_bytes') or 0) / 1024:.1f} KB",
            f"{f.get('risk_score', 0)} ({f.get('risk_level', '')})",
            Paragraph(reasons, _SMALL),
        ])
    if len(file_rows) == 1:
        file_rows.append(["No files recorded", "", "", "", "", ""])
    ft = Table(file_rows, colWidths=[3.3 * cm, 1.3 * cm, 1.3 * cm, 1.8 * cm, 2.3 * cm, 5.5 * cm], repeatRows=1)
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12335B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7FB")]),
    ]))
    story.append(ft)

    # --- Sandbox results ---------------------------------------------------
    if sandbox_runs:
        story.append(PageBreak())
        story.append(Paragraph("Sandbox Runtime Analysis", _H2))
        for run in sandbox_runs:
            story.append(Paragraph(f"Sandbox: {run['sandbox_type']} | Sample SHA-256: {run['file_sha256']}", _styles["Heading4"]))
            diff = run.get("diff", {})
            summary = diff.get("summary", {})
            story.append(Paragraph(
                f"Registry +{summary.get('registry', 0)} | Files +{summary.get('files', 0)} | "
                f"Folders +{summary.get('new_folders', 0)} | Processes +{summary.get('new_processes', 0)} | "
                f"Network {summary.get('network', 0)} connections | Startup +{summary.get('startup', 0)} | "
                f"Services +{summary.get('services', 0)} | Scheduled Tasks +{summary.get('scheduled_tasks', 0)} | "
                f"Ports opened +{summary.get('ports_opened', 0)} / closed {summary.get('ports_closed', 0)} | "
                f"Encrypted or locked file changes {summary.get('encrypted_or_locked', 0)}",
                _BODY,
            ))
            _mode = "Manual" if (scan.get("usb_name") or "") == "Manual sandbox analysis" else "Automatic"
            story.extend(_sandbox_state_story(run, f"{_mode} sandbox - {run.get('sandbox_type', '')}"))
            failures = diff.get('collection_failures', [])
            if failures:
                story.append(Paragraph("Collection failures / unavailable data:", _QUARANTINE_NOTE))
                story.append(Paragraph("<br/>".join(_esc(item) for item in failures[:30]), _SMALL))
            story.append(Paragraph(f"Verdict Notes: {run.get('verdict_notes', '')}", _BODY))
            diff_sections = (
                ("New Files", "new_files"), ("Deleted Files", "deleted_files"),
                ("New Folders", "new_folders"), ("Deleted Folders", "deleted_folders"),
                ("Registry Changes", "registry_changes"),
                ("New Startup Entries", "startup_persistence_new"),
                ("New Services", "new_services"), ("New Scheduled Tasks", "new_scheduled_tasks"),
                ("New Processes", "new_processes"),
                ("Network Activity", "new_network_connections"),
                ("Listening Ports Opened", "new_open_ports"), ("Listening Ports Closed", "closed_ports"),
                ("Encrypted or Locked File Changes", "encrypted_or_locked_changes"),
            )
            for heading, key in diff_sections:
                entries = diff.get(key, [])
                if entries:
                    story.append(Paragraph(f"{_esc(heading)}:", _styles["Heading4"]))
                    story.append(Paragraph("<br/>".join(_esc(entry) for entry in entries[:40]), _SMALL))
            story.append(Spacer(1, 10))

    # --- Quarantine actions ----------------------------------------------------
    story.append(Paragraph("Quarantine Actions", _H2))
    n_auto, n_manual = len(qsum["auto"]), len(qsum["manual"])
    story.append(Paragraph(
        f"Policy: any file with a risk score of <b>{qsum['threshold']} or higher is quarantined "
        f"automatically</b>; files can also be quarantined manually from the Quarantine page. "
        f"Quarantined files are moved, never deleted, and can be restored only after the Windows "
        f"account is verified. In this scan: <b>{n_auto}</b> automatically quarantined, "
        f"<b>{n_manual}</b> manually quarantined.", _BODY))
    story.append(Spacer(1, 6))

    q_rows = [["Original Path", "SHA-256", "Risk", "Quarantined", "Status"]]
    for q in quarantine_items:
        how = "Manual" if q.get("source") == "manual" else f"Automatic ({qsum['threshold']}+)"
        q_rows.append([
            Paragraph(_esc(q["original_path"]), _SMALL), (q.get("sha256") or "")[:16] + "...",
            str(q["risk_score"]), how, q["status"],
        ])
    if len(q_rows) == 1:
        q_rows.append(["No files quarantined", "", "", "", ""])
    qt = Table(q_rows, colWidths=[6.2 * cm, 3.4 * cm, 1.4 * cm, 3.4 * cm, 2.2 * cm], repeatRows=1)
    qt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12335B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(qt)

    if qsum["not_quarantined"]:
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"Files scoring {qsum['threshold']}+ that were NOT quarantined (handle these manually):", _QUARANTINE_NOTE))
        nq_rows = [["File", "Risk", "Why it was not quarantined"]]
        for f in qsum["not_quarantined"]:
            why = next((r for r in f.get("reasons", []) if "quarantine" in r.lower()),
                       "The file could not be moved (see the application log).")
            nq_rows.append([Paragraph(_esc(f.get("absolute_path") or f.get("file_name")), _SMALL),
                            str(f.get("risk_score", 0)), Paragraph(_esc(why), _SMALL)])
        nt = Table(nq_rows, colWidths=[6.8 * cm, 1.4 * cm, 8.4 * cm], repeatRows=1)
        nt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#9B1C31")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(nt)

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        f"Report generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by USB Threat Analyzer.",
        _styles["Italic"],
    ))

    doc.build(story)
    logger.info("Forensic PDF report generated: %s", report_path)
    return str(report_path)
