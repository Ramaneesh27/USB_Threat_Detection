"""Guest-side Windows state collection and BEFORE/AFTER comparison.

The collector is executed inside an isolated Windows VM through the hypervisor's
Guest Tools. It never executes the suspicious sample on the host.
"""
from __future__ import annotations

import json

GUEST_STAGING_PATH = r"C:\Sandbox"
GUEST_SNAPSHOT_SCRIPT = r'''param([string]$OutputPath)
$ErrorActionPreference = 'Stop'
$errors = @()
$roots = @(
  "$env:USERPROFILE\Desktop",
  "$env:USERPROFILE\Downloads",
  "$env:TEMP",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "C:\Sandbox",
  "$env:WINDIR\Temp",
  "$env:PROGRAMDATA"
)
$files=@(); $folders=@(); $encrypted=@(); $encryptedFolders=@(); $locked=@()
$registry=@{}; $connections=@(); $startup=@(); $processes=@(); $services=@(); $tasks=@()

try {
  foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    $folders += $root
    $directories = @(Get-ChildItem -LiteralPath $root -Directory -Force -Recurse -ErrorAction Stop | Select-Object -First 1000)
    $folders += @($directories | ForEach-Object { $_.FullName })
    foreach ($directory in $directories) {
      if (($directory.Attributes -band [IO.FileAttributes]::Encrypted) -ne 0) { $encryptedFolders += $directory.FullName }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction Stop | Select-Object -First 5000)) {
      $files += $file.FullName
      if (($file.Attributes -band [IO.FileAttributes]::Encrypted) -ne 0) { $encrypted += $file.FullName }
      try {
        $stream=[IO.File]::Open($file.FullName,'Open','Read','None'); $stream.Dispose()
      } catch { $locked += $file.FullName }
    }
  }
} catch { $errors += "files_folders: $($_.Exception.Message)" }

try {
  foreach ($keyPath in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
    if (Test-Path $keyPath) {
      $item=Get-ItemProperty $keyPath -ErrorAction Stop
      foreach ($property in $item.PSObject.Properties) {
        if ($property.Name -notmatch '^PS') { $registry["$keyPath\$($property.Name)"]=[string]$property.Value }
      }
    }
  }
} catch { $errors += "registry: $($_.Exception.Message)" }

try {
  foreach ($root in @($roots[3],$roots[4])) {
    if (Test-Path -LiteralPath $root) { $startup += @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction Stop | Select-Object -ExpandProperty FullName) }
  }
} catch { $errors += "startup: $($_.Exception.Message)" }

try { $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,Name,ExecutablePath,ParentProcessId) }
catch { $errors += "processes: $($_.Exception.Message)" }
try { $services=@(Get-Service -ErrorAction Stop | ForEach-Object { "$($_.Name):$($_.Status)" }) }
catch { $errors += "services: $($_.Exception.Message)" }
try { $tasks=@(Get-ScheduledTask -ErrorAction Stop | ForEach-Object { $_.TaskPath + $_.TaskName }) }
catch { $errors += "scheduled_tasks: $($_.Exception.Message)" }
try {
  foreach ($connection in @(Get-NetTCPConnection -ErrorAction Stop)) {
    $connections += @{protocol='TCP';local="$($connection.LocalAddress):$($connection.LocalPort)";remote="$($connection.RemoteAddress):$($connection.RemotePort)";status=[string]$connection.State}
  }
  foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
    $connections += @{protocol='UDP';local="$($endpoint.LocalAddress):$($endpoint.LocalPort)";remote='';status='BOUND'}
  }
} catch { $errors += "network_ports: $($_.Exception.Message)" }

$snapshot=@{
  taken_at=[DateTime]::UtcNow.ToString('o')
  files=@($files | Where-Object { $_ -notmatch 'guest_snapshot' } | Sort-Object -Unique)
  folders=@($folders | Sort-Object -Unique)
  encrypted_files=@($encrypted | Sort-Object -Unique)
  encrypted_folders=@($encryptedFolders | Sort-Object -Unique)
  locked_files=@($locked | Sort-Object -Unique)
  registry_run_keys=$registry
  startup_entries=@($startup | Sort-Object -Unique)
  processes=@($processes)
  services=@($services | Sort-Object -Unique)
  scheduled_tasks=@($tasks | Sort-Object -Unique)
  network_connections=@($connections)
  open_ports=@($connections | Where-Object { $_.status -eq 'Listen' -or $_.protocol -eq 'UDP' } | ForEach-Object { "$($_.protocol):$($_.local)" } | Sort-Object -Unique)
  collection_errors=@($errors)
}
$snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
'''


def diff_guest_snapshots(before: dict, after: dict) -> dict:
    def keyed(values: list) -> dict:
        return {json.dumps(value, sort_keys=True, default=str): value for value in (values or [])}

    def added(key: str) -> list:
        b, a = keyed(before.get(key, [])), keyed(after.get(key, []))
        return [a[item] for item in sorted(a.keys() - b.keys())]

    def removed(key: str) -> list:
        b, a = keyed(before.get(key, [])), keyed(after.get(key, []))
        return [b[item] for item in sorted(b.keys() - a.keys())]

    before_registry = before.get("registry_run_keys", {}) or {}
    after_registry = after.get("registry_run_keys", {}) or {}
    registry_changes = [f"{key}={value}" for key, value in after_registry.items()
                        if before_registry.get(key) != value]
    registry_changes.extend(f"{key} removed" for key in before_registry.keys() - after_registry.keys())

    changed_state = []
    for key in ("encrypted_files", "encrypted_folders", "locked_files"):
        changed_state.extend({"category": key, "path": path, "state": "added"} for path in added(key))
        changed_state.extend({"category": key, "path": path, "state": "cleared"} for path in removed(key))

    errors = sorted(set((before.get("collection_errors") or []) + (after.get("collection_errors") or [])))
    failed_categories = {item.split(":", 1)[0] for item in errors if ":" in item}
    def unavailable(*names: str) -> bool:
        return any(name in failed_categories for name in names)

    diff = {
        "new_files": [] if unavailable("files_folders") else added("files"),
        "deleted_files": [] if unavailable("files_folders") else removed("files"),
        "new_folders": [] if unavailable("files_folders") else added("folders"),
        "deleted_folders": [] if unavailable("files_folders") else removed("folders"),
        "new_processes": [] if unavailable("processes") else added("processes"),
        "registry_changes": [] if unavailable("registry") else registry_changes,
        "startup_persistence_new": [] if unavailable("startup") else added("startup_entries"),
        "new_services": [] if unavailable("services") else added("services"),
        "new_scheduled_tasks": [] if unavailable("scheduled_tasks") else added("scheduled_tasks"),
        "new_network_connections": [] if unavailable("network_ports") else added("network_connections"),
        "new_open_ports": [] if unavailable("network_ports") else added("open_ports"),
        "closed_ports": [] if unavailable("network_ports") else removed("open_ports"),
        "encrypted_or_locked_changes": [] if unavailable("files_folders") else changed_state,
        "collection_failures": errors,
    }
    diff["summary"] = {
        "files": len(diff["new_files"]) + len(diff["deleted_files"]),
        "new_folders": len(diff["new_folders"]) + len(diff["deleted_folders"]),
        "registry": len(registry_changes), "network": len(diff["new_network_connections"]),
        "startup": len(diff["startup_persistence_new"]), "services": len(diff["new_services"]),
        "scheduled_tasks": len(diff["new_scheduled_tasks"]), "new_processes": len(diff["new_processes"]),
        "ports_opened": len(diff["new_open_ports"]), "ports_closed": len(diff["closed_ports"]),
        "encrypted_or_locked": len(changed_state), "collection_failures": len(errors),
    }
    return diff
