# AutoLockdown v4.9.2 Patch Checklist

This file documents code and documentation updates applied in v4.9.2 and defines concise, command-based validation patterns for field verification.

---

## 1. Version Bump: 4.9.1 -> 4.9.2

### Search Patterns

```powershell
Select-String -Path *.ps1, *.md -Pattern "4\.9\.1"
Select-String -Path *.ps1, *.md -Pattern "4\.9\.2"
```

### Expected Results

- `4.9.2` appears in:
  - `AutoLockdown.ps1` (`.SYNOPSIS`, `.NOTES Version`, `$ScriptVersion`)
  - `Verify_Lockdown.ps1` (`.SYNOPSIS`, `.NOTES Version`, `$ScriptVersion`)
  - `Reset_Lockdown.ps1` (`.SYNOPSIS`, `.NOTES Version`, `$ScriptVersion`)
  - `INSTRUCTIONS.md` version heading/footer
  - `AutoLockdown_Context.md` version reference
- `4.9.1` remains only in historical changelog entries and prior-version references.

---

## 1.1 WMI Status Checks, JSON Try/Catch blocks, and Ext Bak Staging

### Problem
- WMI Deduplication only checked for `Error` state instead of `Error` or `Degraded`.
- Missing catch blocks around `ConvertFrom-Json` inside WMI Action handlers led to crashing hidden background WMI instances.
- USB Whitelist blind exports to `.json` without prior staging to a `.bak1` fallback file inside WMI.

### Expected Behavior
- WMI blocks if `$fullDev.Status -eq "Error" -or $fullDev.Status -eq "Degraded"`
- `Try...Catch` implementations wrapped around `ConvertFrom-Json` execution safely
- Standard `Copy-Item ... .bak1` logic executes successfully against `$data.USBWhitelistPath`

---

## 2. Verify Fix: WMI False Warning Removal

### Problem

`Verify_Lockdown.ps1` previously used only `Get-EventSubscriber` / `Get-Job` in the verifier session. Since monitor WMI subscriptions are process-local, this produced false warnings (`WMI Event Handler - Not registered`) even when monitor WMI handling was active.

### Search Patterns

```powershell
Select-String -Path Verify_Lockdown.ps1 -Pattern "process-local|LockFile|Recent WMI evidence|No recent WMI lines yet"
```

### Expected Behavior

- WMI check validates monitor-backed behavior using lockfile/process/log evidence.
- If monitor process is active, WMI check should PASS (not WARN) even without same-session event subscribers.
- If Security.log has WMI evidence (`[WMI]` or `WMI event subscription registered`), detail should report that evidence count.

---

## 3. Reset Fix: Multi-Pass USB Restore

### Problem

Field report indicated reset sometimes needed to run multiple times before blocked USB devices were fully re-enabled.

### Search Patterns

```powershell
Select-String -Path Reset_Lockdown.ps1 -Pattern "maxPasses|statusesToRestore|multi-pass|Start-Sleep -Milliseconds 1000"
```

### Expected Behavior

- `Restore-USBDevices` runs multiple recovery passes (up to 5) in a single reset.
- USB devices in `Error`/`Degraded`/`Unknown` state are retried.
- Step output reports either:
  - full multi-pass recovery complete, or
  - partial recovery warning with remaining device count.

---

## 4. Acceptance Matrix

| Check | Command | Expected |
|------|---------|----------|
| AutoLockdown version | `Select-String AutoLockdown.ps1 '\$ScriptVersion'` | `4.9.2` |
| Verify version | `Select-String Verify_Lockdown.ps1 '\$ScriptVersion'` | `4.9.2` |
| Reset version | `Select-String Reset_Lockdown.ps1 '\$ScriptVersion'` | `4.9.2` |
| Verify WMI logic | `Select-String Verify_Lockdown.ps1 'process-local|Recent WMI evidence'` | New monitor-backed logic present |
| Reset multi-pass logic | `Select-String Reset_Lockdown.ps1 'maxPasses|statusesToRestore'` | Multi-pass USB restore present |
| WMI JSON Try Catch | `Select-String AutoLockdown.ps1 'try .* ConvertFrom-Json'` | Wrapped correctly |
| WMI Deduplication | `Select-String AutoLockdown.ps1 'Degraded'` | Degraded verification integrated |

---

## 5. Rollback Notes

### Version Rollback (4.9.2 -> 4.9.1)

```powershell
(Get-Content AutoLockdown.ps1) |
    ForEach-Object { $_ -replace '(\$ScriptVersion\s*=\s*")4\.9\.2(")', '${1}4.9.1${2}' } |
    Set-Content AutoLockdown.ps1

(Get-Content Verify_Lockdown.ps1) |
    ForEach-Object { $_ -replace '(\$ScriptVersion\s*=\s*")4\.9\.2(")', '${1}4.9.1${2}' } |
    Set-Content Verify_Lockdown.ps1

(Get-Content Reset_Lockdown.ps1) |
    ForEach-Object { $_ -replace '(\$ScriptVersion\s*=\s*")4\.9\.2(")', '${1}4.9.1${2}' } |
    Set-Content Reset_Lockdown.ps1

(Get-Content INSTRUCTIONS.md) |
    ForEach-Object { $_ -replace '\*\*Version 4\.9\.2\*\*', '**Version 4.9.1**' -replace 'AutoLockdown v4\.9\.2', 'AutoLockdown v4.9.1' } |
    Set-Content INSTRUCTIONS.md

(Get-Content AutoLockdown_Context.md) |
    ForEach-Object { $_ -replace '\*\*Version Reference:\*\* v4\.9\.2', '**Version Reference:** v4.9.1' } |
    Set-Content AutoLockdown_Context.md
```
