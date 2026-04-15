# AutoLockdown v4.9.1 Patch Checklist

This file documents every code and documentation change applied in the v4.9.1 patch, provides exact search patterns to validate each change, defines acceptance criteria, and gives rollback guidance.

---

## 1. Version Bump: 4.8.0 → 4.9.0

### Search Patterns (run from repo root)

```powershell
# PowerShell / Select-String
Select-String -Path *.ps1, *.md -Pattern "4\.8\.0"

# Bash / grep
grep -rn "4\.8\.0" .
```

### Expected Findings After Patch

The pattern `4\.8\.0` must return **only** changelog references in the primary files.  
The version `4.9.0` must appear in all of the following locations:

| File | Location | Expected Value |
|------|----------|----------------|
| `AutoLockdown.ps1` | `.SYNOPSIS` line 3 | `AutoLockdown v4.9.0` |
| `AutoLockdown.ps1` | `.NOTES` `Version` field | `4.9.0` |
| `AutoLockdown.ps1` | `$ScriptVersion` variable | `"4.9.0"` |
| `Reset_Lockdown.ps1` | `.SYNOPSIS` line 3 | `Reset_Lockdown.ps1 v4.9.0` |
| `Reset_Lockdown.ps1` | `.NOTES` `Version` field | `4.9.0` |
| `Reset_Lockdown.ps1` | `$ScriptVersion` variable | `"4.9.0"` |
| `Verify_Lockdown.ps1` | `.SYNOPSIS` line 3 | `Verify_Lockdown.ps1 v4.9.0` |
| `Verify_Lockdown.ps1` | `.NOTES` `Version` field | `4.9.0` |
| `Verify_Lockdown.ps1` | `$ScriptVersion` variable | `"4.9.0"` |
| `INSTRUCTIONS.md` | Heading `**Version X.Y.Z**` | `4.9.0` |
| `INSTRUCTIONS.md` | Footer line | `AutoLockdown v4.9.0` |
| `AutoLockdown_Context.md` | `**Version Reference:**` | `v4.9.0` |

### Validation Commands

```powershell
# Confirm all scripts self-report 4.9.0
$scripts = @("AutoLockdown.ps1", "Reset_Lockdown.ps1", "Verify_Lockdown.ps1")
foreach ($s in $scripts) {
    $ver = (Select-String -Path $s -Pattern '\$ScriptVersion\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
    Write-Host "$s  =>  $ver" -ForegroundColor $(if ($ver -eq "4.9.0") {"Green"} else {"Red"})
}
# Expected output: all three lines show "4.9.0" in green
```

---

## 2. Default Learning Window Changed (180 → 5 minutes)

### Search Pattern

```powershell
Select-String -Path AutoLockdown.ps1 -Pattern "LearningWindowMinutes\s*=\s*\d+"
```

### Expected Result

The `$LearningWindowMinutes` default value must be `5` (not `180`).

---

## 3. Finish Early Button Bug Fix

### Problem Statement

When the learning timer countdown was in progress and the user clicked "Finish Early",
the timer form closed but the learning state JSON file was NOT updated. The system
continued in "Learning" mode with the original expiry time, allowing USB devices that
should have been blocked. Users believed the system was protected, but learning mode
was still active.

### Search Pattern

```powershell
Select-String -Path AutoLockdown.ps1 -Pattern "learningResult|Finish Early|transitioning to ENFORCED"
```

### Expected Code After Patch

After `Show-TimerForm` returns, the code must:
1. Capture the return value (timer completed = `$true`, Finish Early = `$false`)
2. Call `Set-LearningState -Mode "Enforced"` to immediately transition
3. Log the transition with an appropriate message

---

## 4. Bug Fixes

### 4.1 PSCustomObject Threat Lookup (AutoLockdown.ps1)

The `Protect-USBDevice` function previously accessed `$script:ThreatMap.PSObject.Properties[$vidpid].Value`
directly, which throws a null-reference if the key does not exist. Fixed to use `.Match()` with
a count guard, consistent with the WMI handler.

### 4.2 Raw ConvertFrom-Json in Verify_Lockdown.ps1

`Test-ThreatDatabase` and `Test-ContainerAllowCache` previously used raw
`Get-Content | ConvertFrom-Json` instead of `Import-JsonSafe`. Fixed to use
`Import-JsonSafe` for consistent fallback-to-backup behavior.

### 4.3 Unsafe Mutex Release in Update-LearningMode (AutoLockdown.ps1)

The `finally` block at the end of `Update-LearningMode` called `$mutex.ReleaseMutex()`
directly without try/catch protection. If `WaitOne` timed out (returned `$false`), calling
`ReleaseMutex()` on an unowned mutex throws `System.ApplicationException`, which propagated
unhandled to the callers (Start-RealtimeMonitoring, Protect-USBDevice), potentially crashing
the monitor service. Fixed to use the same safe `try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() }`
pattern used by all other mutex sites in the codebase.

#### Search Pattern

```powershell
Select-String -Path AutoLockdown.ps1 -Pattern "finally \{ try \{ \`$mutex\.ReleaseMutex\(\)" | Measure-Object
# Expected: Count = 9 (all mutex sites now use safe pattern; zero use the unsafe bare pattern)
```

### 4.4 WMI Handler Whitelist Write Uses Wrong Encoding (AutoLockdown.ps1)

The WMI event handler's learning-mode whitelist write used `Out-File ... -Force` without
`-Encoding UTF8`. In PowerShell 5.1, `Out-File` defaults to UTF-16LE. After the WMI handler
learned a device, the whitelist file was written in UTF-16LE, but all readers (fast-path
watcher `Get-WhitelistFast`, `Import-JsonSafe`, subsequent WMI reads) specify `-Encoding UTF8`.
Reading UTF-16LE as UTF-8 produces garbled data, causing `ConvertFrom-Json` to throw,
returning an empty whitelist. Result: every whitelisted device would be blocked after the
WMI handler learned even one device. Fixed by adding `-Encoding UTF8`.

#### Search Pattern

```powershell
Select-String -Path AutoLockdown.ps1 -Pattern "Out-File \`$data\.USBWhitelistPath" 
# Expected: line must contain "-Encoding UTF8"
```

---

## 5. Acceptance Test Matrix

### 5.1 Version Acceptance

| Check | Command | Expected Output |
|-------|---------|-----------------|
| AutoLockdown version | `Select-String AutoLockdown.ps1 '\$ScriptVersion'` | `4.9.0` |
| Reset version | `Select-String Reset_Lockdown.ps1 '\$ScriptVersion'` | `4.9.0` |
| Verify version | `Select-String Verify_Lockdown.ps1 '\$ScriptVersion'` | `4.9.0` |
| Default learning window | `Select-String AutoLockdown.ps1 'LearningWindowMinutes\s*=\s*\d+'` | `5` |

### 5.2 Finish Early Test

| Scenario | Expected Result | How to Verify |
|----------|-----------------|---------------|
| Timer expires naturally | Learning state set to "Enforced" | Check Learning_State.json |
| User clicks Finish Early | Learning state set to "Enforced" immediately | Check Learning_State.json |
| User extends (+5 min) then timer expires | Learning state set to "Enforced" | Check Learning_State.json |

---

## 6. Rollback Notes

### Version Rollback (4.9.0 → 4.8.0)

```powershell
# In each file, replace version string
(Get-Content AutoLockdown.ps1)  -replace "4\.9\.0", "4.8.0" | Set-Content AutoLockdown.ps1
(Get-Content Reset_Lockdown.ps1) -replace "4\.9\.0", "4.8.0" | Set-Content Reset_Lockdown.ps1
(Get-Content Verify_Lockdown.ps1) -replace "4\.9\.0", "4.8.0" | Set-Content Verify_Lockdown.ps1
(Get-Content INSTRUCTIONS.md)   -replace "4\.9\.0", "4.8.0" | Set-Content INSTRUCTIONS.md
```

---

## 7. Git Reference

```bash
# Show files changed in this patch
git diff --name-only v4.8.0..HEAD

# Show full diff
git diff v4.8.0..HEAD

# Revert this patch commit
git revert HEAD
```
