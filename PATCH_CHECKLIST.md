# AutoLockdown v4.8.0 Patch Checklist

This file documents every code and documentation change applied in the v4.8.0 patch, provides exact search patterns to validate each change, defines acceptance criteria, and gives rollback guidance.

---

## 1. Version Bump: 4.7.1 → 4.8.0

### Search Patterns (run from repo root)

```powershell
# PowerShell / Select-String
Select-String -Path *.ps1, *.md -Pattern "4\.7\.1"

# Bash / grep
grep -rn "4\.7\.1" .
```

### Expected Findings After Patch

The pattern `4\.7\.1` must return **zero** matches in the primary version fields.  
The version `4.8.0` must appear in all of the following locations:

| File | Location | Expected Value |
|------|----------|----------------|
| `AutoLockdown.ps1` | `.SYNOPSIS` line 3 | `AutoLockdown v4.8.0` |
| `AutoLockdown.ps1` | `.NOTES` `Version` field | `4.8.0` |
| `AutoLockdown.ps1` | `$ScriptVersion` variable | `"4.8.0"` |
| `Reset_Lockdown.ps1` | `.SYNOPSIS` line 3 | `Reset_Lockdown.ps1 v4.8.0` |
| `Reset_Lockdown.ps1` | `.NOTES` `Version` field | `4.8.0` |
| `Reset_Lockdown.ps1` | `$ScriptVersion` variable | `"4.8.0"` |
| `Verify_Lockdown.ps1` | `.SYNOPSIS` line 3 | `Verify_Lockdown.ps1 v4.8.0` |
| `Verify_Lockdown.ps1` | `.NOTES` `Version` field | `4.8.0` |
| `Verify_Lockdown.ps1` | `$ScriptVersion` variable | `"4.8.0"` |
| `INSTRUCTIONS.md` | Heading `**Version X.Y.Z**` | `4.8.0` |
| `INSTRUCTIONS.md` | Footer line | `AutoLockdown v4.8.0` |
| `AutoLockdown_Context.md` | `**Version Reference:**` | `v4.8.0` |

### Validation Commands

```powershell
# Confirm all scripts self-report 4.8.0
$scripts = @("AutoLockdown.ps1", "Reset_Lockdown.ps1", "Verify_Lockdown.ps1")
foreach ($s in $scripts) {
    $ver = (Select-String -Path $s -Pattern '\$ScriptVersion\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
    Write-Host "$s  =>  $ver" -ForegroundColor $(if ($ver -eq "4.8.0") {"Green"} else {"Red"})
}
# Expected output: all three lines show "4.8.0" in green
```

---

## 2. Container-Based Allow for JAC 5G Dongle (VID_322B)

### Problem Statement

The JAC 5G dongle (`VID_322B&PID_1914`) initially enumerates as a USB Mass Storage / CD-ROM device.  Once the OS (or a mode-switch driver) sends the switch command, the dongle re-enumerates with a **different VID/PID** representing its modem, RNDIS, or CDC composite interfaces.  Those mode-switched devnodes previously fell through to the block path because they did not carry `VID_322B`, causing the modem/network interfaces to be disabled before their drivers could bind.

### Solution

Windows assigns every devnode that belongs to the same physical USB device a shared **ContainerId** GUID (`DEVPKEY_Device_ContainerId`).  When the initial `VID_322B` devnode is seen and allowed as infrastructure, its ContainerId is recorded in a persistent allow-cache (`ContainerAllowCache.json`).  Subsequent devnodes (modem-mode interfaces) are checked against this cache; if their ContainerId matches a live (non-expired) cache entry they are allowed without needing to know their VID/PID.

### Search Patterns

```powershell
# Confirm container allow cache path constant
Select-String -Path AutoLockdown.ps1 -Pattern "ContainerAllowCacheFile"

# Confirm TTL constant
Select-String -Path AutoLockdown.ps1 -Pattern "CONTAINER_ALLOW_TTL_HOURS"

# Confirm fast-path seeding
Select-String -Path AutoLockdown.ps1 -Pattern "Add-ContainerToCache"

# Confirm fast-path allow check
Select-String -Path AutoLockdown.ps1 -Pattern "ContainerAllow"

# Confirm WMI handler seeding + check
Select-String -Path AutoLockdown.ps1 -Pattern "ContainerAllowCachePath"

# Confirm Reset cleanup
Select-String -Path Reset_Lockdown.ps1 -Pattern "ContainerAllowCache"
```

All commands must return at least one match.

### Expected Code Blocks After Patch

#### `AutoLockdown.ps1` — Constants block
- `$ContainerAllowCacheFile = Join-Path $BasePath "ContainerAllowCache.json"`
- `$CONTAINER_ALLOW_TTL_HOURS = 24`

#### Fast-Path Watcher Runspace
- `Test-ValidContainerGuid` helper validating GUID format.
- `Load-ContainerCacheFast` / `Save-ContainerCacheFast` helpers for disk I/O.
- `Add-ContainerToCache` seeding function (logs `ContainerAllow: seeded ...`).
- After `$isInfra` block: if `$instanceId -imatch '^USB\\VID_322B'`, read `ContainerID` from registry and call `Add-ContainerToCache`.
- Before HID checks: read device `ContainerID`, check against `$containerCache` in-memory; reload from disk if not found; allow with log `ALLOWED ... ContainerAllow`.

#### WMI Handler (`Register-WmiEvent -Action`)
- After always-allowed infrastructure check returns: if `$deviceId -imatch '^USB\\VID_322B'`, call `Get-PnpDeviceProperty DEVPKEY_Device_ContainerId`, update `ContainerAllowCache.json`.
- Before final `BLOCKED ... Not whitelisted`: read ContainerId via `Get-PnpDeviceProperty`, check `ContainerAllowCache.json`; if match with non-expired entry log `ALLOWED ... ContainerAllow` and skip block.

#### `Protect-USBDevice`
- After `Test-AlwaysAllowedUSB` returns true: if `$Device.InstanceId -imatch '^USB\\VID_322B'`, read ContainerId via `Get-PnpDeviceProperty` and update cache file.
- Before `Deny-Device`: read ContainerId and check cache file; if match, log `ALLOWED ... ContainerAllow` and increment `$script:Metrics.TotalAllowed`.

#### `Reset_Lockdown.ps1` — Files-to-remove list
- `"ContainerAllowCache.json"` added to `$filesToRemove`.

### Validation Commands

```powershell
# Confirm constants present
Select-String -Path AutoLockdown.ps1 -Pattern 'ContainerAllowCacheFile|CONTAINER_ALLOW_TTL_HOURS'

# Confirm cache helpers present
Select-String -Path AutoLockdown.ps1 -Pattern 'Load-ContainerCacheFast|Save-ContainerCacheFast|Add-ContainerToCache|Test-ValidContainerGuid'

# Confirm ContainerAllow log message pattern present in all three paths
Select-String -Path AutoLockdown.ps1 -Pattern 'ContainerAllow'

# Confirm cleanup in reset
Select-String -Path Reset_Lockdown.ps1 -Pattern 'ContainerAllowCache'
```

---

## 3. Acceptance Test Matrix

### 3.1 Version Acceptance

| Check | Command | Expected Output |
|-------|---------|-----------------|
| AutoLockdown version | `Select-String AutoLockdown.ps1 '\$ScriptVersion'` | `4.8.0` |
| Reset version | `Select-String Reset_Lockdown.ps1 '\$ScriptVersion'` | `4.8.0` |
| Verify version | `Select-String Verify_Lockdown.ps1 '\$ScriptVersion'` | `4.8.0` |

### 3.2 Container-Allow Behavior Test Matrix

| Scenario | Device | Expected Result | How to Verify |
|----------|--------|-----------------|---------------|
| Initial plug-in | JAC dongle `VID_322B&PID_1914` (mass storage mode) | **ALLOWED — Infrastructure** in log; `ContainerAllowCache.json` created/updated | Plug in, check log + file |
| Mode-switch | Modem/RNDIS interface of same dongle (different VID/PID, same ContainerId) | **ALLOWED — ContainerAllow** in log | Plug in, wait 10 s, check log |
| Mode-switch | `USB Composite Device` of same dongle | **ALLOWED — ContainerAllow** in log | Plug in, check log |
| Unrelated device | Flash drive (different ContainerId) | **BLOCKED — Not whitelisted** in log | Plug in, check log |
| Unrelated device | Unknown USB device (non-VID_322B) | **BLOCKED** — not affected by container cache | Plug in, check log |
| Cache expiry | Any mode-switched interface after 24 h of no VID_322B activity | Falls through to block path | Simulate by editing cache expiry to a past timestamp |

### 3.3 Log Verification Commands

```powershell
# View last 30 lines of security log
Get-Content C:\ProgramData\AutoLockdown\Security.log -Tail 30

# Filter for container-allow events
Get-Content C:\ProgramData\AutoLockdown\Security.log | Where-Object { $_ -match "ContainerAllow" }

# View container allow cache
Get-Content C:\ProgramData\AutoLockdown\ContainerAllowCache.json | ConvertFrom-Json | Select-Object -ExpandProperty Containers
```

---

## 4. HID Behavior Test Matrix (unchanged from v4.7.0)

| Scenario | Device | Expected Result |
|----------|--------|-----------------|
| Any port | Standard keyboard (trusted VID) | **ALLOWED** — `Trusted HID` |
| Any port | Standard mouse (trusted VID) | **ALLOWED** — `Trusted HID` |
| Any port | iPhone (VID_05AC, class=Image) | **BLOCKED** — fast-path or WMI |
| Any port | Android MTP (class=WPD) | **BLOCKED** — fast-path or WMI |
| Any port | Rubber Ducky | **BLOCKED** — threat block |
| Any port | FTDI relay (VID_0403) | **ALLOWED** — Infrastructure |
| Any port | JAC 5G dongle (VID_322B) | **ALLOWED** — Infrastructure + container cache seeded |

---

## 5. Post-Deploy Validation Steps (Operator Guide)

1. Run `.\Verify_Lockdown.ps1` → confirm `Status: HEALTHY`, `Errors: 0`.
2. Unplug and re-plug the JAC 5G dongle.  
   Wait 15–30 seconds for mode-switch to complete.  
   Log must show `ALLOWED ... Infrastructure` for `VID_322B&PID_1914` **and** `ALLOWED ... ContainerAllow` for the modem interfaces.  
   File `C:\ProgramData\AutoLockdown\ContainerAllowCache.json` must exist and contain a non-expired entry.
3. Confirm keyboard and mouse still work.
4. Plug in an unknown USB flash drive — must be blocked within 1 second.

---

## 6. Rollback Notes

### Version Rollback (4.8.0 → 4.7.1)

```powershell
(Get-Content AutoLockdown.ps1)  -replace "4\.8\.0", "4.7.1" | Set-Content AutoLockdown.ps1
(Get-Content Reset_Lockdown.ps1) -replace "4\.8\.0", "4.7.0" | Set-Content Reset_Lockdown.ps1
(Get-Content Verify_Lockdown.ps1) -replace "4\.8\.0", "4.7.0" | Set-Content Verify_Lockdown.ps1
(Get-Content INSTRUCTIONS.md)   -replace "4\.8\.0", "4.7.0" | Set-Content INSTRUCTIONS.md
```

### Container-Allow Logic Rollback

Remove the following sections from `AutoLockdown.ps1`:
- `$ContainerAllowCacheFile` and `$CONTAINER_ALLOW_TTL_HOURS` constants.
- `Test-ValidContainerGuid`, `Load-ContainerCacheFast`, `Save-ContainerCacheFast`, `Add-ContainerToCache` functions in the watcher runspace.
- `Load-ContainerCacheFast` call at runspace startup.
- Container seeding block after `$isInfra` check in the fast-path watcher loop.
- Container cache check block after `$isInfra` check in the fast-path watcher loop.
- Container seeding block in WMI handler after `$isWmiInfra` block.
- Container cache check block before final `BLOCKED` in WMI handler.
- Container seeding and check blocks in `Protect-USBDevice`.
- Remove `ContainerAllowCachePath` and `ContainerAllowTTLHours` from `$watcherConfig` and `$messageData`.
- Remove `"ContainerAllowCache.json"` from `$filesToRemove` in `Reset_Lockdown.ps1`.

> ⚠️ **Rollback Warning:** Reverting the container-allow logic means the JAC 5G dongle's modem-mode interfaces will again be blocked by the fast-path watcher immediately after mode-switch. Only roll back if the patch itself causes issues; document the reason.

---

## 7. Git Reference

```bash
# Show files changed in this patch
git diff --name-only HEAD~1

# Show full diff
git diff HEAD~1

# Revert this patch commit
git revert HEAD
```

---

## 2. HID Allow-Logic Hardening (Fast-Path Registry Watcher)

### Problem Statement

In the previous fast-path logic, when a trusted HID vendor device was detected but the
Windows registry `Class` value had not yet been written (device still enumerating), the
device fell through to the whitelist/block decision.  In enforcement mode with a freshly
plugged-in keyboard or mouse that was **not** in the whitelist (e.g., a replacement
keyboard), this caused a transient block.  The WMI secondary handler then saw the device
as already disabled (`Status = Error`) and skipped re-evaluation, leaving the keyboard or
mouse permanently blocked until the next reboot or re-initialization.

This affects both USB-A and USB-C connections equally (Windows class assignment is
connector-agnostic).

### Search Pattern — Locate the Fast-Path HID Block

```powershell
Select-String -Path AutoLockdown.ps1 -Pattern "Start-RegistryWatcher|HID_CLASS_GUIDS|knownInstanceIds\.Remove"
```

### Expected Code Block After Patch

The section immediately following the infrastructure-allow check should contain:

1. Reads **both** `Class` **and** `ClassGUID` from the instance registry key.
2. Defines `$HID_CLASS_GUIDS` with three GUIDs:
   - `{4D36E96B-E325-11CE-BFC1-08002BE10318}` — Keyboard
   - `{4D36E96F-E325-11CE-BFC1-08002BE10318}` — Mouse / Pointer
   - `{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}` — Human Interface Device
3. First allow check: `$isHIDVendor -and $regClass -and $HID_REGISTRY_CLASSES -contains $regClass`
4. Second allow check (ClassGUID fallback): `$isHIDVendor -and $regClassGuid -and $HID_CLASS_GUIDS -contains $regClassGuid`
5. **Defer / re-queue** check: `$isHIDVendor -and (-not $regClass) -and (-not $regClassGuid)` →  
   removes instance from `$knownInstanceIds` and `continue`s so the next 250 ms poll re-evaluates.

### Validation Commands

```powershell
# Confirm ClassGUID constant is present
Select-String -Path AutoLockdown.ps1 -Pattern "4D36E96B"
Select-String -Path AutoLockdown.ps1 -Pattern "4D36E96F"
Select-String -Path AutoLockdown.ps1 -Pattern "745A17A0"

# Confirm defer logic is present
Select-String -Path AutoLockdown.ps1 -Pattern "DEFERRED"

# Confirm knownInstanceIds.Remove is present in watcher
Select-String -Path AutoLockdown.ps1 -Pattern "knownInstanceIds\.Remove"
```

All five commands must return at least one match.

---

## 3. Acceptance Test Matrix

### 3.1 Version Acceptance

| Check | Command | Expected Output |
|-------|---------|-----------------|
| AutoLockdown version | `(.\AutoLockdown.ps1 -ShowStatus 2>&1)[0]` or `Select-String AutoLockdown.ps1 '\$ScriptVersion'` | `4.7.0` |
| Reset version | `Select-String Reset_Lockdown.ps1 '\$ScriptVersion'` | `4.7.0` |
| Verify version | `Select-String Verify_Lockdown.ps1 '\$ScriptVersion'` | `4.7.0` |
| Fast-Path Watcher check | `.\Verify_Lockdown.ps1` | `Fast-Path Watcher: PASS … monitor v4.7.0` |

### 3.2 HID Behavior Test Matrix

| Scenario | Device | Expected Result | How to Verify |
|----------|--------|-----------------|---------------|
| USB-A direct | Standard keyboard (trusted VID) | **ALLOWED** — `[SUCCESS] ALLOWED … Trusted HID` in Security.log | Plug in, check log |
| USB-A direct | Standard mouse (trusted VID) | **ALLOWED** — `[SUCCESS] ALLOWED … Trusted HID` in Security.log | Plug in, check log |
| USB-C direct | Keyboard via USB-C port | **ALLOWED** — same log entry | Plug in via USB-C, check log |
| USB-C direct | Mouse via USB-C port | **ALLOWED** — same log entry | Plug in via USB-C, check log |
| USB-C hub/dock | Keyboard via dock | **ALLOWED** — same log entry | Plug in via dock, check log |
| USB-C hub/dock | Mouse via dock | **ALLOWED** — same log entry | Plug in via dock, check log |
| Any port | iPhone (VID_05AC, class=Image) | **BLOCKED** — `[BLOCK] BLOCKED … enforcement (fast-path)` or WMI block | Plug in, check log |
| Any port | Android phone (MTP, class=WPD) | **BLOCKED** — fast-path or WMI block | Plug in, check log |
| Any port | USB Rubber Ducky (VID_03EB&PID_2403) | **BLOCKED** — `[BLOCK] BLOCKED … Threat:` | Check ThreatDB match |
| Any port | Bash Bunny (VID_F000&PID_CAFE) | **BLOCKED** — threat block | Check ThreatDB match |
| Any port | O.MG Cable (VID_1D6B&PID_0104) | **BLOCKED** — threat block | Check ThreatDB match |
| Any port | FTDI relay (VID_0403) | **ALLOWED** — `[SUCCESS] ALLOWED … Infrastructure` | Plug in, check log |
| Any port | JAC 5G dongle (VID_322B) | **ALLOWED** — `[SUCCESS] ALLOWED … Infrastructure` | Plug in, check log |

### 3.3 Log Verification Commands

```powershell
# View last 30 lines of security log
Get-Content C:\ProgramData\AutoLockdown\Security.log -Tail 30

# Filter for HID allow events
Get-Content C:\ProgramData\AutoLockdown\Security.log | Where-Object { $_ -match "Trusted HID|HIDClass" }

# Filter for fast-path defer events (new in 4.7.0)
Get-Content C:\ProgramData\AutoLockdown\Security.log | Where-Object { $_ -match "DEFERRED" }

# Filter for block events
Get-Content C:\ProgramData\AutoLockdown\Security.log | Where-Object { $_ -match "\[BLOCK\]" }
```

---

## 4. Post-Deploy HID Validation Steps (Operator Guide)

Run these steps after deploying v4.7.0 and before leaving the site:

1. **Run Verify_Lockdown:**
   ```powershell
   .\Verify_Lockdown.ps1
   ```
   Confirm: `Status: HEALTHY`, `Fast-Path Watcher: PASS`, `Errors: 0`.

2. **Unplug and re-plug the keyboard:**
   Wait 5 seconds. Keyboard input must be responsive. Check the log for `[SUCCESS] ALLOWED … Trusted HID`.

3. **Unplug and re-plug the mouse:**
   Same as above.

4. **If using a USB-C dock or hub:**
   Disconnect and reconnect the dock. All HID devices attached via dock must recover automatically.

5. **Plug in a test USB flash drive (not whitelisted):**
   Drive must appear blocked in the log (`[BLOCK]`) within 1 second. The drive should not mount in Explorer.

6. **Check for DEFERRED log entries:**
   If any `[DEFERRED]` lines appear for your keyboard or mouse, confirm they are followed by a corresponding `[SUCCESS] ALLOWED` entry within the next 500 ms (two polls). If not, file a support issue.

---

## 5. Rollback Notes

If this patch needs to be reverted, apply the following changes manually or via `git revert`:

### Version Rollback (4.7.0 → 4.6.0)

```powershell
# In each file, replace version string
(Get-Content AutoLockdown.ps1)  -replace "4\.7\.0", "4.6.0" | Set-Content AutoLockdown.ps1
(Get-Content Reset_Lockdown.ps1) -replace "4\.7\.0", "4.6.0" | Set-Content Reset_Lockdown.ps1
(Get-Content Verify_Lockdown.ps1) -replace "4\.7\.0", "4.6.0" | Set-Content Verify_Lockdown.ps1
(Get-Content INSTRUCTIONS.md)   -replace "4\.7\.0", "4.6.0" | Set-Content INSTRUCTIONS.md
```

### HID Logic Rollback

Locate the section starting with `# --- Check trusted HID vendors with registry-class guard ---`
in `AutoLockdown.ps1` (inside the `Start-RegistryWatcher` function) and replace the
hardened block with the original logic:

```powershell
# Original pre-patch logic (v4.6.0):
$regClass = $null
try {
    $regClass = (Get-ItemProperty $instanceKey.PSPath -Name "Class" -ErrorAction SilentlyContinue).Class
} catch {}

$isHIDVendor = $false
foreach ($vendor in $HIDVendors) {
    if ($idUpper -match [regex]::Escape($vendor.ToUpper())) { $isHIDVendor = $true; break }
}
if ($isHIDVendor -and $regClass -and $HID_REGISTRY_CLASSES -contains $regClass) {
    Write-WatcherLog "ALLOWED $vidpid - Trusted HID vendor" -Level "SUCCESS"
    continue
}
# If vendor is in the HID list but:
#   - Class value is not yet set (device still enumerating), OR
#   - Class is non-HID (e.g. Apple iPhone: VID_05AC, class=Image/WPD)
# fall through to the whitelist/block decision.
```

> ⚠️ **Rollback Warning:** Reverting the HID logic change re-introduces the transient block
> issue for legitimate keyboards/mice on first plug-in when not already in the whitelist.
> Only roll back if the patch itself causes issues; document the reason for the rollback.

---

## 6. Git Reference

```bash
# Show files changed in this patch
git diff --name-only HEAD~1

# Show full diff
git diff HEAD~1

# Revert this patch commit
git revert HEAD
```
