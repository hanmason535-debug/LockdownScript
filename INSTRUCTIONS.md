# AutoLockdown Field Deployment Guide
**Version 4.9.3** | Created by: Meet Gandhi (Product Security Engineer)

---

## Table of Contents
1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Deployment Steps](#deployment-steps)
5. [Learning Window](#learning-window)
6. [Post-Deployment Verification](#post-deployment-verification)
7. [Script Reference](#script-reference)
8. [Files Created](#files-created)
9. [Troubleshooting](#troubleshooting)
10. [Exit Checklist](#exit-checklist)

---

## Overview

AutoLockdown is an enterprise USB security hardening suite for Intel NUC systems. It consists of three PowerShell scripts:

| Script | Purpose |
|---|---|
| **AutoLockdown.ps1** | Main script â€” initializes protection, monitors USB events, enforces blocking |
| **Verify_Lockdown.ps1** | Health check â€” validates deployment, reports system status |
| **Reset_Lockdown.ps1** | Cleanup â€” removes all components, restores system to pre-deployment state |

### How It Works
1. **Learning Mode** (default: 3 hours) â€” Automatically whitelists all currently connected and newly plugged USB devices
2. **Enforcement Mode** (after learning expires) â€” Blocks all unauthorized USB devices, allows only whitelisted ones
3. **Fast-Path Blocking** â€” A registry watcher polls `HKLM:\SYSTEM\CurrentControlSet\Enum\USB` every 250 ms and disables unknown devices **before the OS can load any driver**, including iOS (Apple MTP) and Android (MTP/PTP) storage interfaces. Standard USB storage is blocked in under 500 ms; iOS/Android internal storage is blocked before Apple/Android drivers install (preventing the 30â€“40 second window seen without this layer).
4. **HID Protection** â€” Always allows trusted keyboard/mouse vendors (~93 vendors); uses the registry device Class value to correctly reject non-HID devices sharing a HID vendor ID (e.g. iPhones use Apple `VID_05AC` but class `Image`/`WPD`, not `HIDClass`)
5. **Infrastructure Bypass** â€” FTDI relay antennas and JAC 5G dongles are never blocked. The suite also learns the exact physical USB port (via `ContainerId`) of JAC dongles, ensuring temporary "mode-switched" modem/RNDIS nodes from the same dongle are instantly allowed.
6. **Threat Detection** â€” Blocks known attack devices (Rubber Ducky, Bash Bunny, O.MG Cable, etc.)

---

## Requirements

- **OS:** Windows 10/11 (64-bit)
- **PowerShell:** 5.1 or higher
- **Privileges:** Administrator (mandatory â€” scripts will not run without elevation)
- **Disk Space:** Minimum 10 MB free on C: drive

---

## Pre-Deployment Checklist (5 minutes)

**Before running initialization, connect ALL devices the NUC will use:**

- âœ… Keyboard, mouse
- âœ… 5G USB dongle (JAC)
- âœ… FTDI relay antenna
- âœ… USB hubs, card readers, any other peripherals
- âœ… Network cables (Ethernet)

> âš ï¸ **Why?** The script learns connected devices during initialization. Any new device plugged in after the learning window closes **will be blocked**.

**Copy all three scripts to the same folder** (e.g., Desktop):
```
AutoLockdown.ps1
Verify_Lockdown.ps1
Reset_Lockdown.ps1
```

---

## Deployment Steps (10 minutes)

### Step 1 â€” Open PowerShell as Administrator
Right-click Start â†’ **Windows Terminal (Admin)** or **PowerShell (Admin)**

### Step 2 â€” Navigate to the script folder
```powershell
cd $env:USERPROFILE\Desktop
```

### Step 3 â€” Run Initialization
```powershell
.\AutoLockdown.ps1 -Initialize
```

**Expected output:**
```
âœ“ Green messages for each step
Protection Status: âœ“ ACTIVE
Learning Window: ACTIVE (expires HH:MM)
```

> âš ï¸ If you see **REBOOT REQUIRED**: Reboot the machine immediately, then run `Verify_Lockdown.ps1` to confirm.

#### Custom Learning Window
To use a different learning duration (default is 5 minutes):
```powershell
# 4-hour learning window
.\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 240

# 5-minute learning window
.\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 5
```

#### Dry Run (Preview)
See what would happen without making any changes:
```powershell
.\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 5 -WhatIf
```

### Step 4 â€” Verify Deployment (MANDATORY)
```powershell
.\Verify_Lockdown.ps1
```

**MUST SEE:**
```
  Status: HEALTHY
  Passed: 22
  Errors: 0
```

> ðŸš« **If errors > 0:** DO NOT LEAVE SITE. Review the errors and re-initialize.

---

## Learning Window

| Aspect | Detail |
|---|---|
| **Default duration** | 5 minutes |
| **What it does** | Auto-whitelists any USB device plugged in during this period |
| **After expiry** | Auto-transitions to Enforcement mode â€” only whitelisted devices allowed |
| **Survives reboots** | Yes â€” the window resumes where it left off if the NUC restarts |
| **Test it** | Plug in a USB drive during the window â†’ should see `[LEARNED]` in the security log |

### Extending Learning
If you need more time after initialization:
```powershell
# Extend by 60 minutes (default)
.\AutoLockdown.ps1 -ExtendLearning

# Extend by a custom duration
.\AutoLockdown.ps1 -ExtendLearning -ExtendMinutes 90
```

### Manually Adding a Device After Deployment
```powershell
.\AutoLockdown.ps1 -AddDevice -DeviceVidPid "VID_1234&PID_5678" -DeviceName "My Device"
```

---

## Post-Deployment Verification

### Basic Verification
```powershell
.\Verify_Lockdown.ps1
```

### Detailed Verification (shows extra diagnostics)
```powershell
.\Verify_Lockdown.ps1 -Detailed
```

### Export Report to File
```powershell
.\Verify_Lockdown.ps1 -ExportReport -OutputPath "C:\Reports"
```
Saves a JSON report to `C:\Reports\AutoLockdown_Verification_<timestamp>.json`

### Interactive GUI Dashboard
```powershell
.\Verify_Lockdown.ps1 -Interactive
```
Opens a visual dashboard with pass/warn/fail counts and check details.

### View Security Status Dashboard
```powershell
.\AutoLockdown.ps1 -ShowStatus
```
Shows a full GUI dashboard with USB device details, network status, and mode info.

---

## Script Reference

### AutoLockdown.ps1

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Initialize` | Switch | â€” | Initialize system protection and start learning mode |
| `-Monitor` | Switch | â€” | Start real-time USB monitoring service (runs as background service) |
| `-ExtendLearning` | Switch | â€” | Extend the current learning window |
| `-AddDevice` | Switch | â€” | Manually add a device to the whitelist |
| `-DeviceVidPid` | String | â€” | VID&PID of device to add (use with `-AddDevice`) |
| `-DeviceName` | String | `"Manually Added"` | Friendly name for manually added device |
| `-ShowStatus` | Switch | â€” | Show security status GUI dashboard |
| `-Silent` | Switch | â€” | Suppress log messages to console and skip GUI dialogs; initialization summary still printed |
| `-LearningWindowMinutes` | Int | `5` | Learning window duration in minutes (used with `-Initialize`) |
| `-ExtendMinutes` | Int | `60` | Duration in minutes when extending learning (used with `-ExtendLearning`) |
| `-RebootDelaySeconds` | Int | `60` | Delay before reboot prompt (seconds) |
| `-EnableWatchdog` | Switch | â€” | Enable watchdog timer for monitor self-healing |
| `-EnableHealthCheck` | Switch | â€” | Enable health check HTTP endpoint |
| `-HealthCheckPort` | Int | `8765` | Port for health check endpoint |
| `-WhatIf` | Switch | â€” | Preview changes without applying them |

### Verify_Lockdown.ps1

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Detailed` | Switch | â€” | Show expanded diagnostic details for each check |
| `-ExportReport` | Switch | â€” | Export results as JSON report |
| `-Interactive` | Switch | â€” | Show GUI verification dashboard |
| `-OutputPath` | String | `"C:\Reports"` | Directory for exported reports |

**Exit Codes:**
| Code | Meaning |
|---|---|
| `0` | Healthy â€” all checks passed |
| `1` | Errors detected â€” critical issues found |
| `2` | Warnings only â€” functional but needs attention |

### Reset_Lockdown.ps1

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Force` | Switch | â€” | Skip confirmation prompt |
| `-KeepLogs` | Switch | â€” | Preserve log files after reset |
| `-KeepWhitelist` | Switch | â€” | Preserve whitelist files (useful for quick re-deploy) |
| `-Interactive` | Switch | â€” | Use GUI confirmation dialog |
| `-WhatIf` | Switch | â€” | Preview what would be removed |

**What Reset Does:**
1. Stops the monitor process
2. Removes WMI event subscription
3. Deletes the scheduled task
4. Re-enables all disabled network adapters
5. Unblocks all blocked USB devices
6. Restores AutoPlay and power settings
7. Removes registry keys (`HKLM:\SOFTWARE\AutoLockdown`)
8. Deletes configuration files and base directory
9. Creates a pre-reset backup snapshot in `%TEMP%`

---

## Files Created

AutoLockdown creates **10 files** in `C:\ProgramData\AutoLockdown\`:

| File | Purpose | Encrypted |
|---|---|---|
| `AutoLockdown.ps1` | Deployed copy of the main script | No |
| `Security.log` | Event and action logging (blocks, learns, errors) | No |
| `USB_Whitelist.json` | Whitelisted USB devices | No |
| `Network_Whitelist.json` | Whitelisted network adapters | No |
| `ThreatDB.json` | Known attack device signatures | No |
| `Learning_State.json` | Current mode and learning window expiry | âœ… DPAPI |
| `Deployment_Meta.json` | Deployment timestamp and machine info | No |
| `System_Backup.json` | Pre-deployment system state backup | No |
| `ContainerAllowCache.json` | Caches ContainerId GUIDs of JAC dongles for mode-switching bypass | No |
| `Trusted_HID.json` | Trusted keyboard/mouse vendor IDs (~93 vendors) | No |
| `monitor.lock` | Lock file indicating monitor is running (contains PID) | No |

**Additional files (created on demand):**

| File | Purpose |
|---|---|
| `EMERGENCY_BYPASS` | Emergency bypass flag (30-minute window) |
| `Security.log.1` â€“ `.5` | Rotated log archives (auto-rotated at 50 MB) |
| `*.bak1`, `*.bak2` | Automatic backup copies of JSON files (corruption recovery) |

### Files Used for Event Detection

| File | Role |
|---|---|
| `Security.log` | Logs all USB events, blocks, learns, and errors |
| `ThreatDB.json` | Matches connected device VID/PID against known attack signatures |
| `USB_Whitelist.json` | Determines if a connected USB device is authorized |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Monitoring failed to start | Reboot â†’ Run `.\Verify_Lockdown.ps1` |
| Network adapter blocked | Must be connected during init. Run `.\Reset_Lockdown.ps1` â†’ re-initialize |
| Keyboard/mouse blocked | Should not happen (93 HID vendors are auto-allowed). If it does, reboot and re-initialize |
| iOS/Android device not blocked quickly | Requires v4.7.0+ (fast-path watcher). Run `.\Verify_Lockdown.ps1` â€” check "Fast-Path Watcher: PASS". If WARN, re-initialize to deploy the updated script. |
| JAC dongle child devnodes blocked | Requires v4.8.0+. Ensure the dongle successfully seeded its ContainerId (check Security.log for a "Seeded Jac ContainerId" entry). |
| Need to remove AutoLockdown | Run `.\Reset_Lockdown.ps1` â†’ Reboot |
| Add a device after deployment | First try: `.\AutoLockdown.ps1 -AddDevice -DeviceVidPid "VID_XXXX&PID_YYYY" -DeviceName "My Device"`. If that fails: Reset â†’ Connect device â†’ Re-initialize |
| Quick re-deploy (keep whitelist) | Run `.\Reset_Lockdown.ps1 -KeepWhitelist` â†’ Re-initialize |
| FTDI/5G dongle blocked | Should never happen (always-allowed). Verify VID matches `VID_0403` (FTDI) or `VID_322B` (JAC) |
| Emergency access needed | Create an empty file at `C:\ProgramData\AutoLockdown\EMERGENCY_BYPASS` â€” gives 30-minute bypass |
| Log file too large | Auto-rotates at 50 MB, keeps up to 5 archives |

### Quick Commands
```powershell
# Initialize with 4-hour learning window
.\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 240

# Detailed verification
.\Verify_Lockdown.ps1 -Detailed

# View recent security events
Get-Content C:\ProgramData\AutoLockdown\Security.log -Tail 20

# Export verification report
.\Verify_Lockdown.ps1 -ExportReport -OutputPath "C:\Reports"

# Reset and keep logs for analysis
.\Reset_Lockdown.ps1 -KeepLogs

# Force reset (no confirmation)
.\Reset_Lockdown.ps1 -Force

# Dry run reset (preview only)
.\Reset_Lockdown.ps1 -WhatIf
```

---

## Exit Checklist

Before leaving site, confirm all boxes:

- [ ] `Verify_Lockdown.ps1` shows **Status: HEALTHY**
- [ ] All required peripherals tested and working
- [ ] Learning window status noted (time remaining or already enforced)
- [ ] No critical failures in verification
- [ ] FTDI relay and 5G dongle confirmed operational
- [ ] Remote access (LogMeIn) confirmed working â€” display/sleep set to "Never"

**âœ… Safe to leave site when all boxes checked.**

---

## Key Paths

| Item | Location |
|---|---|
| Configuration & Data | `C:\ProgramData\AutoLockdown\` |
| Security Log | `C:\ProgramData\AutoLockdown\Security.log` |
| Verification Reports | `C:\Reports\` (or custom `-OutputPath`) |
| Pre-reset Backups | `%TEMP%\AutoLockdown_PreReset_*.json` |
| Reset Log Backup | `%TEMP%\AutoLockdown_Reset_*.log` |

**Rollback:** Run `.\Reset_Lockdown.ps1` to fully restore the system to its pre-deployment state. Reboot after reset.

---

*AutoLockdown v4.9.3 â€” Enterprise USB Security Hardening Suite*

