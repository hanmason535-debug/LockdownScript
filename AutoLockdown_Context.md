# AutoLockdown Project Context
**Version Reference:** v4.7.0
**Repository:** hanmason535-debug/LockdownScript

## Overview
**AutoLockdown** is an enterprise USB security hardening suite designed specifically for Intel NUC systems running Windows 10/11 (64-bit). The project provides real-time monitoring and strict enforcement of connected USB devices to protect environments against unauthorized access, rogue peripherals, and known attack vectors.

The suite is comprised entirely of PowerShell (v5.1+) scripts and relies heavily on background tasks, WMI event subscriptions, and fast-polling registry watchers.

## Core Components
The repository contains three main scripts:

### 1. `AutoLockdown.ps1` (The Engine)
This is the primary script responsible for deploying, initializing, and maintaining the security state.
- **Learning Mode:** When initialized, it starts a learning window (default 3 hours) where any connected USB devices are automatically added to an allowed whitelist (`USB_Whitelist.json`).
- **Enforcement Mode:** Once the learning window expires, any unapproved USB devices are actively blocked and disabled.
- **Fast-Path Blocking:** Polls the Windows registry (`HKLM:\SYSTEM\CurrentControlSet\Enum\USB`) every 250 ms to immediately sever access for unauthorized storage and mobile devices (iOS/Android MTP/PTP) *before* the OS can load their drivers.
- **Threat Detection & Filtering:** Protects against malicious Human Interface Devices (HIDs) like Rubber Duckies and O.MG Cables while utilizing a trusted list of ~93 HID vendors to ensure standard keyboards and mice continue working. Allows infrastructure components (e.g., FTDI relay antennas, JAC 5G dongles) to bypass the block.

### 2. `Verify_Lockdown.ps1` (The Auditor)
A diagnostic tool used to perform health checks and validate the suite's deployment.
- Analyzes over 20+ pass/fail criteria.
- Returns clear status conditions (`HEALTHY`, `WARNING`, `ERROR`).
- Can export state data to JSON reports and offers an interactive dashboard mode for engineers to ensure proper installation before leaving a site.

### 3. `Reset_Lockdown.ps1` (The Uninstaller)
A strict cleanup utility that reverts the system back to its original pre-deployment state.
- Stops background monitor processes and removes WMI subscriptions.
- Unblocks all disabled network adapters and USB devices.
- Clears created configurations/registries while creating backup state snapshots.
- Used both for permanent uninstallation and for wiping the slate clean during troubleshooting.

## File System & Architecture
Once deployed, AutoLockdown builds its environment primarily within `C:\ProgramData\AutoLockdown\`. Critical files include:
- **`Security.log`:** A continuous tracking log for events, blocks, and newly learned devices. Rotates automatically at 50 MB.
- **`USB_Whitelist.json` & `Network_Whitelist.json`:** Approved devices and adapters learned during initialization.
- **`Learning_State.json`:** Tracks mode and timing. Protected via DPAPI encryption.
- **`ThreatDB.json` & `Trusted_HID.json`:** Signature databases for known threats and approved vendors.
- **`EMERGENCY_BYPASS`:** A file trigger that grants a temporary 30-minute bypass for critical physical interventions.

## Workflow Overview
1. **Pre-Deployment:** Engineers connect all required devices (HID, 5G dongles, Network lines).
2. **Initialization:** Run `.\AutoLockdown.ps1 -Initialize` in elevated PowerShell.
3. **Validation:** Run `.\Verify_Lockdown.ps1` and confirm zero errors.
4. **Enforcement:** Leave the site. After 3 hours, the system seamlessly locks out any future untrusted modifications.

## HID (Keyboard/Mouse) Allow Logic — USB-A and USB-C

### Design Principle
HID allowlisting is based exclusively on **device vendor identity (VID) and device class**, not on physical port type. A trusted keyboard or mouse is permitted regardless of whether it is connected via a USB-A port, a USB-C port, or through a USB hub — the Windows USB enumeration subsystem places all USB devices under the same registry hive (`HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_XXXX&PID_YYYY`) regardless of physical connector type.

### Two Enforcement Paths

| Path | Trigger | HID Check |
|---|---|---|
| **Fast-path registry watcher** | New key under `Enum\USB` (250 ms poll) | VID in `$TRUSTED_HID_VENDORS` AND early `Class` registry value in `{"HIDClass","HID","Keyboard","Mouse","Human Interface Device"}` |
| **WMI catch-all handler** | `Win32_PnPEntity` creation event (≤1 s) | `$fullDev.Class` in `{"Keyboard","Mouse","HIDClass"}` AND VID in loaded `Trusted_HID.json` vendors |

### Known Race Condition (Fixed in v4.7.0)
**Root cause:** The fast-path watcher reads the `Class` registry value that Windows writes early during enumeration. If the 250 ms poll fires in the narrow window *after* the `VID_XXXX&PID_YYYY\<serial>` key is created but *before* Windows writes `Class`, the guard condition (`$regClass -and ...`) evaluates false. The device falls through to the whitelist/block decision. In enforcement mode, an unwhitelisted trusted HID device (keyboard or mouse) would be disabled by the fast-path watcher before the class was known.

Previously the WMI catch-all handler contained an early-return dedup check that skipped all devices already in `Status = Error` (i.e., disabled by the fast-path watcher), meaning a keyboard or mouse blocked by the race condition could not be recovered automatically.

**Fix (v4.7.0):** Before returning on `Status = Error`, the WMI handler now:
1. Loads the HID vendor list and threat database.
2. Checks whether the device class is `Keyboard`, `Mouse`, or `HIDClass` AND the VID matches a trusted vendor AND the device is **not** a known threat.
3. If all three conditions are met, the device is re-enabled via `Enable-PnpDevice` and a `RE-ENABLED … Trusted HID (fast-path race-condition recovery)` entry is written to the security log.

This fix applies equally to USB-A and USB-C connections because the recovery logic is solely class- and vendor-based.

### Remaining Risks
- **Threat DB coverage:** A malicious HID device using a spoofed VID from the trusted vendor list could be re-enabled if it also presents as `HIDClass`. Mitigation: the threat database is checked first — any VID/PID in `ThreatDB.json` is never re-enabled.
- **Class spoofing:** A storage or mobile device that misreports its class as `HIDClass` could bypass the guard. Mitigation: the fast-path watcher's class guard (which reads `Class` before the driver binds) provides the primary defense; the WMI path adds the vendor check as a second gate.
- **First-plug during enforcement:** A *new* keyboard or mouse (VID not in the trusted list) connected for the first time during enforcement mode will be blocked. Engineers should connect all HID devices during the learning window so they are whitelisted.
