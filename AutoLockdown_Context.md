# AutoLockdown Project Context
**Version Reference:** v4.7.0
**Repository:** hanmason535-debug/LockdownScript

## Overview
**AutoLockdown** is an enterprise USB security hardening suite designed specifically for Intel NUC systems running Windows 10/11 (64-bit). The project provides real-time monitoring and strict enforcement of connected USB devices to protect environments against unauthorized access, rogue peripherals, and known attack vectors.

The suite is comprised entirely of PowerShell (v5.1+) scripts and relies on background tasks, WMI event subscriptions, and fast-polling registry watchers.

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

## HID Allow Logic (USB-A and USB-C)
Allow/deny decisions are based entirely on **device class, ClassGUID, and vendor identity** — not on the physical connector type (USB-A vs USB-C). Both connector types use identical policy evaluation paths:

### Normal Monitoring Path (`Protect-USBDevice`)
1. Check emergency bypass → allow all.
2. Check device Class (`Keyboard`, `Mouse`, `HIDClass`) **and** `Test-TrustedHIDVendor` → allow.
3. Check always-allowed infrastructure (FTDI, JAC) → allow.
4. Check USB whitelist → allow if present.
5. Check threat database → block if matched.
6. Learning mode → add to whitelist and allow; Enforcement mode → block.

### Fast-Path Registry Watcher Path (250 ms polling)
1. Check emergency bypass → allow.
2. Check always-allowed infrastructure vendors → allow.
3. Check `Class` registry value (written early by Windows):
   - If Class is a known HID class name **and** vendor is trusted → allow.
4. Check `ClassGUID` registry value (written slightly before Class string):
   - If ClassGUID matches `{4D36E96B}` (keyboard), `{4D36E96F}` (mouse), or `{745A17A0}` (HID) **and** vendor is trusted → allow.
5. **Defer if class not yet written:** If vendor is trusted HID but neither `Class` nor `ClassGUID` exists yet (device still enumerating), re-queue for next poll instead of blocking. This prevents transient blocking of legitimate keyboards/mice before the OS writes their class. Non-HID devices (e.g., iPhones with `VID_05AC`, class `Image`/`WPD`) will have their class written within one or two polls and will correctly fall through to the block path.
6. If class is present but non-HID → fall through to whitelist/block decision.
7. Check learning mode → allow.
8. Check whitelist → allow.
9. Enforcement mode → block immediately (pre-driver).

### Key Invariants
- A device connected via USB-C through a hub or dock is enumerated identically to USB-A; Windows assigns the same class/GUID regardless of physical connector.
- The HID vendor list (`Trusted_HID.json`, ~93 vendors) is the sole trust anchor; physical port is irrelevant.
- Threat-device blocking (Rubber Ducky, Bash Bunny, O.MG Cable, etc.) is enforced in both paths and is not affected by connector type.

## Workflow Overview
1. **Pre-Deployment:** Engineers connect all required devices (HID, 5G dongles, Network lines).
2. **Initialization:** Run `.\AutoLockdown.ps1 -Initialize` in elevated PowerShell.
3. **Validation:** Run `.\Verify_Lockdown.ps1` and confirm zero errors.
4. **Enforcement:** Leave the site. After 3 hours, the system seamlessly locks out any future untrusted modifications.
