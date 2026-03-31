# AutoLockdown Project Context
**Version Reference:** v4.6.0
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
